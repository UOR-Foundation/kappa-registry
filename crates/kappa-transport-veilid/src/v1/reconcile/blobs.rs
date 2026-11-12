//! Missing blob discovery after tag convergence, and inline blob fetch.
//!
//! A fetched blob is prepared through the store under the identity the
//! tag names, so bytes that do not hash to it are refused before anything
//! is placed, and every blob fetched in one round is installed in one
//! published execution of the namespace whose tags name it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, warn};

use kappa_reconcile::ReconcileTransport;
use kappa_store::time::Clock;
use kappa_store::traits::BlobStore;
use kappa_store::{ContentIdentity, ExecutionStore, PreparationBounds, PreparedContent};
use kappa_types::kappa::Kappa;
use kappa_types::namespace::NamespaceRef;

use super::wire::{
    BlobFetchReport, BlobPullRequest, BlobPullResponse, DeferredBlob, MissingBlob, TagEntryWire,
};
use super::{PROTO_BLOB_PULL_REQ, PROTO_BLOB_PULL_RESP};

/// Largest blob the inline pull admits; larger blobs travel the bulk lane.
const INLINE_LIMIT: u64 = 31 * 1024;

/// Scan the tags that were just applied and collect kappas for blobs
/// that do not exist in the local store. These need to be fetched
/// from the peer that sent the tags. A blob whose existence cannot be
/// determined is logged and fetched; preparation verifies it either way.
pub(super) fn collect_missing_blobs<S>(store: &S, tags: &[TagEntryWire]) -> Vec<MissingBlob>
where
    S: BlobStore + ?Sized,
{
    let mut missing = Vec::new();
    for tag in tags {
        let Ok(parsed) = Kappa::parse(&tag.kappa) else {
            continue;
        };
        let exists = match store.blob_exists(&parsed) {
            Ok(exists) => exists,
            Err(e) => {
                warn!(kappa = tag.kappa.as_str(), error = %e, "blob existence check failed");
                false
            }
        };
        if !exists {
            missing.push(MissingBlob {
                kappa: tag.kappa.clone(),
                size_hint: None,
            });
        }
    }
    missing
}

/// Fetch missing blobs from a peer. Dispatches each blob by size:
///
/// Blobs with no size hint or size under 31KB: inline pull via
/// protocol byte 0x07/0x08 in a single app_call round-trip. The
/// response carries the blob bytes, which are prepared under the
/// claimed identity and installed with every other blob of the round
/// in one published execution of `namespace`.
///
/// Blobs over 31KB: the inline pull response returns too_large=true
/// with the blob size. These are added to the deferred list and
/// queued for transport over the bulk data lane with credit-based
/// flow control and chunked BLAKE3-verified delivery.
///
/// Blobs that fail to fetch for any reason: added to the deferred
/// list with the failure reason. The caller logs the deferred list.
/// The next reconciliation round rediscovers the same missing blobs
/// via blob_exists and retries.
pub async fn fetch_missing_blobs<T, S>(
    transport: &T,
    store: Arc<S>,
    clock: Arc<dyn Clock>,
    namespace: &NamespaceRef,
    peer_id: &str,
    missing: &[MissingBlob],
    timeout: Duration,
) -> BlobFetchReport
where
    T: ReconcileTransport + ?Sized,
    S: BlobStore + ExecutionStore + Send + Sync + ?Sized + 'static,
{
    let mut report = BlobFetchReport {
        fetched: 0,
        deferred: Vec::new(),
        errors: Vec::new(),
    };
    let mut prepared: Vec<(String, Box<dyn PreparedContent>)> = Vec::new();

    for blob in missing {
        let req = BlobPullRequest {
            kappa: blob.kappa.clone(),
        };
        let encoded = match postcard::to_stdvec(&req) {
            Ok(e) => e,
            Err(e) => {
                report.errors.push(format!("{}: encode: {e}", blob.kappa));
                continue;
            }
        };

        let mut request = vec![PROTO_BLOB_PULL_REQ];
        request.extend_from_slice(&encoded);

        let defer = |reason: String| DeferredBlob {
            kappa: blob.kappa.clone(),
            reason,
        };

        let response_bytes =
            match tokio::time::timeout(timeout, transport.call_peer(peer_id, &request)).await {
                Ok(Ok(resp)) => resp,
                Ok(Err(e)) => {
                    report.deferred.push(defer(format!("call failed: {e}")));
                    continue;
                }
                Err(_) => {
                    report.deferred.push(defer("timeout".into()));
                    continue;
                }
            };

        if response_bytes.len() < 2 {
            report.deferred.push(defer("response too short".into()));
            continue;
        }

        if response_bytes[0] != PROTO_BLOB_PULL_RESP {
            report.deferred.push(defer(format!(
                "unexpected protocol byte 0x{:02x}",
                response_bytes[0]
            )));
            continue;
        }

        let resp: BlobPullResponse = match postcard::from_bytes(&response_bytes[1..]) {
            Ok(r) => r,
            Err(e) => {
                report.deferred.push(defer(format!("decode: {e}")));
                continue;
            }
        };

        if resp.too_large {
            report.deferred.push(defer(format!(
                "blob is {} bytes, exceeds inline limit, queued for bulk data lane",
                resp.size
            )));
            continue;
        }

        if resp.data.is_empty() {
            report
                .deferred
                .push(defer("peer does not have this blob".into()));
            continue;
        }

        let parsed_kappa = match Kappa::parse(&blob.kappa) {
            Ok(k) => k,
            Err(e) => {
                report
                    .errors
                    .push(format!("{}: unparseable kappa: {e}", blob.kappa));
                continue;
            }
        };
        // Preparation hashes and places the bytes outside any writer; a
        // mismatch against the claimed identity is refused here.
        let preparer = Arc::clone(&store);
        let deadline = Instant::now() + timeout;
        let outcome = tokio::task::spawn_blocking(move || {
            preparer.prepare_content(
                ContentIdentity::Verified(parsed_kappa),
                &mut resp.data.as_slice(),
                PreparationBounds {
                    maximum: INLINE_LIMIT,
                    deadline,
                },
            )
        })
        .await;
        match outcome {
            Ok(Ok(content)) => prepared.push((blob.kappa.clone(), content)),
            Ok(Err(e)) => report.errors.push(format!("{}: prepare: {e}", blob.kappa)),
            Err(e) => report
                .errors
                .push(format!("{}: preparation task: {e}", blob.kappa)),
        }
    }

    if prepared.is_empty() {
        return report;
    }
    let namespace = namespace.clone();
    let installed =
        tokio::task::spawn_blocking(move || -> Result<usize, kappa_store::StoreError> {
            let mut execution = store.begin_execution(&namespace, &*clock)?;
            let count = prepared.len();
            for (kappa, content) in prepared {
                execution.content_install(content)?;
                debug!(kappa = kappa.as_str(), "blob fetched and installed");
            }
            execution.publish()?;
            Ok(count)
        })
        .await;
    match installed {
        Ok(Ok(count)) => report.fetched += count as u32,
        Ok(Err(e)) => report.errors.push(format!("blob installation: {e}")),
        Err(e) => report.errors.push(format!("blob installation task: {e}")),
    }
    report
}
