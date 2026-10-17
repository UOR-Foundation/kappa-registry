//! Per-peer initiator: compare epoch roots, pull divergent tags, apply each
//! namespace's tags as one published execution, then fetch missing blobs.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, info};

use kappa_store::ExecutionStore;
use kappa_store::time::Clock;
use kappa_store::traits::{BlobStore, EpochStore, NamespaceStore, TagStore};
use kappa_types::namespace::NamespaceRef;

use rekindle_types::transport::Transport;

use super::apply::apply_namespace_batch;
use super::blobs::{collect_missing_blobs, fetch_missing_blobs};
use super::mst::try_mst_diff;
use super::report::{PeerPhase, PeerReconcileOutcome};
use super::wire::{DiffPullRequest, DiffPullResponse, EpochRootResponse, TagEntryWire};
use super::{
    MAX_PULL_PAGES, MAX_PULL_TAGS, PROTO_DIFF_PULL_REQ, PROTO_DIFF_PULL_RESP, PROTO_EPOCH_ROOT_REQ,
    PROTO_EPOCH_ROOT_RESP, short_id,
};
use crate::error::TransportError;

pub(super) async fn reconcile_peer<T, S>(
    transport: &T,
    store: Arc<S>,
    clock: Arc<dyn Clock>,
    peer_id: &str,
    namespaces: &[(String, NamespaceRef)],
    timeout: Duration,
) -> PeerReconcileOutcome
where
    T: Transport,
    S: NamespaceStore
        + TagStore
        + EpochStore
        + BlobStore
        + ExecutionStore
        + Send
        + Sync
        + ?Sized
        + 'static,
{
    let start = Instant::now();
    let mut outcome = PeerReconcileOutcome::begin(peer_id.to_string(), PeerPhase::Comparing);

    for (ns_name, ns_ref) in namespaces {
        let remote_epoch = match tokio::time::timeout(
            timeout,
            fetch_epoch_root(transport, peer_id, ns_name),
        )
        .await
        {
            Ok(Ok(epoch)) => epoch,
            Ok(Err(e)) => {
                debug!(
                    peer = short_id(peer_id),
                    namespace = ns_name.as_str(),
                    error = %e,
                    "epoch root fetch failed, skipping namespace"
                );
                outcome.errors.push(format!("{ns_name}: {e}"));
                continue;
            }
            Err(_) => {
                outcome.phase = PeerPhase::Failed;
                outcome.errors.push(format!("{ns_name}: timeout"));
                outcome.elapsed = start.elapsed();
                return outcome;
            }
        };

        outcome.namespaces_compared += 1;

        // NotFound means no local epoch yet; any other failure skips the
        // namespace rather than treating it as divergent.
        let local_kappa = match kappa_store::absent(store.epoch_current(ns_ref)) {
            Ok(current) => current.map(|(_, kappa)| kappa.to_string()),
            Err(e) => {
                outcome.errors.push(format!("{ns_name} local epoch: {e}"));
                continue;
            }
        };

        if local_kappa.as_deref() == Some(&remote_epoch.root_kappa) {
            continue;
        }

        if remote_epoch.root_kappa.is_empty() {
            continue;
        }

        outcome.namespaces_divergent += 1;
        outcome.phase = PeerPhase::Pulling;

        let received = pull_namespace(
            transport,
            store.as_ref(),
            peer_id,
            ns_name,
            ns_ref,
            timeout,
            &mut outcome,
        )
        .await;
        let received =
            apply_received(&store, &clock, ns_name, ns_ref, received, &mut outcome).await;

        // After tag convergence for this namespace, check which
        // referenced blobs are missing from the local store and
        // fetch them from the peer. Small blobs under 31KB are
        // fetched inline via 0x07/0x08. Large blobs are queued
        // for transport over the bulk data lane with credit-based
        // flow control and chunked BLAKE3-verified delivery.
        let missing = collect_missing_blobs(store.as_ref(), &received);
        if !missing.is_empty() {
            let blob_report = fetch_missing_blobs(
                transport,
                Arc::clone(&store),
                Arc::clone(&clock),
                ns_ref,
                peer_id,
                &missing,
                timeout,
            )
            .await;

            if blob_report.fetched > 0 {
                info!(
                    peer = short_id(peer_id),
                    namespace = ns_name.as_str(),
                    fetched = blob_report.fetched,
                    deferred = blob_report.deferred.len(),
                    "blobs fetched after tag convergence"
                );
            }

            for d in &blob_report.deferred {
                debug!(
                    peer = short_id(peer_id),
                    namespace = ns_name.as_str(),
                    kappa = d.kappa.as_str(),
                    reason = d.reason.as_str(),
                    "blob deferred for later fetch"
                );
            }

            outcome.errors.extend(blob_report.errors);
        }
    }

    if outcome.errors.is_empty() || outcome.tags_applied > 0 {
        outcome.phase = PeerPhase::Applied;
    } else if outcome.phase != PeerPhase::Failed {
        outcome.phase = PeerPhase::Failed;
    }

    outcome.elapsed = start.elapsed();
    outcome
}

/// Pull every divergent tag of one namespace from the peer, across pages.
///
/// MST diff reduces bandwidth from O(N) to O(delta) by exchanging
/// 16-byte root hashes and page range snapshots, then pulling only
/// tag names that fall in inconsistent ranges. Falls back to full
/// paginated pull when MST exchange fails due to: empty namespace
/// on either side producing a degenerate MST, page range snapshot
/// exceeding 32KB app_call limit for very large namespaces, or
/// network timeout on the snapshot round-trip. A failed page ends the
/// pull; the tags already received are still applied.
async fn pull_namespace<T, S>(
    transport: &T,
    store: &S,
    peer_id: &str,
    ns_name: &str,
    ns_ref: &NamespaceRef,
    timeout: Duration,
    outcome: &mut PeerReconcileOutcome,
) -> Vec<TagEntryWire>
where
    T: Transport,
    S: NamespaceStore + TagStore + ?Sized,
{
    let mut received: Vec<TagEntryWire> = Vec::new();
    match try_mst_diff(transport, store, peer_id, ns_name, ns_ref, timeout).await {
        Ok(tag_names) => {
            debug!(
                peer = short_id(peer_id),
                namespace = ns_name,
                inconsistent_tags = tag_names.len(),
                "MST diff computed, pulling only inconsistent tags"
            );
            for chunk in tag_names.chunks(MAX_PULL_TAGS) {
                let page = match tokio::time::timeout(
                    timeout,
                    pull_tags(transport, peer_id, ns_name, chunk, None),
                )
                .await
                {
                    Ok(Ok(page)) => page,
                    Ok(Err(e)) => {
                        outcome
                            .errors
                            .push(format!("{ns_name} selective pull: {e}"));
                        break;
                    }
                    Err(_) => {
                        outcome
                            .errors
                            .push(format!("{ns_name} selective pull: timeout"));
                        break;
                    }
                };
                outcome.pull_pages += 1;
                outcome.tags_pulled += page.tags.len() as u32;
                received.extend(page.tags);
            }
        }
        Err(e) => {
            debug!(
                peer = short_id(peer_id),
                namespace = ns_name,
                error = %e,
                "MST diff failed, falling back to full paginated pull"
            );
            let mut cursor: Option<String> = None;
            let mut pages = 0u32;
            loop {
                if pages >= MAX_PULL_PAGES as u32 {
                    debug!(
                        peer = short_id(peer_id),
                        namespace = ns_name,
                        pages,
                        "hit MAX_PULL_PAGES, stopping pagination"
                    );
                    break;
                }
                let page = match tokio::time::timeout(
                    timeout,
                    pull_tags(transport, peer_id, ns_name, &[], cursor.as_deref()),
                )
                .await
                {
                    Ok(Ok(page)) => page,
                    Ok(Err(e)) => {
                        outcome
                            .errors
                            .push(format!("{ns_name} pull page {pages}: {e}"));
                        break;
                    }
                    Err(_) => {
                        outcome
                            .errors
                            .push(format!("{ns_name} pull page {pages}: timeout"));
                        break;
                    }
                };
                pages += 1;
                outcome.pull_pages += 1;
                outcome.tags_pulled += page.tags.len() as u32;
                received.extend(page.tags);
                if !page.truncated {
                    break;
                }
                cursor = page.next_cursor;
                if cursor.is_none() {
                    break;
                }
            }
        }
    }
    received
}

/// Apply one namespace's received tags as a single execution on a blocking
/// worker and fold the result into `outcome`. Returns the tags for blob
/// discovery.
async fn apply_received<S>(
    store: &Arc<S>,
    clock: &Arc<dyn Clock>,
    ns_name: &str,
    ns_ref: &NamespaceRef,
    received: Vec<TagEntryWire>,
    outcome: &mut PeerReconcileOutcome,
) -> Vec<TagEntryWire>
where
    S: ExecutionStore + Send + Sync + ?Sized + 'static,
{
    if received.is_empty() {
        return received;
    }
    let store = Arc::clone(store);
    let clock = Arc::clone(clock);
    let namespace = ns_ref.clone();
    let name = ns_name.to_string();
    let count = received.len() as u32;
    let applied = tokio::task::spawn_blocking(move || {
        let batch = apply_namespace_batch(store.as_ref(), &namespace, &name, &received, &*clock);
        (batch, received)
    })
    .await;
    match applied {
        Ok((batch, received)) => {
            outcome.tags_applied += batch.applied;
            outcome.tags_skipped += batch.skipped;
            outcome.errors.extend(batch.errors);
            received
        }
        Err(e) => {
            outcome.tags_skipped += count;
            outcome.errors.push(format!("{ns_name} apply task: {e}"));
            Vec::new()
        }
    }
}

// RPC helpers

async fn fetch_epoch_root<T: Transport>(
    transport: &T,
    peer_id: &str,
    namespace: &str,
) -> Result<EpochRootResponse, TransportError> {
    let mut request = vec![PROTO_EPOCH_ROOT_REQ];
    request.extend_from_slice(namespace.as_bytes());

    let response_bytes = transport
        .call_peer(peer_id, &request)
        .await
        .map_err(TransportError::from)?;

    if response_bytes.len() < 2 {
        return Err(TransportError::CodecError(
            "epoch root response too short".into(),
        ));
    }

    if response_bytes[0] != PROTO_EPOCH_ROOT_RESP {
        return Err(TransportError::CodecError(format!(
            "expected 0x{PROTO_EPOCH_ROOT_RESP:02x}, got 0x{:02x}",
            response_bytes[0]
        )));
    }

    postcard::from_bytes(&response_bytes[1..])
        .map_err(|e| TransportError::CodecError(format!("epoch root decode: {e}")))
}

async fn pull_tags<T: Transport>(
    transport: &T,
    peer_id: &str,
    namespace: &str,
    tag_names: &[String],
    cursor: Option<&str>,
) -> Result<DiffPullResponse, TransportError> {
    let pull_req = DiffPullRequest {
        namespace: namespace.to_string(),
        tag_names: tag_names.to_vec(),
        cursor: cursor.map(String::from),
    };
    let encoded = postcard::to_stdvec(&pull_req)?;

    let mut request = vec![PROTO_DIFF_PULL_REQ];
    request.extend_from_slice(&encoded);

    let response_bytes = transport
        .call_peer(peer_id, &request)
        .await
        .map_err(TransportError::from)?;

    if response_bytes.len() < 2 {
        return Err(TransportError::CodecError("pull response too short".into()));
    }

    if response_bytes[0] != PROTO_DIFF_PULL_RESP {
        return Err(TransportError::CodecError(format!(
            "expected 0x{PROTO_DIFF_PULL_RESP:02x}, got 0x{:02x}",
            response_bytes[0]
        )));
    }

    postcard::from_bytes(&response_bytes[1..])
        .map_err(|e| TransportError::CodecError(format!("pull response decode: {e}")))
}
