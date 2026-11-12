//! Per-peer initiator: compare epoch roots, pull divergent tags, apply each
//! namespace's tags as one published execution, then fetch missing blobs.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, info};

use kappa_reconcile::{InconsistentRange, ReconcileTransport};
use kappa_store::ExecutionStore;
use kappa_store::time::Clock;
use kappa_store::traits::{BlobStore, EpochStore, NamespaceStore, TagStore};
use kappa_types::namespace::NamespaceRef;

use super::apply::apply_namespace_batch;
use super::blobs::{collect_missing_blobs, fetch_missing_blobs};
use super::mst::try_mst_diff;
use super::report::{PeerPhase, PeerReconcileOutcome};
use super::wire::{DiffPullRequest, DiffPullResponse, EpochRootResponse, TagEntryWire};
use super::{
    MAX_PULL_PAGES, PROTO_DIFF_PULL_REQ, PROTO_DIFF_PULL_RESP, PROTO_EPOCH_ROOT_REQ,
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
    T: ReconcileTransport + ?Sized,
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

/// One page of the peer's tags: the named tags, or the page after
/// `cursor`, within `timeout`. A failure is pushed to `outcome.errors`
/// and returns `None`, ending the pull with what was received.
#[allow(
    clippy::too_many_arguments,
    reason = "one request: its target, its selection, its bound and where its outcome is folded"
)]
async fn pull_page<T>(
    transport: &T,
    peer_id: &str,
    ns_name: &str,
    tag_names: &[String],
    cursor: Option<&str>,
    timeout: Duration,
    outcome: &mut PeerReconcileOutcome,
    what: &str,
) -> Option<DiffPullResponse>
where
    T: ReconcileTransport + ?Sized,
{
    match tokio::time::timeout(
        timeout,
        pull_tags(transport, peer_id, ns_name, tag_names, cursor),
    )
    .await
    {
        Ok(Ok(page)) => {
            outcome.pull_pages += 1;
            outcome.tags_pulled += u32::try_from(page.tags.len()).unwrap_or(u32::MAX);
            Some(page)
        }
        Ok(Err(e)) => {
            outcome.errors.push(format!("{ns_name} {what}: {e}"));
            None
        }
        Err(_) => {
            outcome.errors.push(format!("{ns_name} {what}: timeout"));
            None
        }
    }
}

/// Pull every tag of the peer inside each inconsistent range, in full:
/// the range's start key by name (the paginated pull is exclusive of its
/// cursor), then every following page until a tag past the range's end or
/// the peer reports no more. Keys only the peer holds lie strictly inside
/// a range; pulling only the local names there would never fetch them.
/// Bounded by `MAX_PULL_PAGES` for the namespace as a whole.
async fn pull_ranges<T>(
    transport: &T,
    peer_id: &str,
    ns_name: &str,
    ranges: &[InconsistentRange],
    timeout: Duration,
    outcome: &mut PeerReconcileOutcome,
) -> Vec<TagEntryWire>
where
    T: ReconcileTransport + ?Sized,
{
    let mut received: Vec<TagEntryWire> = Vec::new();
    let mut pages = 0usize;
    'ranges: for range in ranges {
        let Some(first) = pull_page(
            transport,
            peer_id,
            ns_name,
            std::slice::from_ref(&range.start),
            None,
            timeout,
            outcome,
            "range start pull",
        )
        .await
        else {
            break;
        };
        pages += 1;
        received.extend(first.tags);
        if range.start == range.end {
            continue;
        }
        let mut cursor = Some(range.start.clone());
        loop {
            if pages >= MAX_PULL_PAGES {
                debug!(
                    peer = short_id(peer_id),
                    namespace = ns_name,
                    pages,
                    "hit MAX_PULL_PAGES, stopping range pull"
                );
                break 'ranges;
            }
            let Some(page) = pull_page(
                transport,
                peer_id,
                ns_name,
                &[],
                cursor.as_deref(),
                timeout,
                outcome,
                "range pull",
            )
            .await
            else {
                break 'ranges;
            };
            pages += 1;
            let mut past_end = false;
            for tag in page.tags {
                if tag.name > range.end {
                    past_end = true;
                    break;
                }
                received.push(tag);
            }
            if past_end || !page.truncated {
                break;
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
    }
    received
}

/// Pull every divergent tag of one namespace from the peer, across pages.
///
/// MST diff reduces bandwidth from O(N) to O(delta) by exchanging
/// 16-byte root hashes and page range snapshots, then pulling every peer
/// key inside the inconsistent ranges. Falls back to a full paginated pull
/// when the MST exchange fails: an empty namespace on either side, a page
/// range snapshot exceeding the 32KB app_call limit, or a timeout on the
/// snapshot round trip. A failed page ends the pull; the tags already
/// received are still applied.
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
    T: ReconcileTransport + ?Sized,
    S: NamespaceStore + TagStore + ?Sized,
{
    let mut received: Vec<TagEntryWire> = Vec::new();
    match try_mst_diff(transport, store, peer_id, ns_name, ns_ref, timeout).await {
        Ok(ranges) => {
            debug!(
                peer = short_id(peer_id),
                namespace = ns_name,
                inconsistent_ranges = ranges.len(),
                "MST diff computed, pulling the inconsistent ranges in full"
            );
            received
                .extend(pull_ranges(transport, peer_id, ns_name, &ranges, timeout, outcome).await);
        }
        Err(e) => {
            debug!(
                peer = short_id(peer_id),
                namespace = ns_name,
                error = %e,
                "MST diff failed, falling back to full paginated pull"
            );
            let mut cursor: Option<String> = None;
            let mut pages = 0usize;
            loop {
                if pages >= MAX_PULL_PAGES {
                    debug!(
                        peer = short_id(peer_id),
                        namespace = ns_name,
                        pages,
                        "hit MAX_PULL_PAGES, stopping pagination"
                    );
                    break;
                }
                let Some(page) = pull_page(
                    transport,
                    peer_id,
                    ns_name,
                    &[],
                    cursor.as_deref(),
                    timeout,
                    outcome,
                    "pull page",
                )
                .await
                else {
                    break;
                };
                pages += 1;
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

async fn fetch_epoch_root<T: ReconcileTransport + ?Sized>(
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

async fn pull_tags<T: ReconcileTransport + ?Sized>(
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
