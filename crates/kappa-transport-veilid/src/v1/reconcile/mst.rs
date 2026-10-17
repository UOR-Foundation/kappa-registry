//! MST diff initiator: names of tags in ranges where local and remote
//! namespace trees diverge.

use std::time::Duration;

use kappa_reconcile::NamespaceMst;
use kappa_store::traits::{NamespaceStore, TagStore};
use kappa_types::namespace::NamespaceRef;
use kappa_types::page::PageRequest;

use rekindle_types::transport::Transport;

use super::wire::{MstSnapshotRequest, MstSnapshotResponse};
use super::{PROTO_MST_SNAPSHOT_REQ, PROTO_MST_SNAPSHOT_RESP};
use crate::error::TransportError;

pub(super) async fn try_mst_diff<T, S>(
    transport: &T,
    store: &S,
    peer_id: &str,
    ns_name: &str,
    ns_ref: &NamespaceRef,
    timeout: Duration,
) -> Result<Vec<String>, TransportError>
where
    T: Transport,
    S: NamespaceStore + TagStore + ?Sized,
{
    // Build local MST from all tags in this namespace
    let local_tags = store
        .tag_list(ns_ref, None, &PageRequest::first(100_000))
        .map_err(|e| TransportError::Internal(format!("tag_list for MST: {e}")))?;

    let mut local_mst = NamespaceMst::new(ns_name.to_string());
    for tag in &local_tags.items {
        local_mst.upsert(&tag.name, &tag.kappa.to_string());
    }

    let local_root = local_mst.root_hash();

    // Send MST snapshot request to peer
    let req = MstSnapshotRequest {
        namespace: ns_name.to_string(),
        local_root_hash: local_root,
    };
    let encoded = postcard::to_stdvec(&req)?;
    let mut request = vec![PROTO_MST_SNAPSHOT_REQ];
    request.extend_from_slice(&encoded);

    let response_bytes = tokio::time::timeout(timeout, transport.call_peer(peer_id, &request))
        .await
        .map_err(|_| TransportError::Timeout("MST snapshot exchange".into()))?
        .map_err(TransportError::from)?;

    if response_bytes.len() < 2 {
        return Err(TransportError::CodecError(
            "MST snapshot response too short".into(),
        ));
    }

    if response_bytes[0] != PROTO_MST_SNAPSHOT_RESP {
        return Err(TransportError::CodecError(format!(
            "expected 0x{PROTO_MST_SNAPSHOT_RESP:02x}, got 0x{:02x}",
            response_bytes[0]
        )));
    }

    let resp: MstSnapshotResponse = postcard::from_bytes(&response_bytes[1..])
        .map_err(|e| TransportError::CodecError(format!("MST snapshot decode: {e}")))?;

    if resp.page_ranges.is_empty() {
        return Err(TransportError::Internal("remote MST snapshot empty".into()));
    }

    // Reconstruct PageRangeSnapshot from the wire representation
    let remote_owned: Vec<merkle_search_tree::diff::OwnedPageRange<String>> = resp
        .page_ranges
        .into_iter()
        .map(|pr| {
            merkle_search_tree::diff::OwnedPageRange::new(
                pr.start,
                pr.end,
                merkle_search_tree::digest::PageDigest::new(pr.hash),
            )
        })
        .collect();
    let remote_snapshot: merkle_search_tree::diff::PageRangeSnapshot<String> = remote_owned.into();

    let local_snapshot = local_mst
        .snapshot()
        .map_err(|e| TransportError::Internal(format!("local MST snapshot: {e}")))?;

    let diff_ranges =
        merkle_search_tree::diff::diff(local_snapshot.snapshot.iter(), remote_snapshot.iter());

    // Collect all tag names that fall within inconsistent ranges.
    // The diff returns key ranges [start, end] where local and remote
    // diverge. We need all local tag names in those ranges, plus the
    // range boundaries themselves (the remote may have tags we lack).
    let mut inconsistent_names: Vec<String> = Vec::new();
    for range in &diff_ranges {
        let start = range.start();
        let end = range.end();
        // Add the range boundary tag names
        inconsistent_names.push(start.clone());
        if end != start {
            inconsistent_names.push(end.clone());
        }
        // Add all local tags within the range
        for tag in &local_tags.items {
            if tag.name.as_str() >= start.as_str()
                && tag.name.as_str() <= end.as_str()
                && !inconsistent_names.contains(&tag.name)
            {
                inconsistent_names.push(tag.name.clone());
            }
        }
    }

    inconsistent_names.sort();
    inconsistent_names.dedup();

    Ok(inconsistent_names)
}
