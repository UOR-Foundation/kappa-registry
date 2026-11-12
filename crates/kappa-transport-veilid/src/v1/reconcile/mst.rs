//! MST diff initiator: the inclusive key ranges of the peer's namespace
//! tree the local tree must fetch in full.
//!
//! The ranges come from `NamespaceMst::diff`, the one diff entry point,
//! over the peer's snapshot rebuilt from the wire. A range is fetched in
//! full by the caller (`peer::pull_namespace`): every key of the peer
//! inside it, not only the names the local tree already holds there,
//! because a key only the peer has lies strictly inside a range and is
//! what the diff found.

use std::time::Duration;

use kappa_reconcile::{InconsistentRange, MstSnapshot, NamespaceMst, ReconcileTransport};
use kappa_store::traits::{NamespaceStore, TagStore};
use kappa_types::namespace::NamespaceRef;
use kappa_types::page::PageRequest;

use super::wire::{MstSnapshotRequest, MstSnapshotResponse};
use super::{PROTO_MST_SNAPSHOT_REQ, PROTO_MST_SNAPSHOT_RESP};
use crate::error::TransportError;

/// The tags one local tree is built from.
const LOCAL_TREE_TAGS: usize = 100_000;

pub(super) async fn try_mst_diff<T, S>(
    transport: &T,
    store: &S,
    peer: &str,
    ns_name: &str,
    ns_ref: &NamespaceRef,
    timeout: Duration,
) -> Result<Vec<InconsistentRange>, TransportError>
where
    T: ReconcileTransport + ?Sized,
    S: NamespaceStore + TagStore + ?Sized,
{
    let local_tags = store
        .tag_list(ns_ref, None, &PageRequest::first(LOCAL_TREE_TAGS))
        .map_err(|e| TransportError::Internal(format!("tag_list for MST: {e}")))?;
    let mut local = NamespaceMst::new(ns_name.to_string());
    for tag in &local_tags.items {
        local.upsert(&tag.name, &tag.kappa.to_string());
    }

    let request = MstSnapshotRequest {
        namespace: ns_name.to_string(),
        local_root_hash: local.root_hash(),
    };
    let encoded = postcard::to_stdvec(&request)?;
    let mut bytes = vec![PROTO_MST_SNAPSHOT_REQ];
    bytes.extend_from_slice(&encoded);

    let response = tokio::time::timeout(timeout, transport.call_peer(peer, &bytes))
        .await
        .map_err(|_| TransportError::Timeout("MST snapshot exchange".into()))?
        .map_err(TransportError::from)?;
    if response.len() < 2 {
        return Err(TransportError::CodecError(
            "MST snapshot response too short".into(),
        ));
    }
    if response[0] != PROTO_MST_SNAPSHOT_RESP {
        return Err(TransportError::CodecError(format!(
            "expected 0x{PROTO_MST_SNAPSHOT_RESP:02x}, got 0x{:02x}",
            response[0]
        )));
    }
    let decoded: MstSnapshotResponse = postcard::from_bytes(&response[1..])
        .map_err(|e| TransportError::CodecError(format!("MST snapshot decode: {e}")))?;
    if decoded.page_ranges.is_empty() {
        return Err(TransportError::Internal("remote MST snapshot empty".into()));
    }
    let remote = MstSnapshot::from_wire(decoded.namespace, decoded.page_ranges)
        .map_err(|e| TransportError::CodecError(format!("remote MST snapshot: {e}")))?;
    let diff = local
        .diff(&remote)
        .map_err(|e| TransportError::Internal(format!("MST diff: {e}")))?;
    Ok(diff.inconsistent_ranges)
}
