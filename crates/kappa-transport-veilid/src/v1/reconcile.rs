//! MST reconciliation protocol over Veilid app_call.
//!
//! Informed by rekindle-transport-buff (concurrent fan-out, credit-bounded
//! admission, panic-safe work guards), rekindle-transport-ipc (typed protocol
//! dispatch, lifecycle phases, durability tiers, delivery reports), and
//! veilid-core (TryAgain retry semantics, 32KB message limit, watch-driven
//! reactivity).
//!
//! Protocol bytes:
//!   0x00  PING              either to either         empty
//!   0x01  EPOCH_ROOT_REQ    initiator to responder   namespace UTF-8
//!   0x02  EPOCH_ROOT_RESP   responder to initiator   EpochRootResponse
//!   0x03  MST_SNAPSHOT_REQ  initiator to responder   MstSnapshotRequest
//!   0x04  MST_SNAPSHOT_RESP responder to initiator   MstSnapshotResponse
//!   0x05  DIFF_PULL_REQ     initiator to responder   DiffPullRequest
//!   0x06  DIFF_PULL_RESP    responder to initiator   DiffPullResponse
//!   0x07  BLOB_PULL_REQ     initiator to responder   BlobPullRequest
//!   0x08  BLOB_PULL_RESP    responder to initiator   BlobPullResponse
//!   0x09-0xFF reserved
//!
//! Module layout by concern:
//!   `wire`       protocol message types
//!   `report`     per-peer and per-round outcomes, reconciliation clock
//!   `round`      the reconciliation loop and concurrent peer fan-out
//!   `peer`       per-peer initiator: compare, pull, apply, fetch blobs
//!   `mst`        MST diff computation against a peer snapshot
//!   `apply`      one execution per namespace batch of reconciled tags
//!   `blobs`      missing blob discovery and inline fetch
//!   `responder`  inbound request handler

use std::time::Duration;

mod apply;
mod blobs;
mod mst;
mod peer;
mod report;
mod responder;
mod round;
mod wire;

pub use apply::{NamespaceBatchOutcome, apply_namespace_batch};
pub use blobs::fetch_missing_blobs;
pub use report::{PeerPhase, PeerReconcileOutcome, ReconcileReport};
pub use responder::handle_reconcile_request;
pub use round::{PeerEntry, PeerSource, ReconcileLoop};
pub use wire::{
    BlobFetchReport, BlobPullRequest, BlobPullResponse, DeferredBlob, DiffPullRequest,
    DiffPullResponse, EpochRootResponse, MissingBlob, MstSnapshotRequest, MstSnapshotResponse,
    PageRangeWire, TagEntryWire,
};

// Protocol byte constants
const PROTO_PING: u8 = 0x00;
const PROTO_EPOCH_ROOT_REQ: u8 = 0x01;
const PROTO_EPOCH_ROOT_RESP: u8 = 0x02;
const PROTO_MST_SNAPSHOT_REQ: u8 = 0x03;
const PROTO_MST_SNAPSHOT_RESP: u8 = 0x04;
const PROTO_DIFF_PULL_REQ: u8 = 0x05;
const PROTO_DIFF_PULL_RESP: u8 = 0x06;
const PROTO_BLOB_PULL_REQ: u8 = 0x07;
const PROTO_BLOB_PULL_RESP: u8 = 0x08;

/// Maximum blob size for inline pull via 0x07/0x08. Blobs larger than
/// this are transferred via the bulk transfer protocol. 31KB leaves
/// room for postcard framing within the 32KB Veilid app_call limit.
const MAX_INLINE_BLOB_SIZE: usize = 31 * 1024;

/// Maximum tags per pull response page. Bounded to fit within Veilid's
/// 32KB app_call limit with postcard encoding overhead. The responder
/// fetches limit+1 from the store and sets truncated + next_cursor when
/// the result set exceeds this bound.
const MAX_PULL_TAGS: usize = 500;

/// Default per-peer timeout for a single reconciliation RPC.
const PEER_TIMEOUT: Duration = Duration::from_secs(30);

/// Default maximum concurrent peer reconciliations.
const MAX_CONCURRENT_PEERS: usize = 8;

/// Maximum pages the initiator will pull per namespace per peer per round.
/// Prevents unbounded pagination against a namespace with millions of tags.
const MAX_PULL_PAGES: usize = 100;

/// Peer identifier prefix for log fields.
fn short_id(peer_id: &str) -> &str {
    &peer_id[..16.min(peer_id.len())]
}
