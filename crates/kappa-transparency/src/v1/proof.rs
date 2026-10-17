//! Proof wire types. Every proof is canonical dCBOR and carries the
//! epoch binding it is verified under.

use dcbor::prelude::*;

use kappa_types::epoch::EpochMutation;

use crate::record::{Commitment, Entry, Transition};

/// What binds a commitment to one admitted epoch of the directory
/// namespace.
///
/// The signed root, the ledger mutation that names the commitment, that
/// mutation's inclusion under the root's `mutations_root`, and the
/// commitment bytes the mutation names.
/// CBOR key assignments (PERMANENT): 0-5
#[derive(Debug, Clone, CBORCodable)]
pub struct EpochBinding {
    /// `EpochRoot::to_bytes` of the signed root.
    #[cbor(n = 0)]
    pub epoch_root: ByteString,
    #[cbor(n = 1)]
    pub mutation: EpochMutation,
    #[cbor(n = 2)]
    pub mutation_index: u64,
    #[cbor(n = 3)]
    pub mutation_count: u64,
    /// Inclusion proof of the mutation's canonical bytes, leaf to root.
    #[cbor(n = 4)]
    pub mutation_path: Vec<ByteString>,
    #[cbor(n = 5)]
    pub commitment: Commitment,
}

/// Inclusion of one map entry at one index of the committed map.
/// CBOR key assignments (PERMANENT): 0-2
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable)]
pub struct LeafProof {
    #[cbor(n = 0)]
    pub entry: Entry,
    #[cbor(n = 1)]
    pub index: u64,
    #[cbor(n = 2)]
    pub path: Vec<ByteString>,
}

/// A label's standing at the proof's epoch.
/// CBOR discriminants (PERMANENT): 0-2
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable)]
pub enum HistoryState {
    #[cbor(n = 0)]
    NeverAsserted,
    #[cbor(n = 1)]
    Active,
    #[cbor(n = 2)]
    Retracted,
}

impl HistoryState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NeverAsserted => "never-asserted",
            Self::Active => "active",
            Self::Retracted => "retracted",
        }
    }
}

/// Three-state history proof for one label.
///
/// Never asserted (the leaves between which it would sit, each absent at
/// an edge of the map, both absent for an empty map), active (its
/// unretracted leaf), or retracted (its retracted leaf, whose
/// `retracted_at` is the epoch).
/// CBOR key assignments (PERMANENT): 0-5
#[derive(Debug, Clone, CBORCodable)]
pub struct HistoryProof {
    #[cbor(n = 0)]
    pub label: ByteString,
    #[cbor(n = 1)]
    pub binding: EpochBinding,
    #[cbor(n = 2)]
    pub state: HistoryState,
    #[cbor(n = 3)]
    pub leaf: Option<LeafProof>,
    #[cbor(n = 4)]
    pub left: Option<LeafProof>,
    #[cbor(n = 5)]
    pub right: Option<LeafProof>,
}

/// Inclusion of one transition at one index of the committed log.
/// CBOR key assignments (PERMANENT): 0-2
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable)]
pub struct TransitionProof {
    #[cbor(n = 0)]
    pub transition: Transition,
    #[cbor(n = 1)]
    pub index: u64,
    #[cbor(n = 2)]
    pub path: Vec<ByteString>,
}

/// Append-only audit between two directory epochs.
///
/// The log at `from` is a prefix of the log at `to` (`consistency`), and
/// `transitions` are the entries appended between them from `offset`,
/// each included in the log at `to`; `next` is the offset to continue
/// from when the page is not the last.
/// CBOR key assignments (PERMANENT): 0-5
#[derive(Debug, Clone, CBORCodable)]
pub struct AuditProof {
    #[cbor(n = 0)]
    pub from: EpochBinding,
    #[cbor(n = 1)]
    pub to: EpochBinding,
    #[cbor(n = 2)]
    pub consistency: Vec<ByteString>,
    #[cbor(n = 3)]
    pub offset: u64,
    #[cbor(n = 4)]
    pub transitions: Vec<TransitionProof>,
    #[cbor(n = 5)]
    pub next: Option<u64>,
}

pub(crate) fn path_bytes(path: &[[u8; 32]]) -> Vec<ByteString> {
    path.iter().map(|node| ByteString::from(*node)).collect()
}

pub(crate) fn path_nodes(path: &[ByteString]) -> Result<Vec<[u8; 32]>, crate::DirectoryError> {
    path.iter()
        .map(|node| crate::record::root_bytes(node, "proof node"))
        .collect()
}
