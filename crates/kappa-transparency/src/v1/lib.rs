//! The authenticated identity directory.
//!
//! One directory maps every (subject, facet) label the identity module
//! has ever published to the assertion it currently names, and records
//! every transition in an append-only log. Both are committed by a
//! [`Commitment`] record that the directory namespace's signed epoch
//! names in its ledger, so a proof about a label is bound to one admitted
//! epoch of this node:
//!
//! - the map is a Merkle tree over the canonical entries in label order
//!   (`record::Entry`); membership is an index-bound inclusion proof, and
//!   absence is the inclusion of the two neighbouring leaves (or the one
//!   edge leaf, or the empty tree), between which the label would sit;
//! - the log is a Merkle tree over the canonical transitions in order
//!   (`record::Transition`); an audit between two epochs is a consistency
//!   proof that the earlier log is a prefix of the later one, with the
//!   transitions appended between them and their inclusion proofs;
//! - a history query answers in three states (`HistoryState`): never
//!   asserted (absence), active (membership of an unretracted entry), or
//!   retracted at an epoch (membership of a retracted entry). Evidence the
//!   node cannot supply (a recovering directory, an epoch it does not
//!   hold) is an error, never an absence.
//!
//! Every proof carries its [`EpochBinding`]: the signed epoch root, the
//! ledger mutation naming the commitment with its inclusion proof under
//! the root's `mutations_root`, and the commitment itself. Verification
//! (`verify`) recomputes everything from those bytes and the node's
//! signing key; nothing is taken from the node's say-so.
//!
//! The directory publishes through the ordinary execution contract of the
//! store it is given, so its state, its commitment and the signed epoch
//! install atomically and recover from the store alone.

pub mod audit;
pub mod directory;
pub mod error;
pub mod history;
pub mod label;
pub mod proof;
pub mod record;
pub mod state;
pub mod verify;

pub use directory::{DIRECTORY_NAMESPACE, Directory, Request};
pub use error::DirectoryError;
pub use label::label;
pub use proof::{AuditProof, EpochBinding, HistoryProof, HistoryState, LeafProof, TransitionProof};
pub use record::{Commitment, Entry, Transition};
