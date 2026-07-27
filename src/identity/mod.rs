//! Identity subsystem -- anchors, assertions, revocations, resolution,
//! node identity, and trust position.
//!
//! Invariants (I-1 through I-8 from KNI-001):
//! - I-1: Bootstrap never touches the network
//! - I-2: Identity is derived, not granted
//! - I-3: Absence is not failure
//! - I-4: Trust accumulates without losing attribution
//! - I-5: Self-asserted claims are marked as self-asserted
//! - I-6: Verify before use, always
//! - I-7: No computed trust value is ever persisted
//! - I-8: Origin is idempotent

pub mod absence;
pub mod anchor;
pub mod assertion;
pub mod audience;
pub mod epoch;
pub mod node;
pub mod resolution;
pub mod revocation;
pub mod trust;
pub mod watermark;

pub use absence::AbsenceProof;
pub use anchor::{AnchorSpec, AsserterAnchor, NodeAnchor, SubjectAnchor};
pub use assertion::IdentityAssertion;
pub use epoch::{EpochMutation, EpochRoot, MutationOp};
pub use node::NodeIdentity;
pub use resolution::{resolve_all, resolve_at};
pub use revocation::{Revocation, RevocationReason};
pub use trust::{DegradeReason, PeerRecord, TrustPosition};
pub use watermark::Watermark;
