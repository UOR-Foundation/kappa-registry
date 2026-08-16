//! Identity subsystem: anchors, assertions, revocations, resolution,
//! node identity, and trust position.
//!
//! Invariants (KNI-001):
//! I-1: Bootstrap never touches the network
//! I-2: Identity is derived, not granted
//! I-3: Absence is not failure
//! I-4: Trust accumulates without losing attribution
//! I-5: Self-asserted claims are marked as self-asserted
//! I-6: Verify before use, always
//! I-7: No computed trust value is ever persisted
//! I-8: Origin is idempotent

pub mod absence;
pub mod assertion;
pub mod audience;
pub mod binding;
pub mod node;
pub mod probe;
pub mod resolution;
pub mod resolver;
pub mod revocation;
pub mod succession;
pub mod trust;
pub mod watermark;

pub use absence::AbsenceProof;
pub use assertion::IdentityAssertion;
pub use node::NodeIdentity;
pub use revocation::{Revocation, RevocationReason};
pub use binding::IdentityBinding;
pub use resolver::{ExternalIdentifierResolver, ResolvedIdentity};
pub use succession::IdentitySuccession;
pub use trust::{DegradeReason, PeerRecord, TrustPosition};
