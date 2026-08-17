//! Shared types for kappa-registry protocol module authors.
//!
//! Re-exports the complete public API surface from kappa-core that
//! protocol modules need. Module authors depend on kappa-types, not
//! kappa-core directly.

pub use kappa_core::availability::AvailabilityIndex;
pub use kappa_core::canonical::{canonical_bytes, from_canonical};
pub use kappa_core::chunks::ChunkSource;
pub use kappa_core::clock::Clock;
pub use kappa_core::coordinator::Coordinator;
pub use kappa_core::counter::MonotonicCounter;
pub use kappa_core::crypto::anchor::{AsserterAnchor, NodeAnchor, SubjectAnchor};
pub use kappa_core::crypto::frost::FrostEd25519Coordinator;
pub use kappa_core::crypto::{CryptoError, Signer, ThresholdSigner, Verifier};
pub use kappa_core::epoch::{EpochRoot, EpochRootFields};
pub use kappa_core::events::{EventLog, TagEvent};
pub use kappa_core::gc::GcResult;
pub use kappa_core::identity::{IdentityAssertion, Revocation, RevocationReason};
pub use kappa_core::kappa::{kappa_from_bytes, kappa_from_value, split_kappa, verify_kappa};
pub use kappa_core::membership::{MembershipView, PeerInfo};
pub use kappa_core::offload::{OffloadReceipt, OffloadVerifier};
pub use kappa_core::store::{
    Edge, EdgeQuery, EdgeRelation, EpochMutation, KappaStore, StoreError, TagEntry, TagUpdate,
};
pub use kappa_core::transport::PeerTransport;
pub use kappa_core::types::*;
pub use kappa_core::witness::{EpochWitness, WitnessReceipt};
