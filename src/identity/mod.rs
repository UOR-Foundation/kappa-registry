//! Identity subsystem -- anchors, assertions, revocations, resolution.
//!
//! Identity is a schema over existing kappa-registry primitives plus
//! two new subsystems: an append-only ZKS (AKD) for absence proofs,
//! and a VRF for label privacy.
//!
//! No new consensus, no new transport, no new addressing.

pub mod absence;
pub mod anchor;
pub mod assertion;
pub mod audience;
pub mod epoch;
pub mod resolution;
pub mod revocation;
pub mod watermark;

pub use absence::AbsenceProof;
pub use anchor::AnchorSpec;
pub use assertion::IdentityAssertion;
pub use epoch::{EpochMutation, EpochRoot, MutationOp};
pub use resolution::{resolve_all, resolve_at};
pub use revocation::{Revocation, RevocationReason};
pub use watermark::Watermark;
