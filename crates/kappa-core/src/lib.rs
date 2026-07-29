//! kappa-core: content-addressed graph database primitives.
//!
//! Provides canonical dCBOR serialization, kappa-label computation,
//! binary Merkle trees with proofs, epoch roots as Merkle trees of
//! dCBOR fields, the KappaStore trait, InMemoryStore, cryptographic
//! signing traits, identity types, and GC reachability.

pub(crate) mod canonical;
pub mod clock;
pub mod crypto;
pub mod epoch;
pub mod gc;
pub mod identity;
pub mod kappa;
pub mod merkle;
pub mod store;
pub mod types;
pub mod version;

pub use crypto::{
    CryptoError, Signer, ThresholdSigner, Verifier,
    anchor::{AsserterAnchor, NodeAnchor, SubjectAnchor},
};
pub use epoch::EpochRoot;
pub use kappa::{kappa_from_bytes, kappa_from_value, split_kappa, verify_kappa};
pub use store::KappaStore;
pub use types::*;
