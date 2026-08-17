//! kappa-core: content-addressed graph database primitives.

// Seam modules (S1-S11, S13)
pub mod availability;
pub mod chunks;
pub mod clock;
pub mod coordinator;
pub mod counter;
pub mod events;
pub mod membership;
pub mod offload;
pub mod transport;
pub mod witness;

// Core modules
pub mod bundle;
pub mod canonical;
pub mod crypto;
pub mod delta;
pub mod epoch;
pub mod gc;
pub mod identity;
pub mod kappa;
pub mod merkle;
pub mod store;
pub mod transaction;
pub mod types;
pub mod verified;
pub mod version;

pub use canonical::{canonical_bytes, from_canonical};
pub use crypto::{
    anchor::{AsserterAnchor, NodeAnchor, SubjectAnchor},
    verifier_for, CryptoError, Signer, ThresholdSigner, Verifier,
};
pub use epoch::{EpochRoot, EpochRootFields};
pub use kappa::{
    axis_of, blob_path_for, compute_kappa, kappa_from_bytes,
    kappa_from_value, sha256_raw, split_kappa, streaming_compute_kappa,
    streaming_compute_multi, verify_kappa, Axis, KappaLabel, LabelError,
};
pub use store::KappaStore;
pub use types::*;
pub use verified::VerifiedContent;
