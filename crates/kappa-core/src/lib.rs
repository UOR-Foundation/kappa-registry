//! kappa-core: content-addressed graph database primitives.

// Seam modules (S1-S11, S13). Membership (S9) and the peer transport (S6)
// are `kappa_reconcile::membership` and `kappa_reconcile::transport`: the
// reconciliation loop is their one consumer.
pub mod availability;
pub mod chunks;
pub mod clock;
pub mod coordinator;
pub mod counter;
pub mod events;
pub mod offload;
pub mod witness;

// Core modules
pub mod bundle;
pub mod canonical;
pub mod delta;
pub mod epoch;
pub mod gc;
pub mod identity;
pub mod kappa;
/// Re-export of `kappa_types::merkle`. New code uses `kappa_types::merkle`
/// directly.
pub use kappa_types::merkle;
pub mod store;
pub mod transaction;
pub mod types;
pub mod verified;
pub mod version;

pub use canonical::{canonical_bytes, from_canonical};
pub use epoch::{EpochRoot, EpochRootFields};
pub use kappa::{
    Axis, KappaLabel, LabelError, axis_of, blob_path_for, compute_kappa, kappa_from_bytes,
    kappa_from_value, sha256_raw, split_kappa, streaming_compute_kappa, streaming_compute_multi,
    verify_kappa,
};
pub use store::KappaStore;
pub use types::*;
pub use verified::VerifiedContent;
