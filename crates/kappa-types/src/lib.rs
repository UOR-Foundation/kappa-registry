//! Shared types for kappa-registry protocol module authors.
//!
//! This crate re-exports the public API surface from kappa-core that
//! protocol modules need. Module authors depend on kappa-types, not
//! kappa-core directly, so internal changes to kappa-core do not
//! break module compilation as long as the re-exports are stable.

pub use kappa_core::types::*;
pub use kappa_core::kappa::{kappa_from_bytes, verify_kappa, split_kappa};
pub use kappa_core::store::KappaStore;
pub use kappa_core::EpochRoot;
