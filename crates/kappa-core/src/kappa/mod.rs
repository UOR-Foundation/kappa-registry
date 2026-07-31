//! Multi-algorithm kappa-label computation, validation, and path management.
//!
//! A kappa-label is the content address of a blob or structured value:
//! `<algorithm>:<lowercase-hex-digest>`. Supported algorithms:
//!
//! | Token    | Digest bytes | Label bytes | Standard       |
//! |----------|-------------|-------------|----------------|
//! | sha1     | 20          | 45          | FIPS 180-4     |
//! | sha256   | 32          | 71          | FIPS 180-4     |
//! | blake3   | 32          | 71          | BLAKE3 spec    |
//! | sha512   | 64          | 135         | FIPS 180-4     |
//!
//! Module organization:
//! - label.rs: KappaLabel struct, Axis enum, parse/validate, complement
//! - compute.rs: per-algorithm hash functions, dispatch, verification
//! - path.rs: blob filesystem path computation (anti-seam), split_kappa
//! - sha1_policy.rs: per-namespace SHA-1 acceptance policy
//! - tests.rs: all unit tests

mod compute;
mod label;
mod path;
pub mod sha1_policy;
#[cfg(test)]
mod tests;

// Re-export the public API.
// External code uses kappa_core::kappa::KappaLabel, kappa_core::kappa::compute_kappa, etc.
// The module boundary is internal organization, not API change.

pub use compute::{compute_kappa, kappa_from_bytes, kappa_from_value, sha256_raw, verify_kappa};
pub use label::{Axis, KappaLabel, LabelError};
pub use path::{axis_of, blob_path_for, encrypted_blob_path_for, split_kappa};
pub use sha1_policy::Sha1Policy;
