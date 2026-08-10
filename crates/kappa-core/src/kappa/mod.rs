//! Multi-algorithm kappa-label computation, validation, and path management.
//!
//! A kappa-label is the content address of a blob or structured value:
//! `<algorithm>:<lowercase-hex-digest>`. Supported algorithms:
//!
//! | Token      | Digest bytes | Label bytes | Standard       |
//! |------------|-------------|-------------|----------------|
//! | sha1       | 20          | 45          | FIPS 180-4     |
//! | sha256     | 32          | 71          | FIPS 180-4     |
//! | blake3     | 32          | 71          | BLAKE3 spec    |
//! | sha512     | 64          | 135         | FIPS 180-4     |
//! | sha3-256   | 32          | 73          | FIPS 202       |
//! | keccak256  | 32          | 74          | Keccak spec    |
//!
//! All six axes are structurally equal. No axis receives special
//! policy treatment. SHA-1 uses collision-detecting hashing via
//! sha1-checked; crafted collision inputs are rejected at the hash
//! computation level.
//!
//! Module organization:
//! - label.rs: KappaLabel struct, Axis enum, parse/validate, complement
//! - compute.rs: per-algorithm hash functions, dispatch, verification,
//!   streaming single-axis and multi-axis computation
//! - path.rs: blob filesystem path computation (anti-seam), split_kappa
//! - tests.rs: all unit tests

mod compute;
mod label;
mod path;
#[cfg(test)]
mod tests;

pub use compute::{
    compute_kappa, kappa_from_bytes, kappa_from_value, sha256_raw,
    streaming_compute_kappa, streaming_compute_multi, verify_kappa,
};
pub use label::{Axis, KappaLabel, LabelError};
pub use path::{axis_of, blob_path_for, split_kappa};
