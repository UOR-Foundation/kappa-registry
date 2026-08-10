//! Blob filesystem path computation.
//!
//! One function, three consumers: InMemoryStore, PersistentStore, and
//! the upload complete handler. This is an anti-seam -- the path layout
//! is defined once and cannot diverge between store implementations.
//!
//! Layout: {root}/{algo}/{hex[0..2]}/{hex[2..4]}/{hex}
//!
//! Two-level sharding prevents any single directory from growing beyond
//! 65,536 entries (256 * 256 = 65,536 shard combinations). At 10M blobs
//! per algorithm, each leaf directory holds ~153 files on average.

use std::path::{Path, PathBuf};

use crate::types::StoreError;

/// Compute the filesystem path for a blob given a root directory
/// and a kappa string.
///
/// Validates the kappa format: requires a colon separator, non-empty
/// algorithm, at least 4 hex digits, and all-lowercase-hex in the
/// digest portion. The hex validation prevents path traversal attacks
/// (no `.`, `/`, `\`, or other special characters can appear in the
/// path components).
///
/// # Errors
///
/// Returns StoreError::Rejected if the kappa string is malformed.
pub fn blob_path_for(root: &Path, kappa: &str) -> Result<PathBuf, StoreError> {
    let (algo, hex) = split_kappa(kappa)
        .ok_or_else(|| StoreError::Rejected(format!("invalid kappa-label: {}", kappa)))?;
    if hex.len() < 4 {
        return Err(StoreError::Rejected(format!(
            "kappa digest too short: {}",
            kappa
        )));
    }
    // Validate hex characters to prevent path traversal.
    // Only 0-9 and a-f are allowed -- no dots, slashes, or other specials.
    for &b in hex.as_bytes() {
        if !matches!(b, b'0'..=b'9' | b'a'..=b'f') {
            return Err(StoreError::Rejected(format!(
                "non-hex character in digest: {}",
                kappa
            )));
        }
    }
    Ok(root
        .join(algo)
        .join(&hex[..2])
        .join(&hex[2..4])
        .join(hex))
}

/// Extract algorithm and hex digest from a kappa-label string.
///
/// Returns None if the format is invalid (no colon, or empty parts).
pub fn split_kappa(kappa: &str) -> Option<(&str, &str)> {
    let colon = kappa.find(':')?;
    if colon == 0 || colon == kappa.len() - 1 {
        return None;
    }
    Some((&kappa[..colon], &kappa[colon + 1..]))
}

/// Extract the axis prefix from a kappa string without full validation.
///
/// Returns the algorithm name (e.g. "sha256") or None if no colon.
pub fn axis_of(kappa: &str) -> Option<&str> {
    kappa.split_once(':').map(|(axis, _)| axis)
}
