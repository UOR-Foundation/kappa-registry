use std::path::{Path, PathBuf};

use crate::error::StoreError;

/// Compute the filesystem path for a blob.
/// Layout: {root}/{algo}/{hex[0..2]}/{hex[2..4]}/{hex}
/// Validates hex characters to prevent path traversal.
pub fn blob_path_for(root: &Path, kappa: &str) -> Result<PathBuf, StoreError> {
    let (algo, hex) = split_kappa(kappa)
        .ok_or_else(|| StoreError::Rejected(format!("invalid kappa-label: {kappa}")))?;
    if hex.len() < 4 {
        return Err(StoreError::Rejected(format!(
            "kappa digest too short: {kappa}"
        )));
    }
    for &b in hex.as_bytes() {
        if !matches!(b, b'0'..=b'9' | b'a'..=b'f') {
            return Err(StoreError::Rejected(format!(
                "non-hex character in digest: {kappa}"
            )));
        }
    }
    Ok(root.join(algo).join(&hex[..2]).join(&hex[2..4]).join(hex))
}

/// Extract algorithm and hex digest from a kappa-label string.
pub fn split_kappa(kappa: &str) -> Option<(&str, &str)> {
    let colon = kappa.find(':')?;
    if colon == 0 || colon == kappa.len() - 1 {
        return None;
    }
    Some((&kappa[..colon], &kappa[colon + 1..]))
}

/// Extract the axis prefix from a kappa string without full validation.
pub fn axis_of(kappa: &str) -> Option<&str> {
    kappa.split_once(':').map(|(axis, _)| axis)
}
