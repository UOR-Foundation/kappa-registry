//! Kappa-label computation.
//!
//! A kappa-label is the content address of a blob or structured value.
//! It is the SHA-256 hash of the canonical dCBOR encoding of the value,
//! represented as a hex string prefixed with the algorithm name.
//!
//! This module is an anti-seam: the hash algorithm and the canonical
//! encoding are fixed here and nowhere else. Changing either changes
//! every kappa-label ever computed.

use sha2::{Digest, Sha256};

use crate::canonical::canonical_bytes;

/// Compute the kappa-label of raw bytes (for blobs).
///
/// Blobs are already opaque bytes -- they are not dCBOR-encoded before
/// hashing. The kappa-label of a blob is sha256(blob_bytes).
pub fn kappa_from_bytes(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    format!("sha256:{}", hex::encode(hash))
}

/// Compute the kappa-label of a structured value.
///
/// The value is first serialized to canonical dCBOR bytes via
/// canonical_bytes(), then SHA-256 hashed. This ensures the kappa-label
/// is deterministic across implementations and architectures.
pub fn kappa_from_value<T: Into<dcbor::CBOR> + Clone>(value: &T) -> String {
    let bytes = canonical_bytes(value);
    kappa_from_bytes(&bytes)
}

/// Compute the raw SHA-256 hash of bytes, returning 32 bytes.
pub fn sha256_raw(bytes: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

/// Validate that a kappa-label matches expected content.
///
/// Recomputes the hash of the provided bytes and compares against the
/// claimed kappa-label. Returns true only if they match exactly.
pub fn verify_kappa(kappa: &str, bytes: &[u8]) -> bool {
    let computed = kappa_from_bytes(bytes);
    computed == kappa
}

/// Extract the algorithm prefix from a kappa-label.
///
/// Returns the algorithm name (e.g., "sha256") and the hex digest
/// as separate strings. Returns None if the format is invalid.
pub fn split_kappa(kappa: &str) -> Option<(&str, &str)> {
    let colon = kappa.find(':')?;
    if colon == 0 || colon == kappa.len() - 1 {
        return None;
    }
    Some((&kappa[..colon], &kappa[colon + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_kappa_is_sha256() {
        let data = b"hello world";
        let kappa = kappa_from_bytes(data);
        assert!(kappa.starts_with("sha256:"));
        // Known SHA-256 of "hello world"
        assert_eq!(
            kappa,
            "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn structured_value_kappa_is_deterministic() {
        let v1 = "test value".to_string();
        let v2 = "test value".to_string();
        assert_eq!(kappa_from_value(&v1), kappa_from_value(&v2));
    }

    #[test]
    fn verify_kappa_succeeds_on_match() {
        let data = b"verify me";
        let kappa = kappa_from_bytes(data);
        assert!(verify_kappa(&kappa, data));
    }

    #[test]
    fn verify_kappa_fails_on_mismatch() {
        let data = b"verify me";
        let kappa = kappa_from_bytes(data);
        assert!(!verify_kappa(&kappa, b"different data"));
    }

    #[test]
    fn split_kappa_parses_correctly() {
        let (algo, digest) = split_kappa("sha256:abcdef").unwrap();
        assert_eq!(algo, "sha256");
        assert_eq!(digest, "abcdef");
    }

    #[test]
    fn split_kappa_rejects_no_colon() {
        assert!(split_kappa("sha256abcdef").is_none());
    }

    #[test]
    fn split_kappa_rejects_empty_parts() {
        assert!(split_kappa(":abcdef").is_none());
        assert!(split_kappa("sha256:").is_none());
    }
}
