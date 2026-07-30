//! Hash computation for kappa-labels.
//!
//! Each supported algorithm has a one-shot compute function on KappaLabel
//! and a dispatch function compute_kappa(axis, content). SHA-1 uses
//! collision detection (sha1-checked crate) and is fallible.
//!
//! dCBOR-aware computation: kappa_from_value() serializes a structured
//! value to canonical dCBOR bytes before hashing with SHA-256.

use sha1_checked::Sha1 as Sha1Checked;
use sha2::{Digest, Sha256, Sha512};

use super::label::{KappaLabel, LabelError, HEX};

impl KappaLabel {
    /// Compute the SHA-256 kappa-label of content. Infallible.
    pub fn sha256(content: &[u8]) -> Self {
        let hash = Sha256::digest(content);
        let mut buf = [0u8; 135];
        buf[..7].copy_from_slice(b"sha256:");
        for (i, &byte) in hash.iter().enumerate() {
            buf[7 + 2 * i] = HEX[(byte >> 4) as usize];
            buf[7 + 2 * i + 1] = HEX[(byte & 0x0f) as usize];
        }
        Self::from_parts(buf, 71)
    }

    /// Compute the BLAKE3 kappa-label of content. Infallible.
    pub fn blake3(content: &[u8]) -> Self {
        let hash = blake3::hash(content);
        let mut buf = [0u8; 135];
        buf[..7].copy_from_slice(b"blake3:");
        for (i, &byte) in hash.as_bytes().iter().enumerate() {
            buf[7 + 2 * i] = HEX[(byte >> 4) as usize];
            buf[7 + 2 * i + 1] = HEX[(byte & 0x0f) as usize];
        }
        Self::from_parts(buf, 71)
    }

    /// Compute the SHA-512 kappa-label of content. Infallible.
    pub fn sha512(content: &[u8]) -> Self {
        let hash = Sha512::digest(content);
        let mut buf = [0u8; 135];
        buf[..7].copy_from_slice(b"sha512:");
        for (i, &byte) in hash.iter().enumerate() {
            buf[7 + 2 * i] = HEX[(byte >> 4) as usize];
            buf[7 + 2 * i + 1] = HEX[(byte & 0x0f) as usize];
        }
        Self::from_parts(buf, 135)
    }

    /// Compute a SHA-1 kappa-label with collision detection.
    ///
    /// Returns Err(LabelError::CollisionDetected) if the content
    /// triggers the SHA-1 collision detection algorithm. Legitimate
    /// content never triggers this -- only crafted collision attacks.
    ///
    /// The sha1-checked crate wraps Marc Stevens' sha1collisiondetection.
    /// safe_hash mode is enabled by default: when a collision block is
    /// detected, the block is hashed 3x (240 rounds instead of 80),
    /// producing a different hash than standard SHA-1. Double protection.
    pub fn sha1(content: &[u8]) -> Result<Self, LabelError> {
        let result = Sha1Checked::try_digest(content);
        if result.has_collision() {
            return Err(LabelError::CollisionDetected);
        }
        let hash = result.hash();
        let mut buf = [0u8; 135];
        buf[..5].copy_from_slice(b"sha1:");
        for (i, &byte) in hash.iter().enumerate() {
            buf[5 + 2 * i] = HEX[(byte >> 4) as usize];
            buf[5 + 2 * i + 1] = HEX[(byte & 0x0f) as usize];
        }
        Ok(Self::from_parts(buf, 45))
    }
}

/// Compute the kappa-label of content under the given axis.
///
/// Dispatches to the correct hash algorithm. Returns LabelError::UnknownAxis
/// for unrecognized algorithm names.
pub fn compute_kappa(axis: &str, content: &[u8]) -> Result<KappaLabel, LabelError> {
    match axis {
        "sha1" => KappaLabel::sha1(content),
        "sha256" => Ok(KappaLabel::sha256(content)),
        "blake3" => Ok(KappaLabel::blake3(content)),
        "sha512" => Ok(KappaLabel::sha512(content)),
        _ => Err(LabelError::UnknownAxis),
    }
}

/// Verify that content hashes to the claimed kappa-label under its own axis.
///
/// Parses the kappa-label to determine the algorithm, recomputes the hash,
/// and compares. Returns Ok(false) on mismatch, Err on parse/compute failure.
pub fn verify_kappa(kappa: &str, content: &[u8]) -> Result<bool, LabelError> {
    let parsed = KappaLabel::parse(kappa)?;
    let computed = compute_kappa(parsed.axis(), content)?;
    Ok(computed.as_str() == kappa)
}

/// Compute the kappa-label of raw bytes using SHA-256.
///
/// Blobs are opaque bytes -- they are not dCBOR-encoded before hashing.
/// The default axis for blob storage is SHA-256.
pub fn kappa_from_bytes(bytes: &[u8]) -> String {
    KappaLabel::sha256(bytes).as_str().to_string()
}

/// Compute the kappa-label of a structured value.
///
/// The value is first serialized to canonical dCBOR bytes via
/// canonical_bytes(), then SHA-256 hashed. This ensures the kappa-label
/// is deterministic across implementations and architectures.
pub fn kappa_from_value<T: Into<dcbor::CBOR> + Clone>(value: &T) -> String {
    let bytes = crate::canonical::canonical_bytes(value);
    kappa_from_bytes(&bytes)
}

/// Compute the raw SHA-256 hash of bytes, returning 32 bytes.
pub fn sha256_raw(bytes: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}
