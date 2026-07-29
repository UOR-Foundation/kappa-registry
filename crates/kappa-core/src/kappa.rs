//! Multi-algorithm kappa-label computation and validation.
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
//! SHA-1 uses collision detection (sha1-checked crate). Content that
//! triggers the collision detection algorithm is rejected -- only
//! crafted collision attacks trigger it, never legitimate content.
//!
//! The KappaLabel struct is a stack-allocated fixed-size buffer (135
//! bytes max, the length of sha512 labels). No heap allocation for
//! label computation or comparison.
//!
//! This module also provides dCBOR-aware kappa computation via
//! kappa_from_value(), which serializes a structured value to canonical
//! dCBOR bytes before hashing.

use sha1_checked::Sha1 as Sha1Checked;
use sha2::{Digest, Sha256, Sha512};

use crate::canonical::canonical_bytes;

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// A validated, stack-allocated kappa-label.
///
/// Maximum 135 bytes (sha512). Implements Copy, Eq, Ord, Hash for use
/// as map keys and set members without allocation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KappaLabel {
    buf: [u8; 135],
    len: u8,
}

/// Errors from kappa-label parsing and computation.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum LabelError {
    #[error("length {got} not in 45..=135")]
    BadLength { got: usize },
    #[error("no colon separator")]
    NoColon,
    #[error("unrecognized axis token")]
    UnknownAxis,
    #[error("non-hex byte 0x{byte:02x} at position {position}")]
    BadHex { position: usize, byte: u8 },
    #[error("expected {expected} hex digits, got {got}")]
    WrongDigitCount { expected: usize, got: usize },
    #[error("SHA-1 collision detected, content rejected")]
    CollisionDetected,
}

impl KappaLabel {
    /// Parse and validate a kappa-label string.
    ///
    /// Accepts sha1 (45 bytes), sha256/blake3 (71 bytes), sha512 (135 bytes).
    /// Rejects unknown axes, wrong digit counts, uppercase hex, and
    /// labels outside the 45..=135 byte range.
    pub fn parse(s: &str) -> Result<Self, LabelError> {
        let bytes = s.as_bytes();
        if !(45..=135).contains(&bytes.len()) {
            return Err(LabelError::BadLength { got: bytes.len() });
        }
        let colon = bytes
            .iter()
            .position(|&b| b == b':')
            .ok_or(LabelError::NoColon)?;
        let axis = &s[..colon];
        let expected_hex = match axis {
            "sha1" => 40,
            "sha256" | "blake3" | "sha3-256" | "keccak256" => 64,
            "sha512" => 128,
            _ => return Err(LabelError::UnknownAxis),
        };
        let hex_part = &bytes[colon + 1..];
        if hex_part.len() != expected_hex {
            return Err(LabelError::WrongDigitCount {
                expected: expected_hex,
                got: hex_part.len(),
            });
        }
        for (i, &b) in hex_part.iter().enumerate() {
            if !matches!(b, b'0'..=b'9' | b'a'..=b'f') {
                return Err(LabelError::BadHex {
                    position: colon + 1 + i,
                    byte: b,
                });
            }
        }
        let mut buf = [0u8; 135];
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(KappaLabel {
            buf,
            len: bytes.len() as u8,
        })
    }

    /// Compute the SHA-256 kappa-label of content. Infallible.
    pub fn sha256(content: &[u8]) -> Self {
        let hash = Sha256::digest(content);
        let mut buf = [0u8; 135];
        buf[..7].copy_from_slice(b"sha256:");
        for (i, &byte) in hash.iter().enumerate() {
            buf[7 + 2 * i] = HEX[(byte >> 4) as usize];
            buf[7 + 2 * i + 1] = HEX[(byte & 0x0f) as usize];
        }
        KappaLabel { buf, len: 71 }
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
        KappaLabel { buf, len: 71 }
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
        KappaLabel { buf, len: 135 }
    }

    /// Compute a SHA-1 kappa-label with collision detection.
    ///
    /// Returns Err(LabelError::CollisionDetected) if the content
    /// triggers the SHA-1 collision detection algorithm. Legitimate
    /// content never triggers this -- only crafted collision attacks.
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
        Ok(KappaLabel { buf, len: 45 })
    }

    /// The label as a string slice.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf[..self.len as usize]).unwrap()
    }

    /// The algorithm prefix (e.g. "sha256").
    pub fn axis(&self) -> &str {
        let s = self.as_str();
        &s[..s.find(':').unwrap()]
    }

    /// Bitwise complement of the digest, preserving the axis prefix.
    ///
    /// Used by CS-F4 involution quotient composition. The complement
    /// of the complement is the original: `k.complement().complement() == k`.
    pub fn complement(&self) -> Self {
        let colon = self.buf[..self.len as usize]
            .iter()
            .position(|&b| b == b':')
            .unwrap();
        let prefix_len = colon + 1;
        let mut buf = [0u8; 135];
        buf[..prefix_len].copy_from_slice(&self.buf[..prefix_len]);
        let hex_bytes = &self.buf[prefix_len..self.len as usize];
        for (i, pair) in hex_bytes.chunks_exact(2).enumerate() {
            let hi = hex_nibble(pair[0]).unwrap();
            let lo = hex_nibble(pair[1]).unwrap();
            let byte = (hi << 4) | lo;
            let comp = !byte;
            buf[prefix_len + 2 * i] = HEX[(comp >> 4) as usize];
            buf[prefix_len + 2 * i + 1] = HEX[(comp & 0x0f) as usize];
        }
        KappaLabel { buf, len: self.len }
    }
}

impl std::fmt::Display for KappaLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::fmt::Debug for KappaLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KappaLabel({})", self.as_str())
    }
}

impl AsRef<str> for KappaLabel {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::ops::Deref for KappaLabel {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
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

/// Extract the axis prefix from a kappa string without full validation.
///
/// Returns the algorithm name (e.g. "sha256") or None if no colon.
pub fn axis_of(kappa: &str) -> Option<&str> {
    kappa.split_once(':').map(|(axis, _)| axis)
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

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_SHA1: &str = "sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709";
    const HELLO_SHA1: &str = "sha1:aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";

    const EMPTY_SHA256: &str =
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const HELLO_SHA256: &str =
        "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    const EMPTY_BLAKE3: &str =
        "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    const HELLO_BLAKE3: &str =
        "blake3:ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f";

    // -- SHA-1 --

    #[test]
    fn sha1_empty() {
        assert_eq!(KappaLabel::sha1(b"").unwrap().as_str(), EMPTY_SHA1);
    }

    #[test]
    fn sha1_hello() {
        assert_eq!(KappaLabel::sha1(b"hello").unwrap().as_str(), HELLO_SHA1);
    }

    #[test]
    fn sha1_label_length() {
        assert_eq!(KappaLabel::sha1(b"x").unwrap().as_str().len(), 45);
    }

    #[test]
    fn parse_roundtrip_sha1() {
        let k = KappaLabel::sha1(b"test").unwrap();
        let parsed = KappaLabel::parse(k.as_str()).unwrap();
        assert_eq!(k, parsed);
    }

    #[test]
    fn parse_sha1_wrong_digits() {
        let s = format!("sha1:{}", "a".repeat(41));
        assert_eq!(s.len(), 46);
        assert!(matches!(
            KappaLabel::parse(&s),
            Err(LabelError::WrongDigitCount {
                expected: 40,
                got: 41
            })
        ));
    }

    #[test]
    fn verify_sha1() {
        assert_eq!(verify_kappa(HELLO_SHA1, b"hello"), Ok(true));
    }

    #[test]
    fn verify_sha1_mismatch() {
        assert_eq!(verify_kappa(HELLO_SHA1, b"wrong"), Ok(false));
    }

    #[test]
    fn complement_sha1_roundtrip() {
        let k = KappaLabel::sha1(b"involution test").unwrap();
        assert_eq!(k.complement().complement(), k);
    }

    // -- SHA-256 --

    #[test]
    fn sha256_empty() {
        assert_eq!(KappaLabel::sha256(b"").as_str(), EMPTY_SHA256);
    }

    #[test]
    fn sha256_hello() {
        assert_eq!(KappaLabel::sha256(b"hello").as_str(), HELLO_SHA256);
    }

    #[test]
    fn blob_kappa_is_sha256() {
        let data = b"hello world";
        let kappa = kappa_from_bytes(data);
        assert!(kappa.starts_with("sha256:"));
        assert_eq!(
            kappa,
            "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    // -- BLAKE3 --

    #[test]
    fn blake3_empty() {
        assert_eq!(KappaLabel::blake3(b"").as_str(), EMPTY_BLAKE3);
    }

    #[test]
    fn blake3_hello() {
        assert_eq!(KappaLabel::blake3(b"hello").as_str(), HELLO_BLAKE3);
    }

    // -- Parse and verify --

    #[test]
    fn parse_roundtrip_sha256() {
        let k = KappaLabel::sha256(b"test");
        let parsed = KappaLabel::parse(k.as_str()).unwrap();
        assert_eq!(k, parsed);
    }

    #[test]
    fn parse_roundtrip_blake3() {
        let k = KappaLabel::blake3(b"test");
        let parsed = KappaLabel::parse(k.as_str()).unwrap();
        assert_eq!(k, parsed);
    }

    #[test]
    fn reject_unknown_axis() {
        let s = format!("unknown:{}", "a".repeat(64));
        assert!(matches!(
            KappaLabel::parse(&s),
            Err(LabelError::UnknownAxis)
        ));
    }

    #[test]
    fn reject_uppercase_hex() {
        let s = format!("sha256:{}", "A".repeat(64));
        assert!(matches!(
            KappaLabel::parse(&s),
            Err(LabelError::BadHex { .. })
        ));
    }

    #[test]
    fn verify_match() {
        assert_eq!(verify_kappa(HELLO_SHA256, b"hello"), Ok(true));
    }

    #[test]
    fn verify_mismatch() {
        assert_eq!(verify_kappa(HELLO_SHA256, b"wrong"), Ok(false));
    }

    #[test]
    fn complement_roundtrip() {
        let k = KappaLabel::sha256(b"involution test");
        assert_eq!(k.complement().complement(), k);
    }

    // -- Structured values --

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
        assert_eq!(verify_kappa(&kappa, data), Ok(true));
    }

    #[test]
    fn verify_kappa_fails_on_mismatch() {
        let data = b"verify me";
        let kappa = kappa_from_bytes(data);
        assert_eq!(verify_kappa(&kappa, b"different data"), Ok(false));
    }

    // -- split_kappa --

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

    // -- compute_kappa multi-axis --

    #[test]
    fn compute_kappa_sha256() {
        let k = compute_kappa("sha256", b"hello").unwrap();
        assert_eq!(k.as_str(), HELLO_SHA256);
    }

    #[test]
    fn compute_kappa_blake3() {
        let k = compute_kappa("blake3", b"hello").unwrap();
        assert_eq!(k.as_str(), HELLO_BLAKE3);
    }

    #[test]
    fn compute_kappa_sha1() {
        let k = compute_kappa("sha1", b"hello").unwrap();
        assert_eq!(k.as_str(), HELLO_SHA1);
    }

    #[test]
    fn compute_kappa_unknown_axis() {
        assert!(matches!(
            compute_kappa("md5", b"hello"),
            Err(LabelError::UnknownAxis)
        ));
    }

    // -- axis_of --

    #[test]
    fn axis_of_sha256() {
        assert_eq!(axis_of("sha256:abc"), Some("sha256"));
    }

    #[test]
    fn axis_of_blake3() {
        assert_eq!(axis_of("blake3:def"), Some("blake3"));
    }

    #[test]
    fn axis_of_no_colon() {
        assert_eq!(axis_of("nocolon"), None);
    }
}
