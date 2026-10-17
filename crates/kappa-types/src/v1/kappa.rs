use std::fmt;

use crate::axis::Axis;

/// Maximum raw digest length in bytes (SHA-512 = 64 bytes).
const MAX_DIGEST: usize = 64;

/// Lookup table for byte-to-lowercase-hex encoding.
const HEX_TABLE: &[u8; 16] = b"0123456789abcdef";

/// Content-address digest stored as raw bytes internally.
///
/// NOT Copy. Clone is a 67-byte memcpy (no heap allocation).
/// Equality comparison operates on raw digest bytes, which is
/// half the length of comparing hex strings.
///
/// Construction is restricted to:
/// - `Kappa::parse(s)` -- validates "algorithm:hex" wire format
/// - `Kappa::sha256(data)`, `Kappa::blake3(data)`, etc.
/// - `Kappa::compute(axis, data)` -- dispatches by axis
///
/// There is no From<String>, no From<&str>.
///
/// Wire format representation ("sha256:abcd...") is produced on
/// demand via Display or `Kappa::format()`. The internal
/// representation is never a string.
#[derive(Clone)]
pub struct Kappa {
    axis: Axis,
    digest: [u8; MAX_DIGEST],
    digest_len: u8,
}

/// Stack-allocated formatted kappa-label string.
///
/// Returned by `Kappa::format()`. Implements Display, `AsRef<str>`,
/// and Deref<str>. Maximum size is 9 (axis) + 1 (:) + 128 (hex)
/// = 138 bytes. The buffer is 140 bytes to allow room.
pub struct FormattedKappa {
    buf: [u8; 140],
    len: usize,
}

/// Errors from kappa-label parsing, computation, and streaming.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KappaParseError {
    #[error("key framing field {field} has {length} bytes, maximum is 65535")]
    KeyFramingLength { field: &'static str, length: usize },
    #[error("no colon separator in '{0}'")]
    NoColon(String),

    #[error("unrecognized axis '{0}'")]
    UnknownAxis(String),

    #[error("expected {expected} hex digits, got {got}")]
    WrongDigitCount { expected: usize, got: usize },

    #[error("non-hex byte 0x{byte:02x} at position {position}")]
    BadHex { position: usize, byte: u8 },

    #[error("SHA-1 collision detected, content rejected")]
    CollisionDetected,

    #[error("digest mismatch on axis {axis}: expected {expected}, computed {computed}")]
    DigestMismatch {
        expected: String,
        computed: String,
        axis: String,
    },

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

// -- Kappa construction -------------------------------------------------------

impl Kappa {
    /// Parse a wire-format "algorithm:hex" string into raw bytes.
    pub fn parse(s: &str) -> Result<Self, KappaParseError> {
        let colon = s
            .find(':')
            .ok_or_else(|| KappaParseError::NoColon(s.to_string()))?;

        let axis_str = &s[..colon];
        let axis = Axis::parse(axis_str)
            .ok_or_else(|| KappaParseError::UnknownAxis(axis_str.to_string()))?;

        let hex_str = &s[colon + 1..];
        let expected_hex = axis.hex_len();
        if hex_str.len() != expected_hex {
            return Err(KappaParseError::WrongDigitCount {
                expected: expected_hex,
                got: hex_str.len(),
            });
        }

        let mut digest = [0u8; MAX_DIGEST];
        let digest_len = axis.digest_len();
        for (i, output) in digest.iter_mut().enumerate().take(digest_len) {
            let hi = hex_nibble(hex_str.as_bytes()[2 * i]).ok_or(KappaParseError::BadHex {
                position: colon + 1 + 2 * i,
                byte: hex_str.as_bytes()[2 * i],
            })?;
            let lo = hex_nibble(hex_str.as_bytes()[2 * i + 1]).ok_or(KappaParseError::BadHex {
                position: colon + 1 + 2 * i + 1,
                byte: hex_str.as_bytes()[2 * i + 1],
            })?;
            *output = (hi << 4) | lo;
        }

        Ok(Self {
            axis,
            digest,
            digest_len: axis.digest_len_u8(),
        })
    }

    /// Compute SHA-256 content address.
    pub fn sha256(content: &[u8]) -> Self {
        Self::from_raw(Axis::Sha256, &crate::sha256::digest(content))
    }

    /// Compute BLAKE3 content address.
    pub fn blake3(content: &[u8]) -> Self {
        let hash = blake3::hash(content);
        Self::from_raw(Axis::Blake3, hash.as_bytes())
    }

    /// Compute SHA-512 content address.
    pub fn sha512(content: &[u8]) -> Self {
        Self::from_raw(Axis::Sha512, &crate::sha512::digest(content))
    }

    /// Compute SHA-1 content address with collision detection.
    pub fn sha1(content: &[u8]) -> Result<Self, KappaParseError> {
        let result = sha1_checked::Sha1::try_digest(content);
        if result.has_collision() {
            return Err(KappaParseError::CollisionDetected);
        }
        Ok(Self::from_raw(Axis::Sha1, result.hash()))
    }

    /// Compute SHA-3-256 content address.
    pub fn sha3_256(content: &[u8]) -> Self {
        Self::from_raw(Axis::Sha3_256, &crate::sha3_256::digest(content))
    }

    /// Compute Keccak-256 content address.
    pub fn keccak256(content: &[u8]) -> Self {
        use sha3::Digest;
        let hash = sha3::Keccak256::digest(content);
        Self::from_raw(Axis::Keccak256, &hash)
    }

    /// Compute content address under a given axis.
    pub fn compute(axis: Axis, content: &[u8]) -> Result<Self, KappaParseError> {
        match axis {
            Axis::Sha256 => Ok(Self::sha256(content)),
            Axis::Sha512 => Ok(Self::sha512(content)),
            Axis::Blake3 => Ok(Self::blake3(content)),
            Axis::Sha1 => Self::sha1(content),
            Axis::Sha3_256 => Ok(Self::sha3_256(content)),
            Axis::Keccak256 => Ok(Self::keccak256(content)),
        }
    }

    /// Compute a content address from cryptographic key material.
    /// Used to derive identity anchors from signing keys.
    /// Deterministic: same (algorithm, `public_key`) always produces
    /// the same Kappa across all nodes.
    pub fn from_key(algorithm: &str, public_key: &[u8]) -> Result<Self, KappaParseError> {
        let algo_bytes = algorithm.as_bytes();
        let algorithm_length =
            u16::try_from(algo_bytes.len()).map_err(|_| KappaParseError::KeyFramingLength {
                field: "algorithm",
                length: algo_bytes.len(),
            })?;
        let key_length =
            u16::try_from(public_key.len()).map_err(|_| KappaParseError::KeyFramingLength {
                field: "public_key",
                length: public_key.len(),
            })?;
        let mut hash = crate::sha256::Hasher::new();
        hash.update(&algorithm_length.to_be_bytes());
        hash.update(algo_bytes);
        hash.update(&key_length.to_be_bytes());
        hash.update(public_key);
        Ok(Self::from_raw(Axis::Sha256, &hash.finalize()))
    }

    /// Construct from an axis and raw digest bytes.
    /// pub(crate) for `IncrementalHasher` in `kappa_streaming`.
    pub(crate) fn from_raw(axis: Axis, raw_digest: &[u8]) -> Self {
        let expected = axis.digest_len();
        assert_eq!(
            raw_digest.len(),
            expected,
            "digest length {} does not match axis {} (expected {})",
            raw_digest.len(),
            axis.as_str(),
            expected,
        );
        let mut digest = [0u8; MAX_DIGEST];
        digest[..expected].copy_from_slice(raw_digest);
        Self {
            axis,
            digest,
            digest_len: axis.digest_len_u8(),
        }
    }

    /// Reconstruct from a discriminant byte and raw digest bytes.
    /// Used for deserializing redb keys.
    pub fn from_key_bytes(bytes: &[u8]) -> Result<Self, KappaParseError> {
        if bytes.is_empty() {
            return Err(KappaParseError::NoColon(String::new()));
        }
        let axis = Axis::from_discriminant(bytes[0])
            .ok_or_else(|| KappaParseError::UnknownAxis(format!("discriminant {}", bytes[0])))?;
        let expected = axis.digest_len();
        if bytes.len() != 1 + expected {
            return Err(KappaParseError::WrongDigitCount {
                expected,
                got: bytes.len() - 1,
            });
        }
        let mut digest = [0u8; MAX_DIGEST];
        digest[..expected].copy_from_slice(&bytes[1..]);
        Ok(Self {
            axis,
            digest,
            digest_len: axis.digest_len_u8(),
        })
    }

    // -- Accessors ------------------------------------------------------------

    /// The digest algorithm.
    pub const fn axis(&self) -> Axis {
        self.axis
    }

    /// The raw digest bytes. Length is `axis.digest_len()`.
    pub fn digest_bytes(&self) -> &[u8] {
        &self.digest[..self.digest_len as usize]
    }

    /// Serialize to compact binary key: [discriminant, `digest_bytes`...].
    /// For redb and `DashMap` keys. No allocation -- writes into caller's buffer.
    pub fn to_key_bytes(&self, buf: &mut [u8]) -> usize {
        let len = 1 + self.digest_len as usize;
        buf[0] = self.axis.discriminant();
        buf[1..len].copy_from_slice(self.digest_bytes());
        len
    }

    /// Allocating version of `to_key_bytes` for convenience.
    pub fn key_bytes(&self) -> Vec<u8> {
        let len = 1 + self.digest_len as usize;
        let mut v = Vec::with_capacity(len);
        v.push(self.axis.discriminant());
        v.extend_from_slice(self.digest_bytes());
        v
    }

    /// Format to the wire-format "algorithm:hex" string on the stack.
    /// No heap allocation. The returned `FormattedKappa` can be used
    /// as &str via Deref or `AsRef<str>`.
    pub fn format(&self) -> FormattedKappa {
        let axis_str = self.axis.as_str().as_bytes();
        let hex_len = self.digest_len as usize * 2;
        let total = axis_str.len() + 1 + hex_len;

        let mut buf = [0u8; 140];
        buf[..axis_str.len()].copy_from_slice(axis_str);
        buf[axis_str.len()] = b':';

        let hex_start = axis_str.len() + 1;
        for (i, &byte) in self.digest_bytes().iter().enumerate() {
            buf[hex_start + 2 * i] = HEX_TABLE[(byte >> 4) as usize];
            buf[hex_start + 2 * i + 1] = HEX_TABLE[(byte & 0x0f) as usize];
        }

        FormattedKappa { buf, len: total }
    }

    /// Verify that content hashes to this kappa.
    pub fn verify(&self, content: &[u8]) -> Result<bool, KappaParseError> {
        let computed = Self::compute(self.axis, content)?;
        Ok(computed == *self)
    }

    /// Bitwise complement of the digest, preserving the axis.
    /// complement(complement(k)) == k.
    #[must_use]
    pub fn complement(&self) -> Self {
        let mut digest = [0u8; MAX_DIGEST];
        for (output, input) in digest.iter_mut().zip(self.digest_bytes()) {
            *output = !input;
        }
        Self {
            axis: self.axis,
            digest,
            digest_len: self.digest_len,
        }
    }
}

// -- Equality, Hash, Ord: operate on raw bytes -------------------------------

impl PartialEq for Kappa {
    fn eq(&self, other: &Self) -> bool {
        self.axis == other.axis
            && self.digest_len == other.digest_len
            && self.digest_bytes() == other.digest_bytes()
    }
}

impl Eq for Kappa {}

impl std::hash::Hash for Kappa {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.axis.hash(state);
        self.digest_bytes().hash(state);
    }
}

impl PartialOrd for Kappa {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Kappa {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.axis
            .discriminant()
            .cmp(&other.axis.discriminant())
            .then_with(|| self.digest_bytes().cmp(other.digest_bytes()))
    }
}

// -- Display: formats to "algorithm:hex" on demand ---------------------------

impl fmt::Display for Kappa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let formatted = self.format();
        f.write_str(formatted.as_str())
    }
}

impl fmt::Debug for Kappa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Kappa({self})")
    }
}

// -- Serde: wire format is "algorithm:hex" -----------------------------------

impl serde::Serialize for Kappa {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let formatted = self.format();
        serializer.serialize_str(formatted.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Kappa {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

// -- FormattedKappa -----------------------------------------------------------

impl FormattedKappa {
    /// Borrow the canonical ASCII label.
    ///
    /// # Panics
    ///
    /// Panics only if the private formatting invariant is violated: the
    /// buffer is populated exclusively from ASCII axis names and hex digits.
    pub fn as_str(&self) -> &str {
        // The buffer contains only ASCII (axis name + colon + hex digits).
        // ASCII is valid UTF-8. We use the checked conversion because
        // the 2ns cost per call is not a forcing function, but the
        // soundness obligation across a decade of contributors is.
        std::str::from_utf8(&self.buf[..self.len])
            .unwrap_or_else(|_| unreachable!("private formatting buffer contains only ASCII"))
    }
}

impl fmt::Display for FormattedKappa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for FormattedKappa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FormattedKappa({})", self.as_str())
    }
}

impl AsRef<str> for FormattedKappa {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::ops::Deref for FormattedKappa {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

// -- Hex helpers --------------------------------------------------------------

/// Decode a single lowercase hex character to its nibble value.
pub(crate) const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

// -- Free functions -----------------------------------------------------------

/// Compute SHA-256 kappa from raw bytes. Returns the Kappa directly.
pub fn kappa_from_bytes(bytes: &[u8]) -> Kappa {
    Kappa::sha256(bytes)
}

/// Compute raw SHA-256 hash, returning 32 bytes.
pub fn sha256_raw(bytes: &[u8]) -> [u8; 32] {
    crate::sha256::digest(bytes)
}

/// Compute the kappa of a structured value.
/// The value is serialized to canonical dCBOR bytes first, then
/// SHA-256 hashed.
pub fn kappa_from_value<T: Into<dcbor::CBOR> + Clone>(value: &T) -> Kappa {
    let bytes = crate::canonical::canonical_bytes(value);
    kappa_from_bytes(&bytes)
}

/// Verify that content hashes to the claimed kappa-label string.
pub fn verify_kappa(kappa_str: &str, content: &[u8]) -> Result<bool, KappaParseError> {
    let parsed = Kappa::parse(kappa_str)?;
    parsed.verify(content)
}

// -- dCBOR: canonical form is the "algorithm:hex" text string ----------------

impl From<Kappa> for dcbor::CBOR {
    fn from(k: Kappa) -> Self {
        let formatted = k.format();
        Self::from(formatted.as_str().to_string())
    }
}

impl TryFrom<dcbor::CBOR> for Kappa {
    type Error = dcbor::Error;
    fn try_from(cbor: dcbor::CBOR) -> Result<Self, dcbor::Error> {
        let s: String = cbor.try_into()?;
        Self::parse(&s).map_err(|e| dcbor::Error::msg(e.to_string()))
    }
}

impl From<&Kappa> for dcbor::CBOR {
    fn from(k: &Kappa) -> Self {
        let formatted = k.format();
        Self::from(formatted.as_str().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty() {
        let k = Kappa::sha256(b"");
        let formatted = k.format();
        assert_eq!(
            formatted.as_str(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(k.axis(), Axis::Sha256);
        assert_eq!(k.digest_bytes().len(), 32);
    }

    #[test]
    fn sha256_hello() {
        let k = Kappa::sha256(b"hello");
        let formatted = k.format();
        assert_eq!(
            formatted.as_str(),
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn blake3_empty() {
        let k = Kappa::blake3(b"");
        assert_eq!(k.axis(), Axis::Blake3);
        assert_eq!(k.digest_bytes().len(), 32);
        let formatted = k.format();
        assert!(formatted.as_str().starts_with("blake3:"));
        assert_eq!(formatted.as_str().len(), 71);
    }

    #[test]
    fn sha512_empty() {
        let k = Kappa::sha512(b"");
        assert_eq!(k.axis(), Axis::Sha512);
        assert_eq!(k.digest_bytes().len(), 64);
        let formatted = k.format();
        assert!(formatted.as_str().starts_with("sha512:"));
        assert_eq!(formatted.as_str().len(), 135);
    }

    #[test]
    fn sha1_empty() -> Result<(), KappaParseError> {
        let k = Kappa::sha1(b"")?;
        assert_eq!(k.axis(), Axis::Sha1);
        assert_eq!(k.digest_bytes().len(), 20);
        let formatted = k.format();
        assert_eq!(
            formatted.as_str(),
            "sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        Ok(())
    }

    #[test]
    fn sha3_256_empty() {
        let k = Kappa::sha3_256(b"");
        assert_eq!(k.axis(), Axis::Sha3_256);
        assert_eq!(k.digest_bytes().len(), 32);
        let formatted = k.format();
        assert!(formatted.as_str().starts_with("sha3-256:"));
    }

    #[test]
    fn keccak256_empty() {
        let k = Kappa::keccak256(b"");
        assert_eq!(k.axis(), Axis::Keccak256);
        assert_eq!(k.digest_bytes().len(), 32);
        let formatted = k.format();
        assert!(formatted.as_str().starts_with("keccak256:"));
    }

    #[test]
    fn parse_roundtrip() -> Result<(), KappaParseError> {
        let original = Kappa::sha256(b"test data");
        let wire = original.format();
        let parsed = Kappa::parse(wire.as_str())?;
        assert_eq!(original, parsed);
        Ok(())
    }

    #[test]
    fn parse_roundtrip_all_axes() -> Result<(), KappaParseError> {
        for axis in [
            Axis::Sha256,
            Axis::Sha512,
            Axis::Blake3,
            Axis::Sha1,
            Axis::Sha3_256,
            Axis::Keccak256,
        ] {
            let k = Kappa::compute(axis, b"roundtrip test")?;
            let wire = k.format();
            let parsed = Kappa::parse(wire.as_str())?;
            assert_eq!(k, parsed, "roundtrip failed for axis {axis}");
        }
        Ok(())
    }

    #[test]
    fn parse_rejects_no_colon() {
        assert!(matches!(
            Kappa::parse("sha256abcdef"),
            Err(KappaParseError::NoColon(_))
        ));
    }

    #[test]
    fn parse_rejects_unknown_axis() {
        assert!(matches!(
            Kappa::parse("md5:d41d8cd98f00b204e9800998ecf8427e"),
            Err(KappaParseError::UnknownAxis(_))
        ));
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(matches!(
            Kappa::parse("sha256:abcdef"),
            Err(KappaParseError::WrongDigitCount { .. })
        ));
    }

    #[test]
    fn parse_rejects_uppercase_hex() {
        let upper = "sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        assert!(matches!(
            Kappa::parse(upper),
            Err(KappaParseError::BadHex { .. })
        ));
    }

    #[test]
    fn key_bytes_roundtrip() -> Result<(), KappaParseError> {
        let k = Kappa::sha256(b"key bytes test");
        let key = k.key_bytes();
        let recovered = Kappa::from_key_bytes(&key)?;
        assert_eq!(k, recovered);
        Ok(())
    }

    #[test]
    fn key_bytes_roundtrip_all_axes() -> Result<(), KappaParseError> {
        for axis in [
            Axis::Sha256,
            Axis::Sha512,
            Axis::Blake3,
            Axis::Sha1,
            Axis::Sha3_256,
            Axis::Keccak256,
        ] {
            let k = Kappa::compute(axis, b"key bytes all axes")?;
            let key = k.key_bytes();
            let recovered = Kappa::from_key_bytes(&key)?;
            assert_eq!(k, recovered, "key_bytes roundtrip failed for axis {axis}");
        }
        Ok(())
    }

    #[test]
    fn complement_roundtrip() {
        let k = Kappa::sha256(b"complement test");
        let c = k.complement();
        assert_ne!(k, c);
        let cc = c.complement();
        assert_eq!(k, cc);
    }

    #[test]
    fn verify_matches() -> Result<(), KappaParseError> {
        let content = b"verify me";
        let k = Kappa::sha256(content);
        assert!(k.verify(content)?);
        Ok(())
    }

    #[test]
    fn verify_rejects_wrong_content() -> Result<(), KappaParseError> {
        let k = Kappa::sha256(b"original");
        assert!(!k.verify(b"tampered")?);
        Ok(())
    }

    #[test]
    fn ordering_is_deterministic() -> Result<(), KappaParseError> {
        let a = Kappa::sha256(b"aaa");
        let b = Kappa::sha256(b"bbb");
        // The ordering must be consistent and reflexive
        assert_eq!(a.cmp(&a), std::cmp::Ordering::Equal);
        assert_ne!(a.cmp(&b), std::cmp::Ordering::Equal);
        // Cross-axis: sha1 discriminant 3, sha256 discriminant 0
        let sha1 = Kappa::sha1(b"test")?;
        let sha256 = Kappa::sha256(b"test");
        assert_eq!(sha256.cmp(&sha1), std::cmp::Ordering::Less);
        Ok(())
    }

    #[test]
    fn serde_json_roundtrip() -> Result<(), serde_json::Error> {
        let k = Kappa::sha256(b"serde test");
        let json = serde_json::to_string(&k)?;
        let parsed: Kappa = serde_json::from_str(&json)?;
        assert_eq!(k, parsed);
        Ok(())
    }

    #[test]
    fn display_matches_format() {
        let k = Kappa::sha256(b"display test");
        let via_display = k.to_string();
        let via_format = k.format().as_str().to_string();
        assert_eq!(via_display, via_format);
    }

    #[test]
    fn size_of_kappa_is_66_or_67() {
        // axis (1 byte enum) + digest (64 bytes) + digest_len (1 byte)
        // Rust may add padding. Verify it's in the expected range.
        let size = std::mem::size_of::<Kappa>();
        assert!(size <= 72, "Kappa is {size} bytes, expected <= 72");
    }
}
