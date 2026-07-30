//! KappaLabel: stack-allocated, validated content address.
//!
//! A kappa-label is `<algorithm>:<lowercase-hex-digest>`. No heap
//! allocation. Copy, Eq, Ord, Hash for use as map keys. The maximum
//! size is 135 bytes (sha512). All smaller labels fit in the same
//! fixed buffer with a length discriminant.
//!
//! Validation is strict: unknown algorithms, uppercase hex, wrong
//! digit counts, and labels outside 45..=135 bytes are rejected.

use std::fmt;

/// Recognized digest algorithms with their hex digit counts.
///
/// Adding an algorithm: add a variant here, update `parse`,
/// add a compute function in compute.rs, update tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Axis {
    Sha1,
    Sha256,
    Blake3,
    Sha512,
    Sha3_256,
    Keccak256,
}

impl Axis {
    /// The string token used in kappa-labels.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Blake3 => "blake3",
            Self::Sha512 => "sha512",
            Self::Sha3_256 => "sha3-256",
            Self::Keccak256 => "keccak256",
        }
    }

    /// Expected number of lowercase hex digits for this algorithm.
    pub fn hex_digits(&self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 | Self::Blake3 | Self::Sha3_256 | Self::Keccak256 => 64,
            Self::Sha512 => 128,
        }
    }

    /// Digest byte count (hex_digits / 2).
    pub fn digest_bytes(&self) -> usize {
        self.hex_digits() / 2
    }

    /// Total kappa-label length: prefix + colon + hex digits.
    pub fn label_len(&self) -> usize {
        self.as_str().len() + 1 + self.hex_digits()
    }

    /// Parse an algorithm token. Returns None for unrecognized tokens.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "sha1" => Some(Self::Sha1),
            "sha256" => Some(Self::Sha256),
            "blake3" => Some(Self::Blake3),
            "sha512" => Some(Self::Sha512),
            "sha3-256" => Some(Self::Sha3_256),
            "keccak256" => Some(Self::Keccak256),
            _ => None,
        }
    }
}

impl fmt::Display for Axis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
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

/// Lookup table for byte-to-hex encoding.
pub(crate) const HEX: &[u8; 16] = b"0123456789abcdef";

/// Decode a single lowercase hex character to its nibble value.
pub(crate) fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// A validated, stack-allocated kappa-label.
///
/// Maximum 135 bytes (sha512). Implements Copy so it can be used
/// as a lightweight value type in hot paths without cloning.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KappaLabel {
    pub(crate) buf: [u8; 135],
    pub(crate) len: u8,
}

impl KappaLabel {
    /// Construct a KappaLabel from pre-validated components.
    /// Used by compute functions that already know the format is valid.
    pub(crate) fn from_parts(buf: [u8; 135], len: u8) -> Self {
        Self { buf, len }
    }

    /// Parse and validate a kappa-label string.
    ///
    /// Rejects: unknown axes, wrong digit counts, uppercase hex,
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
        let axis_str = &s[..colon];
        let axis = Axis::parse(axis_str).ok_or(LabelError::UnknownAxis)?;
        let expected_hex = axis.hex_digits();
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
        Ok(Self {
            buf,
            len: bytes.len() as u8,
        })
    }

    /// The label as a string slice.
    pub fn as_str(&self) -> &str {
        // SAFETY: buf contains only ASCII (algorithm name + colon + hex digits).
        // parse() and compute functions enforce this invariant.
        std::str::from_utf8(&self.buf[..self.len as usize]).unwrap()
    }

    /// The algorithm prefix (e.g. "sha256").
    pub fn axis(&self) -> &str {
        let s = self.as_str();
        &s[..s.find(':').unwrap()]
    }

    /// The parsed Axis enum for this label.
    pub fn axis_enum(&self) -> Axis {
        // Unwrap is safe: labels are only constructed with valid axes.
        Axis::parse(self.axis()).unwrap()
    }

    /// The hex digest portion (after the colon).
    pub fn hex_digest(&self) -> &str {
        let s = self.as_str();
        &s[s.find(':').unwrap() + 1..]
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

impl fmt::Display for KappaLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for KappaLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
