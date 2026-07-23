use sha1_checked::Sha1 as Sha1Checked;
use sha2::{Digest, Sha256, Sha512};
use std::fmt;

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KappaLabel {
    buf: [u8; 135],
    len: u8,
}

#[derive(Debug, PartialEq)]
pub enum LabelError {
    BadLength { got: usize },
    NoColon,
    UnknownAxis,
    BadHex { position: usize, byte: u8 },
    WrongDigitCount { expected: usize, got: usize },
    CollisionDetected,
}

impl fmt::Display for LabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelError::BadLength { got } => write!(f, "length {got} not in 45..=135"),
            LabelError::NoColon => write!(f, "no colon separator"),
            LabelError::UnknownAxis => write!(f, "unrecognized axis token"),
            LabelError::BadHex { position, byte } => {
                write!(f, "non-hex byte 0x{byte:02x} at position {position}")
            }
            LabelError::WrongDigitCount { expected, got } => {
                write!(f, "expected {expected} hex digits, got {got}")
            }
            LabelError::CollisionDetected => {
                write!(f, "SHA-1 collision detected, content rejected")
            }
        }
    }
}

impl std::error::Error for LabelError {}

impl KappaLabel {
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

    /// Compute a SHA-1 label with collision detection via sha1-checked.
    ///
    /// Returns `Err(LabelError::CollisionDetected)` if the content
    /// triggers the SHA-1 collision detection algorithm. Legitimate
    /// content will never trigger this -- only crafted collision attacks.
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

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf[..self.len as usize]).unwrap()
    }

    pub fn axis(&self) -> &str {
        let s = self.as_str();
        &s[..s.find(':').unwrap()]
    }

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

/// Compute the kappa for `content` under the given axis.
pub fn compute_kappa(axis: &str, content: &[u8]) -> Result<KappaLabel, LabelError> {
    match axis {
        "sha1" => KappaLabel::sha1(content),
        "sha256" => Ok(KappaLabel::sha256(content)),
        "blake3" => Ok(KappaLabel::blake3(content)),
        "sha512" => Ok(KappaLabel::sha512(content)),
        _ => Err(LabelError::UnknownAxis),
    }
}

/// Verify that `content` hashes to `kappa` under the kappa's own axis.
pub fn verify_kappa(kappa: &str, content: &[u8]) -> Result<bool, LabelError> {
    let parsed = KappaLabel::parse(kappa)?;
    let computed = compute_kappa(parsed.axis(), content)?;
    Ok(computed.as_str() == kappa)
}

/// Extract the axis prefix from a kappa string without full validation.
pub fn axis_of(kappa: &str) -> Option<&str> {
    kappa.split_once(':').map(|(axis, _)| axis)
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
        // 41 hex digits (46 bytes total, within 45..=135 range) but sha1 expects 40.
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

    #[test]
    fn sha256_empty() {
        assert_eq!(KappaLabel::sha256(b"").as_str(), EMPTY_SHA256);
    }

    #[test]
    fn sha256_hello() {
        assert_eq!(KappaLabel::sha256(b"hello").as_str(), HELLO_SHA256);
    }

    #[test]
    fn blake3_empty() {
        assert_eq!(KappaLabel::blake3(b"").as_str(), EMPTY_BLAKE3);
    }

    #[test]
    fn blake3_hello() {
        assert_eq!(KappaLabel::blake3(b"hello").as_str(), HELLO_BLAKE3);
    }

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
}
