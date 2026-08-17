//! CID (Content Identifier) computation for DAG-CBOR blocks.
//!
//! CIDv1 with:
//!   - multibase: identity (raw bytes, no encoding prefix in binary form)
//!   - multicodec: dag-cbor (0x71)
//!   - multihash: sha2-256 (0x12), 32-byte digest
//!
//! Binary CID layout (36 bytes total):
//!   [version:1][codec_varint:1][hash_func:1][hash_len:1][hash:32]
//!   [0x01]     [0x71]         [0x12]       [0x20]      [32 bytes]

use sha2::{Digest, Sha256};

/// CIDv1 version byte.
const CID_VERSION: u8 = 0x01;
/// dag-cbor multicodec (varint-encoded, single byte since < 128).
const DAG_CBOR_CODEC: u8 = 0x71;
/// sha2-256 multihash function code.
const SHA2_256_CODE: u8 = 0x12;
/// sha2-256 digest length.
const SHA2_256_LEN: u8 = 0x20;

/// Compute a CIDv1 for DAG-CBOR encoded bytes.
///
/// Returns 36 bytes: [0x01, 0x71, 0x12, 0x20, ...32-byte-sha256...]
pub fn cid_for_cbor(data: &[u8]) -> [u8; 36] {
    let hash = Sha256::digest(data);
    let mut cid = [0u8; 36];
    cid[0] = CID_VERSION;
    cid[1] = DAG_CBOR_CODEC;
    cid[2] = SHA2_256_CODE;
    cid[3] = SHA2_256_LEN;
    cid[4..36].copy_from_slice(&hash);
    cid
}

/// Format a CID as a base32-lower multibase string (prefix 'b').
///
/// This is the standard string representation used in atproto for
/// display and logging. The binary form (36 bytes) is used in CBOR
/// and CAR files.
pub fn cid_to_string(cid: &[u8]) -> String {
    let mut s = String::with_capacity(1 + (cid.len() * 8 + 4) / 5);
    s.push('b');
    s.push_str(&base32_lower_encode(cid));
    s
}

/// Parse a base32-lower multibase CID string back to bytes.
pub fn cid_from_string(s: &str) -> Result<Vec<u8>, CidError> {
    if !s.starts_with('b') {
        return Err(CidError::UnsupportedMultibase);
    }
    base32_lower_decode(&s[1..]).ok_or(CidError::InvalidBase32)
}

/// Verify that the given CID matches the given bytes.
pub fn verify_cid(cid: &[u8], data: &[u8]) -> bool {
    if cid.len() != 36 {
        return false;
    }
    let expected = cid_for_cbor(data);
    cid == expected
}

/// Extract the 32-byte SHA-256 digest from a CID.
pub fn cid_digest(cid: &[u8]) -> Option<&[u8]> {
    if cid.len() >= 36 && cid[0] == CID_VERSION && cid[2] == SHA2_256_CODE {
        Some(&cid[4..36])
    } else {
        None
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CidError {
    #[error("unsupported multibase prefix (expected 'b' for base32lower)")]
    UnsupportedMultibase,
    #[error("invalid base32lower encoding")]
    InvalidBase32,
    #[error("CID too short")]
    TooShort,
}

// RFC 4648 base32 lowercase (no padding)
const B32_ALPHA: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn base32_lower_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    for &byte in data {
        bits = (bits << 8) | byte as u32;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            let idx = ((bits >> nbits) & 0x1F) as usize;
            out.push(B32_ALPHA[idx] as char);
        }
    }
    if nbits > 0 {
        let idx = ((bits << (5 - nbits)) & 0x1F) as usize;
        out.push(B32_ALPHA[idx] as char);
    }
    out
}

fn base32_lower_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    for c in s.bytes() {
        let val = match c {
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        bits = (bits << 5) | val as u32;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cid_roundtrip() {
        let data = b"hello world";
        let cid = cid_for_cbor(data);
        assert_eq!(cid.len(), 36);
        assert_eq!(cid[0], 0x01); // CIDv1
        assert_eq!(cid[1], 0x71); // dag-cbor
        assert_eq!(cid[2], 0x12); // sha2-256
        assert_eq!(cid[3], 0x20); // 32 bytes
        assert!(verify_cid(&cid, data));
        assert!(!verify_cid(&cid, b"wrong data"));
    }

    #[test]
    fn cid_string_roundtrip() {
        let data = b"test content";
        let cid = cid_for_cbor(data);
        let s = cid_to_string(&cid);
        assert!(s.starts_with('b'));
        let decoded = cid_from_string(&s).unwrap();
        assert_eq!(decoded, cid);
    }

    #[test]
    fn cid_digest_extraction() {
        let data = b"extract me";
        let cid = cid_for_cbor(data);
        let digest = cid_digest(&cid).unwrap();
        assert_eq!(digest.len(), 32);
        let hash = Sha256::digest(data);
        assert_eq!(digest, hash.as_slice());
    }

    #[test]
    fn deterministic() {
        let a = cid_for_cbor(b"same");
        let b = cid_for_cbor(b"same");
        assert_eq!(a, b);
    }

    #[test]
    fn different_content_different_cid() {
        let a = cid_for_cbor(b"aaa");
        let b = cid_for_cbor(b"bbb");
        assert_ne!(a, b);
    }
}
