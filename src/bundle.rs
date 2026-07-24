//! Bundle wire format for bulk object transfer.
//!
//! A bundle packages multiple content-addressed blobs into a single byte
//! stream for efficient transfer. Each entry is a full object (type 0x01)
//! carrying its kappa-label and raw content. A SHA-256 trailer provides
//! integrity verification over all preceding bytes.
//!
//! Wire format:
//!   HEADER: magic "KBND" (4B) + version u8 + flags u8 + entry_count u32 BE
//!   ENTRY:  type u8 + kappa_len u16 BE + kappa bytes + content_len u64 BE + content bytes
//!   TRAILER: SHA-256 of all preceding bytes (32B)

use sha2::{Digest, Sha256};

use crate::kappa::verify_kappa;
use crate::store::StoreError;

const MAGIC: &[u8; 4] = b"KBND";
const VERSION: u8 = 1;
const ENTRY_TYPE_FULL: u8 = 0x01;

/// Encode a bundle from a list of (kappa, content) pairs.
pub fn encode(objects: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();

    // Header
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(0x00); // flags: no deltas
    out.extend_from_slice(&(objects.len() as u32).to_be_bytes());

    // Entries
    for (kappa, content) in objects {
        out.push(ENTRY_TYPE_FULL);
        let kb = kappa.as_bytes();
        out.extend_from_slice(&(kb.len() as u16).to_be_bytes());
        out.extend_from_slice(kb);
        out.extend_from_slice(&(content.len() as u64).to_be_bytes());
        out.extend_from_slice(content);
    }

    // Trailer: SHA-256 of everything so far
    let hash = Sha256::digest(&out);
    out.extend_from_slice(&hash);

    out
}

/// A parsed bundle entry.
pub struct BundleEntry {
    pub kappa: String,
    pub content: Vec<u8>,
}

/// Decode and verify a bundle. Returns the list of entries on success.
pub fn decode(data: &[u8]) -> Result<Vec<BundleEntry>, StoreError> {
    if data.len() < 10 + 32 {
        return Err(StoreError::Conflict("bundle too short".into()));
    }

    // Verify trailer
    let payload = &data[..data.len() - 32];
    let trailer = &data[data.len() - 32..];
    let computed = Sha256::digest(payload);
    if computed.as_slice() != trailer {
        return Err(StoreError::Conflict("bundle trailer mismatch".into()));
    }

    // Parse header
    if &data[..4] != MAGIC {
        return Err(StoreError::Conflict("bad bundle magic".into()));
    }
    if data[4] != VERSION {
        return Err(StoreError::Conflict("unsupported bundle version".into()));
    }
    // data[5] = flags (ignored for now)
    let entry_count = u32::from_be_bytes([data[6], data[7], data[8], data[9]]) as usize;

    let mut pos = 10;
    let mut entries = Vec::with_capacity(entry_count);

    for _ in 0..entry_count {
        if pos >= payload.len() {
            return Err(StoreError::Conflict("truncated bundle entry".into()));
        }
        let entry_type = payload[pos];
        pos += 1;

        if entry_type != ENTRY_TYPE_FULL {
            return Err(StoreError::Conflict(format!(
                "unsupported entry type 0x{entry_type:02x}"
            )));
        }

        if pos + 2 > payload.len() {
            return Err(StoreError::Conflict("truncated kappa length".into()));
        }
        let kappa_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2;

        if pos + kappa_len > payload.len() {
            return Err(StoreError::Conflict("truncated kappa".into()));
        }
        let kappa = std::str::from_utf8(&payload[pos..pos + kappa_len])
            .map_err(|_| StoreError::Conflict("kappa not UTF-8".into()))?
            .to_string();
        pos += kappa_len;

        if pos + 8 > payload.len() {
            return Err(StoreError::Conflict("truncated content length".into()));
        }
        let content_len = u64::from_be_bytes([
            payload[pos],
            payload[pos + 1],
            payload[pos + 2],
            payload[pos + 3],
            payload[pos + 4],
            payload[pos + 5],
            payload[pos + 6],
            payload[pos + 7],
        ]) as usize;
        pos += 8;

        if pos + content_len > payload.len() {
            return Err(StoreError::Conflict("truncated content".into()));
        }
        let content = payload[pos..pos + content_len].to_vec();
        pos += content_len;

        // Verify kappa matches content
        match verify_kappa(&kappa, &content) {
            Ok(true) => {}
            Ok(false) => {
                return Err(StoreError::Conflict(format!(
                    "bundle entry kappa mismatch: {kappa}"
                )));
            }
            Err(e) => {
                return Err(StoreError::Conflict(format!(
                    "bundle entry kappa invalid: {e}"
                )));
            }
        }

        entries.push(BundleEntry { kappa, content });
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kappa::KappaLabel;

    #[test]
    fn encode_decode_roundtrip() {
        let content_a = b"bundle-test-alpha";
        let content_b = b"bundle-test-beta";
        let ka = KappaLabel::sha256(content_a);
        let kb = KappaLabel::sha256(content_b);

        let bundle = encode(&[
            (ka.as_str(), content_a.as_slice()),
            (kb.as_str(), content_b.as_slice()),
        ]);

        let entries = decode(&bundle).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].kappa, ka.as_str());
        assert_eq!(entries[0].content, content_a);
        assert_eq!(entries[1].kappa, kb.as_str());
        assert_eq!(entries[1].content, content_b);
    }

    #[test]
    fn decode_rejects_corrupted_trailer() {
        let content = b"corruption-test";
        let k = KappaLabel::sha256(content);
        let mut bundle = encode(&[(k.as_str(), content.as_slice())]);
        // Flip a trailer byte
        let last = bundle.len() - 1;
        bundle[last] ^= 0xFF;
        assert!(decode(&bundle).is_err());
    }

    #[test]
    fn decode_rejects_kappa_mismatch() {
        let content = b"mismatch-test";
        let k = KappaLabel::sha256(content);
        let wrong_content = b"different content";
        // Manually build a bundle with mismatched kappa/content
        let bundle = encode(&[(k.as_str(), wrong_content.as_slice())]);
        // The trailer will be valid (computed over the wrong data) but
        // verify_kappa inside decode will catch the mismatch.
        // Actually, encode computes trailer over the encoded bytes which
        // include the wrong content, so trailer is valid. The kappa
        // verification inside decode catches it.
        assert!(decode(&bundle).is_err());
    }

    #[test]
    fn encode_empty_bundle() {
        let bundle = encode(&[]);
        let entries = decode(&bundle).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn header_structure() {
        let bundle = encode(&[]);
        assert_eq!(&bundle[..4], b"KBND");
        assert_eq!(bundle[4], 1); // version
        assert_eq!(bundle[5], 0); // flags
        assert_eq!(
            u32::from_be_bytes([bundle[6], bundle[7], bundle[8], bundle[9]]),
            0
        );
    }
}
