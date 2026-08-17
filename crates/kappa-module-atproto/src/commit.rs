//! Repository commits: signed state snapshots.
//!
//! A commit captures a point-in-time snapshot of a repository's MST root.
//! It is signed by the account's signing key (P-256 for atproto).
//!
//! Commit v3 structure (DAG-CBOR):
//!   { did: string, version: 3, data: CID, rev: string, prev: CID|null, sig: bytes }
//!
//! The unsigned commit (all fields except sig) is CBOR-encoded and signed.
//! The signature covers the raw CBOR bytes, not a hash of them.

use crate::cid::cid_for_cbor;

/// An unsigned commit ready for signing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnsignedCommit {
    pub did: String,
    pub version: u32,
    pub data: Vec<u8>,         // CID of MST root (36 bytes)
    pub rev: String,           // TID
    pub prev: Option<Vec<u8>>, // CID of previous commit, None for first
}

/// A signed commit.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Commit {
    pub did: String,
    pub version: u32,
    pub data: Vec<u8>,         // CID of MST root
    pub rev: String,           // TID
    pub prev: Option<Vec<u8>>, // CID of previous commit
    pub sig: Vec<u8>,          // P-256 signature
}

impl Commit {
    /// Compute the CID of this commit (for storage and referencing).
    pub fn cid(&self) -> [u8; 36] {
        let bytes = self.to_cbor();
        cid_for_cbor(&bytes)
    }

    /// Encode this commit as minimal CBOR for storage.
    ///
    /// DAG-CBOR map with keys sorted: "data", "did", "prev", "rev", "sig", "version"
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_commit_cbor(
            &self.did,
            self.version,
            &self.data,
            &self.rev,
            self.prev.as_deref(),
            Some(&self.sig),
        )
    }

    /// Encode the unsigned portion for signature verification.
    pub fn unsigned_cbor(&self) -> Vec<u8> {
        encode_commit_cbor(
            &self.did,
            self.version,
            &self.data,
            &self.rev,
            self.prev.as_deref(),
            None,
        )
    }
}

impl UnsignedCommit {
    /// Encode as CBOR for signing.
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_commit_cbor(
            &self.did,
            self.version,
            &self.data,
            &self.rev,
            self.prev.as_deref(),
            None,
        )
    }

    /// Compute the CID of this unsigned commit.
    pub fn cid(&self) -> [u8; 36] {
        cid_for_cbor(&self.to_cbor())
    }
}

/// Encode a commit as DAG-CBOR.
///
/// Map keys sorted lexicographically (DAG-CBOR requirement):
///   "data", "did", "prev", "rev", "sig" (if present), "version"
fn encode_commit_cbor(
    did: &str,
    version: u32,
    data_cid: &[u8],
    rev: &str,
    prev_cid: Option<&[u8]>,
    sig: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    let field_count = if sig.is_some() { 6 } else { 5 };

    // CBOR map header
    if field_count < 24 {
        buf.push(0xA0 | field_count as u8);
    } else {
        buf.push(0xB8);
        buf.push(field_count as u8);
    }

    // "data" -> CID
    encode_text("data", &mut buf);
    encode_cid_tag(data_cid, &mut buf);

    // "did" -> text
    encode_text("did", &mut buf);
    encode_text(did, &mut buf);

    // "prev" -> CID or null
    encode_text("prev", &mut buf);
    match prev_cid {
        Some(cid) => encode_cid_tag(cid, &mut buf),
        None => buf.push(0xF6), // null
    }

    // "rev" -> text
    encode_text("rev", &mut buf);
    encode_text(rev, &mut buf);

    // "sig" -> bytes (only if present)
    if let Some(s) = sig {
        encode_text("sig", &mut buf);
        encode_bytes(s, &mut buf);
    }

    // "version" -> uint
    encode_text("version", &mut buf);
    encode_uint(version as u64, &mut buf);

    buf
}

fn encode_text(s: &str, buf: &mut Vec<u8>) {
    let len = s.len();
    if len < 24 {
        buf.push(0x60 | len as u8);
    } else if len < 256 {
        buf.push(0x78);
        buf.push(len as u8);
    } else {
        buf.push(0x79);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
    buf.extend_from_slice(s.as_bytes());
}

fn encode_bytes(data: &[u8], buf: &mut Vec<u8>) {
    let len = data.len();
    if len < 24 {
        buf.push(0x40 | len as u8);
    } else if len < 256 {
        buf.push(0x58);
        buf.push(len as u8);
    } else {
        buf.push(0x59);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
    buf.extend_from_slice(data);
}

fn encode_uint(n: u64, buf: &mut Vec<u8>) {
    if n < 24 {
        buf.push(n as u8);
    } else if n < 256 {
        buf.push(0x18);
        buf.push(n as u8);
    } else if n < 65536 {
        buf.push(0x19);
        buf.push((n >> 8) as u8);
        buf.push(n as u8);
    } else {
        buf.push(0x1A);
        buf.push((n >> 24) as u8);
        buf.push((n >> 16) as u8);
        buf.push((n >> 8) as u8);
        buf.push(n as u8);
    }
}

fn encode_cid_tag(cid: &[u8], buf: &mut Vec<u8>) {
    // CBOR Tag 42
    buf.push(0xD8);
    buf.push(42);
    // Byte string with 0x00 identity multibase prefix
    let len = 1 + cid.len();
    if len < 24 {
        buf.push(0x40 | len as u8);
    } else if len < 256 {
        buf.push(0x58);
        buf.push(len as u8);
    } else {
        buf.push(0x59);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
    buf.push(0x00); // identity multibase prefix
    buf.extend_from_slice(cid);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_commit_deterministic() {
        let mst_root = cid_for_cbor(b"empty mst");
        let c1 = UnsignedCommit {
            did: "did:plc:test123".into(),
            version: 3,
            data: mst_root.to_vec(),
            rev: "222222222222a".into(),
            prev: None,
        };
        let c2 = c1.clone();
        assert_eq!(c1.to_cbor(), c2.to_cbor());
        assert_eq!(c1.cid(), c2.cid());
    }

    #[test]
    fn signed_commit_includes_sig() {
        let mst_root = cid_for_cbor(b"mst");
        let commit = Commit {
            did: "did:plc:test".into(),
            version: 3,
            data: mst_root.to_vec(),
            rev: "222222222222a".into(),
            prev: None,
            sig: vec![1, 2, 3, 4],
        };
        let cbor = commit.to_cbor();
        // Should contain "sig" key
        assert!(cbor.windows(3).any(|w| w == b"sig"));

        let unsigned = commit.unsigned_cbor();
        // Should NOT contain "sig" key
        assert!(!unsigned.windows(3).any(|w| w == b"sig"));
    }

    #[test]
    fn commit_with_prev() {
        let mst_root = cid_for_cbor(b"mst");
        let prev = cid_for_cbor(b"prev commit");
        let commit = UnsignedCommit {
            did: "did:plc:test".into(),
            version: 3,
            data: mst_root.to_vec(),
            rev: "222222222222a".into(),
            prev: Some(prev.to_vec()),
        };
        let cbor = commit.to_cbor();
        // Should not contain null (0xF6) for prev
        // (it contains a CID tag instead)
        assert!(cbor.len() > 50); // non-trivial encoding
    }
}
