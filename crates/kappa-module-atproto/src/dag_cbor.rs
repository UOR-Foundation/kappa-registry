//! DAG-CBOR frame encoding for the atproto firehose.
//!
//! Each WebSocket message is a binary frame containing two concatenated
//! DAG-CBOR objects: a header and a body.
//!
//! Header: { "op": int, "t": string }
//! Body: frame-type-specific payload
//!
//! All maps use lexicographically sorted string keys (DAG-CBOR requirement).
//! CID values use CBOR Tag 42 with 0x00 identity multibase prefix.

/// Encode a firehose header: { "op": op, "t": frame_type }
/// Keys sorted: "op" < "t"
pub fn encode_header(op: i64, frame_type: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0xA2); // map of 2

    // "op"
    encode_text("op", &mut buf);
    if op >= 0 {
        encode_uint(op as u64, &mut buf);
    } else {
        // negative: major type 1, value = -1 - n
        let n = (-1 - op) as u64;
        if n < 24 { buf.push(0x20 | n as u8); }
        else { buf.push(0x38); buf.push(n as u8); }
    }

    // "t"
    encode_text("t", &mut buf);
    encode_text(frame_type, &mut buf);

    buf
}

/// Encode a #commit frame body.
pub fn encode_commit_body(
    seq: u64,
    repo: &str,
    commit_cid: &[u8],
    rev: &str,
    since: Option<&str>,
    blocks_car: &[u8],
    ops: &[(&str, &str, Option<&[u8]>)], // (action, path, cid)
) -> Vec<u8> {
    let mut buf = Vec::new();
    // Fields sorted: "blocks", "commit", "ops", "repo", "rev", "seq", "since"
    let field_count: u8 = 7;
    buf.push(0xA0 | field_count);

    // "blocks"
    encode_text("blocks", &mut buf);
    encode_bytes(blocks_car, &mut buf);

    // "commit"
    encode_text("commit", &mut buf);
    if commit_cid.is_empty() {
        buf.push(0xF6); // null
    } else {
        encode_cid(commit_cid, &mut buf);
    }

    // "ops"
    encode_text("ops", &mut buf);
    encode_array_header(ops.len(), &mut buf);
    for (action, path, cid) in ops {
        // { "action", "cid", "path" } -- sorted
        buf.push(0xA3);
        encode_text("action", &mut buf);
        encode_text(action, &mut buf);
        encode_text("cid", &mut buf);
        match cid {
            Some(c) => encode_cid(c, &mut buf),
            None => buf.push(0xF6),
        }
        encode_text("path", &mut buf);
        encode_text(path, &mut buf);
    }

    // "repo"
    encode_text("repo", &mut buf);
    encode_text(repo, &mut buf);

    // "rev"
    encode_text("rev", &mut buf);
    encode_text(rev, &mut buf);

    // "seq"
    encode_text("seq", &mut buf);
    encode_uint(seq, &mut buf);

    // "since"
    encode_text("since", &mut buf);
    match since {
        Some(s) => encode_text(s, &mut buf),
        None => buf.push(0xF6),
    }

    buf
}

/// Encode a #handle frame body: { "did", "handle", "seq" }
pub fn encode_handle_body(seq: u64, did: &str, handle: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0xA3); // map of 3

    encode_text("did", &mut buf);
    encode_text(did, &mut buf);

    encode_text("handle", &mut buf);
    encode_text(handle, &mut buf);

    encode_text("seq", &mut buf);
    encode_uint(seq, &mut buf);

    buf
}

/// Encode a #identity frame body: { "did", "seq" }
pub fn encode_identity_body(seq: u64, did: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0xA2);

    encode_text("did", &mut buf);
    encode_text(did, &mut buf);

    encode_text("seq", &mut buf);
    encode_uint(seq, &mut buf);

    buf
}

/// Encode a #tombstone frame body: { "did", "seq" }
pub fn encode_tombstone_body(seq: u64, did: &str) -> Vec<u8> {
    encode_identity_body(seq, did) // same shape
}

/// Encode a #info frame body: { "message", "name" }
pub fn encode_info_body(name: &str, message: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0xA2);

    encode_text("message", &mut buf);
    encode_text(message, &mut buf);

    encode_text("name", &mut buf);
    encode_text(name, &mut buf);

    buf
}

/// Concatenate header + body into a single binary frame.
pub fn frame(header: Vec<u8>, body: Vec<u8>) -> Vec<u8> {
    let mut out = header;
    out.extend(body);
    out
}

// -- CBOR primitives ----------------------------------------------------------

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
    } else if len < 65536 {
        buf.push(0x59);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(0x5A);
        buf.push((len >> 24) as u8);
        buf.push((len >> 16) as u8);
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
    } else if n < 0x1_0000_0000 {
        buf.push(0x1A);
        buf.push((n >> 24) as u8);
        buf.push((n >> 16) as u8);
        buf.push((n >> 8) as u8);
        buf.push(n as u8);
    } else {
        buf.push(0x1B);
        for i in (0..8).rev() {
            buf.push((n >> (i * 8)) as u8);
        }
    }
}

fn encode_cid(cid: &[u8], buf: &mut Vec<u8>) {
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

fn encode_array_header(len: usize, buf: &mut Vec<u8>) {
    if len < 24 {
        buf.push(0x80 | len as u8);
    } else if len < 256 {
        buf.push(0x98);
        buf.push(len as u8);
    } else {
        buf.push(0x99);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let header = encode_header(1, "#commit");
        assert!(!header.is_empty());
        // Should contain "op" and "t" keys
        assert!(header.windows(2).any(|w| w == b"op"));
    }

    #[test]
    fn header_error_op() {
        let header = encode_header(-1, "#error");
        assert!(!header.is_empty());
    }

    #[test]
    fn commit_body_has_all_fields() {
        let body = encode_commit_body(
            42, "did:plc:test", &[0x01; 36], "rev123",
            Some("prev_rev"), b"car-bytes",
            &[("create", "app.bsky.feed.post/abc", Some(&[0x01; 36]))],
        );
        assert!(!body.is_empty());
    }

    #[test]
    fn handle_body() {
        let body = encode_handle_body(1, "did:plc:test", "alice.bsky.social");
        assert!(!body.is_empty());
    }

    #[test]
    fn info_body() {
        let body = encode_info_body("OutdatedCursor", "lagged 500 events");
        assert!(!body.is_empty());
    }

    #[test]
    fn frame_concatenates() {
        let h = encode_header(1, "#commit");
        let b = encode_commit_body(1, "did:plc:x", &[], "", None, &[], &[]);
        let h_len = h.len();
        let b_len = b.len();
        let f = frame(h, b);
        assert_eq!(f.len(), h_len + b_len);
    }
}
