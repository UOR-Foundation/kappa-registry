//! DAG-CBOR encoding and decoding for AT Protocol.
//!
//! Thin layer over dcbor providing:
//! - Tag 42 CID encode/decode with 0x00 identity multibase prefix
//! - Sorted-key map construction via dcbor::Map
//! - Float rejection (DAG-CBOR forbids floats)
//! - Firehose frame assembly
//!
//! All CBOR encoding and decoding in the AT Protocol module goes
//! through this file. No hand-rolled CBOR primitives exist elsewhere.

use dcbor::prelude::*;

// -- Error --------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DagCborError {
    #[error("dcbor: {0}")]
    Dcbor(dcbor::Error),
    #[error("expected Tag 42 CID, found tag {0}")]
    NotCidTag(u64),
    #[error("expected byte string inside Tag 42")]
    CidNotByteString,
    #[error("empty CID byte string")]
    EmptyCid,
    #[error("DAG-CBOR forbids float values")]
    FloatForbidden,
    #[error("expected map, found other CBOR type")]
    ExpectedMap,
    #[error("expected array, found other CBOR type")]
    ExpectedArray,
    #[error("expected text string, found other CBOR type")]
    ExpectedText,
    #[error("expected unsigned integer, found other CBOR type")]
    ExpectedUint,
    #[error("expected byte string, found other CBOR type")]
    ExpectedBytes,
    #[error("missing map key: {0}")]
    MissingKey(String),
    #[error("op value out of range: {0}")]
    OpOutOfRange(i64),
    #[error("invalid DAG-CBOR data: {0}")]
    InvalidData(String),
}

impl From<dcbor::Error> for DagCborError {
    fn from(e: dcbor::Error) -> Self {
        Self::Dcbor(e)
    }
}

// -- CID encode/decode --------------------------------------------------------

/// Encode a CID as CBOR Tag 42 with 0x00 identity multibase prefix.
///
/// Input: raw CID bytes (typically 36 bytes for CIDv1+dag-cbor+sha256).
/// Output: a CBOR Tagged value for inclusion in a map or array.
pub fn encode_cid(cid: &[u8]) -> CBOR {
    let mut prefixed = Vec::with_capacity(1 + cid.len());
    prefixed.push(0x00);
    prefixed.extend_from_slice(cid);
    let bs = ByteString::from(prefixed);
    CBORCase::Tagged(Tag::with_value(42), CBOR::from(bs)).into()
}

/// Encode a CID or null. For optional CID fields (prev, since).
pub fn encode_nullable_cid(cid: Option<&[u8]>) -> CBOR {
    match cid {
        Some(c) => encode_cid(c),
        None => CBOR::null(),
    }
}

/// Decode a CBOR Tag 42 value to raw CID bytes, stripping the 0x00 prefix.
pub fn decode_cid(cbor: &CBOR) -> Result<Vec<u8>, DagCborError> {
    match cbor.as_case() {
        CBORCase::Tagged(tag, inner) => {
            if tag.value() != 42 {
                return Err(DagCborError::NotCidTag(tag.value()));
            }
            let bs = inner
                .as_byte_string()
                .ok_or(DagCborError::CidNotByteString)?;
            if bs.is_empty() {
                return Err(DagCborError::EmptyCid);
            }
            if bs[0] == 0x00 {
                Ok(bs[1..].to_vec())
            } else {
                Ok(bs.to_vec())
            }
        }
        _ => Err(DagCborError::NotCidTag(0)),
    }
}

/// Decode a CBOR value that is either a Tag 42 CID or null.
pub fn decode_nullable_cid(cbor: &CBOR) -> Result<Option<Vec<u8>>, DagCborError> {
    match cbor.as_case() {
        CBORCase::Simple(dcbor::Simple::Null) => Ok(None),
        _ => decode_cid(cbor).map(Some),
    }
}

// -- Map construction ---------------------------------------------------------

/// Create a new DAG-CBOR map. Keys are automatically sorted by dcbor::Map.
pub fn new_map() -> Map {
    Map::new()
}

/// Insert a string key and CBOR value into a map.
pub fn map_insert(map: &mut Map, key: &str, value: CBOR) {
    map.insert(CBOR::from(key.to_string()), value);
}

/// Insert a string key and string value into a map.
pub fn map_insert_text(map: &mut Map, key: &str, value: &str) {
    map.insert(CBOR::from(key.to_string()), CBOR::from(value.to_string()));
}

/// Insert a string key and u64 value into a map.
pub fn map_insert_uint(map: &mut Map, key: &str, value: u64) {
    map.insert(CBOR::from(key.to_string()), CBOR::from(value));
}

/// Insert a string key and byte string value into a map.
pub fn map_insert_bytes(map: &mut Map, key: &str, value: &[u8]) {
    map.insert(
        CBOR::from(key.to_string()),
        CBOR::from(ByteString::from(value.to_vec())),
    );
}

/// Insert a string key and CID value (Tag 42) into a map.
pub fn map_insert_cid(map: &mut Map, key: &str, cid: &[u8]) {
    map.insert(CBOR::from(key.to_string()), encode_cid(cid));
}

/// Insert a string key and nullable CID into a map.
pub fn map_insert_nullable_cid(map: &mut Map, key: &str, cid: Option<&[u8]>) {
    map.insert(CBOR::from(key.to_string()), encode_nullable_cid(cid));
}

/// Wrap a Vec<CBOR> as a CBOR array value.
pub fn encode_array(items: Vec<CBOR>) -> CBOR {
    CBOR::from(items)
}

/// Encode a map to DAG-CBOR bytes.
pub fn encode_map(map: Map) -> Vec<u8> {
    CBOR::from(map).to_cbor_data()
}

// -- Map decode helpers -------------------------------------------------------

/// Find a CBOR value in a map by string key.
/// Returns the raw CBOR value, preserving Tag structure.
fn map_find_value<'a>(map: &'a Map, key: &str) -> Option<&'a CBOR> {
    for (k, v) in map.iter() {
        if let CBORCase::Text(s) = k.as_case()
            && s == key
        {
            return Some(v);
        }
    }
    None
}

/// Extract a text string from a map by key.
pub fn map_get_text(map: &Map, key: &str) -> Result<String, DagCborError> {
    map.extract::<&str, String>(key)
        .map_err(|_| DagCborError::MissingKey(key.to_string()))
}

/// Extract an optional text string from a map by key.
pub fn map_get_optional_text(map: &Map, key: &str) -> Option<String> {
    map.get::<&str, String>(key)
}

/// Extract a u64 from a map by key.
pub fn map_get_uint(map: &Map, key: &str) -> Result<u64, DagCborError> {
    map.extract::<&str, u64>(key)
        .map_err(|_| DagCborError::MissingKey(key.to_string()))
}

/// Extract a byte string from a map by key.
pub fn map_get_bytes(map: &Map, key: &str) -> Result<Vec<u8>, DagCborError> {
    map.extract::<&str, ByteString>(key)
        .map(|bs| bs.to_vec())
        .map_err(|_| DagCborError::MissingKey(key.to_string()))
}

/// Extract a CID (Tag 42) from a map by key.
pub fn map_get_cid(map: &Map, key: &str) -> Result<Vec<u8>, DagCborError> {
    let v = map_find_value(map, key).ok_or_else(|| DagCborError::MissingKey(key.to_string()))?;
    decode_cid(v)
}

/// Extract a nullable CID from a map by key.
pub fn map_get_nullable_cid(map: &Map, key: &str) -> Result<Option<Vec<u8>>, DagCborError> {
    let v = map_find_value(map, key).ok_or_else(|| DagCborError::MissingKey(key.to_string()))?;
    decode_nullable_cid(v)
}

// -- Decode from bytes --------------------------------------------------------

/// Decode DAG-CBOR bytes into a dcbor CBOR value.
///
/// Rejects non-canonical encoding (non-minimal integers, unsorted
/// map keys).
pub fn decode(data: &[u8]) -> Result<CBOR, DagCborError> {
    CBOR::try_from_data(data).map_err(DagCborError::Dcbor)
}

/// Decode bytes and extract as a map. Uses as_case to borrow, not
/// into_case which would consume the CBOR value.
pub fn decode_map(data: &[u8]) -> Result<Map, DagCborError> {
    let cbor = decode(data)?;
    match cbor.as_case() {
        CBORCase::Map(m) => Ok(m.clone()),
        _ => Err(DagCborError::ExpectedMap),
    }
}

// -- Float rejection ----------------------------------------------------------

/// Walk a CBOR tree and reject if any float value is present.
/// DAG-CBOR forbids all floating-point values.
pub fn reject_floats(cbor: &CBOR) -> Result<(), DagCborError> {
    match cbor.as_case() {
        CBORCase::Simple(s) => {
            if s.is_float() {
                Err(DagCborError::FloatForbidden)
            } else {
                Ok(())
            }
        }
        CBORCase::Array(items) => {
            for item in items {
                reject_floats(item)?;
            }
            Ok(())
        }
        CBORCase::Map(map) => {
            for (k, v) in map.iter() {
                reject_floats(k)?;
                reject_floats(v)?;
            }
            Ok(())
        }
        CBORCase::Tagged(_, inner) => reject_floats(inner),
        _ => Ok(()),
    }
}

// -- Firehose frame types -----------------------------------------------------

/// AT Protocol firehose header opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameOp {
    /// Regular message (op = 1).
    Message,
    /// Error message (op = -1).
    Error,
}

impl FrameOp {
    fn to_cbor(self) -> CBOR {
        match self {
            Self::Message => CBOR::from(1u64),
            Self::Error => CBORCase::Negative(0).into(), // -1 = -1 - 0
        }
    }
}

/// Fields for a #commit firehose frame body.
pub struct CommitFrame<'a> {
    pub seq: u64,
    pub repo: &'a str,
    pub commit_cid: &'a [u8],
    pub rev: &'a str,
    pub since: Option<&'a str>,
    pub blocks_car: &'a [u8],
    pub ops: &'a [CommitOp<'a>],
}

/// A single operation within a commit frame.
pub struct CommitOp<'a> {
    pub action: &'a str,
    pub path: &'a str,
    pub cid: Option<&'a [u8]>,
}

// -- Firehose frame encoding --------------------------------------------------

/// Encode a firehose frame header.
pub fn encode_header(op: FrameOp, frame_type: &str) -> Vec<u8> {
    let mut map = new_map();
    map_insert(&mut map, "op", op.to_cbor());
    map_insert_text(&mut map, "t", frame_type);
    encode_map(map)
}

/// Encode a #commit frame body from a typed struct.
pub fn encode_commit_body(frame: &CommitFrame<'_>) -> Vec<u8> {
    let mut map = new_map();
    map_insert_bytes(&mut map, "blocks", frame.blocks_car);
    if frame.commit_cid.is_empty() {
        map_insert(&mut map, "commit", CBOR::null());
    } else {
        map_insert_cid(&mut map, "commit", frame.commit_cid);
    }

    let ops_cbor: Vec<CBOR> = frame
        .ops
        .iter()
        .map(|op| {
            let mut op_map = new_map();
            map_insert_text(&mut op_map, "action", op.action);
            map_insert_nullable_cid(&mut op_map, "cid", op.cid);
            map_insert_text(&mut op_map, "path", op.path);
            CBOR::from(op_map)
        })
        .collect();
    map_insert(&mut map, "ops", encode_array(ops_cbor));

    map_insert_text(&mut map, "repo", frame.repo);
    map_insert_text(&mut map, "rev", frame.rev);
    map_insert_uint(&mut map, "seq", frame.seq);
    match frame.since {
        Some(s) => map_insert_text(&mut map, "since", s),
        None => map_insert(&mut map, "since", CBOR::null()),
    }
    encode_map(map)
}

/// Encode a #handle frame body: { "did", "handle", "seq" }
pub fn encode_handle_body(seq: u64, did: &str, handle: &str) -> Vec<u8> {
    let mut map = new_map();
    map_insert_text(&mut map, "did", did);
    map_insert_text(&mut map, "handle", handle);
    map_insert_uint(&mut map, "seq", seq);
    encode_map(map)
}

/// Encode a #identity frame body: { "did", "seq" }
pub fn encode_identity_body(seq: u64, did: &str) -> Vec<u8> {
    let mut map = new_map();
    map_insert_text(&mut map, "did", did);
    map_insert_uint(&mut map, "seq", seq);
    encode_map(map)
}

/// Encode a #tombstone frame body. Same shape as identity.
pub fn encode_tombstone_body(seq: u64, did: &str) -> Vec<u8> {
    encode_identity_body(seq, did)
}

/// Encode a #info frame body: { "message", "name" }
pub fn encode_info_body(name: &str, message: &str) -> Vec<u8> {
    let mut map = new_map();
    map_insert_text(&mut map, "message", message);
    map_insert_text(&mut map, "name", name);
    encode_map(map)
}

/// Concatenate header and body into a single binary firehose frame.
///
/// AT Protocol firehose framing: each WebSocket message is two
/// concatenated DAG-CBOR objects. The first is the header (op + type),
/// the second is the body (type-specific payload). The receiver
/// decodes the first CBOR value as the header, then decodes the
/// remaining bytes as the body.
pub fn frame(header: Vec<u8>, body: Vec<u8>) -> Vec<u8> {
    let mut out = header;
    out.extend(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cid_roundtrip() {
        let cid = [
            0x01u8, 0x71, 0x12, 0x20, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        ];
        let encoded = encode_cid(&cid);
        let bytes = encoded.to_cbor_data();
        let decoded_cbor = CBOR::try_from_data(&bytes).unwrap();
        let decoded_cid = decode_cid(&decoded_cbor).unwrap();
        assert_eq!(decoded_cid, cid);
    }

    #[test]
    fn nullable_cid_some_roundtrip() {
        let cid = [0x01u8; 36];
        let encoded = encode_nullable_cid(Some(&cid));
        let decoded = decode_nullable_cid(&encoded).unwrap();
        assert_eq!(decoded, Some(cid.to_vec()));
    }

    #[test]
    fn nullable_cid_none_roundtrip() {
        let encoded = encode_nullable_cid(None);
        let decoded = decode_nullable_cid(&encoded).unwrap();
        assert_eq!(decoded, None);
    }

    #[test]
    fn map_keys_sorted_regardless_of_insertion_order() {
        let mut map = new_map();
        map_insert_text(&mut map, "zebra", "last");
        map_insert_text(&mut map, "alpha", "first");
        map_insert_text(&mut map, "middle", "mid");
        let bytes = encode_map(map);

        let decoded = CBOR::try_from_data(&bytes).unwrap();
        let m = match decoded.as_case() {
            CBORCase::Map(m) => m,
            _ => panic!("expected map"),
        };
        let keys: Vec<String> = m
            .iter()
            .map(|(k, _)| match k.as_case() {
                CBORCase::Text(s) => s.clone(),
                _ => panic!("expected text key"),
            })
            .collect();
        // DAG-CBOR canonical order: shorter keys first, then bytewise.
        assert_eq!(keys, vec!["alpha", "zebra", "middle"]);
    }

    #[test]
    fn large_uint_roundtrip() {
        let val: u64 = 100_000;
        let cbor = CBOR::from(val);
        let bytes = cbor.to_cbor_data();
        let decoded = CBOR::try_from_data(&bytes).unwrap();
        let result: u64 = decoded.try_into().unwrap();
        assert_eq!(result, val);
    }

    #[test]
    fn max_uint_roundtrip() {
        let val: u64 = u64::MAX;
        let cbor = CBOR::from(val);
        let bytes = cbor.to_cbor_data();
        let decoded = CBOR::try_from_data(&bytes).unwrap();
        let result: u64 = decoded.try_into().unwrap();
        assert_eq!(result, val);
    }

    #[test]
    fn large_byte_string_roundtrip() {
        let data = vec![0xABu8; 70_000];
        let cbor = CBOR::from(ByteString::from(data.clone()));
        let bytes = cbor.to_cbor_data();
        let decoded = CBOR::try_from_data(&bytes).unwrap();
        let result: ByteString = decoded.try_into().unwrap();
        assert_eq!(result.to_vec(), data);
    }

    #[test]
    fn reject_floats_catches_float() {
        let cbor = CBOR::from(1.25f64);
        assert!(reject_floats(&cbor).is_err());
    }

    #[test]
    fn reject_floats_allows_integer() {
        let cbor = CBOR::from(42u64);
        assert!(reject_floats(&cbor).is_ok());
    }

    #[test]
    fn reject_floats_catches_nested_float() {
        let array: Vec<CBOR> = vec![CBOR::from(1u64), CBOR::from(2.5f64)];
        let cbor = CBOR::from(array);
        assert!(reject_floats(&cbor).is_err());
    }

    #[test]
    fn reject_floats_catches_float_in_map_value() {
        let mut map = Map::new();
        // 1.0 would reduce to the integer 1 under dCBOR numeric reduction;
        // a fractional value stays a float.
        map.insert("key", CBOR::from(1.5f64));
        let cbor = CBOR::from(map);
        assert!(reject_floats(&cbor).is_err());
    }

    #[test]
    fn header_message_roundtrip() {
        let bytes = encode_header(FrameOp::Message, "#commit");
        let decoded = CBOR::try_from_data(&bytes).unwrap();
        let map = match decoded.as_case() {
            CBORCase::Map(m) => m,
            _ => panic!("expected map"),
        };
        let op: u64 = map.extract("op").unwrap();
        let t: String = map.extract("t").unwrap();
        assert_eq!(op, 1);
        assert_eq!(t, "#commit");
    }

    #[test]
    fn header_error_roundtrip() {
        let bytes = encode_header(FrameOp::Error, "#error");
        let decoded = CBOR::try_from_data(&bytes).unwrap();
        let map = match decoded.as_case() {
            CBORCase::Map(m) => m,
            _ => panic!("expected map"),
        };
        let t: String = map.extract("t").unwrap();
        assert_eq!(t, "#error");
        for (k, v) in map.iter() {
            if let CBORCase::Text(key) = k.as_case()
                && key == "op"
            {
                match v.as_case() {
                    CBORCase::Negative(n) => assert_eq!(*n, 0),
                    other => panic!("expected negative, got {:?}", other),
                }
            }
        }
    }

    #[test]
    fn commit_body_decodes_all_fields() {
        let cid = [0x01u8; 36];
        let bytes = encode_commit_body(&CommitFrame {
            seq: 42,
            repo: "did:plc:test",
            commit_cid: &cid,
            rev: "rev123",
            since: Some("prev_rev"),
            blocks_car: b"car-bytes",
            ops: &[CommitOp {
                action: "create",
                path: "app.bsky.feed.post/abc",
                cid: Some(&cid),
            }],
        });
        let decoded = CBOR::try_from_data(&bytes).unwrap();
        let map = match decoded.as_case() {
            CBORCase::Map(m) => m,
            _ => panic!("expected map"),
        };
        let seq: u64 = map.extract("seq").unwrap();
        let repo: String = map.extract("repo").unwrap();
        let rev: String = map.extract("rev").unwrap();
        assert_eq!(seq, 42);
        assert_eq!(repo, "did:plc:test");
        assert_eq!(rev, "rev123");
    }

    #[test]
    fn handle_body_roundtrip() {
        let bytes = encode_handle_body(7, "did:plc:alice", "alice.bsky.social");
        let decoded = CBOR::try_from_data(&bytes).unwrap();
        let map = match decoded.as_case() {
            CBORCase::Map(m) => m,
            _ => panic!("expected map"),
        };
        let seq: u64 = map.extract("seq").unwrap();
        let did: String = map.extract("did").unwrap();
        let handle: String = map.extract("handle").unwrap();
        assert_eq!(seq, 7);
        assert_eq!(did, "did:plc:alice");
        assert_eq!(handle, "alice.bsky.social");
    }

    #[test]
    fn info_body_roundtrip() {
        let bytes = encode_info_body("OutdatedCursor", "lagged 500 events");
        let decoded = CBOR::try_from_data(&bytes).unwrap();
        let map = match decoded.as_case() {
            CBORCase::Map(m) => m,
            _ => panic!("expected map"),
        };
        let name: String = map.extract("name").unwrap();
        let message: String = map.extract("message").unwrap();
        assert_eq!(name, "OutdatedCursor");
        assert_eq!(message, "lagged 500 events");
    }

    #[test]
    fn frame_concatenates_header_and_body() {
        let h = encode_header(FrameOp::Message, "#commit");
        let b = encode_identity_body(1, "did:plc:x");
        let h_len = h.len();
        let b_len = b.len();
        let f = frame(h, b);
        assert_eq!(f.len(), h_len + b_len);
    }

    #[test]
    fn identity_and_tombstone_produce_identical_bytes() {
        let id = encode_identity_body(5, "did:plc:test");
        let ts = encode_tombstone_body(5, "did:plc:test");
        assert_eq!(id, ts);
    }

    #[test]
    fn decode_rejects_non_canonical() {
        let non_canonical = [0x18, 0x00];
        assert!(decode(&non_canonical).is_err());
    }

    #[test]
    fn decode_map_borrows_not_consumes() {
        let mut map = new_map();
        map_insert_text(&mut map, "key", "value");
        let bytes = encode_map(map);
        let m = decode_map(&bytes).unwrap();
        let val: String = m.extract("key").unwrap();
        assert_eq!(val, "value");
    }

    #[test]
    fn map_get_cid_extracts_tag42() {
        let cid = [0x01u8; 36];
        let mut map = new_map();
        map_insert_cid(&mut map, "ref", &cid);
        let extracted = map_get_cid(&map, "ref").unwrap();
        assert_eq!(extracted, cid);
    }

    #[test]
    fn map_get_nullable_cid_some() {
        let cid = [0x02u8; 36];
        let mut map = new_map();
        map_insert_nullable_cid(&mut map, "prev", Some(&cid));
        let extracted = map_get_nullable_cid(&map, "prev").unwrap();
        assert_eq!(extracted, Some(cid.to_vec()));
    }

    #[test]
    fn map_get_nullable_cid_null() {
        let mut map = new_map();
        map_insert_nullable_cid(&mut map, "prev", None);
        let extracted = map_get_nullable_cid(&map, "prev").unwrap();
        assert_eq!(extracted, None);
    }
}
