//! MST node DAG-CBOR encode/decode.
//!
//! An MST node is a DAG-CBOR map with two fields:
//!   "e": array of entries [{ "k": bytes, "p": uint, "t": CID|null, "v": CID }]
//!   "l": CID|null (left subtree)
//!
//! The wire format uses prefix compression (p = shared prefix length,
//! k = key suffix). The decode path decompresses to full keys.
//! Callers receive DecodedEntry with complete keys. The prefix
//! compression detail never leaks past the decoder.

use dcbor::prelude::*;

use crate::dag_cbor::{self, DagCborError};

/// Wire format entry used by encode_node.
/// Prefix-compressed: prefix_len bytes shared with the previous key,
/// key_suffix is the remainder.
#[derive(Debug, Clone)]
pub struct MstEntry {
    pub prefix_len: usize,
    pub key_suffix: Vec<u8>,
    pub value: [u8; 36],
    pub tree: Option<[u8; 36]>,
}

/// Decoded entry returned by decode_node.
/// Full key reconstructed from prefix compression.
/// Callers use this type — never MstEntry directly.
#[derive(Debug, Clone)]
pub struct DecodedEntry {
    pub key: Vec<u8>,
    pub value: [u8; 36],
    pub tree: Option<[u8; 36]>,
}

/// Encode an MST node as DAG-CBOR bytes.
pub fn encode_node(left: Option<&[u8]>, entries: &[MstEntry]) -> Vec<u8> {
    let mut map = dag_cbor::new_map();
    let entry_cbors: Vec<CBOR> = entries.iter().map(encode_entry).collect();
    dag_cbor::map_insert(&mut map, "e", CBOR::from(entry_cbors));
    dag_cbor::map_insert(&mut map, "l", dag_cbor::encode_nullable_cid(left));
    dag_cbor::encode_map(map)
}

/// Decode an MST node from DAG-CBOR bytes.
///
/// Returns (left_subtree_cid, entries_with_full_keys).
/// Prefix decompression happens here. Callers get DecodedEntry
/// with complete keys. The prefix_len/key_suffix wire format
/// never leaves this function.
pub fn decode_node(data: &[u8]) -> Result<(Option<Vec<u8>>, Vec<DecodedEntry>), DagCborError> {
    let cbor = dag_cbor::decode(data)?;
    let map = match cbor.as_case() {
        CBORCase::Map(m) => m,
        _ => return Err(DagCborError::ExpectedMap),
    };

    let mut left: Option<Vec<u8>> = None;
    let mut raw_entries: Vec<RawEntry> = Vec::new();

    for (k, v) in map.iter() {
        let key_str = match k.as_case() {
            CBORCase::Text(s) => s.as_str(),
            _ => continue,
        };
        match key_str {
            "e" => {
                let arr = match v.as_case() {
                    CBORCase::Array(a) => a,
                    _ => return Err(DagCborError::ExpectedArray),
                };
                for item in arr {
                    raw_entries.push(decode_raw_entry(item)?);
                }
            }
            "l" => {
                left = dag_cbor::decode_nullable_cid(v)?;
            }
            _ => {}
        }
    }

    // Reconstruct full keys from prefix-compressed entries.
    let mut decoded = Vec::with_capacity(raw_entries.len());
    let mut prev_key: Vec<u8> = Vec::new();

    for raw in &raw_entries {
        if raw.prefix_len > prev_key.len() {
            return Err(DagCborError::InvalidData(format!(
                "prefix_len {} exceeds previous key length {}",
                raw.prefix_len,
                prev_key.len(),
            )));
        }
        let mut full_key = Vec::with_capacity(raw.prefix_len + raw.key_suffix.len());
        full_key.extend_from_slice(&prev_key[..raw.prefix_len]);
        full_key.extend_from_slice(&raw.key_suffix);

        decoded.push(DecodedEntry {
            key: full_key.clone(),
            value: raw.value,
            tree: raw.tree,
        });

        prev_key = full_key;
    }

    Ok((left, decoded))
}

// -- Internal wire format types -----------------------------------------------

const MAX_PREFIX_LEN: usize = 1024;

struct RawEntry {
    prefix_len: usize,
    key_suffix: Vec<u8>,
    value: [u8; 36],
    tree: Option<[u8; 36]>,
}

fn encode_entry(entry: &MstEntry) -> CBOR {
    let mut map = dag_cbor::new_map();
    dag_cbor::map_insert_bytes(&mut map, "k", &entry.key_suffix);
    dag_cbor::map_insert_uint(&mut map, "p", entry.prefix_len as u64);
    dag_cbor::map_insert_nullable_cid(&mut map, "t", entry.tree.as_ref().map(|c| c.as_slice()));
    dag_cbor::map_insert_cid(&mut map, "v", &entry.value);
    CBOR::from(map)
}

fn decode_raw_entry(cbor: &CBOR) -> Result<RawEntry, DagCborError> {
    let map = match cbor.as_case() {
        CBORCase::Map(m) => m,
        _ => return Err(DagCborError::ExpectedMap),
    };

    let mut prefix_len: usize = 0;
    let mut key_suffix: Vec<u8> = Vec::new();
    let mut value = [0u8; 36];
    let mut value_set = false;
    let mut tree: Option<[u8; 36]> = None;

    for (k, v) in map.iter() {
        let key_str = match k.as_case() {
            CBORCase::Text(s) => s.as_str(),
            _ => continue,
        };
        match key_str {
            "p" => {
                let raw = match v.as_case() {
                    CBORCase::Unsigned(n) => *n as usize,
                    _ => return Err(DagCborError::ExpectedUint),
                };
                if raw > MAX_PREFIX_LEN {
                    return Err(DagCborError::InvalidData(format!(
                        "prefix_len {} exceeds max {}",
                        raw, MAX_PREFIX_LEN
                    )));
                }
                prefix_len = raw;
            }
            "k" => {
                key_suffix = v
                    .as_byte_string()
                    .ok_or(DagCborError::ExpectedBytes)?
                    .to_vec();
            }
            "v" => {
                let cid = dag_cbor::decode_cid(v)?;
                if cid.len() != 36 {
                    return Err(DagCborError::CidNotByteString);
                }
                value.copy_from_slice(&cid);
                value_set = true;
            }
            "t" => {
                tree = dag_cbor::decode_nullable_cid(v)?
                    .map(|cid| {
                        cid.try_into().map_err(|_| {
                            DagCborError::InvalidData(
                                "MST subtree CID must contain 36 bytes".into(),
                            )
                        })
                    })
                    .transpose()?;
            }
            _ => {}
        }
    }

    if !value_set {
        return Err(DagCborError::InvalidData(
            "missing required field: v".into(),
        ));
    }

    Ok(RawEntry {
        prefix_len,
        key_suffix,
        value,
        tree,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid::cid_for_cbor;

    #[test]
    fn empty_node_roundtrip() {
        let bytes = encode_node(None, &[]);
        let (left, entries) = decode_node(&bytes).unwrap();
        assert!(left.is_none());
        assert!(entries.is_empty());
    }

    #[test]
    fn node_with_left_roundtrip() {
        let left_cid = cid_for_cbor(b"left-subtree");
        let bytes = encode_node(Some(&left_cid), &[]);
        let (left, entries) = decode_node(&bytes).unwrap();
        assert_eq!(left.unwrap(), left_cid);
        assert!(entries.is_empty());
    }

    #[test]
    fn node_with_entries_roundtrip() {
        let cid1 = cid_for_cbor(b"value1");
        let cid2 = cid_for_cbor(b"value2");
        let left_cid = cid_for_cbor(b"left-subtree");

        let entries = vec![
            MstEntry {
                prefix_len: 0,
                key_suffix: b"app.bsky.feed.post/abc".to_vec(),
                value: cid1,
                tree: None,
            },
            MstEntry {
                prefix_len: 22,
                key_suffix: b"def".to_vec(),
                value: cid2,
                tree: None,
            },
        ];

        let bytes = encode_node(Some(&left_cid), &entries);
        let (decoded_left, decoded_entries) = decode_node(&bytes).unwrap();

        assert_eq!(decoded_left.unwrap(), left_cid);
        assert_eq!(decoded_entries.len(), 2);
        // Full keys reconstructed from prefix compression:
        assert_eq!(decoded_entries[0].key, b"app.bsky.feed.post/abc");
        assert_eq!(decoded_entries[0].value, cid1);
        assert!(decoded_entries[0].tree.is_none());
        // Second entry: prefix_len=22 means first 22 bytes shared with "app.bsky.feed.post/abc"
        assert_eq!(decoded_entries[1].key, b"app.bsky.feed.post/abcdef");
        assert_eq!(decoded_entries[1].value, cid2);
    }

    #[test]
    fn entry_with_right_subtree_roundtrip() {
        let value_cid = cid_for_cbor(b"value");
        let right_cid = cid_for_cbor(b"right-subtree");

        let entries = vec![MstEntry {
            prefix_len: 0,
            key_suffix: b"a/b".to_vec(),
            value: value_cid,
            tree: Some(right_cid),
        }];

        let bytes = encode_node(None, &entries);
        let (_, decoded) = decode_node(&bytes).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].key, b"a/b");
        assert_eq!(decoded[0].tree, Some(right_cid));
    }

    #[test]
    fn oversized_prefix_len_rejected() {
        let cid = cid_for_cbor(b"v");
        let entries = vec![MstEntry {
            prefix_len: 100_000,
            key_suffix: b"x".to_vec(),
            value: cid,
            tree: None,
        }];
        let bytes = encode_node(None, &entries);
        assert!(decode_node(&bytes).is_err());
    }

    #[test]
    fn prefix_len_exceeding_prev_key_rejected() {
        let cid = cid_for_cbor(b"v");
        // First entry has key "ab" (2 bytes). Second entry claims
        // prefix_len=5 — but the previous key is only 2 bytes.
        let entries = vec![
            MstEntry {
                prefix_len: 0,
                key_suffix: b"ab".to_vec(),
                value: cid,
                tree: None,
            },
            MstEntry {
                prefix_len: 5,
                key_suffix: b"x".to_vec(),
                value: cid,
                tree: None,
            },
        ];
        let bytes = encode_node(None, &entries);
        assert!(decode_node(&bytes).is_err());
    }

    #[test]
    fn three_entries_prefix_chain() {
        let c1 = cid_for_cbor(b"v1");
        let c2 = cid_for_cbor(b"v2");
        let c3 = cid_for_cbor(b"v3");

        let entries = vec![
            MstEntry {
                prefix_len: 0,
                key_suffix: b"app.bsky.feed.post/aaa".to_vec(),
                value: c1,
                tree: None,
            },
            MstEntry {
                prefix_len: 21,
                key_suffix: b"ab".to_vec(),
                value: c2,
                tree: None,
            },
            MstEntry {
                prefix_len: 21,
                key_suffix: b"ac".to_vec(),
                value: c3,
                tree: None,
            },
        ];

        let bytes = encode_node(None, &entries);
        let (_, decoded) = decode_node(&bytes).unwrap();

        assert_eq!(decoded[0].key, b"app.bsky.feed.post/aaa");
        assert_eq!(decoded[1].key, b"app.bsky.feed.post/aaab");
        assert_eq!(decoded[2].key, b"app.bsky.feed.post/aaac");
    }
}
