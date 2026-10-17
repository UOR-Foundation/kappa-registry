//! Merkle Search Tree for atproto repositories.
//!
//! Ordered, insert-order-independent, deterministic tree.
//! Keys are SHA-256 hashed and leading 2-bit zero chunks determine
//! which layer a key falls on (~4 fanout per layer).
//!
//! Pure data structure parameterized over block storage.
//! The server handler bridges BlockStore to KappaStore.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::cid::cid_for_cbor;
use crate::mst_node::{self, MstEntry};

pub type MstBlocks = Vec<([u8; 36], Vec<u8>)>;

#[derive(Debug, thiserror::Error)]
pub enum MstError {
    #[error("invalid MST key: {0}")]
    InvalidKey(String),
    #[error("key already exists: {0}")]
    KeyExists(String),
    #[error("key not found: {0}")]
    KeyNotFound(String),
}

// -- Block storage trait ------------------------------------------------------

/// Block storage abstraction for the MST.
pub trait BlockStore {
    /// Retrieve a block by CID. Returns None if not found.
    fn get(&self, cid: &[u8]) -> Option<Vec<u8>>;
    /// Store a block. Returns its CID (36 bytes).
    fn put(&mut self, data: &[u8]) -> [u8; 36];
}

/// In-memory block store for testing.
pub struct MemoryBlockStore {
    blocks: BTreeMap<[u8; 36], Vec<u8>>,
}

impl MemoryBlockStore {
    pub fn new() -> Self {
        Self {
            blocks: BTreeMap::new(),
        }
    }
}

impl Default for MemoryBlockStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockStore for MemoryBlockStore {
    fn get(&self, cid: &[u8]) -> Option<Vec<u8>> {
        if cid.len() != 36 {
            return None;
        }
        let mut key = [0u8; 36];
        key.copy_from_slice(cid);
        self.blocks.get(&key).cloned()
    }

    fn put(&mut self, data: &[u8]) -> [u8; 36] {
        let cid = cid_for_cbor(data);
        self.blocks.insert(cid, data.to_vec());
        cid
    }
}

// -- MST key validation -------------------------------------------------------

const MAX_KEY_LEN: usize = 1024;

fn is_valid_mst_char(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'~' | b'-' | b':' | b'.')
}

/// Validate an MST key: `collection/rkey`, exactly one `/`, max 1024 bytes.
pub fn is_valid_mst_key(key: &str) -> bool {
    if key.len() > MAX_KEY_LEN {
        return false;
    }
    let mut slash_count = 0;
    let mut slash_pos = 0;
    for (i, b) in key.bytes().enumerate() {
        if b == b'/' {
            slash_count += 1;
            slash_pos = i;
        } else if !is_valid_mst_char(b) {
            return false;
        }
    }
    slash_count == 1 && slash_pos > 0 && slash_pos < key.len() - 1
}

// -- Layer computation --------------------------------------------------------

/// Count leading 2-bit zero chunks in SHA-256(key).
pub fn leading_zeros(key: &str) -> usize {
    let hash = Sha256::digest(key.as_bytes());
    let mut zeros = 0;
    for &byte in hash.as_slice() {
        if byte < 64 {
            zeros += 1;
        } else {
            break;
        }
        if byte < 16 {
            zeros += 1;
        } else {
            break;
        }
        if byte < 4 {
            zeros += 1;
        } else {
            break;
        }
        if byte == 0 {
            zeros += 1;
        } else {
            break;
        }
    }
    zeros
}

// -- MST data structure -------------------------------------------------------

/// In-memory MST built from a flat key-value map.
pub struct Mst {
    entries: BTreeMap<String, [u8; 36]>,
}

impl Mst {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, key: &str, value: [u8; 36]) -> Result<(), MstError> {
        if !is_valid_mst_key(key) {
            return Err(MstError::InvalidKey(key.to_string()));
        }
        if self.entries.contains_key(key) {
            return Err(MstError::KeyExists(key.to_string()));
        }
        self.entries.insert(key.to_string(), value);
        Ok(())
    }

    pub fn update(&mut self, key: &str, value: [u8; 36]) -> Result<(), MstError> {
        if !self.entries.contains_key(key) {
            return Err(MstError::KeyNotFound(key.to_string()));
        }
        self.entries.insert(key.to_string(), value);
        Ok(())
    }

    pub fn delete(&mut self, key: &str) -> Result<[u8; 36], MstError> {
        self.entries
            .remove(key)
            .ok_or_else(|| MstError::KeyNotFound(key.to_string()))
    }

    pub fn get(&self, key: &str) -> Option<&[u8; 36]> {
        self.entries.get(key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8; 36])> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Serialize the full tree to a block store and return the root CID
    /// plus all (CID, bytes) pairs stored during serialization.
    pub fn write_to_store(&self, store: &mut dyn BlockStore) -> ([u8; 36], MstBlocks) {
        let mut all_blocks = Vec::new();
        if self.entries.is_empty() {
            let node_bytes = mst_node::encode_node(None, &[]);
            let cid = store.put(&node_bytes);
            all_blocks.push((cid, node_bytes));
            return (cid, all_blocks);
        }

        let keyed: Vec<(&str, &[u8; 36], usize)> = self
            .entries
            .iter()
            .map(|(k, v)| (k.as_str(), v, leading_zeros(k)))
            .collect();

        let max_layer = keyed.iter().map(|(_, _, l)| *l).max().unwrap_or(0);
        let root = build_subtree(&keyed, 0, keyed.len(), max_layer, store, &mut all_blocks);
        (root, all_blocks)
    }

    /// Compute the diff between this MST and another.
    pub fn diff(&self, other: &Mst) -> MstDiff {
        let mut created = Vec::new();
        let mut updated = Vec::new();
        let mut deleted = Vec::new();

        for (key, new_val) in &self.entries {
            match other.entries.get(key) {
                None => created.push((key.clone(), *new_val)),
                Some(old_val) if old_val != new_val => {
                    updated.push((key.clone(), *old_val, *new_val))
                }
                _ => {}
            }
        }

        for (key, old_val) in &other.entries {
            if !self.entries.contains_key(key) {
                deleted.push((key.clone(), *old_val));
            }
        }

        MstDiff {
            created,
            updated,
            deleted,
        }
    }
}

impl Default for Mst {
    fn default() -> Self {
        Self::new()
    }
}

/// Diff between two MSTs.
#[derive(Debug, Clone)]
pub struct MstDiff {
    pub created: Vec<(String, [u8; 36])>,
    pub updated: Vec<(String, [u8; 36], [u8; 36])>,
    pub deleted: Vec<(String, [u8; 36])>,
}

fn build_subtree(
    keys: &[(&str, &[u8; 36], usize)],
    start: usize,
    end: usize,
    layer: usize,
    store: &mut dyn BlockStore,
    all_blocks: &mut Vec<([u8; 36], Vec<u8>)>,
) -> [u8; 36] {
    let mut node_entries: Vec<MstEntry> = Vec::new();
    let mut left_subtree: Option<[u8; 36]> = None;
    let mut prev_key = String::new();

    let mut i = start;
    let mut sub_start = i;
    while i < end && keys[i].2 < layer {
        i += 1;
    }
    if i > sub_start && layer > 0 {
        let sub_cid = build_subtree(keys, sub_start, i, layer - 1, store, all_blocks);
        left_subtree = Some(sub_cid);
    }

    while i < end {
        if keys[i].2 == layer {
            let key = keys[i].0;
            let value = keys[i].1;
            let prefix_len = count_prefix_len(&prev_key, key);
            let key_suffix = key.as_bytes()[prefix_len..].to_vec();

            i += 1;
            sub_start = i;
            while i < end && keys[i].2 < layer {
                i += 1;
            }

            let right_subtree = if i > sub_start && layer > 0 {
                Some(build_subtree(
                    keys,
                    sub_start,
                    i,
                    layer - 1,
                    store,
                    all_blocks,
                ))
            } else {
                None
            };

            node_entries.push(MstEntry {
                prefix_len,
                key_suffix,
                value: *value,
                tree: right_subtree,
            });

            prev_key = key.to_string();
        } else {
            i += 1;
        }
    }

    let left_ref = left_subtree.as_ref().map(|c| c.as_slice());
    let node_bytes = mst_node::encode_node(left_ref, &node_entries);
    let cid = store.put(&node_bytes);
    all_blocks.push((cid, node_bytes));
    cid
}

fn count_prefix_len(a: &str, b: &str) -> usize {
    a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zeros_deterministic() {
        let a = leading_zeros("app.bsky.feed.post/abc123");
        let b = leading_zeros("app.bsky.feed.post/abc123");
        assert_eq!(a, b);
    }

    #[test]
    fn leading_zeros_distribution() {
        let mut counts = [0usize; 20];
        for i in 0..1000 {
            let key = format!("app.bsky.feed.post/{:010}", i);
            let z = leading_zeros(&key);
            if z < counts.len() {
                counts[z] += 1;
            }
        }
        assert!(counts[0] > 500, "layer 0 should dominate: {:?}", counts);
    }

    #[test]
    fn valid_keys() {
        assert!(is_valid_mst_key("app.bsky.feed.post/abc123"));
        assert!(is_valid_mst_key("a/b"));
        assert!(is_valid_mst_key("com.example/rkey-with-dashes"));
        assert!(is_valid_mst_key("com.example/rkey_with_underscores"));
        assert!(is_valid_mst_key("com.example/rkey.with.dots"));
        assert!(is_valid_mst_key("com.example/rkey:with:colons"));
        assert!(is_valid_mst_key("com.example/rkey~with~tildes"));
    }

    #[test]
    fn invalid_keys() {
        assert!(!is_valid_mst_key("no-slash"));
        assert!(!is_valid_mst_key("too/many/slashes"));
        assert!(!is_valid_mst_key("/leading-slash"));
        assert!(!is_valid_mst_key("trailing-slash/"));
        assert!(!is_valid_mst_key("has spaces/key"));
        assert!(!is_valid_mst_key("has/spc key"));
        assert!(!is_valid_mst_key(""));
    }

    #[test]
    fn insert_get() {
        let mut mst = Mst::new();
        let cid = cid_for_cbor(b"test value");
        mst.insert("app.bsky.feed.post/abc", cid).unwrap();
        assert_eq!(mst.get("app.bsky.feed.post/abc"), Some(&cid));
        assert_eq!(mst.get("app.bsky.feed.post/xyz"), None);
    }

    #[test]
    fn insert_duplicate_rejected() {
        let mut mst = Mst::new();
        let cid = cid_for_cbor(b"v");
        mst.insert("a/b", cid).unwrap();
        assert!(mst.insert("a/b", cid).is_err());
    }

    #[test]
    fn update_existing() {
        let mut mst = Mst::new();
        let v1 = cid_for_cbor(b"v1");
        let v2 = cid_for_cbor(b"v2");
        mst.insert("a/b", v1).unwrap();
        mst.update("a/b", v2).unwrap();
        assert_eq!(mst.get("a/b"), Some(&v2));
    }

    #[test]
    fn delete_existing() {
        let mut mst = Mst::new();
        let cid = cid_for_cbor(b"v");
        mst.insert("a/b", cid).unwrap();
        let deleted = mst.delete("a/b").unwrap();
        assert_eq!(deleted, cid);
        assert!(mst.get("a/b").is_none());
    }

    #[test]
    fn write_to_store_nonempty() {
        let mut mst = Mst::new();
        for i in 0..50 {
            let key = format!("app.bsky.feed.post/{:06}", i);
            let cid = cid_for_cbor(format!("value-{}", i).as_bytes());
            mst.insert(&key, cid).unwrap();
        }
        let mut store = MemoryBlockStore::new();
        let (root, all_blocks) = mst.write_to_store(&mut store);
        assert_eq!(root.len(), 36);
        assert!(store.get(&root).is_some());
        assert!(!all_blocks.is_empty());
    }

    #[test]
    fn write_to_store_empty() {
        let mst = Mst::new();
        let mut store = MemoryBlockStore::new();
        let (root, all_blocks) = mst.write_to_store(&mut store);
        assert!(store.get(&root).is_some());
        assert_eq!(all_blocks.len(), 1);
    }

    #[test]
    fn diff_detects_changes() {
        let mut old = Mst::new();
        let v1 = cid_for_cbor(b"v1");
        let v2 = cid_for_cbor(b"v2");
        let v3 = cid_for_cbor(b"v3");
        old.insert("a/1", v1).unwrap();
        old.insert("a/2", v2).unwrap();

        let mut new_mst = Mst::new();
        let v2_updated = cid_for_cbor(b"v2-updated");
        new_mst.insert("a/2", v2_updated).unwrap();
        new_mst.insert("a/3", v3).unwrap();

        let diff = new_mst.diff(&old);
        assert_eq!(diff.created.len(), 1);
        assert_eq!(diff.updated.len(), 1);
        assert_eq!(diff.deleted.len(), 1);
        assert_eq!(diff.created[0].0, "a/3");
        assert_eq!(diff.updated[0].0, "a/2");
        assert_eq!(diff.deleted[0].0, "a/1");
    }

    #[test]
    fn sorted_iteration() {
        let mut mst = Mst::new();
        let cid = cid_for_cbor(b"v");
        mst.insert("z/z", cid).unwrap();
        mst.insert("a/a", cid).unwrap();
        mst.insert("m/m", cid).unwrap();
        let keys: Vec<&str> = mst.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["a/a", "m/m", "z/z"]);
    }

    #[test]
    fn prefix_len_computation() {
        assert_eq!(count_prefix_len("abcdef", "abcxyz"), 3);
        assert_eq!(count_prefix_len("abc", "abc"), 3);
        assert_eq!(count_prefix_len("abc", "xyz"), 0);
        assert_eq!(count_prefix_len("", "abc"), 0);
    }

    #[test]
    fn node_encode_decode_roundtrip() {
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

        let encoded = mst_node::encode_node(Some(&left_cid), &entries);
        let (decoded_left, decoded_entries) = mst_node::decode_node(&encoded).unwrap();

        assert_eq!(decoded_left.unwrap(), left_cid);
        assert_eq!(decoded_entries.len(), 2);
        assert_eq!(decoded_entries[0].key, b"app.bsky.feed.post/abc");
        assert_eq!(decoded_entries[0].value, cid1);
        assert_eq!(decoded_entries[1].key, b"app.bsky.feed.post/abcdef");
        assert_eq!(decoded_entries[1].value, cid2);
    }
}
