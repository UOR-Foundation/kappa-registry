//! Merkle Search Tree (MST) for atproto repositories.
//!
//! An ordered, insert-order-independent, deterministic tree.
//! Keys are laid out in alphabetic order. Each key is SHA-256 hashed
//! and leading 2-bit zero chunks are counted to determine which layer
//! the key falls on (~4 fanout per layer).
//!
//! This is a pure data structure parameterized over block storage.
//! It does not depend on kappa-core. The server handler bridges
//! BlockStore to KappaStore.
//!
//! Source: bluesky-social/atproto packages/repo/src/mst/

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::cid::cid_for_cbor;

// -- Block storage trait ------------------------------------------------------

/// Abstraction over block storage for the MST.
///
/// The MST reads and writes DAG-CBOR encoded node blobs via CID.
/// The server handler implements this by bridging to KappaStore.
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

/// Maximum MST key length in bytes.
const MAX_KEY_LEN: usize = 1024;

/// Valid characters for MST keys.
fn is_valid_mst_char(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'~' | b'-' | b':' | b'.')
}

/// Validate an MST key: `collection/rkey`, exactly one `/`, max 1024 bytes.
pub fn is_valid_mst_key(key: &str) -> bool {
    if key.len() > MAX_KEY_LEN {
        return false;
    }
    let parts: Vec<&str> = key.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    if parts[0].is_empty() || parts[1].is_empty() {
        return false;
    }
    parts[0].bytes().all(is_valid_mst_char) && parts[1].bytes().all(is_valid_mst_char)
}

// -- Layer computation --------------------------------------------------------

/// Count leading 2-bit zero chunks in SHA-256(key).
///
/// This determines which MST layer a key belongs to.
/// Each byte contributes 0-4 zero chunks:
///   byte < 64  -> +1 (top 2 bits are 0)
///   byte < 16  -> +1 (top 4 bits are 0)
///   byte < 4   -> +1 (top 6 bits are 0)
///   byte == 0  -> +1 (all 8 bits are 0)
///   else       -> stop
///
/// This gives ~4 fanout per layer (2 bits per layer).
pub fn leading_zeros(key: &str) -> usize {
    let hash = Sha256::digest(key.as_bytes());
    let mut zeros = 0;
    for &byte in hash.as_slice() {
        if byte < 64 { zeros += 1; } else { break; }
        if byte < 16 { zeros += 1; } else { break; }
        if byte < 4 { zeros += 1; } else { break; }
        if byte == 0 { zeros += 1; } else { break; }
    }
    zeros
}

// -- CBOR encoding for MST nodes (minimal, hand-rolled) -----------------------

/// Encode an MST node as DAG-CBOR.
///
/// Node format: { l: CID|null, e: [{ p: uint, k: bytes, v: CID, t: CID|null }] }
///
/// We encode this as a CBOR map with 2 entries ("e" and "l"),
/// where map keys are sorted lexicographically (DAG-CBOR requirement).
pub fn encode_node(left: Option<&[u8]>, entries: &[MstEntry]) -> Vec<u8> {
    let mut buf = Vec::new();

    // CBOR map with 2 entries
    buf.push(0xA2);

    // Key "e" (comes before "l" lexicographically)
    buf.push(0x61); // text string of length 1
    buf.push(b'e');

    // Value: array of entries
    encode_cbor_array_header(entries.len(), &mut buf);
    for entry in entries {
        encode_tree_entry(entry, &mut buf);
    }

    // Key "l"
    buf.push(0x61);
    buf.push(b'l');

    // Value: CID or null
    match left {
        Some(cid) => encode_cbor_cid(cid, &mut buf),
        None => buf.push(0xF6), // CBOR null
    }

    buf
}

/// Decode an MST node from DAG-CBOR bytes.
///
/// Used by repository CRUD (read MST from store) and sync endpoints
/// (walk MST for CAR export). Returns (left_subtree_cid, entries).
pub fn decode_node(data: &[u8]) -> Result<(Option<Vec<u8>>, Vec<MstEntry>), MstError> {
    let mut pos = 0;
    if pos >= data.len() {
        return Err(MstError::InvalidNode("empty data"));
    }

    let major = data[pos] >> 5;
    let additional = data[pos] & 0x1F;
    if major != 5 {
        return Err(MstError::InvalidNode("expected CBOR map"));
    }
    let map_len = additional as usize;
    pos += 1;

    let mut left: Option<Vec<u8>> = None;
    let mut entries: Vec<MstEntry> = Vec::new();

    for _ in 0..map_len {
        let key = read_cbor_text(data, &mut pos)?;
        match key {
            "e" => {
                entries = read_entries_array(data, &mut pos)?;
            }
            "l" => {
                left = read_nullable_cid(data, &mut pos)?;
            }
            _ => {
                skip_cbor(data, &mut pos)?;
            }
        }
    }

    Ok((left, entries))
}

/// A single entry in a serialized MST node.
#[derive(Debug, Clone)]
pub struct MstEntry {
    /// Prefix length shared with the previous key.
    pub prefix_len: usize,
    /// The key suffix (bytes after the shared prefix).
    pub key_suffix: Vec<u8>,
    /// The value CID (36 bytes).
    pub value: [u8; 36],
    /// Optional right subtree CID.
    pub tree: Option<[u8; 36]>,
}

// -- The MST data structure ---------------------------------------------------

/// An in-memory MST built from a flat key-value map.
///
/// For the initial implementation, we use a simple approach:
/// store all key-value pairs in a BTreeMap and serialize the
/// full tree structure on demand. This is correct but not
/// incremental -- every mutation rebuilds the full tree.
///
/// The atproto reference implementation uses lazy loading and
/// immutable tree nodes with pointer updates. That optimization
/// can be added later without changing the external API.
pub struct Mst {
    /// All key-value pairs in the tree.
    entries: BTreeMap<String, [u8; 36]>,
}

impl Mst {
    /// Create an empty MST.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Insert a key-value pair. Returns error if key already exists.
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

    /// Update the value for an existing key. Returns error if key doesn't exist.
    pub fn update(&mut self, key: &str, value: [u8; 36]) -> Result<(), MstError> {
        if !self.entries.contains_key(key) {
            return Err(MstError::KeyNotFound(key.to_string()));
        }
        self.entries.insert(key.to_string(), value);
        Ok(())
    }

    /// Delete a key. Returns error if key doesn't exist.
    pub fn delete(&mut self, key: &str) -> Result<[u8; 36], MstError> {
        self.entries
            .remove(key)
            .ok_or_else(|| MstError::KeyNotFound(key.to_string()))
    }

    /// Get the value for a key.
    pub fn get(&self, key: &str) -> Option<&[u8; 36]> {
        self.entries.get(key)
    }

    /// Number of key-value pairs.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate all key-value pairs in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8; 36])> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Serialize the full tree to a block store and return the root CID.
    ///
    /// This builds the tree structure from scratch every time.
    /// Keys are partitioned into layers based on their leading zeros.
    pub fn write_to_store(&self, store: &mut dyn BlockStore) -> [u8; 36] {
        if self.entries.is_empty() {
            // Empty tree: single node with no entries and no left pointer
            let node_bytes = encode_node(None, &[]);
            return store.put(&node_bytes);
        }

        // Collect all keys with their layers
        let keyed: Vec<(&str, &[u8; 36], usize)> = self
            .entries
            .iter()
            .map(|(k, v)| (k.as_str(), v, leading_zeros(k)))
            .collect();

        // Find the maximum layer (the root layer)
        let max_layer = keyed.iter().map(|(_, _, l)| *l).max().unwrap_or(0);

        // Build tree recursively
        build_subtree(&keyed, 0, keyed.len(), max_layer, store)
    }

    /// Compute the diff between this MST and another.
    pub fn diff(&self, other: &Mst) -> MstDiff {
        let mut created = Vec::new();
        let mut updated = Vec::new();
        let mut deleted = Vec::new();

        // Find creates and updates
        for (key, new_val) in &self.entries {
            match other.entries.get(key) {
                None => created.push((key.clone(), *new_val)),
                Some(old_val) if old_val != new_val => {
                    updated.push((key.clone(), *old_val, *new_val))
                }
                _ => {}
            }
        }

        // Find deletes
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
    /// Keys created in the new tree: (key, new_cid)
    pub created: Vec<(String, [u8; 36])>,
    /// Keys updated: (key, old_cid, new_cid)
    pub updated: Vec<(String, [u8; 36], [u8; 36])>,
    /// Keys deleted from the old tree: (key, old_cid)
    pub deleted: Vec<(String, [u8; 36])>,
}

/// Build a subtree covering keys[start..end] at the given layer.
///
/// Keys at this layer become leaves at this node.
/// Keys at lower layers go into subtrees between the leaves.
fn build_subtree(
    keys: &[(&str, &[u8; 36], usize)],
    start: usize,
    end: usize,
    layer: usize,
    store: &mut dyn BlockStore,
) -> [u8; 36] {
    let mut node_entries: Vec<MstEntry> = Vec::new();
    let mut left_subtree: Option<[u8; 36]> = None;
    let mut prev_key = String::new();

    // Partition keys into this-layer leaves and lower-layer subtrees
    let mut i = start;

    // Collect keys that belong to lower layers before the first leaf
    let mut sub_start = i;
    while i < end && keys[i].2 < layer {
        i += 1;
    }
    if i > sub_start {
        if layer > 0 {
            let sub_cid = build_subtree(keys, sub_start, i, layer - 1, store);
            left_subtree = Some(sub_cid);
        }
    }

    while i < end {
        if keys[i].2 == layer {
            // This key belongs at this layer
            let key = keys[i].0;
            let value = keys[i].1;
            let prefix_len = count_prefix_len(&prev_key, key);
            let key_suffix = key[prefix_len..].as_bytes().to_vec();

            // Look ahead for a right subtree
            let leaf_idx = i;
            i += 1;
            sub_start = i;
            while i < end && keys[i].2 < layer {
                i += 1;
            }

            let right_subtree = if i > sub_start && layer > 0 {
                Some(build_subtree(keys, sub_start, i, layer - 1, store))
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
            let _ = leaf_idx; // used implicitly via i advancement
        } else {
            // This shouldn't happen at the correct layer partitioning
            i += 1;
        }
    }

    let left_ref = left_subtree.as_ref().map(|c| c.as_slice());
    let node_bytes = encode_node(left_ref, &node_entries);
    store.put(&node_bytes)
}

/// Count the length of the common prefix between two strings.
fn count_prefix_len(a: &str, b: &str) -> usize {
    a.bytes()
        .zip(b.bytes())
        .take_while(|(x, y)| x == y)
        .count()
}

#[derive(Debug, thiserror::Error)]
pub enum MstError {
    #[error("invalid MST key: {0}")]
    InvalidKey(String),
    #[error("key already exists: {0}")]
    KeyExists(String),
    #[error("key not found: {0}")]
    KeyNotFound(String),
    #[error("invalid MST node: {0}")]
    InvalidNode(&'static str),
    #[error("block not found")]
    BlockNotFound,
}

// -- CBOR helpers for node encode/decode --------------------------------------

fn encode_cbor_array_header(len: usize, buf: &mut Vec<u8>) {
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

fn encode_cbor_uint(n: u64, buf: &mut Vec<u8>) {
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
        buf.push(0x1B);
        for i in (0..8).rev() {
            buf.push((n >> (i * 8)) as u8);
        }
    }
}

fn encode_cbor_bytes(data: &[u8], buf: &mut Vec<u8>) {
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

fn encode_cbor_cid(cid: &[u8], buf: &mut Vec<u8>) {
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

fn encode_tree_entry(entry: &MstEntry, buf: &mut Vec<u8>) {
    // CBOR map with 4 entries, keys sorted: "k", "p", "t", "v"
    buf.push(0xA4);

    // "k" -> bytes
    buf.push(0x61);
    buf.push(b'k');
    encode_cbor_bytes(&entry.key_suffix, buf);

    // "p" -> uint
    buf.push(0x61);
    buf.push(b'p');
    encode_cbor_uint(entry.prefix_len as u64, buf);

    // "t" -> CID or null
    buf.push(0x61);
    buf.push(b't');
    match &entry.tree {
        Some(cid) => encode_cbor_cid(cid, buf),
        None => buf.push(0xF6),
    }

    // "v" -> CID
    buf.push(0x61);
    buf.push(b'v');
    encode_cbor_cid(&entry.value, buf);
}

fn read_cbor_text<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a str, MstError> {
    if *pos >= data.len() {
        return Err(MstError::InvalidNode("truncated text"));
    }
    let major = data[*pos] >> 5;
    let additional = data[*pos] & 0x1F;
    if major != 3 {
        return Err(MstError::InvalidNode("expected text string"));
    }
    *pos += 1;
    let len = read_cbor_length(additional, data, pos)?;
    if *pos + len > data.len() {
        return Err(MstError::InvalidNode("text extends past end"));
    }
    let s = std::str::from_utf8(&data[*pos..*pos + len])
        .map_err(|_| MstError::InvalidNode("invalid UTF-8"))?;
    *pos += len;
    Ok(s)
}

fn read_cbor_length(additional: u8, data: &[u8], pos: &mut usize) -> Result<usize, MstError> {
    if additional < 24 {
        Ok(additional as usize)
    } else if additional == 24 {
        if *pos >= data.len() {
            return Err(MstError::InvalidNode("truncated length"));
        }
        let l = data[*pos] as usize;
        *pos += 1;
        Ok(l)
    } else if additional == 25 {
        if *pos + 2 > data.len() {
            return Err(MstError::InvalidNode("truncated length"));
        }
        let l = ((data[*pos] as usize) << 8) | data[*pos + 1] as usize;
        *pos += 2;
        Ok(l)
    } else {
        Err(MstError::InvalidNode("unsupported CBOR length"))
    }
}

fn read_nullable_cid(data: &[u8], pos: &mut usize) -> Result<Option<Vec<u8>>, MstError> {
    if *pos >= data.len() {
        return Err(MstError::InvalidNode("truncated nullable CID"));
    }
    if data[*pos] == 0xF6 {
        *pos += 1;
        return Ok(None);
    }
    let cid = read_cbor_cid_value(data, pos)?;
    Ok(Some(cid))
}

fn read_cbor_cid_value(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, MstError> {
    if *pos + 1 >= data.len() {
        return Err(MstError::InvalidNode("truncated CID tag"));
    }
    if data[*pos] == 0xD8 && data[*pos + 1] == 42 {
        *pos += 2;
    } else {
        return Err(MstError::InvalidNode("expected CID tag 42"));
    }

    if *pos >= data.len() {
        return Err(MstError::InvalidNode("truncated CID bytes"));
    }
    let major = data[*pos] >> 5;
    let additional = data[*pos] & 0x1F;
    if major != 2 {
        return Err(MstError::InvalidNode("expected byte string for CID"));
    }
    *pos += 1;
    let len = read_cbor_length(additional, data, pos)?;
    if *pos + len > data.len() {
        return Err(MstError::InvalidNode("CID data extends past end"));
    }
    let cid_bytes = &data[*pos..*pos + len];
    *pos += len;

    // Strip 0x00 identity multibase prefix
    if !cid_bytes.is_empty() && cid_bytes[0] == 0x00 {
        Ok(cid_bytes[1..].to_vec())
    } else {
        Ok(cid_bytes.to_vec())
    }
}

fn read_entries_array(data: &[u8], pos: &mut usize) -> Result<Vec<MstEntry>, MstError> {
    if *pos >= data.len() {
        return Err(MstError::InvalidNode("truncated entries array"));
    }
    let major = data[*pos] >> 5;
    let additional = data[*pos] & 0x1F;
    if major != 4 {
        return Err(MstError::InvalidNode("expected array for entries"));
    }
    *pos += 1;
    let arr_len = read_cbor_length(additional, data, pos)?;

    let mut entries = Vec::with_capacity(arr_len);
    for _ in 0..arr_len {
        entries.push(read_tree_entry(data, pos)?);
    }
    Ok(entries)
}

fn read_tree_entry(data: &[u8], pos: &mut usize) -> Result<MstEntry, MstError> {
    if *pos >= data.len() {
        return Err(MstError::InvalidNode("truncated entry"));
    }
    let major = data[*pos] >> 5;
    let additional = data[*pos] & 0x1F;
    if major != 5 {
        return Err(MstError::InvalidNode("expected map for entry"));
    }
    let map_len = additional as usize;
    *pos += 1;

    let mut prefix_len: usize = 0;
    let mut key_suffix: Vec<u8> = Vec::new();
    let mut value = [0u8; 36];
    let mut tree: Option<[u8; 36]> = None;

    for _ in 0..map_len {
        let key = read_cbor_text(data, pos)?;
        match key {
            "p" => {
                prefix_len = read_cbor_uint(data, pos)? as usize;
            }
            "k" => {
                key_suffix = read_cbor_bytestring(data, pos)?;
            }
            "v" => {
                let cid = read_cbor_cid_value(data, pos)?;
                if cid.len() == 36 {
                    value.copy_from_slice(&cid);
                } else {
                    return Err(MstError::InvalidNode("value CID wrong length"));
                }
            }
            "t" => {
                let t = read_nullable_cid(data, pos)?;
                tree = t.and_then(|c| {
                    if c.len() == 36 {
                        let mut arr = [0u8; 36];
                        arr.copy_from_slice(&c);
                        Some(arr)
                    } else {
                        None
                    }
                });
            }
            _ => {
                skip_cbor(data, pos)?;
            }
        }
    }

    Ok(MstEntry {
        prefix_len,
        key_suffix,
        value,
        tree,
    })
}

fn read_cbor_uint(data: &[u8], pos: &mut usize) -> Result<u64, MstError> {
    if *pos >= data.len() {
        return Err(MstError::InvalidNode("truncated uint"));
    }
    let major = data[*pos] >> 5;
    let additional = data[*pos] & 0x1F;
    if major != 0 {
        return Err(MstError::InvalidNode("expected unsigned int"));
    }
    *pos += 1;
    if additional < 24 {
        Ok(additional as u64)
    } else if additional == 24 {
        if *pos >= data.len() {
            return Err(MstError::InvalidNode("truncated uint"));
        }
        let v = data[*pos] as u64;
        *pos += 1;
        Ok(v)
    } else if additional == 25 {
        if *pos + 2 > data.len() {
            return Err(MstError::InvalidNode("truncated uint"));
        }
        let v = ((data[*pos] as u64) << 8) | data[*pos + 1] as u64;
        *pos += 2;
        Ok(v)
    } else {
        Err(MstError::InvalidNode("unsupported uint size"))
    }
}

fn read_cbor_bytestring(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, MstError> {
    if *pos >= data.len() {
        return Err(MstError::InvalidNode("truncated bytes"));
    }
    let major = data[*pos] >> 5;
    let additional = data[*pos] & 0x1F;
    if major != 2 {
        return Err(MstError::InvalidNode("expected byte string"));
    }
    *pos += 1;
    let len = read_cbor_length(additional, data, pos)?;
    if *pos + len > data.len() {
        return Err(MstError::InvalidNode("bytes extend past end"));
    }
    let bytes = data[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(bytes)
}

fn skip_cbor(data: &[u8], pos: &mut usize) -> Result<(), MstError> {
    if *pos >= data.len() {
        return Err(MstError::InvalidNode("truncated skip"));
    }
    let major = data[*pos] >> 5;
    let additional = data[*pos] & 0x1F;
    *pos += 1;

    match major {
        0 | 1 => {
            if additional >= 24 && additional <= 27 {
                let extra = 1usize << (additional - 24);
                *pos += extra;
            }
        }
        2 | 3 => {
            let len = read_cbor_length(additional, data, pos)?;
            *pos += len;
        }
        4 => {
            let len = read_cbor_length(additional, data, pos)?;
            for _ in 0..len {
                skip_cbor(data, pos)?;
            }
        }
        5 => {
            let len = read_cbor_length(additional, data, pos)?;
            for _ in 0..len {
                skip_cbor(data, pos)?;
                skip_cbor(data, pos)?;
            }
        }
        6 => {
            // tag: skip the additional info (tag number) then the value
            if additional >= 24 && additional <= 27 {
                let extra = 1usize << (additional - 24);
                *pos += extra;
            }
            skip_cbor(data, pos)?;
        }
        7 => {
            // simple/float
            if additional >= 24 && additional <= 27 {
                let extra = 1usize << (additional - 24);
                *pos += extra;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zeros_computation() {
        // The function is deterministic
        let a = leading_zeros("app.bsky.feed.post/abc123");
        let b = leading_zeros("app.bsky.feed.post/abc123");
        assert_eq!(a, b);
    }

    #[test]
    fn leading_zeros_range() {
        // Most keys should have 0-4 leading zeros
        let mut counts = [0usize; 20];
        for i in 0..1000 {
            let key = format!("app.bsky.feed.post/{:010}", i);
            let z = leading_zeros(&key);
            if z < counts.len() {
                counts[z] += 1;
            }
        }
        // Layer 0 should have the most keys (~75%)
        assert!(counts[0] > 500, "layer 0 should dominate: {:?}", counts);
    }

    #[test]
    fn valid_mst_keys() {
        assert!(is_valid_mst_key("app.bsky.feed.post/abc123"));
        assert!(is_valid_mst_key("a/b"));
        assert!(is_valid_mst_key("com.example/rkey-with-dashes"));
        assert!(is_valid_mst_key("com.example/rkey_with_underscores"));
        assert!(is_valid_mst_key("com.example/rkey.with.dots"));
        assert!(is_valid_mst_key("com.example/rkey:with:colons"));
        assert!(is_valid_mst_key("com.example/rkey~with~tildes"));
    }

    #[test]
    fn invalid_mst_keys() {
        assert!(!is_valid_mst_key("no-slash"));
        assert!(!is_valid_mst_key("too/many/slashes"));
        assert!(!is_valid_mst_key("/leading-slash"));
        assert!(!is_valid_mst_key("trailing-slash/"));
        assert!(!is_valid_mst_key("has spaces/key"));
        assert!(!is_valid_mst_key("has/spc key"));
        assert!(!is_valid_mst_key("")); // empty
    }

    #[test]
    fn mst_insert_get() {
        let mut mst = Mst::new();
        let cid = cid_for_cbor(b"test value");
        mst.insert("app.bsky.feed.post/abc", cid).unwrap();
        assert_eq!(mst.get("app.bsky.feed.post/abc"), Some(&cid));
        assert_eq!(mst.get("app.bsky.feed.post/xyz"), None);
    }

    #[test]
    fn mst_insert_duplicate_rejected() {
        let mut mst = Mst::new();
        let cid = cid_for_cbor(b"v");
        mst.insert("a/b", cid).unwrap();
        assert!(mst.insert("a/b", cid).is_err());
    }

    #[test]
    fn mst_update() {
        let mut mst = Mst::new();
        let v1 = cid_for_cbor(b"v1");
        let v2 = cid_for_cbor(b"v2");
        mst.insert("a/b", v1).unwrap();
        mst.update("a/b", v2).unwrap();
        assert_eq!(mst.get("a/b"), Some(&v2));
    }

    #[test]
    fn mst_delete() {
        let mut mst = Mst::new();
        let cid = cid_for_cbor(b"v");
        mst.insert("a/b", cid).unwrap();
        let deleted = mst.delete("a/b").unwrap();
        assert_eq!(deleted, cid);
        assert!(mst.get("a/b").is_none());
    }

    #[test]
    fn mst_write_to_store() {
        let mut mst = Mst::new();
        for i in 0..50 {
            let key = format!("app.bsky.feed.post/{:06}", i);
            let cid = cid_for_cbor(format!("value-{}", i).as_bytes());
            mst.insert(&key, cid).unwrap();
        }

        let mut store = MemoryBlockStore::new();
        let root = mst.write_to_store(&mut store);

        // Root CID should be 36 bytes
        assert_eq!(root.len(), 36);
        // Root block should exist in store
        assert!(store.get(&root).is_some());
    }

    #[test]
    fn mst_empty_tree() {
        let mst = Mst::new();
        let mut store = MemoryBlockStore::new();
        let root = mst.write_to_store(&mut store);
        assert!(store.get(&root).is_some());
    }

    #[test]
    fn mst_diff() {
        let mut old = Mst::new();
        let v1 = cid_for_cbor(b"v1");
        let v2 = cid_for_cbor(b"v2");
        let v3 = cid_for_cbor(b"v3");
        old.insert("a/1", v1).unwrap();
        old.insert("a/2", v2).unwrap();

        let mut new = Mst::new();
        let v2_updated = cid_for_cbor(b"v2-updated");
        new.insert("a/2", v2_updated).unwrap();
        new.insert("a/3", v3).unwrap();

        let diff = new.diff(&old);
        assert_eq!(diff.created.len(), 1); // a/3
        assert_eq!(diff.updated.len(), 1); // a/2
        assert_eq!(diff.deleted.len(), 1); // a/1
        assert_eq!(diff.created[0].0, "a/3");
        assert_eq!(diff.updated[0].0, "a/2");
        assert_eq!(diff.deleted[0].0, "a/1");
    }

    #[test]
    fn mst_sorted_iteration() {
        let mut mst = Mst::new();
        let cid = cid_for_cbor(b"v");
        mst.insert("z/z", cid).unwrap();
        mst.insert("a/a", cid).unwrap();
        mst.insert("m/m", cid).unwrap();

        let keys: Vec<&str> = mst.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["a/a", "m/m", "z/z"]);
    }

    #[test]
    fn count_prefix_len_works() {
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

        let encoded = encode_node(Some(&left_cid), &entries);
        let (decoded_left, decoded_entries) = decode_node(&encoded).unwrap();

        assert!(decoded_left.is_some());
        assert_eq!(decoded_left.unwrap(), left_cid);
        assert_eq!(decoded_entries.len(), 2);
        assert_eq!(decoded_entries[0].prefix_len, 0);
        assert_eq!(decoded_entries[0].key_suffix, b"app.bsky.feed.post/abc");
        assert_eq!(decoded_entries[0].value, cid1);
        assert_eq!(decoded_entries[1].prefix_len, 22);
        assert_eq!(decoded_entries[1].key_suffix, b"def");
        assert_eq!(decoded_entries[1].value, cid2);
    }
}
