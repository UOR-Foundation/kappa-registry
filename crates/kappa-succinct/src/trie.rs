use sha2::{Digest, Sha256};

use crate::dense::{ChildResult, DenseLevel};
use crate::sparse::SparseLevel;

mod build;
mod decode;
#[cfg(test)]
mod reference;
mod serial;
use decode::{decode_dense, decode_parents, decode_sparse, err, need, read_u32, read_u64};

/// Configuration for LOUDS-DS trie construction.
pub struct TrieConfig {
    /// Dense/Sparse transition depth. Default: 2.
    /// Depth-2 Dense is ~50 KB. Fits L1 cache.
    /// Depth 3 exceeds L1 (~12.5 MB). Depth 1 wastes Dense on one 256-bit node.
    pub cutover_depth: u8,
    /// Nonempty overlay key consultations per second before rebuild fires.
    /// The rebuild amortizes overflow into the trie when reader overhead
    /// exceeds this threshold. Repeated consultations count separately; this
    /// is scheduling telemetry, not a latency or comparison-count estimate.
    pub rebuild_overhead_threshold: u64,
    /// Hard cap on overflow size before forced rebuild regardless of read load.
    pub max_overflow_bound: usize,
}

impl Default for TrieConfig {
    fn default() -> Self {
        Self {
            cutover_depth: 2,
            rebuild_overhead_threshold: 10_000,
            max_overflow_bound: 100_000,
        }
    }
}

#[derive(Debug)]
pub enum TrieError {
    NotSorted { index: usize },
    Duplicate { index: usize },
    KeyTooLong { index: usize, length: usize },
    NodeCapacityExceeded,
    DeserializeFailed { reason: String },
    Empty,
    VerificationFailed,
    LockPoisoned,
    SerializationFailed { reason: String },
}

impl std::fmt::Display for TrieError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSorted { index } => write!(f, "key at index {index} is not sorted"),
            Self::Duplicate { index } => write!(f, "duplicate key at index {index}"),
            Self::KeyTooLong { index, length } => {
                write!(f, "key at index {index} has unsupported length {length}")
            }
            Self::DeserializeFailed { reason } => write!(f, "deserialize: {reason}"),
            Self::Empty => write!(f, "empty key set"),
            Self::NodeCapacityExceeded => write!(f, "trie node coordinates exhausted"),
            Self::VerificationFailed => write!(f, "trie verification failed"),
            Self::LockPoisoned => write!(f, "trie index lock poisoned"),
            Self::SerializationFailed { reason } => write!(f, "serialize: {reason}"),
        }
    }
}

impl std::error::Error for TrieError {}

/// Result of descending the trie matching a key.
pub enum DescentResult {
    Found { ordinal: u32 },
    NotFound,
}

/// LOUDS-DS trie: Dense upper levels + Sparse lower levels.
///
/// Ordinal: O(depth) descent + O(1) rank. Per-level terminal
/// bitvectors with cumulative offsets. No global BFS bitvector.
/// No parent array scan in ordinal or descend.
///
/// `key_at`: O(1) index lookup + O(depth) parent walk.
/// Uses `dense_node_to_bfs` and `sparse_pos_to_bfs` for O(1)
/// position-to-BFS mapping. Parent array for reconstruction only.
pub struct LoudsDsTrie {
    dense_levels: Vec<DenseLevel>,
    sparse: SparseLevel,
    cutover_depth: u8,
    key_count: u64,
    digest: [u8; 32],
    /// Cumulative terminal count at the END of each Dense level.
    /// `dense_terminal_cumulative[d]` = total terminals in levels 0..=d.
    dense_terminal_cumulative: Vec<u64>,
    /// Total terminals across all Dense levels.
    total_dense_terminals: u64,
    /// Total internal children across Dense levels. Sparse child offset.
    sparse_child_offset: u64,
    /// Per Dense level: node-local-index → global BFS number.
    dense_node_to_bfs: Vec<Vec<u64>>,
    /// Per Sparse `s_labels` position -> global BFS number.
    sparse_pos_to_bfs: Vec<u64>,
    /// Per BFS node: (`parent_bfs`, label). Used ONLY by `key_at`.
    parents: Vec<(u32, u8)>,
    total_nodes: u64,
    /// Sum of `node_count()` across all Dense levels. Stored at build time.
    /// Used by `descend_sparse` for O(1) instead of `O(cutover_depth)` per call.
    node_count_dense: u64,
}

#[cfg(test)]
struct BuildNode {
    first_child: u32,
    last_child: u32,
    next_sibling: u32,
    label: u8,
    is_terminal: bool,
}

#[cfg(test)]
impl BuildNode {
    fn new(label: u8) -> Self {
        Self {
            first_child: 0,
            last_child: 0,
            next_sibling: 0,
            label,
            is_terminal: false,
        }
    }

    fn children<'a>(&self, nodes: &'a [Self]) -> impl Iterator<Item = (u8, usize)> + 'a {
        let mut next = self.first_child;
        std::iter::from_fn(move || {
            if next == 0 {
                return None;
            }
            let position = next as usize;
            let node = &nodes[position];
            next = node.next_sibling;
            Some((node.label, position))
        })
    }

    fn has_children(&self) -> bool {
        self.first_child != 0
    }
}

impl LoudsDsTrie {
    #[cfg(test)]
    fn build_reference<'a, I>(config: &TrieConfig, keys: I) -> Result<Self, TrieError>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let (nodes, key_count) = reference::admit(keys)?;
        let reference::Layout {
            bfs_order,
            level_ranges,
            naive_to_bfs,
            parents,
        } = reference::layout(&nodes)?;
        let total_nodes = bfs_order.len() as u64;

        // Level ranges refer to the one BFS order; do not duplicate every node
        // coordinate in a second collection for level grouping.
        let cutover = usize::from(config.cutover_depth);

        // Build Dense levels + cumulative terminals + dense_node_to_bfs.
        let dense_depth = cutover.min(level_ranges.len());
        let reference::DenseEncoding {
            levels: dense_levels,
            cumulative: dense_terminal_cumulative,
            mapping: dense_node_to_bfs,
            terminals: total_dense_terminals,
        } = reference::encode_dense(
            &nodes,
            &bfs_order,
            &level_ranges[..dense_depth],
            &naive_to_bfs,
        )?;
        let node_count_dense: u64 = dense_levels.iter().map(DenseLevel::node_count).sum();

        // Sparse child offset = count of internal children across all Dense levels.
        let mut sparse_child_offset: u64 = 0;
        for dl in &dense_levels {
            sparse_child_offset += dl.internal_child_count();
        }

        // Build Sparse level + sparse_pos_to_bfs.
        let mut s_labels: Vec<u8> = Vec::new();
        let mut s_child_indicators: Vec<bool> = Vec::new();
        let mut s_louds: Vec<bool> = Vec::new();
        let mut s_terminals: Vec<bool> = Vec::new();
        let mut sparse_pos_to_bfs: Vec<u64> = Vec::new();

        for (level, range) in level_ranges.iter().enumerate().skip(dense_depth) {
            for &node_idx in &bfs_order[range.clone()] {
                let node_idx = node_idx as usize;
                let node = &nodes[node_idx];
                let mut first = true;

                // Prefix key: node is terminal AND has children.
                // Emit a synthetic 0xFF entry.
                if node.is_terminal && node.has_children() {
                    s_louds.push(first);
                    first = false;
                    s_labels.push(0xFF);
                    s_child_indicators.push(false);
                    s_terminals.push(true);
                    sparse_pos_to_bfs.push(u64::from(naive_to_bfs[node_idx]));
                }

                if !node.has_children() && node.is_terminal {
                    // Pure leaf.
                    s_louds.push(first);
                    s_labels.push(0xFF);
                    s_child_indicators.push(false);
                    s_terminals.push(level == dense_depth);
                    sparse_pos_to_bfs.push(u64::from(naive_to_bfs[node_idx]));
                } else {
                    for (label, child_idx) in node.children(&nodes) {
                        s_louds.push(first);
                        first = false;
                        s_labels.push(label);
                        s_child_indicators.push(nodes[child_idx].has_children());
                        let child_is_leaf_terminal =
                            nodes[child_idx].is_terminal && !nodes[child_idx].has_children();
                        s_terminals.push(child_is_leaf_terminal);
                        sparse_pos_to_bfs.push(u64::from(naive_to_bfs[child_idx]));
                    }
                }
            }
        }

        if s_labels.is_empty() {
            s_labels.push(0);
            s_child_indicators.push(false);
            s_louds.push(true);
            s_terminals.push(false);
            sparse_pos_to_bfs.push(0);
        }

        let sparse = SparseLevel::new(s_labels, &s_child_indicators, &s_louds, &s_terminals);

        // Construction-only ownership ends before serialization allocates raw
        // bit arrays and output bytes. Do not retain both peaks together.
        drop(nodes);
        drop(bfs_order);
        drop(naive_to_bfs);
        drop(level_ranges);
        drop(s_child_indicators);
        drop(s_louds);
        drop(s_terminals);

        // Serialize and compute digest.
        let mut trie = Self {
            dense_levels,
            sparse,
            cutover_depth: config.cutover_depth,
            key_count,
            digest: [0; 32],
            dense_terminal_cumulative,
            total_dense_terminals,
            sparse_child_offset,
            dense_node_to_bfs,
            sparse_pos_to_bfs,
            parents,
            total_nodes,
            node_count_dense,
        };
        trie.digest = sha256_bytes(&trie.serialize()?);
        Ok(trie)
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub const fn key_count(&self) -> u64 {
        self.key_count
    }
    pub const fn cutover_depth(&self) -> u8 {
        self.cutover_depth
    }
    pub const fn total_nodes(&self) -> u64 {
        self.total_nodes
    }
    pub fn dense_levels(&self) -> &[DenseLevel] {
        &self.dense_levels
    }
    pub const fn sparse(&self) -> &SparseLevel {
        &self.sparse
    }
    pub const fn sparse_child_offset(&self) -> u64 {
        self.sparse_child_offset
    }
    pub const fn node_count_dense(&self) -> u64 {
        self.node_count_dense
    }

    pub(crate) fn sparse_child_bfs(&self, pos: u64) -> u64 {
        // This coordinate originates in the admitted sparse label vector.
        let position = usize::try_from(pos)
            .unwrap_or_else(|_| unreachable!("sparse coordinate fits its allocated mapping"));
        self.sparse_pos_to_bfs[position]
    }

    pub(crate) fn sparse_is_marker(&self, pos: u64) -> bool {
        let Some(&bfs) = usize::try_from(pos)
            .ok()
            .and_then(|position| self.sparse_pos_to_bfs.get(position))
        else {
            return false;
        };
        self.sparse.is_node_start(pos) && bfs == self.node_count_dense + self.sparse.node_rank(pos)
    }

    pub fn ordinal(&self, key: &[u8]) -> Option<u32> {
        match self.descend(key) {
            DescentResult::Found { ordinal } => Some(ordinal),
            DescentResult::NotFound => None,
        }
    }

    fn descend(&self, key: &[u8]) -> DescentResult {
        let cutover = usize::from(self.cutover_depth);
        let mut dense_node: u64 = 0;

        for (depth, &byte) in key.iter().enumerate() {
            if depth < cutover && depth < self.dense_levels.len() {
                let dl = &self.dense_levels[depth];

                match dl.child_lookup(dense_node, byte) {
                    Some(ChildResult::Internal(child_rank)) => {
                        dense_node = child_rank;
                        continue;
                    }
                    Some(ChildResult::Leaf(child_rank_all)) => {
                        if depth + 1 != key.len() {
                            return DescentResult::NotFound;
                        }
                        if depth + 1 < cutover && depth + 1 < self.dense_levels.len() {
                            let next_dl = &self.dense_levels[depth + 1];
                            if !next_dl.is_terminal(child_rank_all) {
                                return DescentResult::NotFound;
                            }
                            let prior = self.dense_terminal_cumulative[depth];
                            let within = next_dl.terminal_rank(child_rank_all);
                            return terminal_ordinal(prior, within);
                        }
                        let Some(s_pos) = self.sparse.first_label_pos_by_rank(child_rank_all)
                        else {
                            return DescentResult::NotFound;
                        };
                        if !self.sparse.is_terminal(s_pos) {
                            return DescentResult::NotFound;
                        }
                        let within = self.sparse.terminal_rank(s_pos);
                        return terminal_ordinal(self.total_dense_terminals, within);
                    }
                    None => return DescentResult::NotFound,
                }
            }
            return self.descend_sparse(key, depth, dense_node);
        }

        if key.len() < self.dense_levels.len() {
            let level = key.len();
            if level < cutover {
                let dl = &self.dense_levels[level];
                if dl.is_terminal(dense_node) {
                    let prior = if level == 0 {
                        0
                    } else {
                        self.dense_terminal_cumulative[level - 1]
                    };
                    let within = dl.terminal_rank(dense_node);
                    return terminal_ordinal(prior, within);
                }
            }
        }

        if key.len() >= self.dense_levels.len() {
            return self.descend_sparse(key, key.len(), dense_node);
        }
        DescentResult::NotFound
    }

    fn descend_sparse(&self, key: &[u8], start_depth: usize, dense_node: u64) -> DescentResult {
        let ncd = self.node_count_dense;

        let Some(mut s_start) = self.sparse.first_label_pos_by_rank(dense_node) else {
            return DescentResult::NotFound;
        };
        let mut s_size = self.sparse.node_size(s_start);

        for s_depth in start_depth..key.len() {
            let target = key[s_depth];
            if self.sparse_is_marker(s_start) {
                s_start += 1;
                s_size -= 1;
            }
            match self.sparse.find_label(s_start, s_size, target) {
                Some(found_pos) => {
                    if s_depth + 1 == key.len() {
                        let terminal_pos = if self.sparse.is_terminal(found_pos) {
                            found_pos
                        } else if self.sparse.has_child(found_pos) {
                            let Some(start) = self
                                .sparse
                                .first_label_pos(self.sparse_child_bfs(found_pos), ncd)
                            else {
                                return DescentResult::NotFound;
                            };
                            if !self.sparse_is_marker(start) || !self.sparse.is_terminal(start) {
                                return DescentResult::NotFound;
                            }
                            start
                        } else {
                            return DescentResult::NotFound;
                        };
                        let within = self.sparse.terminal_rank(terminal_pos);
                        return terminal_ordinal(self.total_dense_terminals, within);
                    }
                    if !self.sparse.has_child(found_pos) {
                        return DescentResult::NotFound;
                    }
                    let child_node = self.sparse_child_bfs(found_pos);
                    let Some(start) = self.sparse.first_label_pos(child_node, ncd) else {
                        return DescentResult::NotFound;
                    };
                    s_start = start;
                    s_size = self.sparse.node_size(s_start);
                }
                None => return DescentResult::NotFound,
            }
        }

        if s_start < self.sparse.label_count()
            && self.sparse.label_at(s_start) == 0xFF
            && self.sparse.is_terminal(s_start)
        {
            let within = self.sparse.terminal_rank(s_start);
            return terminal_ordinal(self.total_dense_terminals, within);
        }

        DescentResult::NotFound
    }

    pub fn key_at(&self, ordinal: u32) -> Option<Vec<u8>> {
        if u64::from(ordinal) >= self.key_count {
            return None;
        }
        let ord = u64::from(ordinal);

        for (level, &cum) in self.dense_terminal_cumulative.iter().enumerate() {
            if ord < cum {
                let prior = if level == 0 {
                    0
                } else {
                    self.dense_terminal_cumulative[level - 1]
                };
                let within = ord - prior;
                let node = self.dense_levels[level].terminal_select(within)?;
                let bfs = *self.dense_node_to_bfs[level].get(usize::try_from(node).ok()?)?;
                return self.reconstruct_key(bfs);
            }
        }

        let sparse_within = ord - self.total_dense_terminals;
        let pos = self.sparse.terminal_select(sparse_within)?;
        let bfs = *self.sparse_pos_to_bfs.get(usize::try_from(pos).ok()?)?;
        self.reconstruct_key(bfs)
    }

    fn reconstruct_key(&self, bfs_node: u64) -> Option<Vec<u8>> {
        let mut labels = Vec::with_capacity(65);
        let mut node = u32::try_from(bfs_node).ok()?;
        while node != 0 {
            if labels.len() == 65 {
                return None;
            }
            let (parent, label) = *self.parents.get(usize::try_from(node).ok()?)?;
            if parent >= node {
                return None;
            }
            labels.push(label);
            node = parent;
        }
        labels.reverse();
        Some(labels)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, TrieError> {
        let mut bytes = Vec::new();
        self.serialize_into(&mut bytes)
            .map_err(|error| TrieError::SerializationFailed {
                reason: error.to_string(),
            })?;
        Ok(bytes)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, TrieError> {
        need(0, 8, data.len())?;
        if &data[0..4] != b"KDST" {
            return Err(err("bad magic"));
        }
        let mut version_pos = 4;
        let version = read_u32(data, &mut version_pos)?;
        if version != 4 {
            return Err(err(&format!("unsupported version {version}")));
        }
        let mut pos = 8;
        need(pos, 1, data.len())?;
        let cutover_depth = data[pos];
        pos += 1;
        let key_count = read_u64(data, &mut pos)?;
        let total_nodes = read_u64(data, &mut pos)?;
        if total_nodes > 1_000_000_000 {
            return Err(err("total_nodes too large"));
        }
        let total_dense_terminals = read_u64(data, &mut pos)?;
        let sparse_child_offset = read_u64(data, &mut pos)?;
        need(pos, 1, data.len())?;
        let dlc = data[pos] as usize;
        pos += 1;
        if dlc > 32 {
            return Err(err("too many dense levels"));
        }

        let read_length = |p: &mut usize| -> Result<usize, TrieError> {
            usize::try_from(read_u64(data, p)?).map_err(|_| err("length exceeds address space"))
        };
        let ct_len = read_length(&mut pos)?;
        if ct_len > 32 || ct_len != dlc {
            return Err(err("too many cumulative terminals"));
        }
        let mut dense_terminal_cumulative = Vec::with_capacity(ct_len);
        for _ in 0..ct_len {
            dense_terminal_cumulative.push(read_u64(data, &mut pos)?);
        }

        let mut dense_levels = Vec::with_capacity(dlc);
        let mut dense_node_to_bfs = Vec::with_capacity(dlc);
        for _ in 0..dlc {
            let (level, mapping) = decode_dense(data, &mut pos)?;
            dense_levels.push(level);
            dense_node_to_bfs.push(mapping);
        }
        let (sparse, sparse_pos_to_bfs) = decode_sparse(data, &mut pos)?;

        let parents = decode_parents(data, &mut pos, total_nodes)?;

        if pos != data.len() {
            return Err(err("trailing bytes"));
        }
        if dense_node_to_bfs
            .iter()
            .flatten()
            .chain(sparse_pos_to_bfs.iter())
            .any(|&node| node >= total_nodes)
        {
            return Err(err("node mapping out of bounds"));
        }

        let digest = sha256_bytes(data);
        let node_count_dense: u64 = dense_levels.iter().map(DenseLevel::node_count).sum();

        let decoded = Self {
            dense_levels,
            sparse,
            cutover_depth,
            key_count,
            digest,
            dense_terminal_cumulative,
            total_dense_terminals,
            sparse_child_offset,
            dense_node_to_bfs,
            sparse_pos_to_bfs,
            parents,
            total_nodes,
            node_count_dense,
        };
        decoded.admit_decoded(data)
    }

    fn admit_decoded(self, data: &[u8]) -> Result<Self, TrieError> {
        let decoded = self;
        // Validate correspondence without using peer-controlled navigation.
        // Parent ordering was checked above, so reconstruction terminates.
        let mut keys = Vec::new();
        for (level, nodes) in decoded.dense_node_to_bfs.iter().enumerate() {
            for (node, &bfs) in nodes.iter().enumerate() {
                if decoded.dense_levels[level].is_terminal(node as u64) {
                    keys.push(
                        decoded
                            .reconstruct_key(bfs)
                            .ok_or_else(|| err("invalid terminal parent path"))?,
                    );
                }
            }
        }
        for (position, &bfs) in decoded.sparse_pos_to_bfs.iter().enumerate() {
            if decoded.sparse.is_terminal(position as u64) {
                keys.push(
                    decoded
                        .reconstruct_key(bfs)
                        .ok_or_else(|| err("invalid terminal parent path"))?,
                );
            }
        }
        keys.sort_unstable();
        if keys.len() as u64 != decoded.key_count || keys.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(err("terminal key count mismatch"));
        }
        let rebuilt = Self::build(
            &TrieConfig {
                cutover_depth: decoded.cutover_depth,
                ..Default::default()
            },
            keys.iter().map(Vec::as_slice),
        )?;
        if rebuilt.serialize()? != data {
            return Err(err("noncanonical or inconsistent trie structure"));
        }
        Ok(rebuilt)
    }
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn terminal_ordinal(prior: u64, within: u64) -> DescentResult {
    prior
        .checked_add(within)
        .and_then(|rank| rank.checked_sub(1))
        .and_then(|ordinal| u32::try_from(ordinal).ok())
        .map_or(DescentResult::NotFound, |ordinal| DescentResult::Found {
            ordinal,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_cursor::KappaCursor;

    fn build(keys: &[&[u8]]) -> Result<LoudsDsTrie, TrieError> {
        LoudsDsTrie::build(&TrieConfig::default(), keys.iter().copied())
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            LoudsDsTrie::build(&TrieConfig::default(), std::iter::empty::<&[u8]>()),
            Err(TrieError::Empty)
        ));
    }

    #[test]
    fn rejects_unsorted() {
        assert!(matches!(
            LoudsDsTrie::build(
                &TrieConfig::default(),
                [b"bb".as_slice(), b"aa"].iter().copied()
            ),
            Err(TrieError::NotSorted { index: 1 })
        ));
    }

    #[test]
    fn rejects_duplicate() {
        assert!(matches!(
            LoudsDsTrie::build(
                &TrieConfig::default(),
                [b"aa".as_slice(), b"aa"].iter().copied()
            ),
            Err(TrieError::Duplicate { index: 1 })
        ));
    }

    #[test]
    fn single_key() -> Result<(), TrieError> {
        let t = build(&[b"hello"])?;
        assert_eq!(t.key_count(), 1);
        assert_eq!(t.ordinal(b"hello"), Some(0));
        assert_eq!(t.key_at(0), Some(b"hello".to_vec()));
        Ok(())
    }

    #[test]
    fn deterministic_digest() -> Result<(), TrieError> {
        let k: &[&[u8]] = &[b"aaa", b"aab", b"bbb", b"ccc"];
        let t1 = LoudsDsTrie::build(&TrieConfig::default(), k.iter().copied())?;
        let t2 = LoudsDsTrie::build(&TrieConfig::default(), k.iter().copied())?;
        assert_eq!(t1.digest(), t2.digest());
        Ok(())
    }

    #[test]
    fn ordinal_sequential() -> Result<(), Box<dyn std::error::Error>> {
        let keys: &[&[u8]] = &[b"aa", b"ab", b"ba", b"bb"];
        let t = build(keys)?;
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(t.ordinal(key), Some(u32::try_from(i)?), "ordinal({key:?})");
        }
        Ok(())
    }

    #[test]
    fn ordinal_absent() -> Result<(), TrieError> {
        let t = build(&[b"aa", b"cc"])?;
        assert_eq!(t.ordinal(b"bb"), None);
        Ok(())
    }

    #[test]
    fn key_at_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let keys: &[&[u8]] = &[b"aa", b"ab", b"ba", b"bb"];
        let t = build(keys)?;
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(t.key_at(u32::try_from(i)?).as_deref(), Some(*key));
        }
        assert_eq!(t.key_at(u32::try_from(keys.len())?), None);
        Ok(())
    }

    #[test]
    fn prefix_key_ordinal() -> Result<(), TrieError> {
        let t = build(&[b"a", b"ab", b"abc"])?;
        assert_eq!(t.ordinal(b"a"), Some(0));
        assert_eq!(t.ordinal(b"ab"), Some(1));
        assert_eq!(t.ordinal(b"abc"), Some(2));
        assert_eq!(t.key_at(0), Some(b"a".to_vec()));
        assert_eq!(t.key_at(1), Some(b"ab".to_vec()));
        assert_eq!(t.key_at(2), Some(b"abc".to_vec()));
        Ok(())
    }

    #[test]
    fn different_keys_different_digest() -> Result<(), TrieError> {
        assert_ne!(build(&[b"aaa"])?.digest(), build(&[b"bbb"])?.digest());
        Ok(())
    }

    #[test]
    fn serialization_roundtrip() -> Result<(), TrieError> {
        let t = build(&[b"aaa", b"aab", b"bbb", b"ccc"])?;
        let s = t.serialize()?;
        let r = LoudsDsTrie::deserialize(&s)?;
        assert_eq!(t.digest(), r.digest());
        assert_eq!(t.key_count(), r.key_count());
        assert_eq!(t.total_nodes(), r.total_nodes());
        assert_eq!(t.serialize()?, r.serialize()?);
        Ok(())
    }

    #[test]
    fn deserialize_rejects_bad_magic() {
        let mut bad = [0u8; 64];
        bad[0..4].copy_from_slice(b"XXXX");
        bad[4..8].copy_from_slice(&4u32.to_le_bytes());
        assert!(LoudsDsTrie::deserialize(&bad).is_err());
    }

    #[test]
    fn deserialize_rejects_truncated() {
        assert!(LoudsDsTrie::deserialize(b"KDS").is_err());
    }

    #[test]
    fn deserialize_rejects_unbacked_dense_mapping_before_allocation() -> Result<(), TrieError> {
        let trie = LoudsDsTrie::build(&TrieConfig::default(), [b"a".as_slice()])?;
        let mut bytes = trie.serialize()?;
        // Header (42), cumulative count (8), two cumulative entries (16),
        // node count (8), label length (8), root labels (256), child length
        // (8), one child (1), terminal length (8), one terminal (1).
        let mapping_length_offset = 42 + 8 + 16 + 8 + 8 + 256 + 8 + 1 + 8 + 1;
        bytes[mapping_length_offset..mapping_length_offset + 8]
            .copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(LoudsDsTrie::deserialize(&bytes).is_err());
        Ok(())
    }

    #[test]
    fn deserialize_never_panics_on_random() {
        for seed in 0u8..255 {
            let garbage: Vec<u8> = (0..100).map(|i| seed.wrapping_add(i)).collect();
            assert!(std::panic::catch_unwind(|| LoudsDsTrie::deserialize(&garbage)).is_ok());
        }
    }

    #[test]
    fn ordinal_matches_cursor_order() -> Result<(), TrieError> {
        let mut keys: Vec<Vec<u8>> = Vec::new();
        for a in 0u8..3 {
            for b in 0u8..4 {
                keys.push(vec![a, b]);
            }
        }
        keys.sort();
        let t = LoudsDsTrie::build(&TrieConfig::default(), keys.iter().map(Vec::as_slice))?;
        let mut c = crate::cursor::TrieCursor::new(&t);
        let mut idx = 0u32;
        while c.key() != kappa_cursor::TERMINATED {
            let k = c.key().to_vec();
            assert_eq!(t.ordinal(&k), Some(idx), "idx={idx} key={k:?}");
            assert_eq!(t.key_at(idx).as_deref(), Some(k.as_slice()));
            idx += 1;
            c.advance();
        }
        assert_eq!(u64::from(idx), t.key_count());
        Ok(())
    }

    #[test]
    fn kappa_key_bytes_pattern() -> Result<(), Box<dyn std::error::Error>> {
        let mut keys: Vec<Vec<u8>> = Vec::new();
        for axis in 0u8..3 {
            for i in 0u8..10 {
                let mut key = vec![axis];
                key.extend_from_slice(&[i; 32]);
                keys.push(key);
            }
        }
        keys.sort();
        let t = LoudsDsTrie::build(&TrieConfig::default(), keys.iter().map(Vec::as_slice))?;
        assert_eq!(t.key_count(), 30);
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(t.ordinal(key), Some(u32::try_from(i)?));
        }
        Ok(())
    }
}
