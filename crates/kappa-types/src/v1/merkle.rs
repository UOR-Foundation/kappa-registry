//! RFC 9162 section 2.1 Merkle tree over domain-separated SHA-256 leaves.
//!
//! Odd nodes are promoted (not duplicated), so the tree shape pins the
//! leaf count: `[a,b,c]` and `[a,b,c,c]` produce different roots.
//! The empty tree root is SHA-256 of the empty string.

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// SHA-256 of the empty string, the defined root of an empty tree.
pub const EMPTY_ROOT: [u8; 32] = {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ]
};

/// Hash a leaf value with the 0x00 domain separator.
pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = crate::sha256::Hasher::new();
    hasher.update(&[LEAF_PREFIX]);
    hasher.update(data);
    hasher.finalize()
}

/// Hash two child nodes with the 0x01 domain separator.
pub fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = crate::sha256::Hasher::new();
    hasher.update(&[NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize()
}

/// Bytes [`hash_leaf`] hashes beyond the leaf: its domain separator.
pub const LEAF_HASH_OVERHEAD: u64 = size_of::<u8>() as u64;

/// Bytes [`hash_node`] hashes: its domain separator and two children.
pub const NODE_HASH_INPUT: u64 = (size_of::<u8>() + 2 * size_of::<[u8; 32]>()) as u64;

/// Internal nodes one [`StreamingTree::push`] completes at most: one per
/// level of a tree of up to `2^64` leaves.
pub const MAX_PUSH_CARRIES: u64 = u64::BITS as u64;

/// Bytes one [`StreamingTree::push`] of a `leaf_len`-byte leaf hashed when
/// it emitted `emitted` nodes.
///
/// `push` emits exactly one node per hash it computes, the leaf first and
/// then each internal node it completes. `None` when `emitted` is not a
/// count a push produces (zero, or more than the leaf and
/// [`MAX_PUSH_CARRIES`]) or the total overflows.
pub const fn push_hash_input(leaf_len: u64, emitted: u64) -> Option<u64> {
    if emitted == 0 || emitted > MAX_PUSH_CARRIES + 1 {
        return None;
    }
    let Some(internal) = (emitted - 1).checked_mul(NODE_HASH_INPUT) else {
        return None;
    };
    let Some(leaf) = leaf_len.checked_add(LEAF_HASH_OVERHEAD) else {
        return None;
    };
    leaf.checked_add(internal)
}

/// The most one [`StreamingTree::push`] of a leaf of at most `leaf_len`
/// bytes hashes. `None` when it overflows.
pub const fn push_hash_bound(leaf_len: u64) -> Option<u64> {
    push_hash_input(leaf_len, MAX_PUSH_CARRIES + 1)
}

/// Compute the Merkle root over `leaves`.
///
/// Each item is hashed with `hash_leaf`. An odd trailing node is promoted
/// to the next level without pairing. An empty input returns `EMPTY_ROOT`.
pub fn merkle_root(leaves: &[&[u8]]) -> [u8; 32] {
    build_tree(leaves, |_, _| {}).root()
}

fn build_tree(leaves: &[&[u8]], mut emit: impl FnMut(u64, &[u8; 32])) -> StreamingTree {
    let mut tree = StreamingTree::new();
    for leaf in leaves {
        tree = match tree.push(leaf, |position, node| {
            emit(position, node);
            Ok::<_, std::convert::Infallible>(())
        }) {
            Ok(tree) => tree,
            Err(never) => match never {},
        };
    }
    tree
}

/// Inclusion proof for the leaf at `index` in a tree of `leaves.len()` items.
///
/// Returns `(sibling_hash, sibling_is_left)` pairs from leaf to root. An
/// odd trailing node is promoted, so the last level with an odd count
/// produces no proof step for the promoted node.
pub fn merkle_proof(leaves: &[&[u8]], index: usize) -> Option<Vec<([u8; 32], bool)>> {
    if leaves.is_empty() || index >= leaves.len() {
        return None;
    }
    let mut nodes = Vec::new();
    build_tree(leaves, |_, node| nodes.push(*node));
    let mut proof = Vec::new();
    for step in audit_path(index as u64, leaves.len() as u64)? {
        match step {
            PathStep::Sibling { position, left } => {
                proof.push((*stored_node(&nodes, position)?, left));
            }
            PathStep::RightPeaks { positions } => {
                let peaks = positions
                    .iter()
                    .map(|position| stored_node(&nodes, *position).copied())
                    .collect::<Option<Vec<_>>>()?;
                proof.push((bag_peaks(&peaks)?, false));
            }
        }
    }

    Some(proof)
}

/// The node emitted at `position`, or `None` when the position does not
/// address the emitted nodes on this target.
fn stored_node(nodes: &[[u8; 32]], position: u64) -> Option<&[u8; 32]> {
    usize::try_from(position)
        .ok()
        .and_then(|index| nodes.get(index))
}

/// Verify a Merkle inclusion proof against a known root.
pub fn merkle_verify(root: &[u8; 32], leaf_data: &[u8], proof: &[([u8; 32], bool)]) -> bool {
    let mut current = hash_leaf(leaf_data);
    for (sibling, sibling_is_left) in proof {
        if *sibling_is_left {
            current = hash_node(sibling, &current);
        } else {
            current = hash_node(&current, sibling);
        }
    }
    current == *root
}

// -----------------------------------------------------------------------------
// Streaming construction and positional proofs.
//
// The same tree as `merkle_root`, built one leaf at a time with O(log n)
// state, and its nodes numbered in emission (post-order) so a store can
// keep them in a flat array and produce an inclusion proof for any leaf by
// O(log n) positional reads. A tree of n leaves decomposes into perfect
// "mountains", one per set bit of n, left to right by descending height;
// the promoted-odd-node rule makes the root equal to the mountain peaks
// bagged right to left: `H(P0, H(P1, ... H(Pk-1, Pk)))`.
//
// Node `(height h, index j)`, the j-th node at height h counted across
// mountains, is emitted right after the carries of the last leaf below it,
// so its position is `pos(leaf L) + h` with `L = (j + 1) * 2^h - 1`, and a
// leaf's position is `2L - popcount(L)`.
// -----------------------------------------------------------------------------

/// Nodes a tree of `leaves` leaves emits: every leaf plus one internal
/// node per pairing.
pub fn node_count(leaves: u64) -> u64 {
    (2 * leaves).saturating_sub(u64::from(leaves.count_ones()))
}

/// Emission position of node `(height, index)`.
pub fn node_position(height: u32, index: u64) -> u64 {
    let last_leaf = (index + 1) * (1u64 << height) - 1;
    2 * last_leaf - u64::from(last_leaf.count_ones()) + u64::from(height)
}

/// One step of a positional inclusion proof, leaf to root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathStep {
    /// A stored node; `left` is whether it is the left operand.
    Sibling { position: u64, left: bool },
    /// The peaks of every mountain right of the leaf's, left to right.
    /// Their bag (`bag_peaks`) is the right operand of this step.
    RightPeaks { positions: Vec<u64> },
}

/// Mountains of a tree of `leaves` leaves as `(height, first_leaf)`, left
/// to right.
fn mountains(leaves: u64) -> Vec<(u32, u64)> {
    let mut result = Vec::with_capacity(leaves.count_ones() as usize);
    let mut offset = 0;
    for height in (0..64).rev() {
        if leaves & (1u64 << height) != 0 {
            result.push((height, offset));
            offset += 1u64 << height;
        }
    }
    result
}

/// Emission positions of the mountain peaks of a tree of `leaves` leaves,
/// left to right: where a store that keeps the emitted nodes reads the
/// peaks [`StreamingTree::resume`] takes.
pub fn peak_positions(leaves: u64) -> Vec<u64> {
    mountains(leaves)
        .iter()
        .map(|(height, start)| node_position(*height, start >> height))
        .collect()
}

/// Positional inclusion proof for leaf `index` in a tree of `leaves`
/// leaves.
///
/// Resolving every position to its stored node, bagging the right
/// peaks, and feeding the result to `merkle_verify` in order proves the
/// leaf against the `merkle_root` of the same leaves.
pub fn audit_path(index: u64, leaves: u64) -> Option<Vec<PathStep>> {
    if index >= leaves {
        return None;
    }
    let mountains = mountains(leaves);
    let mine = mountains
        .iter()
        .position(|(height, start)| index >= *start && index < start + (1u64 << height))?;
    let (height, start) = mountains[mine];
    let mut path = Vec::new();
    let mut local = index - start;
    for level in 0..height {
        let sibling_local = local ^ 1;
        path.push(PathStep::Sibling {
            position: node_position(level, (start >> level) + sibling_local),
            left: local & 1 == 1,
        });
        local >>= 1;
    }
    let right: Vec<u64> = mountains[mine + 1..]
        .iter()
        .map(|(height, start)| node_position(*height, start >> height))
        .collect();
    if !right.is_empty() {
        path.push(PathStep::RightPeaks { positions: right });
    }
    for (height, start) in mountains[..mine].iter().rev() {
        path.push(PathStep::Sibling {
            position: node_position(*height, start >> height),
            left: true,
        });
    }
    Some(path)
}

/// Bag peaks right to left: `H(P0, H(P1, ... H(Pk-1, Pk)))`. `None` for
/// no peaks.
pub fn bag_peaks(peaks: &[[u8; 32]]) -> Option<[u8; 32]> {
    let (last, rest) = peaks.split_last()?;
    Some(
        rest.iter()
            .rev()
            .fold(*last, |acc, peak| hash_node(peak, &acc)),
    )
}

/// Incremental builder of the `merkle_root` tree. Each `push` emits the
/// leaf node and every internal node it completes, in position order;
/// state is one node per set bit of the leaf count.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamingTree {
    peaks: Vec<(u32, [u8; 32])>,
    leaves: u64,
    emitted: u64,
}

impl StreamingTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// The builder of a tree of `leaves` leaves whose mountain peaks, left
    /// to right, are `peaks`: one per set bit of `leaves`, as [`Self::peaks`]
    /// reports them. `None` when the count does not match.
    pub fn resume(leaves: u64, peaks: &[[u8; 32]]) -> Option<Self> {
        let mountains = mountains(leaves);
        if mountains.len() != peaks.len() {
            return None;
        }
        Some(Self {
            peaks: mountains
                .iter()
                .zip(peaks)
                .map(|((height, _), peak)| (*height, *peak))
                .collect(),
            leaves,
            emitted: node_count(leaves),
        })
    }

    /// The mountain peaks, left to right: what [`Self::resume`] takes.
    pub fn peaks(&self) -> Vec<[u8; 32]> {
        self.peaks.iter().map(|(_, peak)| *peak).collect()
    }

    /// Append a leaf. `emit` receives `(position, node)` for each node
    /// produced, leaf first. This consumes the builder: if emission fails,
    /// no builder survives to publish a root over partially written nodes.
    pub fn push<E>(
        mut self,
        leaf_data: &[u8],
        mut emit: impl FnMut(u64, &[u8; 32]) -> Result<(), E>,
    ) -> Result<Self, E> {
        let mut node = hash_leaf(leaf_data);
        let mut height = 0;
        emit(self.emitted, &node)?;
        self.emitted += 1;
        while let Some((top_height, top)) = self.peaks.last().copied() {
            if top_height != height {
                break;
            }
            node = hash_node(&top, &node);
            height += 1;
            emit(self.emitted, &node)?;
            self.emitted += 1;
            self.peaks.pop();
        }
        self.peaks.push((height, node));
        self.leaves += 1;
        Ok(self)
    }

    pub const fn leaves(&self) -> u64 {
        self.leaves
    }

    pub const fn emitted(&self) -> u64 {
        self.emitted
    }

    /// The `merkle_root` of every leaf pushed so far.
    pub fn root(&self) -> [u8; 32] {
        let Some(((_, last), rest)) = self.peaks.split_last() else {
            return EMPTY_ROOT;
        };
        rest.iter()
            .rev()
            .fold(*last, |acc, (_, peak)| hash_node(peak, &acc))
    }
}

#[cfg(test)]
mod streaming_tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn leaves(count: u64) -> Vec<Vec<u8>> {
        (0..count).map(|i| i.to_le_bytes().to_vec()).collect()
    }

    // Independent materialized construction is test-only.
    fn reference_root(leaves: &[&[u8]]) -> [u8; 32] {
        let mut level: Vec<_> = leaves.iter().map(|leaf| hash_leaf(leaf)).collect();
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|pair| match pair {
                    [left, right] => hash_node(left, right),
                    [only] => *only,
                    _ => unreachable!("chunks(2) produces one or two elements"),
                })
                .collect();
        }
        level.first().copied().unwrap_or(EMPTY_ROOT)
    }

    /// The hashing a push reports from its emitted nodes is the hashing it
    /// performs: the eighth leaf emits itself and three internal nodes.
    #[test]
    fn push_hash_input_follows_the_nodes_a_push_emits() -> TestResult {
        let (tree, _) = build(&leaves(7))?;
        let mut emitted = 0u64;
        let leaf = b"eighth";
        let _tree = tree.push(leaf, |_, _| {
            emitted += 1;
            Ok::<(), String>(())
        })?;
        assert_eq!(emitted, 4);
        let leaf_len = leaf.len() as u64;
        let expected = leaf_len + LEAF_HASH_OVERHEAD + 3 * NODE_HASH_INPUT;
        assert_eq!(push_hash_input(leaf_len, emitted), Some(expected));
        assert_eq!(NODE_HASH_INPUT, 65);
        assert_eq!(push_hash_input(leaf_len, 0), None, "a push emits its leaf");
        assert_eq!(push_hash_input(leaf_len, MAX_PUSH_CARRIES + 2), None);
        assert!(push_hash_bound(leaf_len) >= Some(expected));
        assert_eq!(push_hash_bound(u64::MAX), None, "overflow is refused");
        Ok(())
    }

    #[test]
    fn emission_failure_consumes_builder_at_every_carry() -> TestResult {
        // Leaf eight emits its leaf and three carries. Inject a failure
        // after each possible prefix, including a partially written node.
        for fail_at in 0..4 {
            let (tree, mut nodes) = build(&leaves(7))?;
            let mut calls = 0;
            let result = tree.push(b"eighth", |_, node| {
                nodes.push(*node);
                let fail = calls == fail_at;
                calls += 1;
                if fail {
                    Err("injected emission failure")
                } else {
                    Ok(())
                }
            });
            assert_eq!(result.err(), Some("injected emission failure"));
            assert_eq!(calls, fail_at + 1);
        }
        Ok(())
    }

    fn build(data: &[Vec<u8>]) -> Result<(StreamingTree, Vec<[u8; 32]>), String> {
        let mut tree = StreamingTree::new();
        let mut nodes = Vec::new();
        for leaf in data {
            tree = tree.push(leaf, |position, node| {
                if position != nodes.len() as u64 {
                    return Err(format!("position {position} emitted out of order"));
                }
                nodes.push(*node);
                Ok(())
            })?;
        }
        Ok((tree, nodes))
    }

    /// A builder resumed from its peaks continues as the original would:
    /// the history log of a namespace resumes at every epoch from the
    /// peaks its last epoch retained.
    #[test]
    fn a_resumed_builder_continues_the_same_tree() -> TestResult {
        for split in [0u64, 1, 2, 3, 5, 8, 13, 64] {
            let data = leaves(split + 7);
            let (head, _) = build(&data[..usize::try_from(split)?])?;
            let mut resumed =
                StreamingTree::resume(head.leaves(), &head.peaks()).ok_or("resume refused")?;
            assert_eq!(resumed, head);
            for leaf in &data[usize::try_from(split)?..] {
                resumed = resumed.push(leaf, |_, _| Ok::<_, String>(()))?;
            }
            let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
            assert_eq!(resumed.root(), merkle_root(&refs), "split at {split}");
        }
        assert!(
            StreamingTree::resume(3, &[[1; 32]]).is_none(),
            "3 leaves have 2 peaks"
        );
        assert!(StreamingTree::resume(0, &[[1; 32]]).is_none());
        Ok(())
    }

    /// The nodes stored at the peak positions are the peaks a builder
    /// reports, so a store resumes the log from its emitted nodes alone.
    #[test]
    fn peak_positions_address_the_emitted_peaks() -> TestResult {
        assert!(peak_positions(0).is_empty());
        for count in [1u64, 2, 3, 4, 5, 7, 8, 13, 64, 100] {
            let (tree, nodes) = build(&leaves(count))?;
            let stored = peak_positions(count)
                .into_iter()
                .map(|position| stored_node(&nodes, position).copied())
                .collect::<Option<Vec<_>>>()
                .ok_or("peak position outside the emitted nodes")?;
            assert_eq!(stored, tree.peaks(), "{count} leaves");
            let resumed = StreamingTree::resume(count, &stored).ok_or("resume refused")?;
            assert_eq!(resumed, tree, "{count} leaves");
        }
        Ok(())
    }

    #[test]
    fn streaming_root_equals_merkle_root_and_emits_node_count() -> TestResult {
        assert_eq!(StreamingTree::new().root(), EMPTY_ROOT);
        for count in [1u64, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 100, 257] {
            let data = leaves(count);
            let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
            let (tree, nodes) = build(&data)?;
            assert_eq!(tree.root(), merkle_root(&refs), "{count} leaves");
            assert_eq!(tree.root(), reference_root(&refs), "{count} leaves");
            assert_eq!(nodes.len() as u64, node_count(count), "{count} leaves");
            assert_eq!(tree.emitted(), node_count(count));
            for (index, leaf) in data.iter().enumerate() {
                let stored = stored_node(&nodes, node_position(0, index as u64))
                    .ok_or("leaf position outside the emitted nodes")?;
                assert_eq!(*stored, hash_leaf(leaf));
            }
        }
        Ok(())
    }

    #[test]
    fn audit_paths_verify_every_leaf_through_stored_positions() -> TestResult {
        for count in [1u64, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 100, 257] {
            let data = leaves(count);
            let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
            let root = merkle_root(&refs);
            let (_, nodes) = build(&data)?;
            for (index, leaf) in data.iter().enumerate() {
                let path = audit_path(index as u64, count)
                    .ok_or_else(|| format!("no path for {index} of {count}"))?;
                let mut proof = Vec::new();
                for step in path {
                    match step {
                        PathStep::Sibling { position, left } => {
                            let sibling = stored_node(&nodes, position)
                                .ok_or("sibling position outside the emitted nodes")?;
                            proof.push((*sibling, left));
                        }
                        PathStep::RightPeaks { positions } => {
                            let peaks: Vec<[u8; 32]> = positions
                                .iter()
                                .map(|p| stored_node(&nodes, *p).copied())
                                .collect::<Option<_>>()
                                .ok_or("peak position outside the emitted nodes")?;
                            let bag = bag_peaks(&peaks).ok_or("empty right peaks")?;
                            proof.push((bag, false));
                        }
                    }
                }
                assert!(
                    merkle_verify(&root, leaf, &proof),
                    "path failed for {index} of {count}"
                );
                if count.is_power_of_two() {
                    // One mountain, no bag: the positional path is the
                    // materialized proof step for step.
                    let materialized = merkle_proof(&refs, index)
                        .ok_or_else(|| format!("no proof for {index} of {count}"))?;
                    assert_eq!(proof, materialized, "{index} of {count}");
                }
            }
        }
        assert!(audit_path(3, 3).is_none());
        assert!(audit_path(0, 0).is_none());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn empty_tree_root_is_sha256_of_empty() {
        let expected = crate::sha256::digest(b"");
        assert_eq!(EMPTY_ROOT, expected);
        assert_eq!(merkle_root(&[]), EMPTY_ROOT);
    }

    #[test]
    fn single_leaf_root_is_hash_leaf() {
        let root = merkle_root(&[b"only"]);
        assert_eq!(root, hash_leaf(b"only"));
    }

    #[test]
    fn duplicated_tail_does_not_collide() {
        let three = merkle_root(&[b"a", b"b", b"c"]);
        let four = merkle_root(&[b"a", b"b", b"c", b"c"]);
        assert_ne!(three, four);
    }

    #[test]
    fn root_is_deterministic() {
        let a = merkle_root(&[b"x", b"y", b"z"]);
        let b = merkle_root(&[b"x", b"y", b"z"]);
        assert_eq!(a, b);
    }

    #[test]
    fn order_matters() {
        let ab = merkle_root(&[b"a", b"b"]);
        let ba = merkle_root(&[b"b", b"a"]);
        assert_ne!(ab, ba);
    }

    #[test]
    fn proof_verifies_every_leaf() -> TestResult {
        for count in [1usize, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17] {
            let data: Vec<Vec<u8>> = (0..count).map(|i| i.to_le_bytes().to_vec()).collect();
            let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
            let root = merkle_root(&refs);
            for (index, leaf) in data.iter().enumerate() {
                let proof = merkle_proof(&refs, index)
                    .ok_or_else(|| format!("no proof for index {index} in tree of {count}"))?;
                assert!(
                    merkle_verify(&root, leaf, &proof),
                    "proof failed for index {index} in tree of {count}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn proof_rejects_wrong_leaf() -> TestResult {
        let leaves: [&[u8]; 4] = [b"a", b"b", b"c", b"d"];
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 0).ok_or("no proof")?;
        assert!(!merkle_verify(&root, b"wrong", &proof));
        Ok(())
    }

    #[test]
    fn proof_rejects_wrong_root() -> TestResult {
        let leaves: [&[u8]; 3] = [b"a", b"b", b"c"];
        let proof = merkle_proof(&leaves, 1).ok_or("no proof")?;
        let wrong_root = [0xff; 32];
        assert!(!merkle_verify(&wrong_root, b"b", &proof));
        Ok(())
    }

    #[test]
    fn out_of_bounds_returns_none() {
        assert!(merkle_proof(&[], 0).is_none());
        assert!(merkle_proof(&[b"a"], 1).is_none());
    }

    #[test]
    fn promoted_odd_node_proof_is_shorter() -> TestResult {
        // In a 3-leaf tree the last leaf is promoted, so its proof has
        // one fewer step than the paired leaves.
        let leaves: [&[u8]; 3] = [b"a", b"b", b"c"];
        let proof_0 = merkle_proof(&leaves, 0).ok_or("no proof")?;
        let proof_2 = merkle_proof(&leaves, 2).ok_or("no proof")?;
        assert!(
            proof_2.len() < proof_0.len(),
            "promoted node proof ({}) should be shorter than paired ({})",
            proof_2.len(),
            proof_0.len()
        );
        let root = merkle_root(&leaves);
        assert!(merkle_verify(&root, b"c", &proof_2));
        Ok(())
    }
}
