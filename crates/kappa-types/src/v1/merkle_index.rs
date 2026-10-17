//! Index-bound inclusion and consistency proofs over the `merkle` tree
//! (RFC 9162 sections 2.1.3 and 2.1.4).
//!
//! `merkle::merkle_proof` carries a direction bit per step, which a
//! verifier must trust; a proof here is a bare list of node hashes, and
//! the verifier derives every direction from the leaf index and the tree
//! size it was told. A proof therefore binds its leaf to one position in
//! a tree of the size it is verified under, which is what a sorted-leaf
//! map needs: adjacency of two leaves is a statement about their indexes.
//!
//! The proof does not bind the size: a sibling is 32 opaque bytes, so a
//! path whose shape is the same in a larger tree verifies under that size
//! too (leaf 0 of a 3-leaf tree, `[h1, h2]`, verifies against the same root
//! under size 4, where `h2` stands where `hash(h2, h3)` would). The size
//! must come from what authenticates the root.
//!
//! A consistency proof shows that the tree of `first` leaves is a prefix
//! of the tree of `second` leaves: the log only grew.

use crate::merkle::{EMPTY_ROOT, hash_leaf, hash_node};

/// Largest power of two strictly less than `n` (`n >= 2`).
const fn split_point(n: usize) -> usize {
    let mut k = 1usize;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Merkle tree hash of leaf hashes `hashes` (RFC 9162 section 2.1.1).
fn tree_hash(hashes: &[[u8; 32]]) -> [u8; 32] {
    match hashes {
        [] => EMPTY_ROOT,
        [only] => *only,
        _ => {
            let k = split_point(hashes.len());
            hash_node(&tree_hash(&hashes[..k]), &tree_hash(&hashes[k..]))
        }
    }
}

fn leaf_hashes(leaves: &[&[u8]]) -> Vec<[u8; 32]> {
    leaves.iter().map(|leaf| hash_leaf(leaf)).collect()
}

/// The root of `leaves`, equal to `merkle::merkle_root`.
pub fn root(leaves: &[&[u8]]) -> [u8; 32] {
    tree_hash(&leaf_hashes(leaves))
}

fn path(index: usize, hashes: &[[u8; 32]]) -> Vec<[u8; 32]> {
    if hashes.len() <= 1 {
        return Vec::new();
    }
    let k = split_point(hashes.len());
    if index < k {
        let mut proof = path(index, &hashes[..k]);
        proof.push(tree_hash(&hashes[k..]));
        proof
    } else {
        let mut proof = path(index - k, &hashes[k..]);
        proof.push(tree_hash(&hashes[..k]));
        proof
    }
}

/// Inclusion proof of leaf `index` in `leaves`, leaf to root, with no
/// direction bits; `None` when `index` is out of range.
pub fn inclusion_proof(leaves: &[&[u8]], index: usize) -> Option<Vec<[u8; 32]>> {
    if index >= leaves.len() {
        return None;
    }
    Some(path(index, &leaf_hashes(leaves)))
}

/// Verify that `leaf` is the leaf at `index` of a tree of `size` leaves
/// whose root is `root` (RFC 9162 section 2.1.3.2).
pub fn inclusion_verify(
    root: &[u8; 32],
    leaf: &[u8],
    index: u64,
    size: u64,
    proof: &[[u8; 32]],
) -> bool {
    if size == 0 || index >= size {
        return false;
    }
    let mut fn_ = index;
    let mut sn = size - 1;
    let mut r = hash_leaf(leaf);
    for p in proof {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = hash_node(p, &r);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = hash_node(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && r == *root
}

fn subproof(m: usize, hashes: &[[u8; 32]], complete: bool) -> Vec<[u8; 32]> {
    let n = hashes.len();
    if m == n {
        return if complete {
            Vec::new()
        } else {
            vec![tree_hash(hashes)]
        };
    }
    let k = split_point(n);
    if m <= k {
        let mut proof = subproof(m, &hashes[..k], complete);
        proof.push(tree_hash(&hashes[k..]));
        proof
    } else {
        let mut proof = subproof(m - k, &hashes[k..], false);
        proof.push(tree_hash(&hashes[..k]));
        proof
    }
}

/// Consistency proof from the tree of the first `first` leaves to the
/// tree of all `leaves` (RFC 9162 section 2.1.4.1).
///
/// `None` unless `0 < first <= leaves.len()`. An empty proof when `first`
/// equals the size: the trees are the same.
pub fn consistency_proof(leaves: &[&[u8]], first: usize) -> Option<Vec<[u8; 32]>> {
    if first == 0 || first > leaves.len() {
        return None;
    }
    Some(subproof(first, &leaf_hashes(leaves), true))
}

/// Verify that the tree of `first` leaves with root `first_root` is a
/// prefix of the tree of `second` leaves with root `second_root`.
///
/// RFC 9162 section 2.1.4.2. An empty first tree (`first == 0`,
/// `first_root == EMPTY_ROOT`) is a prefix of every tree.
pub fn consistency_verify(
    first: u64,
    second: u64,
    first_root: &[u8; 32],
    second_root: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    if first == 0 {
        return *first_root == EMPTY_ROOT && proof.is_empty();
    }
    if first > second {
        return false;
    }
    if first == second {
        return first_root == second_root && proof.is_empty();
    }
    let mut steps: Vec<[u8; 32]> = Vec::with_capacity(proof.len() + 1);
    if first.is_power_of_two() {
        steps.push(*first_root);
    }
    steps.extend_from_slice(proof);
    let Some((head, rest)) = steps.split_first() else {
        return false;
    };
    let mut fn_ = first - 1;
    let mut sn = second - 1;
    if fn_ & 1 == 1 {
        while fn_ & 1 == 1 {
            fn_ >>= 1;
            sn >>= 1;
        }
    }
    let mut fr = *head;
    let mut sr = *head;
    for c in rest {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = hash_node(c, &fr);
            sr = hash_node(c, &sr);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = hash_node(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    fr == *first_root && sr == *second_root && sn == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::merkle_root;

    fn leaves(count: usize) -> Vec<Vec<u8>> {
        (0..count).map(|i| i.to_le_bytes().to_vec()).collect()
    }

    #[test]
    fn root_matches_the_streaming_tree() {
        for count in [0usize, 1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 100] {
            let data = leaves(count);
            let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
            assert_eq!(root(&refs), merkle_root(&refs), "{count} leaves");
        }
    }

    #[test]
    fn inclusion_binds_index_and_size() -> Result<(), String> {
        for count in [1usize, 2, 3, 4, 5, 7, 8, 9, 16, 17, 100] {
            let data = leaves(count);
            let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
            let tree_root = root(&refs);
            for (index, leaf) in data.iter().enumerate() {
                let proof = inclusion_proof(&refs, index)
                    .ok_or_else(|| format!("no proof {index}/{count}"))?;
                assert!(inclusion_verify(
                    &tree_root,
                    leaf,
                    index as u64,
                    count as u64,
                    &proof
                ));
                if count > 1 {
                    let other = (index + 1) % count;
                    assert!(
                        !inclusion_verify(&tree_root, leaf, other as u64, count as u64, &proof),
                        "index {other} accepted for leaf {index} of {count}"
                    );
                }
                assert!(!inclusion_verify(
                    &tree_root,
                    b"other",
                    index as u64,
                    count as u64,
                    &proof
                ));
            }
        }
        assert!(inclusion_proof(&[], 0).is_none());
        Ok(())
    }

    /// The size a proof is verified under is not bound by the proof: leaf
    /// 0 of a 3-leaf tree also verifies under size 4, while a size whose
    /// path is longer or shorter is refused. Callers take the size from
    /// what authenticates the root.
    #[test]
    fn the_size_is_bound_by_its_path_shape_only() -> Result<(), String> {
        let data = leaves(3);
        let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let tree_root = root(&refs);
        let proof = inclusion_proof(&refs, 0).ok_or("no proof")?;
        assert!(inclusion_verify(&tree_root, &data[0], 0, 3, &proof));
        assert!(
            inclusion_verify(&tree_root, &data[0], 0, 4, &proof),
            "control: a same-shape size verifies"
        );
        for size in [1, 2, 5, 8] {
            assert!(
                !inclusion_verify(&tree_root, &data[0], 0, size, &proof),
                "size {size} accepted"
            );
        }
        Ok(())
    }

    #[test]
    fn consistency_proves_prefix_and_rejects_rewrites() -> Result<(), String> {
        for second in [1usize, 2, 3, 4, 5, 7, 8, 9, 16, 17, 33] {
            let data = leaves(second);
            let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
            let second_root = root(&refs);
            for first in 1..=second {
                let first_root = root(&refs[..first]);
                let proof = consistency_proof(&refs, first)
                    .ok_or_else(|| format!("no consistency proof {first}/{second}"))?;
                assert!(
                    consistency_verify(
                        first as u64,
                        second as u64,
                        &first_root,
                        &second_root,
                        &proof
                    ),
                    "{first} -> {second}"
                );
                let mut rewritten = data.clone();
                rewritten[first - 1] = b"rewritten".to_vec();
                let rewritten_root = root(
                    &rewritten[..first]
                        .iter()
                        .map(Vec::as_slice)
                        .collect::<Vec<_>>(),
                );
                assert!(
                    !consistency_verify(
                        first as u64,
                        second as u64,
                        &rewritten_root,
                        &second_root,
                        &proof
                    ),
                    "rewritten prefix accepted {first} -> {second}"
                );
            }
            assert!(consistency_verify(
                0,
                second as u64,
                &EMPTY_ROOT,
                &second_root,
                &[]
            ));
            assert!(!consistency_verify(
                0,
                second as u64,
                &second_root,
                &second_root,
                &[]
            ));
        }
        assert!(consistency_proof(&[], 1).is_none());
        Ok(())
    }
}
