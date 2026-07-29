//! Binary Merkle tree builder, proof generation, and verification.
//!
//! Used for:
//! - Epoch roots (Merkle over dCBOR-encoded fields)
//! - Per-field selective disclosure (Merkle over field leaves)
//! - Chunk manifests (Merkle over chunk kappa-labels)
//! - State roots (Merkle over all tag entries in a namespace)
//!
//! The tree is binary, bottom-up, with SHA-256 as the hash function.
//! Odd leaves are promoted (the last leaf is hashed with itself when
//! the level has an odd count). Leaf nodes are prefixed with 0x00 and
//! internal nodes with 0x01 to prevent second-preimage attacks.

use sha2::{Digest, Sha256};

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// Hash a leaf value with the leaf domain separator.
pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Hash two child nodes with the internal node domain separator.
fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute the Merkle root of a list of leaf data items.
///
/// Each item is hashed with hash_leaf() first, then the tree is built
/// bottom-up. Returns the 32-byte root hash, or None if the input is
/// empty.
pub fn merkle_root(leaves: &[&[u8]]) -> Option<[u8; 32]> {
    if leaves.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|l| hash_leaf(l)).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(hash_node(&level[i], &level[i + 1]));
            } else {
                // Odd leaf: hash with itself
                next.push(hash_node(&level[i], &level[i]));
            }
            i += 2;
        }
        level = next;
    }
    Some(level[0])
}

/// Generate a Merkle inclusion proof for the leaf at `index`.
///
/// Returns a vector of (sibling_hash, is_left) pairs, from leaf level
/// to root. The verifier walks this path to reconstruct the root.
/// Returns None if index is out of bounds or leaves is empty.
pub fn merkle_proof(leaves: &[&[u8]], index: usize) -> Option<Vec<([u8; 32], bool)>> {
    if leaves.is_empty() || index >= leaves.len() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|l| hash_leaf(l)).collect();
    let mut proof = Vec::new();
    let mut idx = index;

    while level.len() > 1 {
        let sibling_idx = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };
        let sibling = if sibling_idx < level.len() {
            level[sibling_idx]
        } else {
            // Odd level: sibling is self
            level[idx]
        };
        // is_left = true means the sibling is on the left (idx is odd)
        let is_left = idx % 2 == 1;
        proof.push((sibling, is_left));

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(hash_node(&level[i], &level[i + 1]));
            } else {
                next.push(hash_node(&level[i], &level[i]));
            }
            i += 2;
        }
        level = next;
        idx /= 2;
    }

    Some(proof)
}

/// Verify a Merkle inclusion proof.
///
/// Given a leaf's data, its proof path, and the expected root hash,
/// recompute the root and check equality.
pub fn merkle_verify(root: &[u8; 32], leaf_data: &[u8], proof: &[([u8; 32], bool)]) -> bool {
    let mut current = hash_leaf(leaf_data);
    for (sibling, is_left) in proof {
        if *is_left {
            current = hash_node(sibling, &current);
        } else {
            current = hash_node(&current, sibling);
        }
    }
    current == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf() {
        let leaves: Vec<&[u8]> = vec![b"only leaf"];
        let root = merkle_root(&leaves).unwrap();
        assert_eq!(root, hash_leaf(b"only leaf"));
    }

    #[test]
    fn two_leaves() {
        let leaves: Vec<&[u8]> = vec![b"left", b"right"];
        let root = merkle_root(&leaves).unwrap();
        let expected = hash_node(&hash_leaf(b"left"), &hash_leaf(b"right"));
        assert_eq!(root, expected);
    }

    #[test]
    fn three_leaves_odd_promotion() {
        let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let root = merkle_root(&leaves).unwrap();
        let ab = hash_node(&hash_leaf(b"a"), &hash_leaf(b"b"));
        let cc = hash_node(&hash_leaf(b"c"), &hash_leaf(b"c"));
        let expected = hash_node(&ab, &cc);
        assert_eq!(root, expected);
    }

    #[test]
    fn four_leaves() {
        let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        let root = merkle_root(&leaves).unwrap();
        let ab = hash_node(&hash_leaf(b"a"), &hash_leaf(b"b"));
        let cd = hash_node(&hash_leaf(b"c"), &hash_leaf(b"d"));
        let expected = hash_node(&ab, &cd);
        assert_eq!(root, expected);
    }

    #[test]
    fn empty_returns_none() {
        let leaves: Vec<&[u8]> = vec![];
        assert!(merkle_root(&leaves).is_none());
    }

    #[test]
    fn deterministic_root() {
        let l1: Vec<&[u8]> = vec![b"x", b"y", b"z"];
        let l2: Vec<&[u8]> = vec![b"x", b"y", b"z"];
        assert_eq!(merkle_root(&l1), merkle_root(&l2));
    }

    #[test]
    fn order_matters() {
        let l1: Vec<&[u8]> = vec![b"a", b"b"];
        let l2: Vec<&[u8]> = vec![b"b", b"a"];
        assert_ne!(merkle_root(&l1), merkle_root(&l2));
    }

    #[test]
    fn proof_verifies_each_leaf_two() {
        let leaves: Vec<&[u8]> = vec![b"left", b"right"];
        let root = merkle_root(&leaves).unwrap();
        for i in 0..leaves.len() {
            let proof = merkle_proof(&leaves, i).unwrap();
            assert!(
                merkle_verify(&root, leaves[i], &proof),
                "proof failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn proof_verifies_each_leaf_five() {
        let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d", b"e"];
        let root = merkle_root(&leaves).unwrap();
        for i in 0..leaves.len() {
            let proof = merkle_proof(&leaves, i).unwrap();
            assert!(
                merkle_verify(&root, leaves[i], &proof),
                "proof failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn proof_rejects_wrong_leaf() {
        let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let root = merkle_root(&leaves).unwrap();
        let proof = merkle_proof(&leaves, 0).unwrap();
        assert!(!merkle_verify(&root, b"wrong", &proof));
    }

    #[test]
    fn proof_out_of_bounds_returns_none() {
        let leaves: Vec<&[u8]> = vec![b"a", b"b"];
        assert!(merkle_proof(&leaves, 5).is_none());
    }

    #[test]
    fn proof_empty_returns_none() {
        let leaves: Vec<&[u8]> = vec![];
        assert!(merkle_proof(&leaves, 0).is_none());
    }

    #[test]
    fn leaf_prefix_prevents_second_preimage() {
        // hash_leaf(data) != hash_node(data_as_32bytes, data_as_32bytes)
        // because different prefix bytes
        let data = [0u8; 32];
        let leaf = hash_leaf(&data);
        let node = hash_node(&data, &data);
        assert_ne!(leaf, node);
    }
}
