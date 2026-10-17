//! Merkle tree conformance tests (top-level, via kappa-core re-export).

use kappa_core::merkle::{EMPTY_ROOT, hash_leaf, merkle_proof, merkle_root, merkle_verify};

#[test]
fn single_leaf_is_its_hash() {
    let root = merkle_root(&[b"only"]);
    assert_eq!(root, hash_leaf(b"only"));
}

#[test]
fn two_leaves() {
    let root = merkle_root(&[b"a", b"b"]);
    assert_ne!(root, hash_leaf(b"a"));
    assert_ne!(root, hash_leaf(b"b"));
}

#[test]
fn deterministic() {
    assert_eq!(
        merkle_root(&[b"x", b"y", b"z"]),
        merkle_root(&[b"x", b"y", b"z"])
    );
}

#[test]
fn order_matters() {
    assert_ne!(merkle_root(&[b"a", b"b"]), merkle_root(&[b"b", b"a"]));
}

#[test]
fn empty_returns_empty_root() {
    assert_eq!(merkle_root(&[]), EMPTY_ROOT);
}

#[test]
fn proof_verifies_each_leaf() {
    let leaves: [&[u8]; 5] = [b"a", b"b", b"c", b"d", b"e"];
    let root = merkle_root(&leaves);
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = merkle_proof(&leaves, i).expect("proof must exist");
        assert!(
            merkle_verify(&root, leaf, &proof),
            "proof failed for leaf {i}"
        );
    }
}

#[test]
fn proof_rejects_wrong_leaf() {
    let leaves: [&[u8]; 3] = [b"a", b"b", b"c"];
    let root = merkle_root(&leaves);
    let proof = merkle_proof(&leaves, 0).expect("proof must exist");
    assert!(!merkle_verify(&root, b"wrong", &proof));
}

#[test]
fn domain_separation() {
    let data = [0u8; 32];
    let leaf = hash_leaf(&data);
    assert_ne!(leaf, data);
}

#[test]
fn odd_leaf_count() {
    let leaves: [&[u8]; 3] = [b"a", b"b", b"c"];
    let root = merkle_root(&leaves);
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = merkle_proof(&leaves, i).expect("proof must exist");
        assert!(merkle_verify(&root, leaf, &proof));
    }
}

#[test]
fn duplicate_tail_does_not_collide() {
    assert_ne!(
        merkle_root(&[b"a", b"b", b"c"]),
        merkle_root(&[b"a", b"b", b"c", b"c"])
    );
}
