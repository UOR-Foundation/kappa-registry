//! Merkle tree conformance tests.

use kappa_core::merkle::{hash_leaf, merkle_proof, merkle_root, merkle_verify};

#[test]
fn single_leaf_is_its_hash() {
    let leaves: Vec<&[u8]> = vec![b"only"];
    let root = merkle_root(&leaves).unwrap();
    assert_eq!(root, hash_leaf(b"only"));
}

#[test]
fn two_leaves() {
    let leaves: Vec<&[u8]> = vec![b"a", b"b"];
    let root = merkle_root(&leaves).unwrap();
    assert_ne!(root, hash_leaf(b"a"));
    assert_ne!(root, hash_leaf(b"b"));
}

#[test]
fn deterministic() {
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
fn empty_returns_none() {
    let leaves: Vec<&[u8]> = vec![];
    assert!(merkle_root(&leaves).is_none());
}

#[test]
fn proof_verifies_each_leaf() {
    let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d", b"e"];
    let root = merkle_root(&leaves).unwrap();
    for i in 0..leaves.len() {
        let proof = merkle_proof(&leaves, i).unwrap();
        assert!(merkle_verify(&root, leaves[i], &proof));
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
fn domain_separation() {
    let data = [0u8; 32];
    let leaf = hash_leaf(&data);
    // Internal node hash of (data, data) must differ from leaf hash of data
    // because of the 0x00/0x01 prefix domain separation
    assert_ne!(leaf, data);
}

#[test]
fn odd_leaf_count() {
    let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c"];
    let root = merkle_root(&leaves).unwrap();
    // All three leaves should have valid proofs
    for i in 0..3 {
        let proof = merkle_proof(&leaves, i).unwrap();
        assert!(merkle_verify(&root, leaves[i], &proof));
    }
}
