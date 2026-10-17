//! Merkle tree conformance: RFC 9162 semantics, domain separation,
//! proof generation and verification, odd-node promotion.

use kappa_store::merkle::{EMPTY_ROOT, hash_leaf, merkle_proof, merkle_root, merkle_verify};

use super::support::TestResult;

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
fn proof_verifies_each_leaf() -> TestResult {
    let leaves: [&[u8]; 5] = [b"a", b"b", b"c", b"d", b"e"];
    let root = merkle_root(&leaves);
    for (index, leaf) in leaves.iter().enumerate() {
        let proof =
            merkle_proof(&leaves, index).ok_or_else(|| format!("no proof for leaf {index}"))?;
        assert!(
            merkle_verify(&root, leaf, &proof),
            "proof failed for leaf {index}"
        );
    }
    Ok(())
}

#[test]
fn proof_rejects_wrong_leaf() -> TestResult {
    let leaves: [&[u8]; 3] = [b"a", b"b", b"c"];
    let root = merkle_root(&leaves);
    let proof = merkle_proof(&leaves, 0).ok_or("no proof")?;
    assert!(!merkle_verify(&root, b"wrong", &proof));
    Ok(())
}

#[test]
fn domain_separation() {
    let data = [0u8; 32];
    let leaf = hash_leaf(&data);
    assert_ne!(leaf, data);
}

#[test]
fn odd_leaf_promoted_not_duplicated() {
    // RFC 9162: [a,b,c] and [a,b,c,c] must produce different roots.
    assert_ne!(
        merkle_root(&[b"a", b"b", b"c"]),
        merkle_root(&[b"a", b"b", b"c", b"c"])
    );
}

#[test]
fn odd_leaf_count_proofs_verify() -> TestResult {
    let leaves: [&[u8]; 3] = [b"a", b"b", b"c"];
    let root = merkle_root(&leaves);
    for (index, leaf) in leaves.iter().enumerate() {
        let proof =
            merkle_proof(&leaves, index).ok_or_else(|| format!("no proof for leaf {index}"))?;
        assert!(merkle_verify(&root, leaf, &proof));
    }
    Ok(())
}

#[test]
fn seven_leaves_epoch_shape() -> TestResult {
    let leaves: [&[u8]; 7] = [
        b"ns",
        b"epoch",
        b"prev",
        b"state",
        b"mutations",
        b"ts",
        b"signer",
    ];
    let root = merkle_root(&leaves);
    for (index, leaf) in leaves.iter().enumerate() {
        let proof = merkle_proof(&leaves, index)
            .ok_or_else(|| format!("no proof for 7-leaf index {index}"))?;
        assert!(
            merkle_verify(&root, leaf, &proof),
            "7-leaf proof failed for index {index}"
        );
    }
    Ok(())
}

#[test]
fn proof_out_of_bounds_returns_none() {
    assert!(merkle_proof(&[b"a", b"b"], 5).is_none());
}

#[test]
fn large_tree() -> TestResult {
    let data: Vec<Vec<u8>> = (0..100u32).map(|i| i.to_be_bytes().to_vec()).collect();
    let leaves: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
    let root = merkle_root(&leaves);
    for index in [0, 50, 99] {
        let proof = merkle_proof(&leaves, index).ok_or_else(|| format!("no proof at {index}"))?;
        assert!(
            merkle_verify(&root, leaves[index], &proof),
            "100-leaf proof failed at {index}"
        );
    }
    Ok(())
}
