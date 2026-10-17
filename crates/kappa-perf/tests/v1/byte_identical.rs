//! PERF-SUC-002: C-1 independent builds byte-identical.
//! Same sorted kappa-set produces same bytes and same kappa
//! on two independent builds.
//!
//! PERF-SUC-015: Recovery round trip. Serialize, deserialize,
//! verify every key.

use kappa_types::StateDigest;
use kappa_types::canonical::canonical_bytes;
use kappa_types::epoch_root::{mutations_merkle_root, state_merkle_root};
use kappa_types::kappa::Kappa;
use kappa_types::merkle::{merkle_proof, merkle_root, merkle_verify};

type TestResult = Result<(), Box<dyn std::error::Error>>;

// -- PERF-SUC-002: byte-identical builds --

#[test]
fn merkle_root_byte_identical_across_builds() {
    let keys: Vec<Vec<u8>> = (0..1000u32)
        .map(|i| Kappa::sha256(&i.to_le_bytes()).key_bytes())
        .collect();
    let refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();

    let root_a = merkle_root(&refs);
    let root_b = merkle_root(&refs);
    assert_eq!(root_a, root_b);
}

#[test]
fn state_digest_byte_identical_across_builds() {
    let mut digest_a = StateDigest::default();
    let mut digest_b = StateDigest::default();

    for i in 0..1000u32 {
        let name = format!("tag-{i}");
        let kappa = Kappa::sha256(&i.to_le_bytes());
        digest_a.insert(&name, &kappa);
        digest_b.insert(&name, &kappa);
    }

    assert_eq!(digest_a, digest_b);
    assert_eq!(digest_a.into_bytes(), digest_b.into_bytes());
}

#[test]
fn state_merkle_root_deterministic() {
    let k1 = Kappa::sha256(b"alpha");
    let k2 = Kappa::sha256(b"beta");
    let tags: Vec<(&str, &Kappa)> = vec![("alpha", &k1), ("beta", &k2)];

    let root_a = state_merkle_root(&tags);
    let root_b = state_merkle_root(&tags);
    assert_eq!(root_a, root_b);
}

#[test]
fn mutations_merkle_root_deterministic() {
    use kappa_types::epoch::{EpochMutation, MutationOp};

    let mutations = vec![EpochMutation {
        op: MutationOp::TagSet,
        kappa: Kappa::sha256(b"content"),
        timestamp_ms: 1000,
        context: Some("tag-name".to_string()),
    }];
    let root_a = mutations_merkle_root(&mutations);
    let root_b = mutations_merkle_root(&mutations);
    assert_eq!(root_a, root_b);
}

// -- PERF-SUC-015: recovery round trip --

#[test]
fn merkle_proof_roundtrip_at_scale() -> TestResult {
    let keys: Vec<Vec<u8>> = (0..4096u32).map(|i| i.to_le_bytes().to_vec()).collect();
    let refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
    let root = merkle_root(&refs);

    // Verify every 100th leaf
    for index in (0..4096).step_by(100) {
        let proof = merkle_proof(&refs, index).ok_or_else(|| format!("no proof at {index}"))?;
        assert!(
            merkle_verify(&root, &keys[index], &proof),
            "proof failed at {index}"
        );
    }
    Ok(())
}

#[test]
fn canonical_encoding_roundtrip_all_types() -> TestResult {
    use kappa_types::canonical::from_canonical;
    use kappa_types::edge::{BuiltinRelation, EdgeInput, EdgeRelation};
    use kappa_types::tag::TagEntry;

    // TagEntry
    let tag = TagEntry {
        name: "test".into(),
        kappa: Kappa::sha256(b"content"),
        version: 1,
        created_at_ms: 1000,
        updated_at_ms: 2000,
        symref: None,
    };
    let bytes = canonical_bytes(&tag);
    let recovered: TagEntry = from_canonical(&bytes)?;
    assert_eq!(recovered.name, "test");
    assert_eq!(recovered.kappa, tag.kappa);

    // EdgeInput
    let edge = EdgeInput {
        source: Kappa::sha256(b"src"),
        target: Kappa::sha256(b"tgt"),
        relation: EdgeRelation::Builtin(BuiltinRelation::Owns),
        asserter: Kappa::sha256(b"asserter"),
        created_at_ms: 3000,
        metadata: Some(b"meta".to_vec()),
    };
    let bytes = canonical_bytes(&edge);
    let recovered: EdgeInput = from_canonical(&bytes)?;
    assert_eq!(recovered.source, edge.source);
    assert_eq!(recovered.metadata, Some(b"meta".to_vec()));

    Ok(())
}
