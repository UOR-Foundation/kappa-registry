//! PERF-EPO-010: Exhaustive `BuiltinRelation` GC reachability.
//! Compile-time exhaustive match plus table test.
//!
//! PERF-EPO-011: Semantic relation IRIs round-trip through dCBOR.

use kappa_types::canonical::{canonical_bytes, from_canonical};
use kappa_types::edge::{BuiltinRelation, EdgeRelation, SemanticRelation, semantic};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn builtin_gc_reachability_exhaustive() {
    // Every variant must be handled. The exhaustive match in
    // BuiltinRelation::gc_reachable guarantees compile-time coverage.
    // This test documents the expected values.
    let reachable = [
        (BuiltinRelation::Owns, true),
        (BuiltinRelation::Assertion, true),
        (BuiltinRelation::Revocation, true),
        (BuiltinRelation::Capability, true),
        (BuiltinRelation::Delegation, true),
        (BuiltinRelation::RecoveryShare, true),
        (BuiltinRelation::EpochRoot, true),
        (BuiltinRelation::DirectoryRecord, true),
        (BuiltinRelation::ChunkManifest, true),
        (BuiltinRelation::Watermark, true),
        (BuiltinRelation::Member, true),
        (BuiltinRelation::WitnessReceipt, false),
        (BuiltinRelation::OffloadReceipt, false),
    ];

    assert_eq!(
        reachable.len(),
        BuiltinRelation::ALL.len(),
        "test must cover all variants"
    );

    for (rel, expected) in reachable {
        assert_eq!(
            rel.gc_reachable(),
            expected,
            "{rel:?} gc_reachable mismatch"
        );
    }
}

#[test]
fn semantic_gc_reachable_known_iris() {
    assert!(SemanticRelation(semantic::DERIVED_FROM.to_string()).gc_reachable());
    assert!(SemanticRelation(semantic::COMPOSED_OF.to_string()).gc_reachable());
    assert!(SemanticRelation(semantic::IS_PART_OF.to_string()).gc_reachable());
    assert!(!SemanticRelation(semantic::REFERENCES.to_string()).gc_reachable());
    assert!(!SemanticRelation(semantic::ATTRIBUTED_TO.to_string()).gc_reachable());
    assert!(!SemanticRelation("https://example.org/custom".to_string()).gc_reachable());
}

#[test]
fn builtin_relation_cbor_roundtrip() -> TestResult {
    for rel in BuiltinRelation::ALL {
        let bytes = canonical_bytes(&rel);
        let recovered: BuiltinRelation = from_canonical(&bytes)?;
        assert_eq!(recovered, rel, "{rel:?} roundtrip failed");
    }
    Ok(())
}

#[test]
fn semantic_relation_cbor_roundtrip() -> TestResult {
    for iri in [
        semantic::DERIVED_FROM,
        semantic::ATTRIBUTED_TO,
        semantic::GENERATED_BY,
        semantic::IS_PART_OF,
        semantic::REFERENCES,
        semantic::CERTIFIED_BY,
        semantic::COMPOSED_OF,
        semantic::EVIDENCE_PROVENANCE,
    ] {
        let rel = SemanticRelation(iri.to_string());
        let bytes = canonical_bytes(&rel);
        let recovered: SemanticRelation = from_canonical(&bytes)?;
        assert_eq!(recovered.0, iri, "IRI {iri} roundtrip failed");
    }
    Ok(())
}

#[test]
fn edge_relation_two_level_roundtrip() -> TestResult {
    // Builtin
    let builtin = EdgeRelation::Builtin(BuiltinRelation::Delegation);
    let bytes = canonical_bytes(&builtin);
    let recovered: EdgeRelation = from_canonical(&bytes)?;
    assert_eq!(recovered, builtin);

    // Semantic
    let sem = EdgeRelation::Semantic(SemanticRelation(semantic::DERIVED_FROM.to_string()));
    let bytes = canonical_bytes(&sem);
    let recovered: EdgeRelation = from_canonical(&bytes)?;
    assert_eq!(recovered, sem);

    Ok(())
}
