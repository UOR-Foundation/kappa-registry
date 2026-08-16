//! Edge primitive conformance tests.

use kappa_core::clock::ntp_lamport::NtpLamportClock;
use kappa_core::store::memory::{InMemoryStore, MemoryStoreConfig};
use kappa_core::store::KappaStore;
use kappa_core::types::{Direction, Edge, EdgeQuery, EdgeRelation, NamespaceRef};
use std::sync::Arc;

fn new_store() -> (InMemoryStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(NtpLamportClock::new());
    let store = InMemoryStore::new(
        MemoryStoreConfig::new(dir.path().join("blobs")),
        clock,
    )
    .unwrap();
    (store, dir)
}

#[test]
fn put_query_outbound() {
    let (s, _d) = new_store();
    let ns = NamespaceRef::from("ns");
    let edge = Edge {
        source: "src".into(),
        target: "tgt".into(),
        relation: EdgeRelation::DerivedFrom,
        asserter: "a".into(),
        value_kappa: None,
        metadata: None,
    };
    s.edge_put(&ns, &edge).unwrap();
    let results = s
        .edge_query(
            &ns,
            &EdgeQuery {
                anchor: "src".into(),
                direction: Direction::Outbound,
                relation: None,
                asserter: None,
            },
        )
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].target, "tgt");
}

#[test]
fn put_query_inbound() {
    let (s, _d) = new_store();
    let ns = NamespaceRef::from("ns");
    let edge = Edge {
        source: "src".into(),
        target: "tgt".into(),
        relation: EdgeRelation::Assertion,
        asserter: "a".into(),
        value_kappa: None,
        metadata: None,
    };
    s.edge_put(&ns, &edge).unwrap();
    let results = s
        .edge_query(
            &ns,
            &EdgeQuery {
                anchor: "tgt".into(),
                direction: Direction::Inbound,
                relation: None,
                asserter: None,
            },
        )
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].source, "src");
}

#[test]
fn query_filters_by_relation() {
    let (s, _d) = new_store();
    let ns = NamespaceRef::from("ns");
    s.edge_put(
        &ns,
        &Edge {
            source: "a".into(),
            target: "b".into(),
            relation: EdgeRelation::Owns,
            asserter: "x".into(),
            value_kappa: None,
            metadata: None,
        },
    )
    .unwrap();
    s.edge_put(
        &ns,
        &Edge {
            source: "a".into(),
            target: "c".into(),
            relation: EdgeRelation::DerivedFrom,
            asserter: "x".into(),
            value_kappa: None,
            metadata: None,
        },
    )
    .unwrap();
    let results = s
        .edge_query(
            &ns,
            &EdgeQuery {
                anchor: "a".into(),
                direction: Direction::Outbound,
                relation: Some(EdgeRelation::Owns),
                asserter: None,
            },
        )
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].relation, EdgeRelation::Owns);
}

#[test]
fn delete_cleans_all_indexes() {
    let (s, _d) = new_store();
    let ns = NamespaceRef::from("ns");
    s.edge_put(
        &ns,
        &Edge {
            source: "s".into(),
            target: "t".into(),
            relation: EdgeRelation::Owns,
            asserter: "a".into(),
            value_kappa: None,
            metadata: None,
        },
    )
    .unwrap();
    s.edge_delete(&ns, "s", "t", EdgeRelation::Owns).unwrap();
    let fwd = s
        .edge_query(
            &ns,
            &EdgeQuery {
                anchor: "s".into(),
                direction: Direction::Outbound,
                relation: None,
                asserter: None,
            },
        )
        .unwrap();
    assert!(fwd.is_empty());
    let rev = s
        .edge_query(
            &ns,
            &EdgeQuery {
                anchor: "t".into(),
                direction: Direction::Inbound,
                relation: None,
                asserter: None,
            },
        )
        .unwrap();
    assert!(rev.is_empty());
}

#[test]
fn edge_relation_roundtrip() {
    use kappa_core::canonical::{canonical_bytes, from_canonical};
    for rel in [
        EdgeRelation::Owns,
        EdgeRelation::Assertion,
        EdgeRelation::DerivedFrom,
        EdgeRelation::RefersTo,
    ] {
        let bytes = canonical_bytes(&rel);
        let decoded: EdgeRelation = from_canonical(&bytes).unwrap();
        assert_eq!(decoded, rel);
    }
}

#[test]
fn gc_reachable_exhaustive() {
    let all = [
        EdgeRelation::Owns,
        EdgeRelation::ComposedOf,
        EdgeRelation::Assertion,
        EdgeRelation::Revocation,
        EdgeRelation::Capability,
        EdgeRelation::RecoveryShare,
        EdgeRelation::EpochRoot,
        EdgeRelation::AkdTreeNode,
        EdgeRelation::ChunkManifest,
        EdgeRelation::WitnessReceipt,
        EdgeRelation::OffloadReceipt,
        EdgeRelation::DerivedFrom,
        EdgeRelation::CertifiedBy,
        EdgeRelation::EvidenceProvenance,
        EdgeRelation::SectionOf,
        EdgeRelation::RefersTo,
    ];
    for rel in all {
        let _ = rel.gc_reachable();
    }
}
