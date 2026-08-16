//! Tests for InMemoryStore.

use std::sync::Arc;

use crate::clock::ntp_lamport::NtpLamportClock;
use crate::kappa::kappa_from_bytes;
use crate::store::blob_put_computed;
use crate::types::NamespaceRef;

use super::*;

fn test_store() -> (InMemoryStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(NtpLamportClock::new());
    let store = InMemoryStore::new(
        MemoryStoreConfig::new(dir.path().join("blobs")),
        clock,
    )
    .unwrap();
    (store, dir)
}

// -- Blob -------------------------------------------------------------------

#[test]
fn blob_put_get_roundtrip() {
    let (store, _dir) = test_store();
    let kappa = kappa_from_bytes(b"hello world");
    assert!(store.ingest_verified(&kappa,b"hello world").unwrap().newly_stored);
    assert!(kappa.starts_with("sha256:"));
    assert_eq!(store.blob_get(&kappa).unwrap(), b"hello world");
}

#[test]
fn blob_put_idempotent() {
    let (store, _dir) = test_store();
    let kappa = kappa_from_bytes(b"same");
    assert!(store.ingest_verified(&kappa,b"same").unwrap().newly_stored);
    assert!(!store.ingest_verified(&kappa,b"same").unwrap().newly_stored);
}

#[test]
fn blob_get_not_found() {
    let (store, _dir) = test_store();
    let k = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    assert!(matches!(store.blob_get(k), Err(StoreError::NotFound(_))));
}

#[test]
fn blob_exists_and_delete() {
    let (store, _dir) = test_store();
    let kappa = kappa_from_bytes(b"exists");
    store.ingest_verified(&kappa,b"exists").unwrap();
    assert!(store.blob_exists(&kappa).unwrap());
    store.blob_delete(&kappa).unwrap();
    assert!(!store.blob_exists(&kappa).unwrap());
}

#[test]
fn blob_get_range() {
    let (store, _dir) = test_store();
    let kappa = kappa_from_bytes(b"0123456789");
    store.ingest_verified(&kappa,b"0123456789").unwrap();
    assert_eq!(store.blob_get_range(&kappa, 3, 4).unwrap(), b"3456");
}

#[test]
fn blob_get_range_past_end() {
    let (store, _dir) = test_store();
    let kappa = kappa_from_bytes(b"short");
    store.ingest_verified(&kappa,b"short").unwrap();
    assert_eq!(store.blob_get_range(&kappa, 3, 100).unwrap(), b"rt");
}

#[test]
fn blob_put_computed_convenience() {
    let (store, _dir) = test_store();
    let kappa = blob_put_computed(&store, b"via convenience").unwrap();
    assert!(kappa.starts_with("sha256:"));
    assert_eq!(store.blob_get(&kappa).unwrap(), b"via convenience");
}

// -- Blob metadata ----------------------------------------------------------

#[test]
fn blob_meta_put_get_roundtrip() {
    let (store, _dir) = test_store();
    let kappa = kappa_from_bytes(b"meta test");
    store.ingest_verified(&kappa,b"meta test").unwrap();
    store
        .blob_put_meta(&kappa, "content-type", b"text/plain")
        .unwrap();
    assert_eq!(
        store.blob_get_meta(&kappa, "content-type").unwrap(),
        b"text/plain"
    );
}

#[test]
fn blob_meta_not_found() {
    let (store, _dir) = test_store();
    let kappa = kappa_from_bytes(b"no meta");
    store.ingest_verified(&kappa,b"no meta").unwrap();
    assert!(matches!(
        store.blob_get_meta(&kappa, "missing"),
        Err(StoreError::NotFound(_))
    ));
}

#[test]
fn blob_meta_delete() {
    let (store, _dir) = test_store();
    let kappa = kappa_from_bytes(b"del meta");
    store.ingest_verified(&kappa,b"del meta").unwrap();
    store.blob_put_meta(&kappa, "key", b"value").unwrap();
    store.blob_delete_meta(&kappa, "key").unwrap();
    assert!(matches!(
        store.blob_get_meta(&kappa, "key"),
        Err(StoreError::NotFound(_))
    ));
}

// -- Tag --------------------------------------------------------------------

#[test]
fn tag_set_get() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    assert_eq!(store.tag_set(&ns, "latest", "sha256:aaa").unwrap(), 1);
    let e = store.tag_get(&ns, "latest").unwrap();
    assert_eq!(e.name, "latest");
    assert_eq!(e.kappa, "sha256:aaa");
    assert_eq!(e.version, 1);
}

#[test]
fn tag_version_increments() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    assert_eq!(store.tag_set(&ns, "t", "sha256:a").unwrap(), 1);
    assert_eq!(store.tag_set(&ns, "t", "sha256:b").unwrap(), 2);
    assert_eq!(store.tag_set(&ns, "t", "sha256:c").unwrap(), 3);
}

#[test]
fn tag_delete_and_not_found() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    store.tag_set(&ns, "t", "sha256:a").unwrap();
    store.tag_delete(&ns, "t").unwrap();
    assert!(matches!(
        store.tag_get(&ns, "t"),
        Err(StoreError::NotFound(_))
    ));
}

#[test]
fn tag_list_sorted() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    store.tag_set(&ns, "c", "sha256:c").unwrap();
    store.tag_set(&ns, "a", "sha256:a").unwrap();
    store.tag_set(&ns, "b", "sha256:b").unwrap();
    let list = store.tag_list(&ns).unwrap();
    let names: Vec<&str> = list.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["a", "b", "c"]);
}

#[test]
fn tag_prefix_filters() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    store.tag_set(&ns, "v1.0", "sha256:a").unwrap();
    store.tag_set(&ns, "v1.1", "sha256:b").unwrap();
    store.tag_set(&ns, "v2.0", "sha256:c").unwrap();
    assert_eq!(store.tag_prefix(&ns, "v1.").unwrap().len(), 2);
}

#[test]
fn tag_set_batch_all_or_nothing() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    store.tag_set(&ns, "a", "sha256:1").unwrap();
    let updates = vec![
        TagUpdate {
            name: "a".into(),
            kappa: "sha256:2".into(),
            expected_version: Some(1),
        },
        TagUpdate {
            name: "b".into(),
            kappa: "sha256:3".into(),
            expected_version: Some(1),
        },
    ];
    assert!(matches!(
        store.tag_set_batch(&ns, &updates),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(store.tag_get(&ns, "a").unwrap().kappa, "sha256:1");
}

#[test]
fn tag_set_batch_unconditional() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    let updates = vec![
        TagUpdate {
            name: "x".into(),
            kappa: "sha256:a".into(),
            expected_version: None,
        },
        TagUpdate {
            name: "y".into(),
            kappa: "sha256:b".into(),
            expected_version: None,
        },
    ];
    store.tag_set_batch(&ns, &updates).unwrap();
    assert_eq!(store.tag_get(&ns, "x").unwrap().kappa, "sha256:a");
    assert_eq!(store.tag_get(&ns, "y").unwrap().kappa, "sha256:b");
}

// -- Edge -------------------------------------------------------------------

#[test]
fn edge_put_query_outbound() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    let edge = Edge {
        source: "sha256:src".into(),
        target: "sha256:tgt".into(),
        relation: EdgeRelation::DerivedFrom,
        asserter: "anchor-1".into(),
        value_kappa: None,
        metadata: None,
    };
    store.edge_put(&ns, &edge).unwrap();
    let results = store
        .edge_query(
            &ns,
            &EdgeQuery {
                anchor: "sha256:src".into(),
                direction: Direction::Outbound,
                relation: None,
                asserter: None,
            },
        )
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].target, "sha256:tgt");
}

#[test]
fn edge_put_query_inbound() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    let edge = Edge {
        source: "sha256:src".into(),
        target: "sha256:tgt".into(),
        relation: EdgeRelation::Assertion,
        asserter: "anchor-1".into(),
        value_kappa: None,
        metadata: None,
    };
    store.edge_put(&ns, &edge).unwrap();
    let results = store
        .edge_query(
            &ns,
            &EdgeQuery {
                anchor: "sha256:tgt".into(),
                direction: Direction::Inbound,
                relation: None,
                asserter: None,
            },
        )
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].source, "sha256:src");
}

#[test]
fn edge_query_filters_relation() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    store
        .edge_put(
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
    store
        .edge_put(
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
    let results = store
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
fn edge_delete_cleans_indexes() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    store
        .edge_put(
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
    store
        .edge_delete(&ns, "s", "t", EdgeRelation::Owns)
        .unwrap();
    let results = store
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
    assert_eq!(results.len(), 0);
}

// -- Sequence ---------------------------------------------------------------

#[test]
fn sequence_monotonic() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    assert_eq!(store.sequence_current(&ns, "epoch").unwrap(), 0);
    assert_eq!(store.sequence_next(&ns, "epoch").unwrap(), 1);
    assert_eq!(store.sequence_next(&ns, "epoch").unwrap(), 2);
    assert_eq!(store.sequence_next(&ns, "epoch").unwrap(), 3);
    assert_eq!(store.sequence_current(&ns, "epoch").unwrap(), 3);
}

#[test]
fn sequence_isolated_by_namespace() {
    let (store, _dir) = test_store();
    let ns1 = NamespaceRef::deterministic("ns1");
    let ns2 = NamespaceRef::deterministic("ns2");
    store.sequence_next(&ns1, "seq").unwrap();
    store.sequence_next(&ns1, "seq").unwrap();
    assert_eq!(store.sequence_current(&ns1, "seq").unwrap(), 2);
    assert_eq!(store.sequence_current(&ns2, "seq").unwrap(), 0);
}

// -- Epoch ------------------------------------------------------------------

#[test]
fn epoch_advance_and_get() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    let mutations = vec![EpochMutation {
        op: MutationOp::TagSet,
        namespace: "ns".into(),
        tag_name: "t".into(),
        old_kappa: None,
        new_kappa: Some("sha256:aaa".into()),
    }];
    let kappa = store.epoch_advance(&ns, mutations).unwrap();
    assert!(kappa.starts_with("sha256:"));
    let root = store.epoch_get(&kappa).unwrap();
    assert_eq!(root.namespace, "ns");
    assert_eq!(root.epoch_number, 1);
    assert!(root.prev_root_kappa.is_none());
}

#[test]
fn epoch_chain_links() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    let k1 = store.epoch_advance(&ns, vec![]).unwrap();
    let k2 = store.epoch_advance(&ns, vec![]).unwrap();
    let r2 = store.epoch_get(&k2).unwrap();
    assert_eq!(r2.epoch_number, 2);
    assert_eq!(r2.prev_root_kappa, Some(k1));
}

#[test]
fn epoch_current_tracks_latest() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    assert!(store.epoch_current(&ns).unwrap().is_none());
    let k1 = store.epoch_advance(&ns, vec![]).unwrap();
    assert_eq!(store.epoch_current(&ns).unwrap(), Some(k1));
    let k2 = store.epoch_advance(&ns, vec![]).unwrap();
    assert_eq!(store.epoch_current(&ns).unwrap(), Some(k2));
}

// -- blob_open (default impl via Cursor<Vec<u8>>) ----------------------------

#[test]
fn blob_open_default_roundtrip() {
    let (store, _dir) = test_store();
    let kappa = kappa_from_bytes(b"open default");
    store.ingest_verified(&kappa,b"open default").unwrap();
    let mut file = store.blob_open(&kappa).unwrap();
    let mut buf = Vec::new();
    use std::io::Read;
    file.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"open default");
}

#[test]
fn blob_open_default_not_found() {
    let (store, _dir) = test_store();
    let k = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    assert!(store.blob_open(k).is_err());
}

#[test]
fn blob_open_default_matches_blob_get() {
    let (store, _dir) = test_store();
    let content: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    let kappa = kappa_from_bytes(&content);
    store.ingest_verified(&kappa,&content).unwrap();

    let get_result = store.blob_get(&kappa).unwrap();
    let mut file = store.blob_open(&kappa).unwrap();
    let mut open_result = Vec::new();
    use std::io::Read;
    file.read_to_end(&mut open_result).unwrap();
    assert_eq!(get_result, open_result);
}

// -- Namespace --------------------------------------------------------------

#[test]
fn namespace_tracked() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    assert!(!store.namespace_exists("ns", None).unwrap());
    store.tag_set(&ns, "t", "sha256:a").unwrap();
    assert!(store.namespace_exists("ns", None).unwrap());
    let records = store.namespace_list(None).unwrap();
    assert!(records.iter().any(|r| r.aliases.contains(&"ns".to_string())));
}

// -- Multi-axis ingest --------------------------------------------------------

#[test]
fn ingest_verified_sha1_produces_sha256_additional() {
    let (store, _dir) = test_store();
    let content = b"multi-axis test content";
    let sha1_label = crate::kappa::KappaLabel::sha1(content).unwrap();
    let sha1_kappa = sha1_label.as_str();
    let sha256_label = crate::kappa::KappaLabel::sha256(content);
    let sha256_kappa = sha256_label.as_str();

    let result = store.ingest_verified(sha1_kappa, content).unwrap();
    assert!(result.newly_stored);
    assert_eq!(result.kappa, sha1_kappa);
    assert_eq!(result.additional_kappas.len(), 1);
    assert_eq!(result.additional_kappas[0], sha256_kappa);

    // Content retrievable by both addresses
    assert_eq!(store.blob_get(sha1_kappa).unwrap(), content);
    assert_eq!(store.blob_get(sha256_kappa).unwrap(), content);
}

#[test]
fn ingest_verified_sha256_no_additional() {
    let (store, _dir) = test_store();
    let content = b"sha256 is the mandatory axis";
    let sha256_kappa = kappa_from_bytes(content);

    let result = store.ingest_verified(&sha256_kappa, content).unwrap();
    assert!(result.newly_stored);
    assert!(
        result.additional_kappas.is_empty(),
        "sha256 IS the mandatory axis, no extra computation"
    );
}

#[test]
fn ingest_compute_blake3_produces_sha256_additional() {
    let (store, _dir) = test_store();
    let content = b"blake3 ingest compute";
    let blake3_label = crate::kappa::KappaLabel::blake3(content);
    let sha256_label = crate::kappa::KappaLabel::sha256(content);

    let result = store.ingest_compute(crate::kappa::Axis::Blake3, content).unwrap();
    assert_eq!(result.kappa, blake3_label.as_str());
    assert_eq!(result.additional_kappas.len(), 1);
    assert_eq!(result.additional_kappas[0], sha256_label.as_str());

    // Both addresses resolve to the same content
    assert_eq!(store.blob_get(blake3_label.as_str()).unwrap(), content);
    assert_eq!(store.blob_get(sha256_label.as_str()).unwrap(), content);
}

#[test]
fn ingest_compute_sha256_no_additional() {
    let (store, _dir) = test_store();
    let content = b"sha256 compute no extra";

    let result = store.ingest_compute(crate::kappa::Axis::Sha256, content).unwrap();
    assert!(result.additional_kappas.is_empty());
}

#[test]
fn multi_axis_idempotent() {
    let (store, _dir) = test_store();
    let content = b"idempotent multi-axis";
    let sha1_label = crate::kappa::KappaLabel::sha1(content).unwrap();

    let r1 = store.ingest_verified(sha1_label.as_str(), content).unwrap();
    assert!(r1.newly_stored);
    let r2 = store.ingest_verified(sha1_label.as_str(), content).unwrap();
    assert!(!r2.newly_stored);
    assert_eq!(r1.additional_kappas, r2.additional_kappas);
}

// -- Upload lifecycle expiration tests ----------------------------------------

fn test_store_with_timeout(timeout_secs: u64) -> (InMemoryStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = super::MemoryStoreConfig::new(dir.path().join("blobs"));
    config.upload_timeout_secs = Some(timeout_secs);
    let clock = Arc::new(NtpLamportClock::new());
    let store = InMemoryStore::new(config, clock).unwrap();
    (store, dir)
}

#[test]
fn upload_put_part_on_expired_session() {
    let (store, _dir) = test_store_with_timeout(0);
    let ns = NamespaceRef::deterministic("ns");
    let id = store.upload_begin(&ns, 0).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    let result = store.upload_put_part(&id, 0, b"data");
    assert!(result.is_err(), "put_part on expired session should fail");
}

#[test]
fn upload_complete_on_expired_session() {
    // Use timeout 1 so put_part succeeds, then sleep past expiry
    let (store, _dir) = test_store_with_timeout(1);
    let ns = NamespaceRef::deterministic("ns");
    let id = store.upload_begin(&ns, 0).unwrap();
    store.upload_put_part(&id, 0, b"data").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let result = store.upload_complete(&id, None);
    assert!(result.is_err(), "complete on expired session should fail");
}

#[test]
fn upload_bytes_received_on_expired_session() {
    let (store, _dir) = test_store_with_timeout(0);
    let ns = NamespaceRef::deterministic("ns");
    let id = store.upload_begin(&ns, 0).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(store.upload_bytes_received(&id).is_none());
}

#[test]
fn upload_namespace_on_expired_session() {
    let (store, _dir) = test_store_with_timeout(0);
    let ns = NamespaceRef::deterministic("ns");
    let id = store.upload_begin(&ns, 0).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(store.upload_namespace(&id).is_none());
}

#[test]
fn upload_evict_expired_returns_correct_count() {
    let (store, _dir) = test_store_with_timeout(0);
    let ns = NamespaceRef::deterministic("ns");
    for _ in 0..5 {
        store.upload_begin(&ns, 0).unwrap();
    }
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(store.upload_evict_expired(0), 5);
}

#[test]
fn upload_evict_expired_preserves_active() {
    let (store, _dir) = test_store_with_timeout(10);
    let ns = NamespaceRef::deterministic("ns");
    store.upload_begin(&ns, 0).unwrap();
    store.upload_begin(&ns, 0).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(store.upload_evict_expired(10), 0);
}

// -- Compression-transparent blob storage ------------------------------------

#[test]
fn compression_memory_store_roundtrip() {
    let (store, _dir) = test_store();
    let original = b"InMemoryStore compression roundtrip test content";
    let compressed = zstd::encode_all(std::io::Cursor::new(original), 3).unwrap();
    let hash = crate::kappa::kappa_from_bytes(original);

    store.ingest_compressed(&hash, &compressed, "zstd", original.len() as u64).unwrap();

    let mut reader = store.blob_open_decompressed(&hash).unwrap();
    let mut got = Vec::new();
    use std::io::Read;
    reader.read_to_end(&mut got).unwrap();
    assert_eq!(got, original);
}

// -- edge_put_batch adversarial tests ----------------------------------------

#[test]
fn edge_put_batch_empty() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    store.edge_put_batch(&ns, &[]).unwrap();
}

#[test]
fn edge_put_batch_single() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    let edge = Edge {
        source: "sha256:src".into(),
        target: "sha256:tgt".into(),
        relation: EdgeRelation::Owns,
        asserter: "a".into(),
        value_kappa: None,
        metadata: None,
    };
    store.edge_put_batch(&ns, &[edge]).unwrap();
    let q = EdgeQuery {
        anchor: "sha256:src".into(),
        direction: Direction::Outbound,
        relation: None,
        asserter: None,
    };
    let results = store.edge_query(&ns, &q).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].target, "sha256:tgt");
}

#[test]
fn edge_put_batch_multiple() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    let edges: Vec<Edge> = (0..10).map(|i| Edge {
        source: format!("sha256:src{i}"),
        target: format!("sha256:tgt{i}"),
        relation: EdgeRelation::RefersTo,
        asserter: "a".into(),
        value_kappa: None,
        metadata: None,
    }).collect();
    store.edge_put_batch(&ns, &edges).unwrap();
    for i in 0..10 {
        let q = EdgeQuery {
            anchor: format!("sha256:src{i}"),
            direction: Direction::Outbound,
            relation: None,
            asserter: None,
        };
        let results = store.edge_query(&ns, &q).unwrap();
        assert_eq!(results.len(), 1, "missing edge {i}");
    }
}

#[test]
fn edge_put_batch_large() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    let edges: Vec<Edge> = (0..500).map(|i| Edge {
        source: "sha256:root".into(),
        target: format!("sha256:dep{i}"),
        relation: EdgeRelation::RefersTo,
        asserter: "a".into(),
        value_kappa: None,
        metadata: None,
    }).collect();
    store.edge_put_batch(&ns, &edges).unwrap();
    let q = EdgeQuery {
        anchor: "sha256:root".into(),
        direction: Direction::Outbound,
        relation: Some(EdgeRelation::RefersTo),
        asserter: None,
    };
    let results = store.edge_query(&ns, &q).unwrap();
    assert_eq!(results.len(), 500);
}

#[test]
fn edge_put_batch_mixed_relations() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    let edges = vec![
        Edge { source: "s".into(), target: "t1".into(), relation: EdgeRelation::Owns, asserter: "a".into(), value_kappa: None, metadata: None },
        Edge { source: "s".into(), target: "t2".into(), relation: EdgeRelation::DerivedFrom, asserter: "a".into(), value_kappa: None, metadata: None },
        Edge { source: "s".into(), target: "t3".into(), relation: EdgeRelation::RefersTo, asserter: "a".into(), value_kappa: None, metadata: None },
    ];
    store.edge_put_batch(&ns, &edges).unwrap();
    let q = EdgeQuery { anchor: "s".into(), direction: Direction::Outbound, relation: Some(EdgeRelation::DerivedFrom), asserter: None };
    let results = store.edge_query(&ns, &q).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].target, "t2");
}

#[test]
fn edge_put_batch_all_queryable_by_target() {
    let (store, _dir) = test_store();
    let ns = NamespaceRef::deterministic("ns");
    let edges: Vec<Edge> = (0..5).map(|i| Edge {
        source: format!("sha256:src{i}"),
        target: "sha256:shared_target".into(),
        relation: EdgeRelation::RefersTo,
        asserter: "a".into(),
        value_kappa: None,
        metadata: None,
    }).collect();
    store.edge_put_batch(&ns, &edges).unwrap();
    let q = EdgeQuery {
        anchor: "sha256:shared_target".into(),
        direction: Direction::Inbound,
        relation: None,
        asserter: None,
    };
    let results = store.edge_query(&ns, &q).unwrap();
    assert_eq!(results.len(), 5);
}

#[test]
fn compression_memory_store_compressed_reader() {
    let (store, _dir) = test_store();
    let original = b"InMemoryStore compressed reader test";
    let compressed = zstd::encode_all(std::io::Cursor::new(original), 3).unwrap();
    let hash = crate::kappa::kappa_from_bytes(original);

    store.ingest_compressed(&hash, &compressed, "zstd", original.len() as u64).unwrap();

    let mut reader = store.blob_open_compressed(&hash).unwrap();
    let mut got = Vec::new();
    use std::io::Read;
    reader.read_to_end(&mut got).unwrap();
    assert_eq!(got, compressed);
}
