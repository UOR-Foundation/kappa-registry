//! Tests for InMemoryStore.

use std::sync::Arc;

use crate::clock::ntp_lamport::NtpLamportClock;

use super::*;

fn test_store() -> (InMemoryStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(NtpLamportClock::new());
    let store = InMemoryStore::new(
        MemoryStoreConfig { blob_root: dir.path().join("blobs") },
        clock,
    ).unwrap();
    (store, dir)
}

// -- Blob -------------------------------------------------------------------

#[test]
fn blob_put_get_roundtrip() {
    let (store, _dir) = test_store();
    let kappa = store.blob_put(b"hello world").unwrap();
    assert!(kappa.starts_with("sha256:"));
    assert_eq!(store.blob_get(&kappa).unwrap(), b"hello world");
}

#[test]
fn blob_put_idempotent() {
    let (store, _dir) = test_store();
    let k1 = store.blob_put(b"same").unwrap();
    let k2 = store.blob_put(b"same").unwrap();
    assert_eq!(k1, k2);
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
    let k = store.blob_put(b"exists").unwrap();
    assert!(store.blob_exists(&k).unwrap());
    store.blob_delete(&k).unwrap();
    assert!(!store.blob_exists(&k).unwrap());
}

#[test]
fn blob_get_range() {
    let (store, _dir) = test_store();
    let k = store.blob_put(b"0123456789").unwrap();
    assert_eq!(store.blob_get_range(&k, 3, 4).unwrap(), b"3456");
}

#[test]
fn blob_get_range_past_end() {
    let (store, _dir) = test_store();
    let k = store.blob_put(b"short").unwrap();
    assert_eq!(store.blob_get_range(&k, 3, 100).unwrap(), b"rt");
}

// -- Tag --------------------------------------------------------------------

#[test]
fn tag_set_get() {
    let (store, _dir) = test_store();
    assert_eq!(store.tag_set("ns", "latest", "sha256:aaa").unwrap(), 1);
    let e = store.tag_get("ns", "latest").unwrap();
    assert_eq!(e.name, "latest");
    assert_eq!(e.kappa, "sha256:aaa");
    assert_eq!(e.version, 1);
}

#[test]
fn tag_version_increments() {
    let (store, _dir) = test_store();
    assert_eq!(store.tag_set("ns", "t", "sha256:a").unwrap(), 1);
    assert_eq!(store.tag_set("ns", "t", "sha256:b").unwrap(), 2);
    assert_eq!(store.tag_set("ns", "t", "sha256:c").unwrap(), 3);
}

#[test]
fn tag_delete_and_not_found() {
    let (store, _dir) = test_store();
    store.tag_set("ns", "t", "sha256:a").unwrap();
    store.tag_delete("ns", "t").unwrap();
    assert!(matches!(store.tag_get("ns", "t"), Err(StoreError::NotFound(_))));
}

#[test]
fn tag_list_sorted() {
    let (store, _dir) = test_store();
    store.tag_set("ns", "c", "sha256:c").unwrap();
    store.tag_set("ns", "a", "sha256:a").unwrap();
    store.tag_set("ns", "b", "sha256:b").unwrap();
    let names: Vec<&str> = store.tag_list("ns").unwrap()
        .iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["a", "b", "c"]);
}

#[test]
fn tag_prefix_filters() {
    let (store, _dir) = test_store();
    store.tag_set("ns", "v1.0", "sha256:a").unwrap();
    store.tag_set("ns", "v1.1", "sha256:b").unwrap();
    store.tag_set("ns", "v2.0", "sha256:c").unwrap();
    assert_eq!(store.tag_prefix("ns", "v1.").unwrap().len(), 2);
}

#[test]
fn tag_set_batch_all_or_nothing() {
    let (store, _dir) = test_store();
    store.tag_set("ns", "a", "sha256:1").unwrap();
    let updates = vec![
        TagUpdate { name: "a".into(), kappa: "sha256:2".into(), expected_version: Some(1) },
        TagUpdate { name: "b".into(), kappa: "sha256:3".into(), expected_version: Some(1) },
    ];
    assert!(matches!(store.tag_set_batch("ns", &updates), Err(StoreError::Conflict(_))));
    assert_eq!(store.tag_get("ns", "a").unwrap().kappa, "sha256:1");
}

#[test]
fn tag_set_batch_unconditional() {
    let (store, _dir) = test_store();
    let updates = vec![
        TagUpdate { name: "x".into(), kappa: "sha256:a".into(), expected_version: None },
        TagUpdate { name: "y".into(), kappa: "sha256:b".into(), expected_version: None },
    ];
    store.tag_set_batch("ns", &updates).unwrap();
    assert_eq!(store.tag_get("ns", "x").unwrap().kappa, "sha256:a");
    assert_eq!(store.tag_get("ns", "y").unwrap().kappa, "sha256:b");
}

// -- Edge -------------------------------------------------------------------

#[test]
fn edge_put_query_outbound() {
    let (store, _dir) = test_store();
    let edge = Edge {
        source: "sha256:src".into(), target: "sha256:tgt".into(),
        relation: EdgeRelation::DerivedFrom, asserter: "anchor-1".into(),
        value_kappa: None, metadata: None,
    };
    store.edge_put("ns", &edge).unwrap();
    let results = store.edge_query("ns", &EdgeQuery {
        anchor: "sha256:src".into(), direction: Direction::Outbound,
        relation: None, asserter: None,
    }).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].target, "sha256:tgt");
}

#[test]
fn edge_put_query_inbound() {
    let (store, _dir) = test_store();
    let edge = Edge {
        source: "sha256:src".into(), target: "sha256:tgt".into(),
        relation: EdgeRelation::Assertion, asserter: "anchor-1".into(),
        value_kappa: None, metadata: None,
    };
    store.edge_put("ns", &edge).unwrap();
    let results = store.edge_query("ns", &EdgeQuery {
        anchor: "sha256:tgt".into(), direction: Direction::Inbound,
        relation: None, asserter: None,
    }).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].source, "sha256:src");
}

#[test]
fn edge_query_filters_relation() {
    let (store, _dir) = test_store();
    store.edge_put("ns", &Edge {
        source: "a".into(), target: "b".into(),
        relation: EdgeRelation::Owns, asserter: "x".into(),
        value_kappa: None, metadata: None,
    }).unwrap();
    store.edge_put("ns", &Edge {
        source: "a".into(), target: "c".into(),
        relation: EdgeRelation::DerivedFrom, asserter: "x".into(),
        value_kappa: None, metadata: None,
    }).unwrap();
    let results = store.edge_query("ns", &EdgeQuery {
        anchor: "a".into(), direction: Direction::Outbound,
        relation: Some(EdgeRelation::Owns), asserter: None,
    }).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].relation, EdgeRelation::Owns);
}

#[test]
fn edge_delete_cleans_indexes() {
    let (store, _dir) = test_store();
    let ek = store.edge_put("ns", &Edge {
        source: "s".into(), target: "t".into(),
        relation: EdgeRelation::Owns, asserter: "a".into(),
        value_kappa: None, metadata: None,
    }).unwrap();
    store.edge_delete("ns", &ek).unwrap();
    let results = store.edge_query("ns", &EdgeQuery {
        anchor: "s".into(), direction: Direction::Outbound,
        relation: None, asserter: None,
    }).unwrap();
    assert_eq!(results.len(), 0);
}

// -- Sequence ---------------------------------------------------------------

#[test]
fn sequence_monotonic() {
    let (store, _dir) = test_store();
    assert_eq!(store.sequence_current("ns", "epoch").unwrap(), 0);
    assert_eq!(store.sequence_next("ns", "epoch").unwrap(), 1);
    assert_eq!(store.sequence_next("ns", "epoch").unwrap(), 2);
    assert_eq!(store.sequence_next("ns", "epoch").unwrap(), 3);
    assert_eq!(store.sequence_current("ns", "epoch").unwrap(), 3);
}

#[test]
fn sequence_isolated_by_namespace() {
    let (store, _dir) = test_store();
    store.sequence_next("ns1", "seq").unwrap();
    store.sequence_next("ns1", "seq").unwrap();
    assert_eq!(store.sequence_current("ns1", "seq").unwrap(), 2);
    assert_eq!(store.sequence_current("ns2", "seq").unwrap(), 0);
}

// -- Epoch ------------------------------------------------------------------

#[test]
fn epoch_advance_and_get() {
    let (store, _dir) = test_store();
    let mutations = vec![EpochMutation {
        op: MutationOp::TagSet, namespace: "ns".into(),
        tag_name: "t".into(), old_kappa: None,
        new_kappa: Some("sha256:aaa".into()),
    }];
    let kappa = store.epoch_advance("ns", mutations).unwrap();
    assert!(kappa.starts_with("sha256:"));
    let root = store.epoch_get(&kappa).unwrap();
    assert_eq!(root.namespace, "ns");
    assert_eq!(root.epoch_number, 1);
    assert!(root.prev_root_kappa.is_none());
}

#[test]
fn epoch_chain_links() {
    let (store, _dir) = test_store();
    let k1 = store.epoch_advance("ns", vec![]).unwrap();
    let k2 = store.epoch_advance("ns", vec![]).unwrap();
    let r2 = store.epoch_get(&k2).unwrap();
    assert_eq!(r2.epoch_number, 2);
    assert_eq!(r2.prev_root_kappa, Some(k1));
}

#[test]
fn epoch_current_tracks_latest() {
    let (store, _dir) = test_store();
    assert!(store.epoch_current("ns").unwrap().is_none());
    let k1 = store.epoch_advance("ns", vec![]).unwrap();
    assert_eq!(store.epoch_current("ns").unwrap(), Some(k1));
    let k2 = store.epoch_advance("ns", vec![]).unwrap();
    assert_eq!(store.epoch_current("ns").unwrap(), Some(k2));
}

// -- Namespace --------------------------------------------------------------

#[test]
fn namespace_tracked() {
    let (store, _dir) = test_store();
    assert!(!store.namespace_exists("ns").unwrap());
    store.tag_set("ns", "t", "sha256:a").unwrap();
    assert!(store.namespace_exists("ns").unwrap());
    assert!(store.namespace_list().unwrap().contains(&"ns".to_string()));
}
