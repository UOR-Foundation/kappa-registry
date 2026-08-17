//! Tag primitive conformance tests.

use kappa_core::clock::ntp_lamport::NtpLamportClock;
use kappa_core::store::memory::{InMemoryStore, MemoryStoreConfig};
use kappa_core::store::KappaStore;
use kappa_core::types::{NamespaceRef, StoreError, TagUpdate};
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
fn set_get_roundtrip() {
    let (s, _d) = new_store();
    let ns = NamespaceRef::deterministic("ns");
    let v = s.tag_set(&ns, "latest", "sha256:aaa").unwrap();
    assert_eq!(v, 1);
    let entry = s.tag_get(&ns, "latest").unwrap();
    assert_eq!(entry.name, "latest");
    assert_eq!(entry.kappa, "sha256:aaa");
    assert_eq!(entry.version, 1);
}

#[test]
fn version_increments() {
    let (s, _d) = new_store();
    let ns = NamespaceRef::deterministic("ns");
    assert_eq!(s.tag_set(&ns, "t", "k1").unwrap(), 1);
    assert_eq!(s.tag_set(&ns, "t", "k2").unwrap(), 2);
    assert_eq!(s.tag_set(&ns, "t", "k3").unwrap(), 3);
}

#[test]
fn delete_then_not_found() {
    let (s, _d) = new_store();
    let ns = NamespaceRef::deterministic("ns");
    s.tag_set(&ns, "t", "k").unwrap();
    s.tag_delete(&ns, "t").unwrap();
    assert!(matches!(s.tag_get(&ns, "t"), Err(StoreError::NotFound(_))));
}

#[test]
fn list_returns_sorted() {
    let (s, _d) = new_store();
    let ns = NamespaceRef::deterministic("ns");
    s.tag_set(&ns, "c", "k3").unwrap();
    s.tag_set(&ns, "a", "k1").unwrap();
    s.tag_set(&ns, "b", "k2").unwrap();
    let list = s.tag_list(&ns).unwrap();
    let names: Vec<&str> = list.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["a", "b", "c"]);
}

#[test]
fn prefix_filters() {
    let (s, _d) = new_store();
    let ns = NamespaceRef::deterministic("ns");
    s.tag_set(&ns, "v1.0", "k1").unwrap();
    s.tag_set(&ns, "v1.1", "k2").unwrap();
    s.tag_set(&ns, "v2.0", "k3").unwrap();
    let result = s.tag_prefix(&ns, "v1.").unwrap();
    assert_eq!(result.len(), 2);
}

#[test]
fn batch_all_or_nothing_on_conflict() {
    let (s, _d) = new_store();
    let ns = NamespaceRef::deterministic("ns");
    s.tag_set(&ns, "a", "k1").unwrap();
    let updates = vec![
        TagUpdate {
            name: "a".into(),
            kappa: "k2".into(),
            expected_version: Some(1),
        },
        TagUpdate {
            name: "b".into(),
            kappa: "k3".into(),
            expected_version: Some(1),
        },
    ];
    assert!(matches!(
        s.tag_set_batch(&ns, &updates),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(s.tag_get(&ns, "a").unwrap().kappa, "k1");
}

#[test]
fn batch_unconditional_succeeds() {
    let (s, _d) = new_store();
    let ns = NamespaceRef::deterministic("ns");
    let updates = vec![
        TagUpdate {
            name: "x".into(),
            kappa: "kx".into(),
            expected_version: None,
        },
        TagUpdate {
            name: "y".into(),
            kappa: "ky".into(),
            expected_version: None,
        },
    ];
    s.tag_set_batch(&ns, &updates).unwrap();
    assert_eq!(s.tag_get(&ns, "x").unwrap().kappa, "kx");
    assert_eq!(s.tag_get(&ns, "y").unwrap().kappa, "ky");
}

#[test]
fn batch_create_if_absent() {
    let (s, _d) = new_store();
    let ns = NamespaceRef::deterministic("ns");
    let updates = vec![TagUpdate {
        name: "new".into(),
        kappa: "kn".into(),
        expected_version: Some(0),
    }];
    s.tag_set_batch(&ns, &updates).unwrap();
    assert_eq!(s.tag_get(&ns, "new").unwrap().version, 1);
}

#[test]
fn namespaces_isolated() {
    let (s, _d) = new_store();
    let ns1 = NamespaceRef::deterministic("ns1");
    let ns2 = NamespaceRef::deterministic("ns2");
    s.tag_set(&ns1, "t", "k1").unwrap();
    s.tag_set(&ns2, "t", "k2").unwrap();
    assert_eq!(s.tag_get(&ns1, "t").unwrap().kappa, "k1");
    assert_eq!(s.tag_get(&ns2, "t").unwrap().kappa, "k2");
}
