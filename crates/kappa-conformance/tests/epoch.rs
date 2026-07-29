//! Epoch primitive conformance tests.

use kappa_core::clock::ntp_lamport::NtpLamportClock;
use kappa_core::store::memory::{InMemoryStore, MemoryStoreConfig};
use kappa_core::store::KappaStore;
use kappa_core::types::{EpochMutation, MutationOp};
use std::sync::Arc;

fn new_store() -> (InMemoryStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(NtpLamportClock::new());
    let store = InMemoryStore::new(
        MemoryStoreConfig {
            blob_root: dir.path().join("blobs"),
        },
        clock,
    )
    .unwrap();
    (store, dir)
}

#[test]
fn advance_returns_kappa() {
    let (s, _d) = new_store();
    let k = s.epoch_advance("ns", vec![]).unwrap();
    assert!(k.starts_with("sha256:"));
}

#[test]
fn get_returns_epoch_root() {
    let (s, _d) = new_store();
    let k = s
        .epoch_advance(
            "ns",
            vec![EpochMutation {
                op: MutationOp::TagSet,
                namespace: "ns".into(),
                tag_name: "t".into(),
                old_kappa: None,
                new_kappa: Some("sha256:aaa".into()),
            }],
        )
        .unwrap();
    let root = s.epoch_get(&k).unwrap();
    assert_eq!(root.namespace, "ns");
    assert_eq!(root.epoch_number, 1);
}

#[test]
fn chain_links() {
    let (s, _d) = new_store();
    let k1 = s.epoch_advance("ns", vec![]).unwrap();
    let k2 = s.epoch_advance("ns", vec![]).unwrap();
    let r2 = s.epoch_get(&k2).unwrap();
    assert_eq!(r2.epoch_number, 2);
    assert_eq!(r2.prev_root_kappa, Some(k1));
}

#[test]
fn current_tracks_latest() {
    let (s, _d) = new_store();
    assert!(s.epoch_current("ns").unwrap().is_none());
    let k1 = s.epoch_advance("ns", vec![]).unwrap();
    assert_eq!(s.epoch_current("ns").unwrap(), Some(k1));
    let k2 = s.epoch_advance("ns", vec![]).unwrap();
    assert_eq!(s.epoch_current("ns").unwrap(), Some(k2));
}

#[test]
fn origin_has_no_prev() {
    let (s, _d) = new_store();
    let k = s.epoch_advance("ns", vec![]).unwrap();
    let root = s.epoch_get(&k).unwrap();
    assert!(root.prev_root_kappa.is_none());
}

#[test]
fn selective_disclosure() {
    let (s, _d) = new_store();
    let k = s.epoch_advance("ns", vec![]).unwrap();
    let root = s.epoch_get(&k).unwrap();
    let proof = root.proof_for_leaf(0).unwrap();
    let ns_leaf = kappa_core::canonical::canonical_bytes(&"ns".to_string());
    assert!(root.verify_leaf(&ns_leaf, &proof));
}

#[test]
fn selective_disclosure_rejects_wrong() {
    let (s, _d) = new_store();
    let k = s.epoch_advance("ns", vec![]).unwrap();
    let root = s.epoch_get(&k).unwrap();
    let proof = root.proof_for_leaf(0).unwrap();
    let wrong = kappa_core::canonical::canonical_bytes(&"wrong".to_string());
    assert!(!root.verify_leaf(&wrong, &proof));
}
