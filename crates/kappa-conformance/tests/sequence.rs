//! Sequence primitive conformance tests.

use kappa_core::clock::ntp_lamport::NtpLamportClock;
use kappa_core::store::memory::{InMemoryStore, MemoryStoreConfig};
use kappa_core::store::KappaStore;
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
fn starts_at_zero() {
    let (s, _d) = new_store();
    assert_eq!(s.sequence_current("ns", "seq").unwrap(), 0);
}

#[test]
fn next_increments() {
    let (s, _d) = new_store();
    assert_eq!(s.sequence_next("ns", "seq").unwrap(), 1);
    assert_eq!(s.sequence_next("ns", "seq").unwrap(), 2);
    assert_eq!(s.sequence_next("ns", "seq").unwrap(), 3);
}

#[test]
fn current_returns_last_value() {
    let (s, _d) = new_store();
    s.sequence_next("ns", "seq").unwrap();
    s.sequence_next("ns", "seq").unwrap();
    assert_eq!(s.sequence_current("ns", "seq").unwrap(), 2);
}

#[test]
fn namespaces_independent() {
    let (s, _d) = new_store();
    s.sequence_next("ns1", "seq").unwrap();
    s.sequence_next("ns1", "seq").unwrap();
    assert_eq!(s.sequence_current("ns1", "seq").unwrap(), 2);
    assert_eq!(s.sequence_current("ns2", "seq").unwrap(), 0);
}

#[test]
fn names_independent() {
    let (s, _d) = new_store();
    s.sequence_next("ns", "a").unwrap();
    s.sequence_next("ns", "a").unwrap();
    s.sequence_next("ns", "b").unwrap();
    assert_eq!(s.sequence_current("ns", "a").unwrap(), 2);
    assert_eq!(s.sequence_current("ns", "b").unwrap(), 1);
}
