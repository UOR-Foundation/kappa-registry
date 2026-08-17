//! Blob primitive conformance tests.

use kappa_core::clock::ntp_lamport::NtpLamportClock;
use kappa_core::kappa::kappa_from_bytes;
use kappa_core::store::memory::{InMemoryStore, MemoryStoreConfig};
use kappa_core::store::{blob_put_computed, KappaStore};
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
fn put_get_roundtrip() {
    let (s, _d) = new_store();
    let k = kappa_from_bytes(b"hello");
    assert!(s.ingest_verified(&k,b"hello").unwrap().newly_stored);
    assert!(k.starts_with("sha256:"));
    assert_eq!(s.blob_get(&k).unwrap(), b"hello");
}

#[test]
fn content_addressed_identity() {
    let (s, _d) = new_store();
    let k = kappa_from_bytes(b"same");
    assert!(s.ingest_verified(&k,b"same").unwrap().newly_stored);
    assert!(!s.ingest_verified(&k,b"same").unwrap().newly_stored);
}

#[test]
fn different_content_different_kappa() {
    let (s, _d) = new_store();
    let k1 = kappa_from_bytes(b"aaa");
    let k2 = kappa_from_bytes(b"bbb");
    s.ingest_verified(&k1,b"aaa").unwrap();
    s.ingest_verified(&k2,b"bbb").unwrap();
    assert_ne!(k1, k2);
}

#[test]
fn exists_after_put() {
    let (s, _d) = new_store();
    let k = kappa_from_bytes(b"exists");
    s.ingest_verified(&k,b"exists").unwrap();
    assert!(s.blob_exists(&k).unwrap());
}

#[test]
fn not_exists_before_put() {
    let (s, _d) = new_store();
    let fake = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    assert!(!s.blob_exists(fake).unwrap());
}

#[test]
fn delete_removes_blob() {
    let (s, _d) = new_store();
    let k = kappa_from_bytes(b"delete me");
    s.ingest_verified(&k,b"delete me").unwrap();
    s.blob_delete(&k).unwrap();
    assert!(!s.blob_exists(&k).unwrap());
}

#[test]
fn get_after_delete_fails() {
    let (s, _d) = new_store();
    let k = kappa_from_bytes(b"gone");
    s.ingest_verified(&k,b"gone").unwrap();
    s.blob_delete(&k).unwrap();
    assert!(s.blob_get(&k).is_err());
}

#[test]
fn size_matches_content() {
    let (s, _d) = new_store();
    let data = b"twelve bytes";
    let k = kappa_from_bytes(data);
    s.ingest_verified(&k,data).unwrap();
    assert_eq!(s.blob_size(&k).unwrap(), data.len() as u64);
}

#[test]
fn get_range_middle() {
    let (s, _d) = new_store();
    let k = kappa_from_bytes(b"0123456789");
    s.ingest_verified(&k,b"0123456789").unwrap();
    assert_eq!(s.blob_get_range(&k, 3, 4).unwrap(), b"3456");
}

#[test]
fn get_range_past_end_truncates() {
    let (s, _d) = new_store();
    let k = kappa_from_bytes(b"short");
    s.ingest_verified(&k,b"short").unwrap();
    assert_eq!(s.blob_get_range(&k, 3, 100).unwrap(), b"rt");
}

#[test]
fn get_range_at_end_returns_empty() {
    let (s, _d) = new_store();
    let k = kappa_from_bytes(b"end");
    s.ingest_verified(&k,b"end").unwrap();
    assert!(s.blob_get_range(&k, 100, 10).unwrap().is_empty());
}

#[test]
fn empty_blob() {
    let (s, _d) = new_store();
    let k = kappa_from_bytes(b"");
    s.ingest_verified(&k,b"").unwrap();
    assert_eq!(s.blob_get(&k).unwrap(), b"");
    assert_eq!(s.blob_size(&k).unwrap(), 0);
}

#[test]
fn blob_put_computed_convenience() {
    let (s, _d) = new_store();
    let k = blob_put_computed(&s, b"convenience").unwrap();
    assert!(k.starts_with("sha256:"));
    assert_eq!(s.blob_get(&k).unwrap(), b"convenience");
}

#[test]
fn blob_meta_roundtrip() {
    let (s, _d) = new_store();
    let k = kappa_from_bytes(b"meta");
    s.ingest_verified(&k,b"meta").unwrap();
    s.blob_put_meta(&k, "content-type", b"text/plain").unwrap();
    assert_eq!(s.blob_get_meta(&k, "content-type").unwrap(), b"text/plain");
}

#[test]
fn blob_meta_not_found() {
    let (s, _d) = new_store();
    let k = kappa_from_bytes(b"no meta");
    s.ingest_verified(&k,b"no meta").unwrap();
    assert!(s.blob_get_meta(&k, "missing").is_err());
}

#[test]
fn blob_meta_delete() {
    let (s, _d) = new_store();
    let k = kappa_from_bytes(b"del meta");
    s.ingest_verified(&k,b"del meta").unwrap();
    s.blob_put_meta(&k, "key", b"val").unwrap();
    s.blob_delete_meta(&k, "key").unwrap();
    assert!(s.blob_get_meta(&k, "key").is_err());
}

#[test]
fn sha512_blob_first_class() {
    let (s, _d) = new_store();
    let data = b"sha512 is a first class citizen";
    let k = kappa_core::kappa::KappaLabel::sha512(data);
    let kappa = k.as_str();
    s.ingest_verified(kappa,data).unwrap();
    assert_eq!(s.blob_get(kappa).unwrap(), data);
    assert!(s.blob_exists(kappa).unwrap());
    assert_eq!(s.blob_size(kappa).unwrap(), data.len() as u64);
    s.blob_delete(kappa).unwrap();
    assert!(!s.blob_exists(kappa).unwrap());
}

#[test]
fn blake3_blob_first_class() {
    let (s, _d) = new_store();
    let data = b"blake3 is a first class citizen";
    let k = kappa_core::kappa::KappaLabel::blake3(data);
    let kappa = k.as_str();
    s.ingest_verified(kappa,data).unwrap();
    assert_eq!(s.blob_get(kappa).unwrap(), data);
    assert!(s.blob_exists(kappa).unwrap());
    s.blob_delete(kappa).unwrap();
    assert!(!s.blob_exists(kappa).unwrap());
}
