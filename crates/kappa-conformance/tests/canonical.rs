//! Canonical serialization conformance tests.

use dcbor::prelude::*;
use kappa_core::canonical::{canonical_bytes, from_canonical};

#[test]
fn integer_roundtrip() {
    let bytes = canonical_bytes(&42u64);
    let decoded: u64 = from_canonical(&bytes).unwrap();
    assert_eq!(decoded, 42);
}

#[test]
fn string_roundtrip() {
    let bytes = canonical_bytes(&"hello".to_string());
    let decoded: String = from_canonical(&bytes).unwrap();
    assert_eq!(decoded, "hello");
}

#[test]
fn deterministic() {
    let a = canonical_bytes(&"same".to_string());
    let b = canonical_bytes(&"same".to_string());
    assert_eq!(a, b);
}

#[test]
fn different_values_different_bytes() {
    let a = canonical_bytes(&"one".to_string());
    let b = canonical_bytes(&"two".to_string());
    assert_ne!(a, b);
}

#[test]
fn rejects_non_canonical_integer() {
    // 0x1900ff encodes 255 in 3 bytes; canonical is 0x18ff (2 bytes)
    let non_canonical: &[u8] = &[0x19, 0x00, 0xff];
    assert!(CBOR::try_from_data(non_canonical).is_err());
}

#[test]
fn rejects_empty_input() {
    let result: Result<u64, _> = from_canonical(&[]);
    assert!(result.is_err());
}

#[test]
fn tag_entry_roundtrip() {
    use kappa_core::types::TagEntry;
    let entry = TagEntry {
        name: "v1".into(),
        kappa: "sha256:abc".into(),
        version: 3,
    };
    let bytes = canonical_bytes(&entry);
    let decoded: TagEntry = from_canonical(&bytes).unwrap();
    assert_eq!(decoded, entry);
}

#[test]
fn tag_entry_deterministic() {
    use kappa_core::types::TagEntry;
    let e1 = TagEntry {
        name: "t".into(),
        kappa: "k".into(),
        version: 1,
    };
    let e2 = TagEntry {
        name: "t".into(),
        kappa: "k".into(),
        version: 1,
    };
    assert_eq!(canonical_bytes(&e1), canonical_bytes(&e2));
}
