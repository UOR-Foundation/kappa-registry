//! Kappa-label computation conformance tests.

use kappa_core::kappa::{kappa_from_bytes, kappa_from_value, split_kappa, verify_kappa};

#[test]
fn blob_kappa_is_sha256() {
    let k = kappa_from_bytes(b"hello world");
    assert!(k.starts_with("sha256:"));
    assert_eq!(
        k,
        "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
}

#[test]
fn value_kappa_is_deterministic() {
    let k1 = kappa_from_value(&"test".to_string());
    let k2 = kappa_from_value(&"test".to_string());
    assert_eq!(k1, k2);
}

#[test]
fn different_content_different_kappa() {
    assert_ne!(kappa_from_bytes(b"a"), kappa_from_bytes(b"b"));
}

#[test]
fn verify_succeeds_on_match() {
    let data = b"verify me";
    let k = kappa_from_bytes(data);
    assert_eq!(verify_kappa(&k, data), Ok(true));
}

#[test]
fn verify_fails_on_mismatch() {
    let k = kappa_from_bytes(b"original");
    assert_eq!(verify_kappa(&k, b"different"), Ok(false));
}

#[test]
fn split_parses() {
    let (algo, digest) = split_kappa("sha256:abcdef").unwrap();
    assert_eq!(algo, "sha256");
    assert_eq!(digest, "abcdef");
}

#[test]
fn split_rejects_no_colon() {
    assert!(split_kappa("nocolon").is_none());
}

#[test]
fn split_rejects_empty_parts() {
    assert!(split_kappa(":abc").is_none());
    assert!(split_kappa("sha256:").is_none());
}
