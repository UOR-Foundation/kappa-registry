//! Kappa label conformance: construction, parsing, verification,
//! complement, multi-axis, wire format.

use kappa_store::axis::Axis;
use kappa_store::kappa::{
    Kappa, KappaParseError, kappa_from_bytes, kappa_from_value, verify_kappa,
};

use super::support::TestResult;

#[test]
fn blob_kappa_is_sha256() {
    let k = kappa_from_bytes(b"hello world");
    assert_eq!(
        k.to_string(),
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
fn verify_succeeds_on_match() -> TestResult {
    let data = b"verify me";
    let k = kappa_from_bytes(data);
    assert!(verify_kappa(&k.to_string(), data)?);
    Ok(())
}

#[test]
fn verify_fails_on_mismatch() -> TestResult {
    let k = kappa_from_bytes(b"original");
    assert!(!verify_kappa(&k.to_string(), b"different")?);
    Ok(())
}

#[test]
fn parse_valid_sha256() -> TestResult {
    let k =
        Kappa::parse("sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")?;
    assert_eq!(k.axis(), Axis::Sha256);
    Ok(())
}

#[test]
fn parse_rejects_no_colon() {
    assert!(matches!(
        Kappa::parse("nocolon"),
        Err(KappaParseError::NoColon(_))
    ));
}

#[test]
fn parse_rejects_unknown_algorithm() {
    assert!(matches!(
        Kappa::parse("md5:d41d8cd98f00b204e9800998ecf8427e"),
        Err(KappaParseError::UnknownAxis(_))
    ));
}

#[test]
fn parse_rejects_uppercase_hex() {
    let upper = "sha256:B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9";
    assert!(Kappa::parse(upper).is_err());
}

#[test]
fn parse_rejects_wrong_length() {
    assert!(matches!(
        Kappa::parse("sha256:abcd"),
        Err(KappaParseError::WrongDigitCount { .. })
    ));
}

#[test]
fn complement_roundtrip() {
    let k = Kappa::sha256(b"complement test");
    let comp = k.complement();
    let double = comp.complement();
    assert_eq!(k, double);
    assert_ne!(k, comp);
}

#[test]
fn sha512_label_length() {
    let k = Kappa::sha512(b"sha512");
    assert_eq!(k.to_string().len(), 135);
    assert!(k.to_string().starts_with("sha512:"));
}

#[test]
fn blake3_compute() {
    let k = Kappa::blake3(b"blake3 test");
    let s = k.to_string();
    assert!(s.starts_with("blake3:"));
    assert_eq!(s.len(), 71);
}

#[test]
fn sha1_compute() -> TestResult {
    let k = Kappa::sha1(b"sha1 test")?;
    let s = k.to_string();
    assert!(s.starts_with("sha1:"));
    assert_eq!(s.len(), 45);
    Ok(())
}

#[test]
fn sha3_256_compute() {
    let k = Kappa::sha3_256(b"sha3 test");
    assert!(k.to_string().starts_with("sha3-256:"));
}

#[test]
fn keccak256_compute() {
    let k = Kappa::keccak256(b"keccak test");
    assert!(k.to_string().starts_with("keccak256:"));
}

#[test]
fn all_axes_verify() -> TestResult {
    let data = b"verify all axes";
    for axis in [
        Axis::Sha256,
        Axis::Blake3,
        Axis::Sha512,
        Axis::Sha1,
        Axis::Sha3_256,
        Axis::Keccak256,
    ] {
        let k = Kappa::compute(axis, data)?;
        assert!(k.verify(data)?, "verify failed for {axis}");
    }
    Ok(())
}

#[test]
fn sha256_known_empty_hash() {
    let k = Kappa::sha256(b"");
    assert_eq!(
        k.to_string(),
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn axis_enum_roundtrip() {
    let k = Kappa::blake3(b"axis");
    assert_eq!(k.axis(), Axis::Blake3);
    let k2 = Kappa::sha512(b"axis");
    assert_eq!(k2.axis(), Axis::Sha512);
}
