//! VerifiedContent conformance: construction is sealed, verification
//! catches mismatches, all axes produce valid proofs, owned and
//! borrowed paths agree.

use kappa_store::axis::Axis;
use kappa_store::kappa::{Kappa, KappaParseError};
use kappa_store::verified::VerifiedContent;

use super::support::TestResult;

#[test]
fn verify_succeeds_on_correct_digest() -> TestResult {
    let k = Kappa::sha256(b"correct");
    let v = VerifiedContent::verify(&k, b"correct")?;
    assert_eq!(*v.kappa(), k);
    Ok(())
}

#[test]
fn verify_rejects_wrong_content() {
    let k = Kappa::sha256(b"expected");
    let result = VerifiedContent::verify(&k, b"different");
    assert!(
        matches!(result, Err(KappaParseError::DigestMismatch { .. })),
        "expected DigestMismatch"
    );
}

#[test]
fn compute_produces_valid_proof() -> TestResult {
    let v = VerifiedContent::compute(Axis::Sha256, b"computed")?;
    assert!(v.kappa().to_string().starts_with("sha256:"));
    let recheck = VerifiedContent::verify(v.kappa(), b"computed");
    assert!(recheck.is_ok());
    Ok(())
}

#[test]
fn into_parts_consumes_proof() -> TestResult {
    let v = VerifiedContent::compute(Axis::Sha256, b"consume")?;
    let expected = v.kappa().clone();
    let (k, data) = v.into_parts();
    assert_eq!(k, expected);
    assert_eq!(data, b"consume");
    Ok(())
}

#[test]
fn compute_blake3() -> TestResult {
    let v = VerifiedContent::compute(Axis::Blake3, b"blake3")?;
    assert!(v.kappa().to_string().starts_with("blake3:"));
    Ok(())
}

#[test]
fn compute_sha512() -> TestResult {
    let v = VerifiedContent::compute(Axis::Sha512, b"sha512")?;
    assert!(v.kappa().to_string().starts_with("sha512:"));
    Ok(())
}

#[test]
fn compute_sha1() -> TestResult {
    let v = VerifiedContent::compute(Axis::Sha1, b"sha1")?;
    assert!(v.kappa().to_string().starts_with("sha1:"));
    Ok(())
}

#[test]
fn compute_sha3_256() -> TestResult {
    let v = VerifiedContent::compute(Axis::Sha3_256, b"sha3")?;
    assert!(v.kappa().to_string().starts_with("sha3-256:"));
    Ok(())
}

#[test]
fn compute_keccak256() -> TestResult {
    let v = VerifiedContent::compute(Axis::Keccak256, b"keccak")?;
    assert!(v.kappa().to_string().starts_with("keccak256:"));
    Ok(())
}

#[test]
fn verify_all_six_axes() -> TestResult {
    let data = b"all axes";
    for axis in [
        Axis::Sha256,
        Axis::Sha512,
        Axis::Blake3,
        Axis::Sha1,
        Axis::Sha3_256,
        Axis::Keccak256,
    ] {
        let v = VerifiedContent::compute(axis, data)?;
        let recheck = VerifiedContent::verify(v.kappa(), data);
        assert!(recheck.is_ok(), "axis {axis:?} failed roundtrip");
    }
    Ok(())
}

#[test]
fn empty_content() -> TestResult {
    let v = VerifiedContent::compute(Axis::Sha256, b"")?;
    assert!(v.is_empty());
    assert_eq!(v.len(), 0);
    let recheck = VerifiedContent::verify(v.kappa(), b"");
    assert!(recheck.is_ok());
    Ok(())
}

#[test]
fn large_content() -> TestResult {
    let data = vec![0xABu8; 1024 * 1024];
    let v = VerifiedContent::compute(Axis::Sha256, &data)?;
    let recheck = VerifiedContent::verify(v.kappa(), &data);
    assert!(recheck.is_ok());
    Ok(())
}

#[test]
fn malformed_kappa_rejected() -> TestResult {
    let bad =
        Kappa::parse("sha256:0000000000000000000000000000000000000000000000000000000000000000")?;
    let result = VerifiedContent::verify(&bad, b"not zeros");
    assert!(matches!(
        result,
        Err(KappaParseError::DigestMismatch { .. })
    ));
    Ok(())
}

#[test]
fn compute_owned_matches_borrowed() -> TestResult {
    let data = b"owned vs borrowed";
    let borrowed = VerifiedContent::compute(Axis::Sha256, data)?;
    let owned = VerifiedContent::compute_owned(Axis::Sha256, data.to_vec())?;
    assert_eq!(*borrowed.kappa(), *owned.kappa());
    assert_eq!(borrowed.content(), owned.content());
    Ok(())
}

#[test]
fn verify_str_roundtrip() -> TestResult {
    let kappa = Kappa::sha256(b"str verify");
    let wire = kappa.to_string();
    let vc = VerifiedContent::verify_str(&wire, b"str verify")?;
    assert_eq!(*vc.kappa(), kappa);
    Ok(())
}
