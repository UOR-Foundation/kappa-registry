//! PERF-IDN-007: Revocation decode failure fails closed (INV-3).
//! Malformed revocation bytes must not be admitted. Tampered
//! fields must not verify. A revoked assertion must not resolve.

use kappa_crypto::Signer;
use kappa_crypto::ed25519::Ed25519Signer;
use kappa_crypto::signed_types::{admit_revocation, sign_revocation};
use kappa_types::canonical::{canonical_bytes, from_canonical};
use kappa_types::identity::{Revocation, RevocationReason};
use kappa_types::kappa::Kappa;
use kappa_types::signed::SignedPayload;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn test_signer() -> Result<Ed25519Signer, Box<dyn std::error::Error>> {
    Ok(Ed25519Signer::from_bytes(&[42; 32])?)
}

fn test_anchor(s: &Ed25519Signer) -> Result<Kappa, kappa_types::KappaParseError> {
    Kappa::from_key(s.algorithm(), s.public_key())
}

fn make_revocation(s: &Ed25519Signer) -> Result<Revocation, Box<dyn std::error::Error>> {
    let record = Revocation {
        assertion_kappa: Kappa::sha256(b"assertion-to-revoke"),
        asserter: test_anchor(s)?,
        reason: RevocationReason::KeyCompromise,
        revoked_at_ms: 2000,
        cose_signature: SignedPayload::empty(),
    };
    Ok(sign_revocation(record, s)?)
}

#[test]
fn valid_revocation_admits() -> TestResult {
    let s = test_signer()?;
    let signed = make_revocation(&s)?;
    let verified = admit_revocation(signed, s.public_key())?;
    assert_eq!(verified.get().reason, RevocationReason::KeyCompromise);
    Ok(())
}

#[test]
fn wrong_key_rejected() -> TestResult {
    let s = test_signer()?;
    let signed = make_revocation(&s)?;
    let wrong = Ed25519Signer::from_bytes(&[99; 32])?;
    assert!(
        admit_revocation(signed, wrong.public_key()).is_err(),
        "wrong key must reject"
    );
    Ok(())
}

#[test]
fn tampered_assertion_kappa_rejected() -> TestResult {
    let s = test_signer()?;
    let mut signed = make_revocation(&s)?;
    signed.assertion_kappa = Kappa::sha256(b"different-assertion");
    assert!(
        admit_revocation(signed, s.public_key()).is_err(),
        "tampered assertion_kappa must reject"
    );
    Ok(())
}

#[test]
fn tampered_reason_rejected() -> TestResult {
    let s = test_signer()?;
    let mut signed = make_revocation(&s)?;
    signed.reason = RevocationReason::Superseded;
    assert!(
        admit_revocation(signed, s.public_key()).is_err(),
        "tampered reason must reject"
    );
    Ok(())
}

#[test]
fn tampered_revoked_at_rejected() -> TestResult {
    let s = test_signer()?;
    let mut signed = make_revocation(&s)?;
    signed.revoked_at_ms = 9999;
    assert!(
        admit_revocation(signed, s.public_key()).is_err(),
        "tampered revoked_at must reject"
    );
    Ok(())
}

#[test]
fn truncated_cose_rejected() -> TestResult {
    let s = test_signer()?;
    let mut signed = make_revocation(&s)?;
    let half = signed.cose_signature.as_bytes().len() / 2;
    signed.cose_signature =
        SignedPayload::from_cose_bytes(signed.cose_signature.as_bytes()[..half].to_vec());
    assert!(
        admit_revocation(signed, s.public_key()).is_err(),
        "truncated COSE signature must reject"
    );
    Ok(())
}

#[test]
fn malformed_cbor_fails_decode() {
    let garbage = vec![0xFF, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
    let result = from_canonical::<Revocation>(&garbage);
    assert!(result.is_err(), "malformed CBOR must not decode");
}

#[test]
fn revocation_reason_roundtrip() -> TestResult {
    for reason in [
        RevocationReason::KeyCompromise,
        RevocationReason::Superseded,
        RevocationReason::Erroneous,
        RevocationReason::PrivilegeWithdrawn,
        RevocationReason::CessationOfOperation,
    ] {
        let bytes = canonical_bytes(&reason);
        let recovered: RevocationReason = from_canonical(&bytes)?;
        assert_eq!(recovered, reason, "reason {reason:?} roundtrip failed");
    }
    Ok(())
}

#[test]
fn empty_signature_rejected() -> TestResult {
    let s = test_signer()?;
    let record = Revocation {
        assertion_kappa: Kappa::sha256(b"target"),
        asserter: test_anchor(&s)?,
        reason: RevocationReason::KeyCompromise,
        revoked_at_ms: 1000,
        cose_signature: SignedPayload::empty(),
    };
    assert!(
        admit_revocation(record, s.public_key()).is_err(),
        "unsigned revocation must not admit"
    );
    Ok(())
}
