//! Identity type conformance: binding fields, succession, handle
//! records, watermark invalidation, revocation reason roundtrip,
//! assertion signable bytes.

use kappa_store::canonical::{canonical_bytes, from_canonical};
use kappa_store::identity::{
    BindingMethod, HandleRecord, IdentityAssertion, IdentityBinding, Revocation, RevocationReason,
    Succession, SuccessionReason, TrustLevel, Watermark, WatermarkReason,
};
use kappa_store::kappa::Kappa;
use kappa_store::namespace::ProtocolId;
use kappa_store::signed::SignedPayload;

use super::support::TestResult;

#[test]
fn binding_fields_preserved() -> TestResult {
    let b = IdentityBinding {
        source: "user@example.com".into(),
        target: Kappa::sha256(b"anchor"),
        method: BindingMethod::HttpChallenge,
        trust_level: TrustLevel::SelfSovereign,
        verified_at_ms: Some(12345),
        metadata: None,
    };
    let json = serde_json::to_vec(&b)?;
    let decoded: IdentityBinding = serde_json::from_slice(&json)?;
    assert_eq!(decoded.source, b.source);
    assert_eq!(decoded.target, b.target);
    assert_eq!(decoded.method, BindingMethod::HttpChallenge);
    assert_eq!(decoded.trust_level, TrustLevel::SelfSovereign);
    assert_eq!(decoded.verified_at_ms, Some(12345));
    Ok(())
}

#[test]
fn succession_reason_variants() {
    assert_eq!(SuccessionReason::Rotation.as_str(), "rotation");
    assert_eq!(SuccessionReason::KeyCompromise.as_str(), "key-compromise");
    assert_eq!(SuccessionReason::Administrative.as_str(), "administrative");
}

#[test]
fn succession_fields() {
    let s = Succession {
        old_anchor: Kappa::sha256(b"old"),
        new_anchor: Kappa::sha256(b"new"),
        reason: SuccessionReason::Rotation,
        effective_at_ms: 5000,
        chain_anchor: None,
        prev_identifier: None,
        old_cose_signature: SignedPayload::from_cose_bytes(vec![1, 2]),
        new_cose_signature: SignedPayload::from_cose_bytes(vec![3, 4]),
    };
    assert_eq!(s.reason, SuccessionReason::Rotation);
    assert_eq!(s.effective_at_ms, 5000);
}

#[test]
fn handle_record_serialization() -> TestResult {
    let r = HandleRecord {
        anchor: Kappa::sha256(b"anchor"),
        handle: "alice.example.com".into(),
        protocol: ProtocolId::new("atproto")?,
        claimed_at_ms: 1000,
        attested_at_ms: Some(2000),
    };
    let json = serde_json::to_vec(&r)?;
    let decoded: HandleRecord = serde_json::from_slice(&json)?;
    assert_eq!(decoded.handle, r.handle);
    assert_eq!(decoded.attested_at_ms, Some(2000));
    Ok(())
}

#[test]
fn watermark_invalidates_below_threshold() {
    let w = Watermark {
        asserter: Kappa::sha256(b"compromised"),
        invalidate_before_ms: 1000,
        reason: WatermarkReason::KeyCompromise,
        set_at_ms: 1001,
        cose_signature: SignedPayload::empty(),
    };
    assert!(w.invalidates(999));
    assert!(!w.invalidates(1000));
    assert!(!w.invalidates(1001));
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
        let decoded: RevocationReason = from_canonical(&bytes)?;
        assert_eq!(decoded, reason);
    }
    Ok(())
}

#[test]
fn assertion_signable_bytes_deterministic() {
    let a = IdentityAssertion {
        asserter: Kappa::sha256(b"asserter"),
        subject: "subject".into(),
        facet: "facet".into(),
        value: b"value".to_vec(),
        basis: "self-asserted".into(),
        valid_from_ms: 1000,
        valid_until_ms: None,
        cose_signature: SignedPayload::empty(),
    };
    let b = IdentityAssertion {
        asserter: Kappa::sha256(b"asserter"),
        subject: "subject".into(),
        facet: "facet".into(),
        value: b"value".to_vec(),
        basis: "self-asserted".into(),
        valid_from_ms: 1000,
        valid_until_ms: None,
        cose_signature: SignedPayload::from_cose_bytes(vec![99]),
    };
    // Signable bytes exclude the signature
    assert_eq!(a.signable_bytes(), b.signable_bytes());
}

#[test]
fn succession_signable_bytes_deterministic() {
    let s = Succession {
        old_anchor: Kappa::sha256(b"old"),
        new_anchor: Kappa::sha256(b"new"),
        reason: SuccessionReason::Rotation,
        effective_at_ms: 5000,
        chain_anchor: None,
        prev_identifier: None,
        old_cose_signature: SignedPayload::empty(),
        new_cose_signature: SignedPayload::empty(),
    };
    let s2 = Succession {
        old_cose_signature: SignedPayload::from_cose_bytes(vec![1]),
        new_cose_signature: SignedPayload::from_cose_bytes(vec![2]),
        ..s.clone()
    };
    assert_eq!(s.signable_bytes(), s2.signable_bytes());
}

#[test]
fn binding_method_parse_roundtrip() {
    for method in [
        BindingMethod::SelfDeclared,
        BindingMethod::DnsChallenge,
        BindingMethod::HttpChallenge,
        BindingMethod::KeyChallenge,
        BindingMethod::Delegation,
        BindingMethod::PeerAttestation,
        BindingMethod::DeviceAttestation,
    ] {
        let parsed = BindingMethod::parse(method.as_str());
        assert_eq!(parsed, Some(method));
    }
}

#[test]
fn watermark_reason_parse_roundtrip() {
    for reason in [
        WatermarkReason::Rotation,
        WatermarkReason::KeyCompromise,
        WatermarkReason::Administrative,
        WatermarkReason::Policy,
    ] {
        let parsed = WatermarkReason::parse(reason.as_str());
        assert_eq!(parsed, Some(reason));
    }
}

#[test]
fn revocation_signable_bytes_exclude_signature() {
    let r = Revocation {
        assertion_kappa: Kappa::sha256(b"assertion"),
        asserter: Kappa::sha256(b"asserter"),
        reason: RevocationReason::Superseded,
        revoked_at_ms: 2000,
        cose_signature: SignedPayload::empty(),
    };
    let r2 = Revocation {
        assertion_kappa: Kappa::sha256(b"assertion"),
        asserter: Kappa::sha256(b"asserter"),
        reason: RevocationReason::Superseded,
        revoked_at_ms: 2000,
        cose_signature: SignedPayload::from_cose_bytes(vec![99]),
    };
    assert_eq!(r.signable_bytes(), r2.signable_bytes());
}

#[test]
fn revocation_fields_preserved() {
    let r = Revocation {
        assertion_kappa: Kappa::sha256(b"target-assertion"),
        asserter: Kappa::sha256(b"revoker"),
        reason: RevocationReason::KeyCompromise,
        revoked_at_ms: 5000,
        cose_signature: SignedPayload::empty(),
    };
    assert_eq!(r.assertion_kappa, Kappa::sha256(b"target-assertion"));
    assert_eq!(r.asserter, Kappa::sha256(b"revoker"));
    assert_eq!(r.revoked_at_ms, 5000);
}
