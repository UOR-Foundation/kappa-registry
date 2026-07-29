//! Identity type conformance tests.

use kappa_core::canonical::{canonical_bytes, from_canonical};
use kappa_core::identity::assertion::IdentityAssertion;
use kappa_core::identity::resolution;
use kappa_core::identity::revocation::{Revocation, RevocationReason};
use kappa_core::identity::trust::TrustPosition;
use kappa_core::identity::watermark::Watermark;

#[test]
fn assertion_roundtrip() {
    let a = IdentityAssertion {
        asserter: "anchor-1".into(),
        subject: "anchor-2".into(),
        facet: "node/version".into(),
        value: b"1.0.0".to_vec(),
        basis: "self-asserted".into(),
        valid_from_ms: 1000,
        valid_until_ms: None,
        signature: vec![1, 2, 3],
    };
    let bytes = canonical_bytes(&a);
    let decoded: IdentityAssertion = from_canonical(&bytes).unwrap();
    assert_eq!(decoded.asserter, a.asserter);
    assert_eq!(decoded.facet, a.facet);
    assert_eq!(decoded.value, a.value);
}

#[test]
fn signable_bytes_exclude_signature() {
    let a1 = IdentityAssertion {
        asserter: "a".into(),
        subject: "s".into(),
        facet: "f".into(),
        value: vec![],
        basis: "self-asserted".into(),
        valid_from_ms: 0,
        valid_until_ms: None,
        signature: vec![1, 2, 3],
    };
    let a2 = IdentityAssertion {
        asserter: "a".into(),
        subject: "s".into(),
        facet: "f".into(),
        value: vec![],
        basis: "self-asserted".into(),
        valid_from_ms: 0,
        valid_until_ms: None,
        signature: vec![99, 99],
    };
    assert_eq!(a1.signable_bytes(), a2.signable_bytes());
}

#[test]
fn revocation_roundtrip() {
    let r = Revocation {
        asserter: "a".into(),
        assertion_kappa: "sha256:abc".into(),
        reason: RevocationReason::KeyCompromise,
        revoked_at_ms: 5000,
        signature: vec![9, 8, 7],
    };
    let bytes = canonical_bytes(&r);
    let decoded: Revocation = from_canonical(&bytes).unwrap();
    assert_eq!(decoded.reason, r.reason);
}

#[test]
fn revocation_reasons_roundtrip() {
    for reason in [
        RevocationReason::KeyCompromise,
        RevocationReason::Superseded,
        RevocationReason::Erroneous,
        RevocationReason::PrivilegeWithdrawn,
        RevocationReason::CessationOfOperation,
    ] {
        let bytes = canonical_bytes(&reason);
        let decoded: RevocationReason = from_canonical(&bytes).unwrap();
        assert_eq!(decoded, reason);
    }
}

#[test]
fn watermark_invalidates() {
    let w = Watermark {
        asserter: "a".into(),
        invalidate_before_ms: 1000,
        reason: "key compromise".into(),
        set_at_ms: 1001,
    };
    assert!(w.invalidates(999));
    assert!(!w.invalidates(1000));
    assert!(!w.invalidates(1001));
}

#[test]
fn resolve_filters_by_time() {
    let assertions = vec![
        IdentityAssertion {
            asserter: "a".into(),
            subject: "s".into(),
            facet: "f1".into(),
            value: vec![],
            basis: "self-asserted".into(),
            valid_from_ms: 100,
            valid_until_ms: Some(200),
            signature: vec![],
        },
        IdentityAssertion {
            asserter: "a".into(),
            subject: "s".into(),
            facet: "f2".into(),
            value: vec![],
            basis: "self-asserted".into(),
            valid_from_ms: 300,
            valid_until_ms: None,
            signature: vec![],
        },
    ];
    let result = resolution::resolve_at(&assertions, &[], &[], 150);
    assert_eq!(result.valid.len(), 1);
    assert_eq!(result.valid[0].facet, "f1");
}

#[test]
fn resolve_excludes_revoked() {
    let assertion = IdentityAssertion {
        asserter: "a".into(),
        subject: "s".into(),
        facet: "f".into(),
        value: vec![],
        basis: "self-asserted".into(),
        valid_from_ms: 100,
        valid_until_ms: None,
        signature: vec![],
    };
    let assertion_kappa = kappa_core::kappa::kappa_from_bytes(&canonical_bytes(&assertion));
    let revocation = Revocation {
        asserter: "a".into(),
        assertion_kappa,
        reason: RevocationReason::Superseded,
        revoked_at_ms: 500,
        signature: vec![],
    };
    let result = resolution::resolve_at(&[assertion], &[revocation], &[], 200);
    assert_eq!(result.valid.len(), 0);
    assert_eq!(result.revoked.len(), 1);
}

#[test]
fn trust_position_states() {
    assert_eq!(TrustPosition::Unprobed.as_str(), "unprobed");
    assert!(!TrustPosition::Unprobed.is_faulted());
    assert_eq!(TrustPosition::Standalone.as_str(), "standalone");
    assert!(!TrustPosition::Standalone.is_faulted());
}
