//! Identity substrate conformance: binding, succession, handle,
//! watermark, revocation, and assertion through published executions.

use kappa_store::identity::{
    BindingMethod, HandleRecord, IdentityAssertion, IdentityBinding, Revocation, RevocationReason,
    Succession, SuccessionReason, TrustLevel, Watermark, WatermarkReason,
};
use kappa_store::kappa::Kappa;
use kappa_store::namespace::ProtocolId;
use kappa_store::signed::SignedPayload;
use kappa_store::traits::identity::IdentityStore;

use super::support::{MemoryFixture, TestResult, create_ns, publish};

fn anchor(seed: &str) -> Result<Kappa, kappa_store::KappaParseError> {
    Kappa::from_key("ed25519", seed.as_bytes())
}

fn test_binding(
    source: &str,
    target_seed: &str,
) -> Result<IdentityBinding, kappa_store::KappaParseError> {
    Ok(IdentityBinding {
        source: source.into(),
        target: anchor(target_seed)?,
        method: BindingMethod::SelfDeclared,
        trust_level: TrustLevel::Verified,
        verified_at_ms: Some(1000),
        metadata: None,
    })
}

// =========================================================================
// Binding lifecycle
// =========================================================================

#[test]
fn binding_put_get_roundtrip() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "identity")?;
    let b = test_binding("user@example.com", "key-a")?;
    publish(&f.store, &ns, |ex| ex.binding_put(&b))?;
    let bindings = f.store.binding_get("user@example.com")?;
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].source, "user@example.com");
    Ok(())
}

#[test]
fn binding_delete_removes() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "identity")?;
    let b = test_binding("del@example.com", "key-b")?;
    let target = b.target.clone();
    publish(&f.store, &ns, |ex| ex.binding_put(&b))?;
    publish(&f.store, &ns, |ex| {
        ex.binding_delete("del@example.com", &target)
    })?;
    let bindings = f.store.binding_get("del@example.com")?;
    assert!(bindings.is_empty());
    Ok(())
}

#[test]
fn binding_duplicate_idempotent() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "dup")?;
    let b = test_binding("dup@example.com", "key-c")?;
    publish(&f.store, &ns, |ex| ex.binding_put(&b))?;
    publish(&f.store, &ns, |ex| ex.binding_put(&b))?;
    let bindings = f.store.binding_get("dup@example.com")?;
    assert_eq!(bindings.len(), 1);
    Ok(())
}

// =========================================================================
// Handle lifecycle
// =========================================================================

#[test]
fn handle_put_get_roundtrip() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "handles")?;
    let protocol = ProtocolId::new("atproto")?;
    let record = HandleRecord {
        anchor: anchor("handle-key")?,
        handle: "alice.test".into(),
        protocol: protocol.clone(),
        claimed_at_ms: 1000,
        attested_at_ms: None,
    };
    publish(&f.store, &ns, |ex| ex.handle_put(&record))?;
    let got = f.store.handle_get(protocol, "alice.test")?;
    assert_eq!(got.handle, "alice.test");
    Ok(())
}

#[test]
fn handle_delete_removes() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "handles")?;
    let protocol = ProtocolId::new("atproto")?;
    let record = HandleRecord {
        anchor: anchor("handle-del")?,
        handle: "bob.test".into(),
        protocol: protocol.clone(),
        claimed_at_ms: 1000,
        attested_at_ms: None,
    };
    publish(&f.store, &ns, |ex| ex.handle_put(&record))?;
    publish(&f.store, &ns, |ex| ex.handle_delete(&protocol, "bob.test"))?;
    assert!(f.store.handle_get(protocol.clone(), "bob.test").is_err());
    Ok(())
}

// =========================================================================
// Watermark
// =========================================================================

#[test]
fn watermark_invalidates_assertions() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "watermark")?;
    let w = Watermark {
        asserter: Kappa::sha256(b"compromised"),
        invalidate_before_ms: 5000,
        reason: WatermarkReason::KeyCompromise,
        set_at_ms: 6000,
        cose_signature: SignedPayload::empty(),
    };
    publish(&f.store, &ns, |ex| {
        ex.watermark_put(&w)?;
        Ok(())
    })?;
    assert!(w.invalidates(4999));
    assert!(!w.invalidates(5000));
    Ok(())
}

// =========================================================================
// Assertion
// =========================================================================

#[test]
fn assertion_put_through_execution() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "assertions")?;
    let assertion = IdentityAssertion {
        asserter: Kappa::sha256(b"asserter"),
        subject: "subject".into(),
        facet: "entity-kind".into(),
        value: b"human".to_vec(),
        basis: "self-asserted".into(),
        valid_from_ms: 1000,
        valid_until_ms: None,
        cose_signature: SignedPayload::empty(),
    };
    publish(&f.store, &ns, |ex| {
        ex.assertion_put(&assertion)?;
        Ok(())
    })?;
    Ok(())
}

// =========================================================================
// Revocation
// =========================================================================

#[test]
fn revocation_put_through_execution() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "revocations")?;
    let revocation = Revocation {
        assertion_kappa: Kappa::sha256(b"assertion-content"),
        asserter: Kappa::sha256(b"asserter"),
        reason: RevocationReason::Superseded,
        revoked_at_ms: 2000,
        cose_signature: SignedPayload::empty(),
    };
    publish(&f.store, &ns, |ex| {
        ex.revocation_put(&revocation)?;
        Ok(())
    })?;
    Ok(())
}

#[test]
fn revocation_is_retrievable_after_publication() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "rev-read")?;
    let asserter = Kappa::sha256(b"rev-asserter");
    let revocation = Revocation {
        assertion_kappa: Kappa::sha256(b"revoked-assertion"),
        asserter: asserter.clone(),
        reason: RevocationReason::KeyCompromise,
        revoked_at_ms: 3000,
        cose_signature: SignedPayload::empty(),
    };
    publish(&f.store, &ns, |ex| {
        ex.revocation_put(&revocation)?;
        Ok(())
    })?;
    let listed = f.store.revocation_list_by_asserter(&asserter)?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].revoked_at_ms, 3000);
    Ok(())
}

// =========================================================================
// Succession
// =========================================================================

#[test]
fn succession_sign_publish_and_resolve() -> TestResult {
    use kappa_crypto::Signer;
    use kappa_crypto::ed25519::Ed25519Signer;

    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "succession")?;

    let old_signer = Ed25519Signer::from_bytes(&[1; 32])?;
    let new_signer = Ed25519Signer::from_bytes(&[2; 32])?;
    let old_anchor = Kappa::from_key(old_signer.algorithm(), old_signer.public_key())?;
    let new_anchor = Kappa::from_key(new_signer.algorithm(), new_signer.public_key())?;

    let unsigned = Succession {
        old_anchor: old_anchor.clone(),
        new_anchor: new_anchor.clone(),
        reason: SuccessionReason::Rotation,
        effective_at_ms: 5000,
        chain_anchor: None,
        prev_identifier: None,
        old_cose_signature: SignedPayload::empty(),
        new_cose_signature: SignedPayload::empty(),
    };

    // Signable bytes exclude signatures
    let signable = unsigned.signable_bytes();
    let signed = kappa_crypto::signed_types::sign_succession(unsigned, &old_signer, &new_signer)?;
    assert_eq!(signed.signable_bytes(), signable);

    // Admit produces a Verified<Succession>
    let verified = kappa_crypto::signed_types::admit_succession(
        signed,
        old_signer.algorithm(),
        old_signer.public_key(),
        new_signer.algorithm(),
        new_signer.public_key(),
    )?;

    // Publish the succession through an execution
    publish(&f.store, &ns, |ex| {
        ex.succession_put(&verified)?;
        Ok(())
    })?;

    // Verify the store resolves old_anchor to new_anchor
    let resolved = f.store.succession_get(&old_anchor)?;
    assert_eq!(resolved, new_anchor);
    Ok(())
}

#[test]
fn succession_signable_bytes_deterministic() -> TestResult {
    let succession = Succession {
        old_anchor: anchor("det-old")?,
        new_anchor: anchor("det-new")?,
        reason: SuccessionReason::Rotation,
        effective_at_ms: 5000,
        chain_anchor: None,
        prev_identifier: None,
        old_cose_signature: SignedPayload::empty(),
        new_cose_signature: SignedPayload::empty(),
    };
    let succession2 = Succession {
        old_cose_signature: SignedPayload::from_cose_bytes(vec![1]),
        new_cose_signature: SignedPayload::from_cose_bytes(vec![2]),
        ..succession.clone()
    };
    assert_eq!(succession.signable_bytes(), succession2.signable_bytes());
    Ok(())
}
