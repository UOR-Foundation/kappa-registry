//! PERF-IDN-004: Delegation capability lattice. Intersection narrows,
//! union widens, subset checks. Depth <= `DELEGATION_CHAIN_MAX_DEPTH`.
//!
//! PERF-IDN-006: `SessionAnchor` symmetric, deterministic, self-rejecting.
//!
//! PERF-IDN-005: Scoped projection unlinkable across scopes.

use kappa_types::delegation::{Capability, CapabilitySet, DELEGATION_CHAIN_MAX_DEPTH};
use kappa_types::identity::{derive_scoped_projection, derive_session_anchor};
use kappa_types::kappa::Kappa;

type TestResult = Result<(), Box<dyn std::error::Error>>;

// -- PERF-IDN-004: Delegation capability lattice --

#[test]
fn intersection_narrows() {
    let a = CapabilitySet::from_iter([Capability::Read, Capability::Write, Capability::Admin]);
    let b = CapabilitySet::from_iter([Capability::Read, Capability::Write]);
    let c = a.intersection(&b);
    assert_eq!(c.len(), 2);
    assert!(c.contains(&Capability::Read));
    assert!(c.contains(&Capability::Write));
    assert!(!c.contains(&Capability::Admin));
}

#[test]
fn union_widens() {
    let a = CapabilitySet::from_iter([Capability::Read]);
    let b = CapabilitySet::from_iter([Capability::Write]);
    let c = a.union(&b);
    assert_eq!(c.len(), 2);
}

#[test]
fn subset_checks() {
    let narrow = CapabilitySet::from_iter([Capability::Read]);
    let wide = CapabilitySet::from_iter([Capability::Read, Capability::Write]);
    assert!(narrow.is_subset(&wide));
    assert!(!wide.is_subset(&narrow));
}

#[test]
fn empty_intersection_is_revocation() {
    let a = CapabilitySet::from_iter([Capability::Read]);
    let b = CapabilitySet::from_iter([Capability::Write]);
    let c = a.intersection(&b);
    assert!(c.is_empty());
}

#[test]
fn delegation_depth_constant() {
    assert_eq!(DELEGATION_CHAIN_MAX_DEPTH, 256);
}

fn authority_depth_contract(store: &dyn kappa_store::KappaStore) -> TestResult {
    use kappa_crypto::{Signer, ed25519::Ed25519Signer};
    use kappa_handler::{
        auth::Operation,
        authority::{Grant, authority},
    };
    use kappa_store::{BuiltinRelation, DelegationScope, EdgeInput, EdgeRelation, SignedPayload};
    let clock = kappa_handler::clock_at(kappa_store::ClockMs::from_raw(1000))?;
    let signers = (0u32..=257)
        .map(|index| {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&index.to_be_bytes());
            Ed25519Signer::from_bytes(&seed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let anchors = signers
        .iter()
        .map(|signer| Kappa::from_key(signer.algorithm(), signer.public_key()))
        .collect::<Result<Vec<_>, _>>()?;
    kappa_store::namespace_ensure(store, "_root", None, None, &clock)?;
    let ns = kappa_store::namespace_ensure(store, "depth-floor", Some(&anchors[0]), None, &clock)?;
    let mut execution = store.begin_execution(&ns, &clock)?;
    let mut middle = None;
    for index in 0..257usize {
        let scope = kappa_crypto::signed_types::sign_delegation(
            DelegationScope {
                delegator: anchors[index].clone(),
                delegate: anchors[index + 1].clone(),
                scope: vec!["read".into()],
                namespaces: Some(vec!["depth-floor".into()]),
                valid_from_ms: 0,
                valid_until_ms: Some(100),
                max_depth: u32::try_from(256 - index)?,
                nonce: index.to_be_bytes().to_vec(),
                cose_signature: SignedPayload::empty(),
            },
            &signers[index],
        )?;
        let edge = execution.edge_put(&EdgeInput {
            source: scope.delegator.clone(),
            target: scope.delegate.clone(),
            relation: EdgeRelation::Builtin(BuiltinRelation::Delegation),
            asserter: scope.delegator.clone(),
            created_at_ms: 0,
            metadata: Some(serde_json::to_vec(&scope)?),
        })?;
        if index == 127 {
            middle = Some(edge);
        }
    }
    execution.publish()?;
    assert_eq!(
        authority(store, &ns, &anchors[256], Operation::Read, 50)?,
        Some(Grant::Delegation)
    );
    assert_eq!(
        authority(store, &ns, &anchors[257], Operation::Read, 50)?,
        None
    );
    assert_eq!(
        authority(store, &ns, &anchors[256], Operation::Read, 100)?,
        None
    );
    let mut execution = store.begin_execution(&ns, &clock)?;
    execution.edge_delete(&middle.ok_or("missing middle delegation")?)?;
    execution.publish()?;
    assert_eq!(
        authority(store, &ns, &anchors[256], Operation::Read, 50)?,
        None
    );
    Ok(())
}

#[test]
fn memory_authority_honors_256_links_and_revocation() -> TestResult {
    let fixture = kappa_store_memory::test_support::test_store()?;
    authority_depth_contract(fixture.store())
}

#[test]
fn persistent_authority_honors_256_links_and_revocation() -> TestResult {
    let fixture = kappa_store_redb::test_support::persistent_store()?;
    authority_depth_contract(fixture.store())
}

// -- PERF-IDN-006: SessionAnchor --

#[test]
fn session_anchor_symmetric() -> TestResult {
    let a = Kappa::from_key("ed25519", b"key-a")?;
    let b = Kappa::from_key("ed25519", b"key-b")?;
    let ab = derive_session_anchor(&a, &b)?;
    let ba = derive_session_anchor(&b, &a)?;
    assert_eq!(ab, ba);
    Ok(())
}

#[test]
fn session_anchor_deterministic() -> TestResult {
    let a = Kappa::from_key("ed25519", b"key-a")?;
    let b = Kappa::from_key("ed25519", b"key-b")?;
    assert_eq!(
        derive_session_anchor(&a, &b)?,
        derive_session_anchor(&a, &b)?
    );
    Ok(())
}

#[test]
fn session_anchor_self_rejected() -> TestResult {
    let a = Kappa::from_key("ed25519", b"key-a")?;
    assert!(derive_session_anchor(&a, &a).is_err());
    Ok(())
}

#[test]
fn session_anchor_distinct_pairs() -> TestResult {
    let a = Kappa::from_key("ed25519", b"a")?;
    let b = Kappa::from_key("ed25519", b"b")?;
    let c = Kappa::from_key("ed25519", b"c")?;
    let ab = derive_session_anchor(&a, &b)?;
    let ac = derive_session_anchor(&a, &c)?;
    let bc = derive_session_anchor(&b, &c)?;
    assert_ne!(ab, ac);
    assert_ne!(ab, bc);
    assert_ne!(ac, bc);
    Ok(())
}

// -- PERF-IDN-005: Scoped projection unlinkable --

#[test]
fn scoped_projection_deterministic() -> TestResult {
    let anchor = Kappa::from_key("ed25519", b"proj-key")?;
    let scope = Kappa::sha256(b"community-a");
    let a = derive_scoped_projection(&anchor, &scope);
    let b = derive_scoped_projection(&anchor, &scope);
    assert_eq!(a, b);
    Ok(())
}

#[test]
fn scoped_projection_unlinkable_across_scopes() -> TestResult {
    let anchor = Kappa::from_key("ed25519", b"proj-key")?;
    let scope_a = Kappa::sha256(b"scope-a");
    let scope_b = Kappa::sha256(b"scope-b");
    let proj_a = derive_scoped_projection(&anchor, &scope_a);
    let proj_b = derive_scoped_projection(&anchor, &scope_b);
    assert_ne!(
        proj_a, proj_b,
        "projections under different scopes must differ"
    );

    // Different anchors under the same scope also differ
    let other = Kappa::from_key("ed25519", b"other-key")?;
    let proj_other = derive_scoped_projection(&other, &scope_a);
    assert_ne!(proj_a, proj_other);
    Ok(())
}
