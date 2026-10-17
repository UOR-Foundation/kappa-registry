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
    assert_eq!(DELEGATION_CHAIN_MAX_DEPTH, 4);
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
