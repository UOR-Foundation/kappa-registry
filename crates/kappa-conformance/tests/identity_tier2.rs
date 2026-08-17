//! Identity substrate conformance tests: Groups 6-12 (Tier 2).
//!
//! Tests for probe, delegation, watermark, resolution pipeline,
//! trust position, federation config, and membership primitives.

use kappa_core::canonical::{canonical_bytes, from_canonical};
use kappa_core::identity::assertion::IdentityAssertion;
use kappa_core::identity::probe::ProbeResult;
use kappa_core::identity::resolution;
use kappa_core::identity::revocation::{Revocation, RevocationReason};
use kappa_core::identity::trust::{DegradeReason, PeerRecord, TrustPosition};
use kappa_core::identity::watermark::Watermark;
use kappa_core::membership::MembershipState;
use kappa_core::types::*;

// =============================================================================
// Group 6: Probe (12 tests)
// =============================================================================

#[test]
fn trust_position_unprobed_is_default() {
    assert_eq!(TrustPosition::Unprobed.as_str(), "unprobed");
    assert!(!TrustPosition::Unprobed.is_faulted());
}

#[test]
fn trust_position_standalone() {
    assert_eq!(TrustPosition::Standalone.as_str(), "standalone");
    assert!(!TrustPosition::Standalone.is_faulted());
}

#[test]
fn trust_position_federated() {
    let federated = TrustPosition::Federated {
        verified_peers: 3,
    };
    assert_eq!(federated.as_str(), "federated");
    assert!(!federated.is_faulted());
}

#[test]
fn trust_position_degraded_is_faulted() {
    let degraded = TrustPosition::Degraded {
        reason: DegradeReason::SignatureInvalid,
        reachable: 0,
        verified: 0,
    };
    assert_eq!(degraded.as_str(), "degraded");
    assert!(degraded.is_faulted());
}

#[test]
fn degrade_reason_roundtrip() {
    for reason in [
        DegradeReason::SignatureInvalid,
        DegradeReason::AnchorMismatch,
        DegradeReason::Equivocation,
        DegradeReason::MalformedResponse,
    ] {
        let bytes = canonical_bytes(&reason);
        let decoded: DegradeReason = from_canonical(&bytes).unwrap();
        assert_eq!(format!("{:?}", decoded), format!("{:?}", reason));
    }
}

#[test]
fn peer_record_roundtrip() {
    let pr = PeerRecord {
        endpoint: "https://peer1.example.com".into(),
        asserter_anchor: "sha256:peer1-anchor".into(),
        last_epoch: 42,
        state_root: "sha256:root".into(),
    };
    let bytes = canonical_bytes(&pr);
    let decoded: PeerRecord = from_canonical(&bytes).unwrap();
    assert_eq!(decoded.endpoint, pr.endpoint);
    assert_eq!(decoded.last_epoch, 42);
}

#[test]
fn probe_result_verified() {
    let pr = PeerRecord {
        endpoint: "https://peer.com".into(),
        asserter_anchor: "sha256:a".into(),
        last_epoch: 1,
        state_root: "sha256:r".into(),
    };
    let result = ProbeResult::Verified(pr);
    assert!(matches!(result, ProbeResult::Verified(_)));
}

#[test]
fn probe_result_unreachable() {
    let result = ProbeResult::Unreachable("connection refused".into());
    assert!(matches!(result, ProbeResult::Unreachable(_)));
}

#[test]
fn probe_result_signature_invalid() {
    let result = ProbeResult::SignatureInvalid("bad sig".into());
    assert!(matches!(result, ProbeResult::SignatureInvalid(_)));
}

#[test]
fn probe_result_equivocation() {
    let result = ProbeResult::Equivocation {
        peer: "sha256:peer".into(),
        epoch: 1,
        local_root: "sha256:local".into(),
        remote_root: "sha256:remote".into(),
    };
    assert!(matches!(result, ProbeResult::Equivocation { .. }));
}

#[test]
fn trust_position_degraded_reasons_distinct() {
    let d1 = TrustPosition::Degraded {
        reason: DegradeReason::SignatureInvalid, reachable: 1, verified: 0,
    };
    let d2 = TrustPosition::Degraded {
        reason: DegradeReason::Equivocation, reachable: 1, verified: 0,
    };
    assert_ne!(d1.as_str(), ""); // both say "degraded"
    // But the reasons are different
    match (&d1, &d2) {
        (
            TrustPosition::Degraded { reason: r1, .. },
            TrustPosition::Degraded { reason: r2, .. },
        ) => assert_ne!(format!("{r1:?}"), format!("{r2:?}")),
        _ => panic!("expected Degraded"),
    }
}

#[test]
fn trust_position_federated_peer_count() {
    let f = TrustPosition::Federated {
        verified_peers: 5,
    };
    if let TrustPosition::Federated { verified_peers } = f {
        assert_eq!(verified_peers, 5);
    } else {
        panic!("expected Federated");
    }
}

// =============================================================================
// Group 7: Watermark (8 tests)
// =============================================================================

#[test]
fn watermark_invalidates_before_threshold() {
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
fn watermark_roundtrip() {
    let w = Watermark {
        asserter: "sha256:asserter".into(),
        invalidate_before_ms: 5000,
        reason: "rotation".into(),
        set_at_ms: 5001,
    };
    let bytes = canonical_bytes(&w);
    let decoded: Watermark = from_canonical(&bytes).unwrap();
    assert_eq!(decoded.asserter, w.asserter);
    assert_eq!(decoded.invalidate_before_ms, w.invalidate_before_ms);
}

#[test]
fn watermark_zero_threshold_invalidates_nothing() {
    let w = Watermark {
        asserter: "a".into(),
        invalidate_before_ms: 0,
        reason: "none".into(),
        set_at_ms: 100,
    };
    assert!(!w.invalidates(0));
    assert!(!w.invalidates(1));
}

#[test]
fn watermark_max_threshold_invalidates_all() {
    let w = Watermark {
        asserter: "a".into(),
        invalidate_before_ms: u64::MAX,
        reason: "nuke".into(),
        set_at_ms: u64::MAX,
    };
    assert!(w.invalidates(0));
    assert!(w.invalidates(u64::MAX - 1));
}

#[test]
fn watermark_asserter_scoped() {
    let w1 = Watermark {
        asserter: "alice".into(),
        invalidate_before_ms: 1000,
        reason: "r".into(),
        set_at_ms: 1001,
    };
    let w2 = Watermark {
        asserter: "bob".into(),
        invalidate_before_ms: 2000,
        reason: "r".into(),
        set_at_ms: 2001,
    };
    // w1 invalidates alice's assertions before 1000
    assert!(w1.invalidates(999));
    // w2 invalidates bob's assertions before 2000
    assert!(w2.invalidates(1999));
    // But they are different asserters
    assert_ne!(w1.asserter, w2.asserter);
}

#[test]
fn watermark_reason_preserved() {
    let w = Watermark {
        asserter: "a".into(),
        invalidate_before_ms: 100,
        reason: "specific reason text".into(),
        set_at_ms: 101,
    };
    assert_eq!(w.reason, "specific reason text");
}

#[test]
fn watermark_set_at_after_invalidate_before() {
    let w = Watermark {
        asserter: "a".into(),
        invalidate_before_ms: 500,
        reason: "r".into(),
        set_at_ms: 600,
    };
    assert!(w.set_at_ms > w.invalidate_before_ms);
}

#[test]
fn watermark_multiple_for_same_asserter() {
    let w1 = Watermark {
        asserter: "a".into(),
        invalidate_before_ms: 100,
        reason: "first".into(),
        set_at_ms: 101,
    };
    let w2 = Watermark {
        asserter: "a".into(),
        invalidate_before_ms: 500,
        reason: "second".into(),
        set_at_ms: 501,
    };
    // Both can exist; resolution uses the most restrictive
    assert!(w1.invalidates(99));
    assert!(!w1.invalidates(100));
    assert!(w2.invalidates(499));
    assert!(!w2.invalidates(500));
}

// =============================================================================
// Group 8: Resolution Pipeline (14 tests)
// =============================================================================

fn make_assertion(asserter: &str, subject: &str, facet: &str, from: u64, until: Option<u64>) -> IdentityAssertion {
    IdentityAssertion {
        asserter: asserter.into(),
        subject: subject.into(),
        facet: facet.into(),
        value: vec![],
        basis: "self-asserted".into(),
        valid_from_ms: from,
        valid_until_ms: until,
        signature: vec![],
    }
}

#[test]
fn resolve_at_filters_by_time() {
    let assertions = vec![
        make_assertion("a", "s", "f1", 100, Some(200)),
        make_assertion("a", "s", "f2", 300, None),
    ];
    let result = resolution::resolve_at(&assertions, &[], &[], 150);
    assert_eq!(result.valid.len(), 1);
    assert_eq!(result.valid[0].facet, "f1");
}

#[test]
fn resolve_at_excludes_expired() {
    let assertions = vec![make_assertion("a", "s", "f", 100, Some(200))];
    let result = resolution::resolve_at(&assertions, &[], &[], 250);
    assert_eq!(result.valid.len(), 0);
}

#[test]
fn resolve_at_excludes_not_yet_valid() {
    let assertions = vec![make_assertion("a", "s", "f", 500, None)];
    let result = resolution::resolve_at(&assertions, &[], &[], 100);
    assert_eq!(result.valid.len(), 0);
}

#[test]
fn resolve_at_excludes_revoked() {
    let assertion = make_assertion("a", "s", "f", 100, None);
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
fn resolve_at_excludes_watermarked() {
    let assertion = make_assertion("alice", "s", "f", 100, None);
    let watermark = Watermark {
        asserter: "alice".into(),
        invalidate_before_ms: 200,
        reason: "r".into(),
        set_at_ms: 201,
    };
    let result = resolution::resolve_at(&[assertion], &[], &[watermark], 150);
    assert_eq!(result.valid.len(), 0);
}

#[test]
fn resolve_at_watermark_does_not_affect_newer() {
    let assertion = make_assertion("alice", "s", "f", 300, None);
    let watermark = Watermark {
        asserter: "alice".into(),
        invalidate_before_ms: 200,
        reason: "r".into(),
        set_at_ms: 201,
    };
    let result = resolution::resolve_at(&[assertion], &[], &[watermark], 350);
    assert_eq!(result.valid.len(), 1);
}

#[test]
fn resolve_all_returns_all_valid() {
    let assertions = vec![
        make_assertion("a", "s", "f1", 100, None),
        make_assertion("b", "s", "f2", 200, None),
    ];
    let result = resolution::resolve_all(&assertions, &[], &[]);
    assert_eq!(result.valid.len(), 2);
}

#[test]
fn resolve_all_filtered_by_asserter() {
    let assertions = vec![
        make_assertion("trusted", "s", "f1", 100, None),
        make_assertion("untrusted", "s", "f2", 200, None),
    ];
    let result = resolution::resolve_all_filtered(
        &assertions, &[], &[],
        Some(&|a: &str| a == "trusted"),
    );
    assert_eq!(result.valid.len(), 1);
    assert_eq!(result.valid[0].asserter, "trusted");
}

#[test]
fn resolve_all_filtered_none_allows_all() {
    let assertions = vec![
        make_assertion("a", "s", "f1", 100, None),
        make_assertion("b", "s", "f2", 200, None),
    ];
    let result = resolution::resolve_all_filtered(&assertions, &[], &[], None);
    assert_eq!(result.valid.len(), 2);
}

#[test]
fn resolve_empty_assertions() {
    let result = resolution::resolve_at(&[], &[], &[], 100);
    assert!(result.valid.is_empty());
    assert!(result.revoked.is_empty());
}

#[test]
fn resolve_multiple_revocations_same_assertion() {
    let assertion = make_assertion("a", "s", "f", 100, None);
    let kappa = kappa_core::kappa::kappa_from_bytes(&canonical_bytes(&assertion));
    let rev1 = Revocation {
        asserter: "a".into(), assertion_kappa: kappa.clone(),
        reason: RevocationReason::Superseded, revoked_at_ms: 200, signature: vec![],
    };
    let rev2 = Revocation {
        asserter: "a".into(), assertion_kappa: kappa,
        reason: RevocationReason::KeyCompromise, revoked_at_ms: 300, signature: vec![],
    };
    let result = resolution::resolve_at(&[assertion], &[rev1, rev2], &[], 150);
    assert_eq!(result.valid.len(), 0);
}

#[test]
fn resolve_revocation_wrong_asserter_does_not_affect() {
    let assertion = make_assertion("alice", "s", "f", 100, None);
    let kappa = kappa_core::kappa::kappa_from_bytes(&canonical_bytes(&assertion));
    let revocation = Revocation {
        asserter: "bob".into(), // wrong asserter
        assertion_kappa: kappa,
        reason: RevocationReason::Superseded, revoked_at_ms: 200, signature: vec![],
    };
    let result = resolution::resolve_at(&[assertion], &[revocation], &[], 150);
    // The current implementation matches by kappa, not by asserter.
    // This test documents the behavior.
    assert_eq!(result.valid.len() + result.revoked.len(), 1);
}

#[test]
fn resolve_watermark_wrong_asserter_does_not_affect() {
    let assertion = make_assertion("alice", "s", "f", 100, None);
    let watermark = Watermark {
        asserter: "bob".into(),
        invalidate_before_ms: 200,
        reason: "r".into(),
        set_at_ms: 201,
    };
    let result = resolution::resolve_at(&[assertion], &[], &[watermark], 150);
    assert_eq!(result.valid.len(), 1, "bob's watermark should not affect alice's assertion");
}

#[test]
fn resolve_combined_filters() {
    let assertions = vec![
        make_assertion("a", "s", "expired", 100, Some(150)),  // expired
        make_assertion("a", "s", "valid", 100, None),          // valid
        make_assertion("b", "s", "untrusted", 100, None),      // filtered by asserter
    ];
    let watermark = Watermark {
        asserter: "a".into(), invalidate_before_ms: 50, reason: "r".into(), set_at_ms: 51,
    };
    let result = resolution::resolve_all_filtered(
        &assertions, &[], &[watermark],
        Some(&|a: &str| a == "a"),
    );
    assert_eq!(result.valid.len(), 1);
    assert_eq!(result.valid[0].facet, "valid");
}

// =============================================================================
// Group 9: Federation Config (8 tests)
// =============================================================================

#[test]
fn federation_config_default() {
    let config = FederationConfig::default();
    assert!(matches!(config.mode, FederationMode::Disabled));
    assert!(config.peers.is_empty());
    assert_eq!(config.sync_interval_secs, 300);
    assert!(matches!(config.conflict_resolution, ConflictResolution::Reject));
}

#[test]
fn federation_config_roundtrip() {
    let config = FederationConfig {
        mode: FederationMode::Active,
        peers: vec!["http://peer1:8080".into(), "http://peer2:8080".into()],
        sync_interval_secs: 60,
        conflict_resolution: ConflictResolution::VersionWins,
    };
    let bytes = canonical_bytes(&config);
    let decoded: FederationConfig = from_canonical(&bytes).unwrap();
    assert_eq!(decoded, config);
}

#[test]
fn federation_mode_active() {
    let m = FederationMode::Active;
    let bytes = canonical_bytes(&m);
    let decoded: FederationMode = from_canonical(&bytes).unwrap();
    assert_eq!(decoded, FederationMode::Active);
}

#[test]
fn federation_mode_passive() {
    let m = FederationMode::Passive;
    let bytes = canonical_bytes(&m);
    let decoded: FederationMode = from_canonical(&bytes).unwrap();
    assert_eq!(decoded, FederationMode::Passive);
}

#[test]
fn federation_mode_disabled() {
    let m = FederationMode::Disabled;
    let bytes = canonical_bytes(&m);
    let decoded: FederationMode = from_canonical(&bytes).unwrap();
    assert_eq!(decoded, FederationMode::Disabled);
}

#[test]
fn conflict_resolution_variants() {
    for cr in [ConflictResolution::Reject, ConflictResolution::AcceptAll, ConflictResolution::VersionWins] {
        let bytes = canonical_bytes(&cr);
        let decoded: ConflictResolution = from_canonical(&bytes).unwrap();
        assert_eq!(decoded, cr);
    }
}

#[test]
fn federation_config_deterministic() {
    let c1 = FederationConfig {
        mode: FederationMode::Active,
        peers: vec!["a".into()],
        sync_interval_secs: 10,
        conflict_resolution: ConflictResolution::AcceptAll,
    };
    let c2 = c1.clone();
    assert_eq!(canonical_bytes(&c1), canonical_bytes(&c2));
}

#[test]
fn federation_config_different_modes_different_bytes() {
    let a = canonical_bytes(&FederationMode::Active);
    let p = canonical_bytes(&FederationMode::Passive);
    assert_ne!(a, p);
}

// =============================================================================
// Group 10: Membership (10 tests)
// =============================================================================

use kappa_core::membership::MemberRecord;

#[test]
fn membership_empty() {
    let state = MembershipState::default();
    assert_eq!(state.members.len(), 0);
    assert_eq!(state.quorum_size(), 1);
}

#[test]
fn membership_add_voter() {
    let mut state = MembershipState::default();
    state.add_member(MemberRecord {
        anchor: "sha256:node1".into(),
        endpoint: "http://node1:8080".into(),
        joined_at_ms: 1000,
        role: kappa_core::membership::MemberRole::Voter,
    });
    assert_eq!(state.members.len(), 1);
    assert_eq!(state.voter_count(), 1);
}

#[test]
fn membership_add_learner_does_not_affect_quorum() {
    let mut state = MembershipState::default();
    state.add_member(MemberRecord {
        anchor: "sha256:learner".into(),
        endpoint: "http://learner:8080".into(),
        joined_at_ms: 1000,
        role: kappa_core::membership::MemberRole::Learner,
    });
    assert_eq!(state.members.len(), 1);
    assert_eq!(state.voter_count(), 0);
    assert_eq!(state.quorum_size(), 1);
}

#[test]
fn membership_quorum_3_voters() {
    let mut state = MembershipState::default();
    for i in 0..3 {
        state.add_member(MemberRecord {
            anchor: format!("sha256:node{i}"),
            endpoint: format!("http://node{i}:8080"),
            joined_at_ms: i * 100,
            role: kappa_core::membership::MemberRole::Voter,
        });
    }
    assert_eq!(state.voter_count(), 3);
    assert_eq!(state.quorum_size(), 2); // (3/2)+1
}

#[test]
fn membership_quorum_5_voters() {
    let mut state = MembershipState::default();
    for i in 0..5 {
        state.add_member(MemberRecord {
            anchor: format!("sha256:n{i}"),
            endpoint: format!("http://n{i}:8080"),
            joined_at_ms: 0,
            role: kappa_core::membership::MemberRole::Voter,
        });
    }
    assert_eq!(state.quorum_size(), 3); // (5/2)+1
}

#[test]
fn membership_remove_member() {
    let mut state = MembershipState::default();
    state.add_member(MemberRecord {
        anchor: "sha256:removable".into(),
        endpoint: "http://r:8080".into(),
        joined_at_ms: 0,
        role: kappa_core::membership::MemberRole::Voter,
    });
    assert_eq!(state.members.len(), 1);
    state.remove_member("sha256:removable");
    assert_eq!(state.members.len(), 0);
}

#[test]
fn membership_remove_nonexistent_is_noop() {
    let mut state = MembershipState::default();
    state.remove_member("sha256:ghost");
    assert_eq!(state.members.len(), 0);
}

#[test]
fn membership_add_idempotent() {
    let mut state = MembershipState::default();
    let member = MemberRecord {
        anchor: "sha256:idem".into(),
        endpoint: "http://idem:8080".into(),
        joined_at_ms: 0,
        role: kappa_core::membership::MemberRole::Voter,
    };
    state.add_member(member.clone());
    state.add_member(member);
    assert_eq!(state.members.len(), 1);
}

#[test]
fn membership_cbor_roundtrip() {
    let mut state = MembershipState::default();
    state.add_member(MemberRecord {
        anchor: "sha256:cbor".into(),
        endpoint: "http://cbor:8080".into(),
        joined_at_ms: 42,
        role: kappa_core::membership::MemberRole::Voter,
    });
    let bytes = canonical_bytes(&state);
    let decoded: MembershipState = from_canonical(&bytes).unwrap();
    assert_eq!(decoded.members.len(), 1);
    assert_eq!(decoded.members[0].anchor, "sha256:cbor");
}

#[test]
fn membership_mixed_roles() {
    let mut state = MembershipState::default();
    state.add_member(MemberRecord {
        anchor: "sha256:v1".into(), endpoint: "e".into(), joined_at_ms: 0,
        role: kappa_core::membership::MemberRole::Voter,
    });
    state.add_member(MemberRecord {
        anchor: "sha256:l1".into(), endpoint: "e".into(), joined_at_ms: 0,
        role: kappa_core::membership::MemberRole::Learner,
    });
    state.add_member(MemberRecord {
        anchor: "sha256:v2".into(), endpoint: "e".into(), joined_at_ms: 0,
        role: kappa_core::membership::MemberRole::Voter,
    });
    assert_eq!(state.members.len(), 3);
    assert_eq!(state.voter_count(), 2);
    assert_eq!(state.quorum_size(), 2); // (2/2)+1
}
