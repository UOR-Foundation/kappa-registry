//! Identity tier 2 conformance: trust position, probe results,
//! degrade reasons, peer records, trust state machine.

use std::num::NonZeroUsize;

use kappa_store::identity::{
    DegradeReason, PeerRecord, ProbeResult, TrustEvent, TrustPosition, TrustState, trust_transition,
};
use kappa_store::kappa::Kappa;

#[test]
fn trust_position_unprobed() {
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
    let f = TrustPosition::federated(NonZeroUsize::new(3).expect("nonzero"));
    assert_eq!(f.as_str(), "federated");
    assert!(!f.is_faulted());
}

#[test]
fn trust_position_degraded() {
    let d = TrustPosition::Degraded {
        reason: DegradeReason::Equivocation,
        reachable: 2,
        verified: 0,
    };
    assert_eq!(d.as_str(), "degraded");
    assert!(d.is_faulted());
}

#[test]
fn degrade_reason_exhaustive() {
    for (reason, name) in [
        (DegradeReason::SignatureInvalid, "signature-invalid"),
        (DegradeReason::AnchorMismatch, "anchor-mismatch"),
        (DegradeReason::Equivocation, "equivocation"),
        (DegradeReason::MalformedResponse, "malformed-response"),
    ] {
        assert_eq!(reason.as_str(), name);
    }
}

#[test]
fn probe_verified() {
    let record = PeerRecord {
        endpoint: "https://peer.example.com".into(),
        asserter_anchor: Kappa::sha256(b"peer-anchor"),
        last_epoch: 42,
        state_root: Kappa::sha256(b"state"),
    };
    let result = ProbeResult::Verified(record);
    assert!(matches!(result, ProbeResult::Verified(_)));
}

#[test]
fn probe_unreachable() {
    let result = ProbeResult::Unreachable("timeout".into());
    assert!(matches!(result, ProbeResult::Unreachable(_)));
}

#[test]
fn probe_equivocation() {
    let result = ProbeResult::Equivocation {
        peer: Kappa::sha256(b"peer"),
        epoch: 10,
        local_root: Kappa::sha256(b"local"),
        remote_root: Kappa::sha256(b"remote"),
    };
    assert!(matches!(result, ProbeResult::Equivocation { .. }));
}

#[test]
fn trust_first_contact_pinned() {
    let (state, latch) = trust_transition(TrustState::Pinned, false, TrustEvent::RootObserved);
    assert_eq!(state, TrustState::Pinned);
    assert!(!latch);
}

#[test]
fn trust_verification_sets_latch() {
    let (state, latch) =
        trust_transition(TrustState::Pinned, false, TrustEvent::VerificationSucceeded);
    assert_eq!(state, TrustState::Verified);
    assert!(latch);
}

#[test]
fn trust_unexplained_change_with_latch_becomes_violation() {
    let (state, latch) = trust_transition(
        TrustState::Verified,
        true,
        TrustEvent::UnexplainedRootChange,
    );
    assert_eq!(state, TrustState::VerificationViolation);
    assert!(latch);
}

#[test]
fn trust_withdraw_clears_latch() {
    let (state, latch) = trust_transition(
        TrustState::Verified,
        true,
        TrustEvent::VerificationWithdrawn,
    );
    assert_eq!(state, TrustState::Pinned);
    assert!(!latch);
}

#[test]
fn trust_full_lifecycle() {
    let (state, latch) = trust_transition(TrustState::Pinned, false, TrustEvent::RootObserved);
    assert_eq!(state, TrustState::Pinned);
    let (state, latch) = trust_transition(state, latch, TrustEvent::VerificationSucceeded);
    assert_eq!(state, TrustState::Verified);
    assert!(latch);
    let (state, latch) = trust_transition(state, latch, TrustEvent::UnexplainedRootChange);
    assert_eq!(state, TrustState::VerificationViolation);
    let (state, latch) = trust_transition(state, latch, TrustEvent::UserAcknowledged);
    assert_eq!(state, TrustState::Pinned);
    assert!(latch);
}
