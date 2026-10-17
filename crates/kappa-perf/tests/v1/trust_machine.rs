//! PERF-IDN-002: Trust state machine exhaustive transition table.
//! 4 states x 8 events x 2 latch values = 64 transitions.

use kappa_types::identity::{TrustEvent, TrustState, trust_transition};

/// Every (state, latch, event) triple must produce a defined result
/// without panic.
#[test]
fn exhaustive_transition_table() {
    let states = [
        TrustState::Pinned,
        TrustState::PinViolation,
        TrustState::Verified,
        TrustState::VerificationViolation,
    ];
    let events = [
        TrustEvent::RootObserved,
        TrustEvent::UnexplainedRootChange,
        TrustEvent::RotationProofVerified,
        TrustEvent::VerificationSucceeded,
        TrustEvent::UserAcknowledged,
        TrustEvent::VerificationWithdrawn,
        TrustEvent::RevocationReceived,
        TrustEvent::TombstoneReceived,
    ];

    let mut count = 0;
    for state in states {
        for latch in [false, true] {
            for event in events {
                let (new_state, new_latch) = trust_transition(state, latch, event);
                // Verify invariants
                match event {
                    TrustEvent::VerificationSucceeded => {
                        assert_eq!(new_state, TrustState::Verified);
                        assert!(new_latch, "verification must set latch");
                    }
                    TrustEvent::VerificationWithdrawn => {
                        if matches!(
                            state,
                            TrustState::Verified | TrustState::VerificationViolation
                        ) {
                            assert!(!new_latch, "withdrawal must clear latch");
                        }
                    }
                    TrustEvent::UnexplainedRootChange
                    | TrustEvent::RevocationReceived
                    | TrustEvent::TombstoneReceived => {
                        if latch {
                            assert_eq!(
                                new_state,
                                TrustState::VerificationViolation,
                                "with latch, violation events -> VerificationViolation"
                            );
                        } else {
                            assert_eq!(
                                new_state,
                                TrustState::PinViolation,
                                "without latch, violation events -> PinViolation"
                            );
                        }
                    }
                    _ => {}
                }
                count += 1;
            }
        }
    }
    assert_eq!(count, 64, "must cover all 4 x 2 x 8 = 64 transitions");
}

/// The latch is monotonic except through `VerificationWithdrawn`.
#[test]
fn latch_monotonic_except_withdrawal() {
    // Once set by VerificationSucceeded, the latch survives every
    // event except VerificationWithdrawn.
    let events_that_preserve_latch = [
        TrustEvent::RootObserved,
        TrustEvent::UnexplainedRootChange,
        TrustEvent::RotationProofVerified,
        TrustEvent::UserAcknowledged,
        TrustEvent::RevocationReceived,
        TrustEvent::TombstoneReceived,
    ];

    for state in [
        TrustState::Pinned,
        TrustState::PinViolation,
        TrustState::Verified,
        TrustState::VerificationViolation,
    ] {
        for event in events_that_preserve_latch {
            let (_, new_latch) = trust_transition(state, true, event);
            assert!(new_latch, "latch must survive {event:?} from {state:?}");
        }
    }
}
