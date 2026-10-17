use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use kappa_types::identity::{DegradeReason, PeerRecord, ProbeResult, TrustPosition};
use kappa_types::kappa::Kappa;

use super::{Availability, NodeIdentity, Successor, TransitionOutcome};
use crate::CryptoError;
use crate::keystore::{KeyStore, Settlement};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Setup<T> = Result<T, Box<dyn std::error::Error>>;

/// Bound on every wait for another thread, so a regression fails instead
/// of hanging.
const DEADLINE: Duration = Duration::from_secs(30);

/// A key store in a fresh scope it retains.
fn keys() -> Setup<KeyStore> {
    crate::testing::key_store()
}

/// The first node key of `keys`, generated and settled as committed.
fn settled(keys: &KeyStore) -> Setup<Settlement> {
    let custody = keys.node_keys()?;
    let first = custody
        .candidates("ed25519")?
        .current
        .ok_or("no current key after first generation")?;
    Ok(custody.settle(first.anchor())?)
}

fn verifies(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
    crate::verifier_for("ed25519")?.verify(public_key, message, signature)
}

fn failure(reason: &str) -> CryptoError {
    CryptoError::SigningFailed {
        algorithm: "test".into(),
        reason: reason.into(),
    }
}

#[test]
fn identity_names_and_signs_under_its_authority() -> TestResult {
    let keys = keys()?;
    let settled = settled(&keys)?;
    let expected = settled.authority.anchor().clone();
    let identity = NodeIdentity::new(&settled);
    assert_eq!(identity.anchor()?, expected);
    assert_eq!(identity.algorithm()?, "ed25519");
    assert_eq!(identity.status(), Availability::Active(expected));
    assert!(!identity.is_unresolved());
    assert_eq!(identity.position(), TrustPosition::Unprobed);
    let signature = identity.sign(b"message")?;
    assert!(verifies(
        &identity.public_key_bytes()?,
        b"message",
        &signature
    )?);
    Ok(())
}

#[test]
fn installed_transition_reports_the_anchor_and_signs_with_the_incoming_key() -> TestResult {
    let keys = keys()?;
    let identity = NodeIdentity::new(&settled(&keys)?);
    let outgoing = identity.public_key_bytes()?;
    let custody = keys.node_keys()?;
    let staged = custody.stage_successor("ed25519")?;
    let next_anchor = staged.authority.anchor().clone();
    let incoming = staged.authority.signer().public_key().to_vec();
    let (installed, report) = identity.transition::<&str, CryptoError>(&custody, |_, live| {
        assert_ne!(live.anchor(), staged.authority.anchor());
        TransitionOutcome::Installed(Successor::from(&staged), "committed")
    })?;
    drop(custody);
    assert_eq!(installed, next_anchor);
    assert_eq!(report, "committed");
    assert_eq!(identity.status(), Availability::Active(next_anchor.clone()));
    let signature = identity.sign(b"after")?;
    assert!(verifies(&incoming, b"after", &signature)?);
    assert!(!verifies(&outgoing, b"after", &signature)?);
    Ok(())
}

#[test]
fn unchanged_transition_keeps_the_outgoing_authority_live() -> TestResult {
    let keys = keys()?;
    let settled = settled(&keys)?;
    let anchor = settled.authority.anchor().clone();
    let identity = NodeIdentity::new(&settled);
    let custody = keys.node_keys()?;
    let outcome = identity.transition::<(), CryptoError>(&custody, |_, _| {
        TransitionOutcome::Unchanged(failure("rejected before commit"))
    });
    assert!(
        matches!(&outcome, Err(CryptoError::SigningFailed { reason, .. }) if reason == "rejected before commit"),
        "{outcome:?}"
    );
    assert_eq!(identity.status(), Availability::Active(anchor));
    let signature = identity.sign(b"still")?;
    assert!(verifies(
        &identity.public_key_bytes()?,
        b"still",
        &signature
    )?);
    Ok(())
}

#[test]
fn unresolved_transition_refuses_signing_naming_and_further_transitions() -> TestResult {
    let keys = keys()?;
    let settled = settled(&keys)?;
    let last = settled.authority.anchor().clone();
    let identity = NodeIdentity::new(&settled);
    let custody = keys.node_keys()?;
    let outcome = identity.transition::<(), CryptoError>(&custody, |_, _| {
        TransitionOutcome::Unresolved(failure("commit outcome unknown"))
    });
    assert!(
        matches!(&outcome, Err(CryptoError::SigningFailed { reason, .. }) if reason == "commit outcome unknown"),
        "the step's own error is returned: {outcome:?}"
    );
    assert_eq!(
        identity.status(),
        Availability::Unresolved { last: last.clone() }
    );
    assert!(identity.is_unresolved());
    let refused = |result: Result<(), CryptoError>| matches!(result, Err(CryptoError::AuthorityUnresolved { last: ref named }) if **named == last);
    assert!(refused(identity.sign(b"x").map(drop)));
    assert!(refused(identity.anchor().map(drop)));
    assert!(refused(identity.public_key_bytes().map(drop)));
    let ran = AtomicBool::new(false);
    let staged = custody.stage_successor("ed25519");
    let again = identity.transition::<(), CryptoError>(&custody, |_, _| {
        ran.store(true, Ordering::SeqCst);
        match &staged {
            Ok(staged) => TransitionOutcome::Installed(Successor::from(staged), ()),
            Err(_) => TransitionOutcome::Unchanged(failure("staging failed")),
        }
    });
    assert!(
        matches!(&again, Err(CryptoError::AuthorityUnresolved { .. })),
        "{again:?}"
    );
    assert!(
        !ran.load(Ordering::SeqCst),
        "a step ran on an unresolved identity"
    );
    Ok(())
}

#[test]
fn diverged_transition_refuses_signing_and_names_both_authorities() -> TestResult {
    let keys = keys()?;
    let settled = settled(&keys)?;
    let live = settled.authority.anchor().clone();
    let identity = NodeIdentity::new(&settled);
    let committed = Kappa::sha256(b"another committed authority");
    let custody = keys.node_keys()?;
    let outcome =
        identity.transition::<(), CryptoError>(&custody, |_, _| TransitionOutcome::Diverged {
            committed: committed.clone(),
            error: failure("live differs from committed"),
        });
    assert!(outcome.is_err());
    assert_eq!(
        identity.status(),
        Availability::Diverged {
            live: live.clone(),
            committed: committed.clone()
        }
    );
    assert!(identity.is_unresolved());
    assert!(matches!(
        identity.sign(b"x"),
        Err(CryptoError::AuthorityDiverged { live: ref l, committed: ref c }) if **l == live && **c == committed
    ));
    Ok(())
}

#[test]
fn interrupted_transition_reports_interrupted_and_refuses_signing() -> TestResult {
    let keys = keys()?;
    let identity = NodeIdentity::new(&settled(&keys)?);
    let custody = keys.node_keys()?;
    let panicked = std::panic::catch_unwind(AssertUnwindSafe(|| {
        identity.transition::<(), CryptoError>(&custody, |_, _| {
            panic!("injected panic inside a transition step")
        })
    }));
    assert!(panicked.is_err());
    assert_eq!(identity.status(), Availability::Interrupted);
    assert!(
        identity.is_unresolved(),
        "status must agree with signing refusal"
    );
    assert!(matches!(
        identity.sign(b"x"),
        Err(CryptoError::AuthorityInterrupted)
    ));
    assert!(matches!(
        identity.anchor(),
        Err(CryptoError::AuthorityInterrupted)
    ));
    Ok(())
}

/// Custody of another key store admits no change, and the step never runs.
#[test]
fn another_key_stores_custody_is_refused_before_the_step() -> TestResult {
    let local_keys = keys()?;
    let other_keys = keys()?;
    let local_settlement = settled(&local_keys)?;
    let anchor = local_settlement.authority.anchor().clone();
    let identity = NodeIdentity::new(&local_settlement);
    let ran = AtomicBool::new(false);
    let foreign = other_keys.node_keys()?;
    let outcome = identity.transition::<(), CryptoError>(&foreign, |_, _| {
        ran.store(true, Ordering::SeqCst);
        TransitionOutcome::Unchanged(failure("must not run"))
    });
    assert!(
        matches!(outcome, Err(CryptoError::CustodyMismatch)),
        "{outcome:?}"
    );
    assert!(!ran.load(Ordering::SeqCst));
    assert_eq!(identity.status(), Availability::Active(anchor));
    Ok(())
}

/// A successor another key store holds is never installed. The step may
/// have committed it, so the identity becomes unresolved.
#[test]
fn a_successor_from_another_key_store_is_never_installed() -> TestResult {
    let local_keys = keys()?;
    let other_keys = keys()?;
    let local_settlement = settled(&local_keys)?;
    let last = local_settlement.authority.anchor().clone();
    let identity = NodeIdentity::new(&local_settlement);
    let foreign = Successor::from(&settled(&other_keys)?);
    let custody = local_keys.node_keys()?;
    let outcome = identity
        .transition::<(), CryptoError>(&custody, |_, _| TransitionOutcome::Installed(foreign, ()));
    assert!(
        matches!(outcome, Err(CryptoError::CustodyMismatch)),
        "{outcome:?}"
    );
    assert_eq!(identity.status(), Availability::Unresolved { last });
    Ok(())
}

/// A signature requested while a transition holds the authority waits for
/// it and is produced by the authority it installs, never the one it
/// retires. The signer is observed entering acquisition before the
/// transition is released, so the two genuinely overlap. Workers are
/// detached and report over channels with deadlines: a deadlock fails the
/// test instead of hanging it.
#[test]
fn signing_overlapping_a_transition_uses_the_installed_authority() -> TestResult {
    // The store retains its scope, so the detached transition worker's
    // handle keeps the directory alive whatever the test thread does.
    let keys = Arc::new(keys()?);
    let identity = Arc::new(NodeIdentity::new(&settled(&keys)?));
    let outgoing = identity.public_key_bytes()?;

    let (held_tx, held_rx) = mpsc::channel::<Vec<u8>>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (rotated_tx, rotated_rx) = mpsc::channel::<Result<Kappa, CryptoError>>();
    {
        let (keys, identity) = (keys.clone(), identity.clone());
        std::thread::spawn(move || {
            let outcome = keys.node_keys().and_then(|custody| {
                let staged = custody.stage_successor("ed25519")?;
                identity
                    .transition::<(), CryptoError>(&custody, |_, _| {
                        let incoming = staged.authority.signer().public_key().to_vec();
                        if held_tx.send(incoming).is_err() {
                            return TransitionOutcome::Unchanged(failure("test thread gone"));
                        }
                        match release_rx.recv_timeout(DEADLINE) {
                            Ok(()) => TransitionOutcome::Installed(Successor::from(&staged), ()),
                            Err(_) => TransitionOutcome::Unchanged(failure("release never sent")),
                        }
                    })
                    .map(|(anchor, ())| anchor)
            });
            // The receiver is gone only if the test already failed.
            let _ = rotated_tx.send(outcome);
        });
    }
    let incoming = held_rx
        .recv_timeout(DEADLINE)
        .map_err(|_| "the transition never took the authority")?;

    let before = identity.acquiring.load(Ordering::SeqCst);
    let (signed_tx, signed_rx) = mpsc::channel::<Result<Vec<u8>, CryptoError>>();
    {
        let identity = identity.clone();
        std::thread::spawn(move || {
            // The receiver is gone only if the test already failed.
            let _ = signed_tx.send(identity.sign(b"overlap"));
        });
    }
    let started = std::time::Instant::now();
    while identity.acquiring.load(Ordering::SeqCst) == before {
        if started.elapsed() > DEADLINE {
            // Release the parked transition so its worker can finish.
            let _ = release_tx.send(());
            return Err("the signer never reached authority acquisition".into());
        }
        std::thread::yield_now();
    }
    assert!(
        matches!(signed_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "a signature completed while the transition held the authority"
    );
    release_tx.send(())?;

    let installed = rotated_rx
        .recv_timeout(DEADLINE)
        .map_err(|_| "the transition did not finish")??;
    let signature = signed_rx
        .recv_timeout(DEADLINE)
        .map_err(|_| "the signer did not finish: deadlock behind the transition")??;
    assert!(verifies(&incoming, b"overlap", &signature)?);
    assert!(!verifies(&outgoing, b"overlap", &signature)?);
    // The reported anchor is the one the incoming key derives, and the one
    // the identity now names.
    assert_eq!(installed, Kappa::from_key("ed25519", &incoming)?);
    assert_eq!(identity.anchor()?, installed);
    assert_eq!(identity.status(), Availability::Active(installed));
    Ok(())
}

fn peer() -> PeerRecord {
    PeerRecord {
        endpoint: "https://peer".into(),
        asserter_anchor: Kappa::sha256(b"peer"),
        last_epoch: 1,
        state_root: Kappa::sha256(b"root"),
    }
}

#[test]
fn probes_set_the_trust_position() -> TestResult {
    let keys = keys()?;
    let identity = NodeIdentity::new(&settled(&keys)?);
    identity.update_from_probes(&[]);
    assert_eq!(identity.position(), TrustPosition::Unprobed);
    identity.update_from_probes(&[ProbeResult::Unreachable("down".into())]);
    assert_eq!(identity.position(), TrustPosition::Standalone);
    identity.update_from_probes(&[
        ProbeResult::Verified(peer()),
        ProbeResult::Unreachable("down".into()),
    ]);
    assert_eq!(
        identity.position(),
        TrustPosition::Federated { verified_peers: 1 }
    );
    identity.update_from_probes(&[
        ProbeResult::Verified(peer()),
        ProbeResult::SignatureInvalid("bad".into()),
        ProbeResult::Equivocation {
            peer: Kappa::sha256(b"peer"),
            epoch: 2,
            local_root: Kappa::sha256(b"a"),
            remote_root: Kappa::sha256(b"b"),
        },
    ]);
    assert_eq!(
        identity.position(),
        TrustPosition::Degraded {
            reason: DegradeReason::SignatureInvalid,
            reachable: 3,
            verified: 1,
        }
    );
    Ok(())
}
