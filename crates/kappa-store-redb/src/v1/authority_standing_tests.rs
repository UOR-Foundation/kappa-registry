//! Standing of rotation witnesses at activation, read through predicate
//! discovery: a revocation or watermark of a witness's asserter refuses the
//! activation from its commit on, before settlement projects it and after,
//! and activation is `Unavailable` while discovery cannot claim to name
//! every instance holding such a record. The standing observed holds
//! through the activation's commit: a revocation cannot be signed or
//! committed between the check and the commit.

use std::sync::{Arc, Mutex, mpsc};

use kappa_crypto::SigningAuthority;
use kappa_crypto::ed25519::Ed25519Signer;
use kappa_crypto::signed_types::{sign_revocation, sign_watermark};
use kappa_fixture::FixtureRoot;
use kappa_handler::clock_at;
use kappa_store::{
    AuthorityRotationError, Axis, ClockMs, EpochStore, ExecutionStore, Kappa, NamespaceRef,
    Revocation, RevocationReason, SignedPayload, StoreError, VerifiedSuccession, Watermark,
    WatermarkReason, WitnessEvidence, canonical_bytes,
};

use super::{TestResult, authority, control, open, publish_tag, succession};
use crate::PersistentStore;
use crate::settlement::Origin;
use crate::store_access::Coverage;
use crate::test_hooks::Point;
use crate::unsettled_index::DiscoveryKey;

/// Bound on every cross-thread wait that must complete.
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
/// How long a publication is given to commit while a rotation is paused
/// between its standing check and its commit. The fence makes the wait
/// always expire; a publication slower than this would hide a missing
/// fence, never fail a correct one.
const WINDOW: std::time::Duration = std::time::Duration::from_millis(500);

/// Seed of the witness whose standing each test changes.
const WITNESS: [u8; 32] = [91; 32];
/// Seed of a witness nothing revokes.
const STANDING: [u8; 32] = [92; 32];
/// When every witness's validity begins.
const VALID_FROM: i64 = 1000;
/// When every succession takes effect, and the rotation's clock.
const EFFECTIVE: i64 = 2000;

/// Advance the retained production clock inside the governing signing call,
/// after the signature has been produced but before publication can commit.
struct ExpiringSigner {
    signer: Ed25519Signer,
    clock: Arc<dyn kappa_store::time::Clock>,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl kappa_crypto::Signer for ExpiringSigner {
    fn algorithm(&self) -> &'static str {
        kappa_crypto::Signer::algorithm(&self.signer)
    }

    fn public_key(&self) -> &[u8] {
        kappa_crypto::Signer::public_key(&self.signer)
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, kappa_crypto::CryptoError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let signature = kappa_crypto::Signer::sign(&self.signer, message)?;
        for _ in 0..8 {
            self.clock
                .now()
                .map_err(|error| kappa_crypto::CryptoError::SigningFailed {
                    algorithm: self.algorithm().into(),
                    reason: error.to_string(),
                })?;
        }
        Ok(signature)
    }
}

#[test]
fn witness_expiring_inside_signing_retains_the_governing_epoch() -> TestResult {
    use kappa_store::time::Clock;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let root = FixtureRoot::temporary()?;
    let store = open(&root, 1)?;
    let (a, b) = (authority(1)?, authority(2)?);
    let control = control(&store, VALID_FROM)?;
    let head = store.epoch_current(&control)?;
    let record = succession(&a, &b, EFFECTIVE)?;
    let witnessed = kappa_store::sign_witness(
        &Ed25519Signer::from_bytes(&WITNESS)?,
        record.inner(),
        &store.authority_origin(),
        store.activation_domain(&control)?,
        VALID_FROM,
        Some(EFFECTIVE + 5),
    )?;
    let clock = clock_at(ClockMs::from_raw(EFFECTIVE))?;
    let calls = Arc::new(AtomicUsize::new(0));
    let incoming = SigningAuthority::new(Arc::new(ExpiringSigner {
        signer: Ed25519Signer::from_bytes(&[2; 32])?,
        clock: clock.retain(),
        calls: Arc::clone(&calls),
    }))?;
    let outcome = store.rotate_authority(incoming, record, vec![witnessed], &control, &clock);
    assert!(matches!(outcome, Err(AuthorityRotationError::Retained(
        StoreError::PublicationRetained(ref retained)
    )) if retained.disposition == kappa_store::RecoveryDisposition::Terminal));
    assert_eq!(store.epoch_current(&control)?, head);
    assert_eq!(&store.node_anchor(), a.anchor());
    assert!(store.activation_intent_pending()?);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let resolved = ExecutionStore::resolve_publication(
        &store,
        &control,
        &clock,
        &mut kappa_store::work::WorkMeter::new(store.step_limit),
    )?;
    assert!(
        matches!(resolved, kappa_store::PublicationResolution::Retained(ref retained)
        if retained.disposition == kappa_store::RecoveryDisposition::Terminal)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.epoch_current(&control)?, head);
    Ok(())
}

/// The witness by `seed` of `succession`, activating in `control`.
fn witness(
    store: &PersistentStore,
    control: &NamespaceRef,
    succession: &VerifiedSuccession,
    seed: [u8; 32],
) -> Result<WitnessEvidence, Box<dyn std::error::Error>> {
    let signer = Ed25519Signer::from_bytes(&seed)?;
    Ok(kappa_store::sign_witness(
        &signer,
        succession.inner(),
        &store.authority_origin(),
        store.activation_domain(control)?,
        VALID_FROM,
        None,
    )?)
}

/// `record` admitted again: the same succession, so the same identity every
/// witness of it binds. `VerifiedSuccession` is consumed by a rotation.
fn again(
    record: &VerifiedSuccession,
    old: &SigningAuthority,
    new: &SigningAuthority,
) -> Result<VerifiedSuccession, StoreError> {
    VerifiedSuccession::verify(
        record.inner().clone(),
        old.signer().algorithm(),
        old.signer().public_key(),
        new.signer().algorithm(),
        new.signer().public_key(),
    )
}

/// Rotate `store` to `next` witnessed by `witness` alone.
fn rotate(
    store: &PersistentStore,
    control: &NamespaceRef,
    next: &SigningAuthority,
    succession: VerifiedSuccession,
    witness: WitnessEvidence,
) -> Result<Result<(), AuthorityRotationError>, Box<dyn std::error::Error>> {
    Ok(store.rotate_authority(
        next.clone(),
        succession,
        vec![witness],
        control,
        &clock_at(ClockMs::from_raw(EFFECTIVE))?,
    ))
}

/// The rotation was refused as `Rejected` and nothing was committed: the
/// origin is still the only history row and `current` still signs.
fn refused_as_rejected(
    store: &PersistentStore,
    outcome: &Result<(), AuthorityRotationError>,
    current: &SigningAuthority,
) -> TestResult {
    assert!(
        matches!(
            outcome,
            Err(AuthorityRotationError::NotCommitted(StoreError::Rejected(
                _
            )))
        ),
        "a witness without standing activated a rotation: {outcome:?}"
    );
    assert_eq!(store.persisted_authority_rows()?, 1);
    assert_eq!(&store.node_anchor(), current.anchor());
    Ok(())
}

/// A namespace that publishes the witness asserter's records, created at
/// `VALID_FROM`.
fn issuer(store: &PersistentStore) -> Result<NamespaceRef, Box<dyn std::error::Error>> {
    let ns = NamespaceRef::generate("witness-issuer", ClockMs::from_raw(VALID_FROM))?;
    publish_tag(store, &ns, VALID_FROM, true, "issuer")?;
    Ok(ns)
}

/// A revocation of the witness committed and not yet settled refuses the
/// activation; settled, it still does; a second witness nothing revoked
/// activates the same succession, so the refusal was the revocation's.
#[test]
fn a_revoked_witness_refuses_activation_before_and_after_settlement() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let store = open(&root, 1)?;
    let (a, b) = (authority(1)?, authority(2)?);
    let control = control(&store, VALID_FROM)?;
    let issuer = issuer(&store)?;
    let record = succession(&a, &b, EFFECTIVE)?;
    let revoked = witness(&store, &control, &record, WITNESS)?;
    let signer = Ed25519Signer::from_bytes(&WITNESS)?;
    let revocation = sign_revocation(
        Revocation {
            assertion_kappa: Kappa::compute(Axis::Sha256, &canonical_bytes(&revoked.assertion))?,
            asserter: revoked.assertion.asserter.clone(),
            reason: RevocationReason::KeyCompromise,
            revoked_at_ms: 1500,
            cose_signature: SignedPayload::empty(),
        },
        &signer,
    )?;
    let mut execution = store.begin_execution(&issuer, &clock_at(ClockMs::from_raw(1500))?)?;
    let identity = execution.revocation_put(&revocation)?;
    execution.publish()?;

    // Control: committed, registered under its predicate, not projected.
    assert!(store.pending_settlements()?.contains(issuer.id()));
    assert!(
        !store
            .unsettled_candidates(
                &DiscoveryKey::RevocationsBy(revocation.asserter.clone()),
                &mut kappa_store::work::WorkMeter::unbounded(),
            )?
            .is_empty(),
        "the revocation is registered under its asserter before settlement"
    );
    assert!(matches!(
        store.read_revocation(&identity, &mut store.read_meter()),
        Err(StoreError::NotFound(_))
    ));
    refused_as_rejected(
        &store,
        &rotate(
            &store,
            &control,
            &b,
            again(&record, &a, &b)?,
            revoked.clone(),
        )?,
        &a,
    )?;

    store.settlement_step(u64::MAX)?;
    assert!(!store.pending_settlements()?.contains(issuer.id()));
    assert_eq!(
        store.read_revocation(&identity, &mut store.read_meter())?,
        revocation
    );
    refused_as_rejected(
        &store,
        &rotate(&store, &control, &b, again(&record, &a, &b)?, revoked)?,
        &a,
    )?;

    let standing = witness(&store, &control, &record, STANDING)?;
    rotate(&store, &control, &b, record, standing)??;
    assert_eq!(store.persisted_authority_rows()?, 2);
    assert_eq!(&store.node_anchor(), b.anchor());
    Ok(())
}

/// A watermark of the witness's asserter invalidating assertions from
/// before `VALID_FROM` onwards refuses the activation while it is unsettled.
#[test]
fn an_unsettled_watermark_of_the_witness_refuses_activation() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let store = open(&root, 1)?;
    let (a, b) = (authority(1)?, authority(2)?);
    let control = control(&store, VALID_FROM)?;
    let issuer = issuer(&store)?;
    let record = succession(&a, &b, EFFECTIVE)?;
    let invalidated = witness(&store, &control, &record, WITNESS)?;
    let watermark = sign_watermark(
        Watermark {
            asserter: invalidated.assertion.asserter.clone(),
            invalidate_before_ms: VALID_FROM + 1,
            reason: WatermarkReason::KeyCompromise,
            set_at_ms: 1500,
            cose_signature: SignedPayload::empty(),
        },
        &Ed25519Signer::from_bytes(&WITNESS)?,
    )?;
    let mut execution = store.begin_execution(&issuer, &clock_at(ClockMs::from_raw(1500))?)?;
    execution.watermark_put(&watermark)?;
    execution.publish()?;

    assert!(store.pending_settlements()?.contains(issuer.id()));
    assert!(
        !store
            .unsettled_candidates(
                &DiscoveryKey::WatermarksBy(watermark.asserter),
                &mut kappa_store::work::WorkMeter::unbounded(),
            )?
            .is_empty(),
        "the watermark is registered under its asserter before settlement"
    );
    refused_as_rejected(
        &store,
        &rotate(&store, &control, &b, again(&record, &a, &b)?, invalidated)?,
        &a,
    )?;
    let standing = witness(&store, &control, &record, STANDING)?;
    rotate(&store, &control, &b, record, standing)??;
    assert_eq!(&store.node_anchor(), b.anchor());
    Ok(())
}

/// While an unresolved recovery obligation leaves discovery incomplete, the
/// absence of a revocation cannot be established, so activation is
/// `Unavailable` and commits nothing; once settlement resolves the
/// obligation the same witness activates.
#[test]
fn incomplete_discovery_makes_activation_unavailable() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let store = open(&root, 1)?;
    let (a, b) = (authority(1)?, authority(2)?);
    let control = control(&store, VALID_FROM)?;
    let failed = issuer(&store)?;
    let failed_instance = store.namespace_snapshot(&failed)?.controller().instance;
    let record = succession(&a, &b, EFFECTIVE)?;
    let standing = witness(&store, &control, &record, STANDING)?;
    // Recorded the way recovery records an instance whose effects it cannot
    // read.
    store.record_unresolved(
        &failed_instance,
        Origin::Marker,
        "effects unreadable".into(),
    )?;
    assert!(matches!(
        store.discovery_coverage(),
        Coverage::Incomplete { .. }
    ));

    let outcome = rotate(
        &store,
        &control,
        &b,
        again(&record, &a, &b)?,
        standing.clone(),
    )?;
    assert!(
        matches!(
            &outcome,
            Err(AuthorityRotationError::NotCommitted(
                StoreError::Unavailable(_)
            ))
        ),
        "activation claimed standing under incomplete discovery: {outcome:?}"
    );
    assert_eq!(store.persisted_authority_rows()?, 1);
    assert_eq!(&store.node_anchor(), a.anchor());

    store.settlement_step(u64::MAX)?;
    assert_eq!(store.discovery_coverage(), Coverage::Complete);
    rotate(&store, &control, &b, record, standing)??;
    assert_eq!(store.persisted_authority_rows()?, 2);
    assert_eq!(&store.node_anchor(), b.anchor());
    Ok(())
}

/// A rotation paused after finding its witness standing, holding the
/// exclusive activation gate, admits no revocation of that witness: the
/// revocation's publication waits at the shared gate it signs under, so it
/// commits only after the activation, signed by the incoming authority.
/// Standing observed under the gate is standing at the commit.
#[test]
fn a_revocation_cannot_commit_between_standing_and_activation() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let store = Arc::new(open(&root, 1)?);
    let (a, b) = (authority(1)?, authority(2)?);
    let control = control(&store, VALID_FROM)?;
    let issuer = issuer(&store)?;
    let record = succession(&a, &b, EFFECTIVE)?;
    let witnessed = witness(&store, &control, &record, WITNESS)?;
    let revocation = sign_revocation(
        Revocation {
            assertion_kappa: Kappa::compute(Axis::Sha256, &canonical_bytes(&witnessed.assertion))?,
            asserter: witnessed.assertion.asserter.clone(),
            reason: RevocationReason::KeyCompromise,
            revoked_at_ms: 2500,
            cose_signature: SignedPayload::empty(),
        },
        &Ed25519Signer::from_bytes(&WITNESS)?,
    )?;

    let (checked_tx, checked_rx) = mpsc::channel::<()>();
    let (proceed_tx, proceed_rx) = mpsc::channel::<()>();
    let proceed_rx = Mutex::new(proceed_rx);
    store
        .hooks
        .install(Point::RotationStandingChecked, move || {
            // A test that stopped waiting reports its own deadline; the
            // rotation is not failed by it.
            let _ = checked_tx.send(());
            let receiver = proceed_rx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Bounded: if the test stops waiting, the rotation continues.
            let _ = receiver.recv_timeout(DEADLINE);
        });
    let (committed_tx, committed_rx) = mpsc::channel::<()>();
    store.hooks.install(Point::AfterEpochCommit, move || {
        // Commits after the test stopped listening are not observations.
        let _ = committed_tx.send(());
    });

    let (rotated_tx, rotated_rx) = mpsc::channel();
    {
        let (store, b) = (Arc::clone(&store), b.clone());
        let clock = clock_at(ClockMs::from_raw(EFFECTIVE))?;
        std::thread::spawn(move || {
            let outcome = store.rotate_authority(b, record, vec![witnessed], &control, &clock);
            // The test thread reports a missing outcome at its deadline.
            let _ = rotated_tx.send(outcome);
        });
    }
    checked_rx
        .recv_timeout(DEADLINE)
        .map_err(|_| "rotation never reached its standing check")?;

    let (published_tx, published_rx) = mpsc::channel();
    {
        let store = Arc::clone(&store);
        let clock = clock_at(ClockMs::from_raw(2500))?;
        std::thread::spawn(move || {
            let outcome = (|| {
                let mut execution = store.begin_execution(&issuer, &clock)?;
                execution.revocation_put(&revocation)?;
                Ok::<_, StoreError>(execution.publish()?.root)
            })();
            // The test thread reports a missing outcome at its deadline.
            let _ = published_tx.send(outcome);
        });
    }
    let early = committed_rx.recv_timeout(WINDOW);
    // Release the rotation whatever happened, so a failure below does not
    // also leave it parked.
    proceed_tx.send(())?;
    assert!(
        matches!(early, Err(mpsc::RecvTimeoutError::Timeout)),
        "an epoch committed while a rotation held its standing check uncommitted: {early:?}"
    );

    let outcome = rotated_rx
        .recv_timeout(DEADLINE)
        .map_err(|_| "rotation did not finish: deadlock at the activation gate")?;
    assert!(
        outcome.is_ok(),
        "the witness stood when checked: {outcome:?}"
    );
    let revocation_root = published_rx
        .recv_timeout(DEADLINE)
        .map_err(|_| "revocation publication did not finish")??;
    store.hooks.clear(Point::RotationStandingChecked);
    store.hooks.clear(Point::AfterEpochCommit);
    assert_eq!(
        store.epoch_get(&revocation_root)?.signer_anchor(),
        b.anchor(),
        "the revocation is ordered after the activation"
    );
    assert_eq!(store.persisted_authority_rows()?, 2);
    Ok(())
}
