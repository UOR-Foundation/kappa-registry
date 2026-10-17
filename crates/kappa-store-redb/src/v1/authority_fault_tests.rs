//! Rotation under injected storage faults, and the ordering between epoch
//! commit, the published-time bound and rotation.
//!
//! Each fault lands at a known point of redb 4.3's one-phase durable commit
//! (see [`Fault`]), so each test asserts the one persisted outcome that
//! point produces, not either of two.

use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, mpsc};

use kappa_crypto::SigningAuthority;
use kappa_crypto::ed25519::Ed25519Signer;
use kappa_fixture::FixtureRoot;
use kappa_handler::clock_at;
use kappa_store::{AuthorityRotationError, ClockMs, EpochStore, NamespaceRef, StoreError};

use super::{
    TestResult, acquisition_error, authenticated_replay_matches, authority, control, mismatch,
    publish_tag, rotation, succession,
};
use crate::PersistentStore;
use crate::test_hooks::Point;
use crate::test_support::{
    Fault, FaultBackend, FaultControl, OpOutcome, PersistentSpec, StorageOp,
};

type UnknownOutcomeResult = Result<
    (
        PersistentSpec,
        NamespaceRef,
        SigningAuthority,
        SigningAuthority,
        Vec<(StorageOp, OpOutcome)>,
    ),
    Box<dyn std::error::Error>,
>;

/// A store over a fault-injecting backend, signing as A, with namespace
/// `kept` and the activation control namespace published at 1000.
struct Faulty {
    spec: PersistentSpec,
    control: FaultControl,
    store: PersistentStore,
    ns: NamespaceRef,
    governing: NamespaceRef,
    a: SigningAuthority,
    b: SigningAuthority,
}

fn faulty() -> Result<Faulty, Box<dyn std::error::Error>> {
    let root = FixtureRoot::temporary()?;
    let (backend, control) = FaultBackend::factory(&root.resolve(Path::new("store.redb"))?)?;
    let spec = PersistentSpec::new().in_root(&root).backend(backend);
    let (a, b) = (authority(1)?, authority(2)?);
    let store = spec.clone().authority(a.clone()).acquire()?.into_store();
    let ns = NamespaceRef::generate("kept", ClockMs::from_raw(1000))?;
    publish_tag(&store, &ns, 1000, true, "kept")?;
    let governing = super::control(&store, 1000)?;
    Ok(Faulty {
        spec,
        control,
        store,
        ns,
        governing,
        a,
        b,
    })
}

/// Rotate A to B with `fault` armed and assert everything a failed rotation
/// commit leaves on its handle: an unknown outcome, the outgoing authority
/// still installed, the handle unresolved, a further rotation refused
/// before commit naming A, published history still admitted, and no
/// further write transaction. Then drop the handle with the fault armed,
/// disarm, and return what reopening needs.
fn rotate_into_unknown_outcome(faulty: Faulty, fault: Fault) -> UnknownOutcomeResult {
    let Faulty {
        spec,
        control,
        store,
        ns,
        governing,
        a,
        b,
    } = faulty;
    // The witness is signed before the fault is armed: only the rotation's
    // commit meets it.
    let succession_ab = succession(&a, &b, 2000)?;
    let witness = Ed25519Signer::from_bytes(&[77; 32])?;
    let origin = store.authority.load().origin().anchor().clone();
    let witnesses = vec![kappa_store::sign_witness(
        &witness,
        succession_ab.inner(),
        &origin,
        store.activation_domain(&governing)?,
        i64::MIN,
        None,
    )?];
    control.arm(fault);
    let outcome = store.rotate_authority(
        b.clone(),
        succession_ab,
        witnesses,
        &governing,
        &clock_at(ClockMs::from_raw(2000))?,
    );
    let trace = control.trace();
    assert!(
        matches!(outcome, Err(AuthorityRotationError::Indeterminate(_))),
        "a failed commit must report an unknown outcome, got {outcome:?}"
    );
    assert_eq!(
        &store.node_anchor(),
        a.anchor(),
        "uncommitted authority installed"
    );
    assert!(store.authority_unresolved(), "unknown outcome not recorded");
    let c = authority(3)?;
    let second = store.rotate_authority(
        c.clone(),
        succession(&a, &c, 2500)?,
        Vec::new(),
        &governing,
        &clock_at(ClockMs::from_raw(2500))?,
    );
    assert!(
        matches!(
            &second,
            Err(AuthorityRotationError::NotCommitted(
                StoreError::AuthorityUnresolved { outgoing }
            )) if outgoing.as_ref() == a.anchor()
        ),
        "a rotation on an unresolved handle must be refused before commit: {second:?}"
    );
    authenticated_replay_matches(&store, &ns)?;
    assert!(
        store.registry.begin_write().is_err(),
        "a registry whose commit failed must not admit further writes"
    );
    drop(store);
    control.disarm();
    Ok((spec, ns, a, b, trace))
}

/// Reopen and require the persisted head to be `head`, with `rows` history
/// rows, the other key refused by a typed mismatch naming `head`, the
/// authority resolved, and the published namespace still admitted.
fn reopens_to(
    spec: &PersistentSpec,
    ns: &NamespaceRef,
    head: &SigningAuthority,
    other: &SigningAuthority,
    rows: u64,
) -> Result<PersistentStore, Box<dyn std::error::Error>> {
    let refused = acquisition_error(spec.clone().authority(other.clone()).acquire())?;
    assert!(mismatch(&refused, other, head), "{refused:?}");
    let reopened = spec
        .clone()
        .authority(other.clone())
        .alternates(vec![head.clone()])
        .acquire()?
        .into_store();
    assert_eq!(&reopened.node_anchor(), head.anchor());
    assert_eq!(reopened.persisted_authority_rows()?, rows);
    assert!(
        !reopened.authority_unresolved(),
        "reopening resolves the authority"
    );
    authenticated_replay_matches(&reopened, ns)?;
    Ok(reopened)
}

/// Writes refused before they reach the file: the transition never lands,
/// so the store reopens under A only.
#[test]
fn rotation_with_refused_writes_reopens_under_the_outgoing_authority() -> TestResult {
    let (spec, ns, a, b, trace) = rotate_into_unknown_outcome(faulty()?, Fault::RefuseWrites)?;
    assert!(
        trace
            .iter()
            .any(|(op, outcome)| matches!(op, StorageOp::Write { .. })
                && *outcome == OpOutcome::Refused),
        "nothing was refused: {trace:?}"
    );
    assert!(
        !trace
            .iter()
            .any(|(op, outcome)| matches!(op, StorageOp::Write { .. })
                && *outcome != OpOutcome::Refused),
        "a write reached the file: {trace:?}"
    );
    let reopened = reopens_to(&spec, &ns, &a, &b, 1)?;
    assert!(reopened.retired_authorities().is_empty());
    publish_tag(&reopened, &ns, 3000, false, "after")?;
    Ok(())
}

/// Synchronized, then reported failed: the transition is durable although
/// its writer was told otherwise, so the store reopens under B only, with A
/// retired, and the outgoing key is refused.
#[test]
fn unacknowledged_durable_rotation_reopens_under_the_incoming_authority() -> TestResult {
    let (spec, ns, a, b, trace) = rotate_into_unknown_outcome(faulty()?, Fault::FailSyncAfter)?;
    assert_eq!(
        trace
            .iter()
            .filter(|(op, _)| *op == StorageOp::Sync)
            .map(|(_, outcome)| *outcome)
            .collect::<Vec<_>>(),
        vec![OpOutcome::PerformedThenFailed],
        "the one-phase commit synchronizes once, after switching the header"
    );
    let reopened = reopens_to(&spec, &ns, &b, &a, 2)?;
    assert_eq!(reopened.retired_authorities(), vec![a.anchor().clone()]);
    let next = reopened.epoch_get(&publish_tag(&reopened, &ns, 3000, false, "after")?)?;
    assert_eq!(next.signer_anchor(), b.anchor());
    Ok(())
}

/// Synchronization refused after the commit's writes reached the file:
/// without a crash the written header stays in the file and redb's
/// one-phase recovery selects it, so the store reopens under B.
#[test]
fn rotation_with_refused_sync_after_writes_reopens_under_the_incoming_authority() -> TestResult {
    let (spec, ns, a, b, trace) = rotate_into_unknown_outcome(faulty()?, Fault::FailSyncBefore)?;
    assert!(
        trace
            .iter()
            .any(|(op, outcome)| matches!(op, StorageOp::Write { .. })
                && *outcome == OpOutcome::Performed),
        "the commit's writes did not reach the file: {trace:?}"
    );
    reopens_to(&spec, &ns, &b, &a, 2)?;
    Ok(())
}

/// A rotation refused before its commit leaves A committed, installed and
/// operational: nothing persisted, nothing unresolved, and A keeps sealing.
#[test]
fn rejected_rotation_keeps_the_outgoing_authority_operational() -> TestResult {
    let Faulty {
        store,
        ns,
        governing,
        a,
        b,
        ..
    } = faulty()?;
    let refused = rotation(&store, &governing, &b, succession(&a, &b, 1000)?, 2000)?;
    assert!(
        matches!(
            refused,
            Err(AuthorityRotationError::NotCommitted(StoreError::Rejected(
                _
            )))
        ),
        "{refused:?}"
    );
    assert!(!store.authority_unresolved());
    assert_eq!(store.persisted_authority_rows()?, 1);
    let next = store.epoch_get(&publish_tag(&store, &ns, 2500, false, "after")?)?;
    assert_eq!(next.signer_anchor(), a.anchor());
    authenticated_replay_matches(&store, &ns)?;
    Ok(())
}

/// An unresolved handle refuses rotation through its authority gate, not
/// through storage: on a database that still admits write transactions the
/// refusal is the typed authority state, and nothing is persisted.
#[test]
fn unresolved_authority_refuses_rotation_on_a_writable_database() -> TestResult {
    let Faulty {
        store,
        ns,
        governing,
        a,
        b,
        ..
    } = faulty()?;
    store.authority_unresolved.store(true, Ordering::SeqCst);
    let refused = rotation(&store, &governing, &b, succession(&a, &b, 2000)?, 2000)?;
    assert!(
        matches!(
            &refused,
            Err(AuthorityRotationError::NotCommitted(
                StoreError::AuthorityUnresolved { outgoing }
            )) if outgoing.as_ref() == a.anchor()
        ),
        "{refused:?}"
    );
    assert!(
        store.registry.begin_write().is_ok(),
        "the refusal must come from the authority gate, not from storage"
    );
    assert_eq!(store.persisted_authority_rows()?, 1);
    assert_eq!(&store.node_anchor(), a.anchor());
    authenticated_replay_matches(&store, &ns)?;
    Ok(())
}

/// Bound on every cross-thread wait in the overlap test.
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// A publication holds the shared activation gate from its commit until it
/// has raised the published-time bound. A rotation that obtains the
/// database writer the moment that commit releases it must wait at the gate,
/// and then sees the bound: a succession effective at the committed epoch's
/// time is rejected. The interleaving is forced by the store's pause points.
///
/// Workers are detached threads reporting over channels, and every wait is
/// bounded: a regression that deadlocks fails at its deadline instead of
/// hanging the suite, and the stuck workers are left behind rather than
/// joined.
#[test]
fn rotation_cannot_pass_a_commit_before_its_time_bound() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let (a, b) = (authority(1)?, authority(2)?);
    let store = Arc::new(
        PersistentSpec::new()
            .in_root(&root)
            .authority(a.clone())
            .acquire()?
            .into_store(),
    );
    let ns = NamespaceRef::generate("bounded", ClockMs::from_raw(1000))?;
    publish_tag(&store, &ns, 1000, true, "first")?;
    let governing = control(&store, 1000)?;
    let rotation_record = succession(&a, &b, 2000)?;
    let rotation_witnesses = vec![kappa_store::sign_witness(
        &Ed25519Signer::from_bytes(&[77; 32])?,
        rotation_record.inner(),
        &store.authority.load().origin().anchor().clone(),
        store.activation_domain(&governing)?,
        i64::MIN,
        None,
    )?];
    let rotation_clock = clock_at(ClockMs::from_raw(2500))?;

    let (committed_tx, committed_rx) = mpsc::channel::<()>();
    let (proceed_tx, proceed_rx) = mpsc::channel::<()>();
    let proceed_rx = Mutex::new(proceed_rx);
    // A hook runs on a worker thread. If the test thread stops waiting, the
    // hook's own bounded wait ends and the worker finishes.
    store.hooks.install(Point::AfterEpochCommit, move || {
        let _ = committed_tx.send(());
        let receiver = proceed_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = receiver.recv_timeout(DEADLINE);
    });
    let (writer_tx, writer_rx) = mpsc::channel::<()>();
    store.hooks.install(Point::RotationWriterHeld, move || {
        let _ = writer_tx.send(());
    });

    let (published_tx, published_rx) = mpsc::channel();
    let publisher = {
        let (store, ns) = (Arc::clone(&store), ns);
        move || {
            let outcome =
                publish_tag(&store, &ns, 2000, false, "second").map_err(|error| error.to_string());
            let _ = published_tx.send(outcome);
        }
    };
    std::thread::spawn(publisher);
    committed_rx
        .recv_timeout(DEADLINE)
        .map_err(|_| "publication never reached its commit")?;

    let (rotated_tx, rotated_rx) = mpsc::channel();
    let rotation = {
        let (store, b) = (Arc::clone(&store), b);
        move || {
            let outcome = store.rotate_authority(
                b,
                rotation_record,
                rotation_witnesses,
                &governing,
                &rotation_clock,
            );
            let _ = rotated_tx.send(outcome);
        }
    };
    std::thread::spawn(rotation);
    // The rotation holds the writer the publication released and is about
    // to request the gate the publication still holds shared.
    let writer_held = writer_rx.recv_timeout(DEADLINE);
    // Release the publication whatever happened, so a failure below does
    // not also leave it parked.
    proceed_tx.send(())?;
    writer_held.map_err(|_| "rotation never obtained the database writer")?;

    published_rx
        .recv_timeout(DEADLINE)
        .map_err(|_| "publication did not finish: deadlock between commit and rotation")??;
    let outcome = rotated_rx
        .recv_timeout(DEADLINE)
        .map_err(|_| "rotation did not finish: deadlock at the activation gate")?;
    assert!(
        matches!(
            outcome,
            Err(AuthorityRotationError::NotCommitted(StoreError::Rejected(
                _
            )))
        ),
        "a rotation passed a committed epoch's time bound: {outcome:?}"
    );
    store.hooks.clear(Point::AfterEpochCommit);
    store.hooks.clear(Point::RotationWriterHeld);
    assert_eq!(&store.node_anchor(), a.anchor());
    assert_eq!(store.persisted_authority_rows()?, 1);
    Ok(())
}

/// A publication prepared and then abandoned commits nothing and does not
/// bound rotation; a store reopened after real publications recovers the
/// bound from its persisted epoch heads.
#[test]
fn only_committed_epochs_bound_rotation_and_reopen_recovers_the_bound() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let (a, b, c) = (authority(1)?, authority(2)?, authority(3)?);
    let spec = PersistentSpec::new().in_root(&root);
    let store = spec.clone().authority(a.clone()).acquire()?.into_store();
    let ns = NamespaceRef::generate("abandoned", ClockMs::from_raw(1000))?;
    publish_tag(&store, &ns, 1000, true, "first")?;
    let governing = control(&store, 1000)?;

    let writer = store.test_writer(&ns)?;
    let abandoned = store.prepare_test_writer(writer, &ns, ClockMs::from_raw(5000))?;
    drop(abandoned);
    assert_eq!(store.latest_epoch_ms.load(Ordering::SeqCst), 1000);
    rotation(&store, &governing, &b, succession(&a, &b, 3000)?, 3000)??;
    publish_tag(&store, &ns, 4000, false, "second")?;
    drop(store);

    let reopened = spec
        .authority(a)
        .alternates(vec![b.clone()])
        .acquire()?
        .into_store();
    assert_eq!(reopened.latest_epoch_ms.load(Ordering::SeqCst), 4000);
    let refused = rotation(&reopened, &governing, &c, succession(&b, &c, 4000)?, 4500)?;
    assert!(
        matches!(
            refused,
            Err(AuthorityRotationError::NotCommitted(StoreError::Rejected(
                _
            )))
        ),
        "{refused:?}"
    );
    rotation(&reopened, &governing, &c, succession(&b, &c, 4500)?, 4500)??;
    assert_eq!(&reopened.node_anchor(), c.anchor());
    authenticated_replay_matches(&reopened, &ns)?;
    Ok(())
}
