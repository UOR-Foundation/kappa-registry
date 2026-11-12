//! Activation under injected faults, and the ordering between epoch commit,
//! the published-time bound and activation.
//!
//! An activation commits exactly when its governing epoch commits in the
//! control namespace. The governing commit is faulted on the control
//! namespace's own database, at known points of redb 4.3's one-phase
//! durable commit (see [`Fault`]); the registry's intent and projection are
//! faulted on the registry's database. Each test asserts the one outcome
//! its point produces, on the handle and after reopening.

use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, mpsc};

use kappa_crypto::SigningAuthority;
use kappa_crypto::ed25519::Ed25519Signer;
use kappa_fixture::FixtureRoot;
use kappa_handler::clock_at;
use kappa_store::{
    AuthorityRotationError, ClockMs, EpochStore, ExecutionStore, NamespaceRef, StoreError,
};

use super::{
    TestResult, acquisition_error, authenticated_replay_matches, authority, control, mismatch,
    publish_tag, rotation, succession,
};
use crate::PersistentStore;
use crate::test_hooks::Point;
use crate::test_support::{
    Fault, FaultBackend, FaultControl, OpOutcome, PersistentSpec, StorageOp,
};

/// A store signing as A, with namespace `kept` and the control namespace
/// published at 1000; the registry and the control namespace's database
/// each on a fault-injecting backend.
struct Faulty {
    spec: PersistentSpec,
    registry: FaultControl,
    governing_db: FaultControl,
    store: PersistentStore,
    ns: NamespaceRef,
    governing: NamespaceRef,
    a: SigningAuthority,
    b: SigningAuthority,
}

fn faulty() -> Result<Faulty, Box<dyn std::error::Error>> {
    let root = FixtureRoot::temporary()?;
    let (registry_backend, registry) =
        FaultBackend::factory(&root.resolve(Path::new("store.redb"))?)?;
    let spec = PersistentSpec::new()
        .in_root(&root)
        .backend(registry_backend);
    let (a, b) = (authority(1)?, authority(2)?);
    let ns = NamespaceRef::generate("kept", ClockMs::from_raw(1000))?;
    // Deterministic, so its database can be put behind its own backend
    // when the store reopens.
    let governing = NamespaceRef::deterministic("activation-control");
    {
        let store = spec.clone().authority(a.clone()).acquire()?.into_store();
        publish_tag(&store, &ns, 1000, true, "kept")?;
        publish_tag(&store, &governing, 1000, true, "control")?;
    }
    let directory = crate::storage::NamespaceController::directory(
        &root.resolve(Path::new("."))?,
        governing.id(),
    );
    let (governing_backend, governing_db) = FaultBackend::factory(&directory.join("state.redb"))?;
    let spec = spec.namespace_backend(*governing.id(), governing_backend);
    let store = spec.clone().authority(a.clone()).acquire()?.into_store();
    Ok(Faulty {
        spec,
        registry,
        governing_db,
        store,
        ns,
        governing,
        a,
        b,
    })
}

/// The rotation A to B of `faulty`, effective and clocked at 2000,
/// witnessed in its control namespace.
fn rotate_ab(
    faulty: &Faulty,
) -> Result<Result<(), AuthorityRotationError>, Box<dyn std::error::Error>> {
    rotation(
        &faulty.store,
        &faulty.governing,
        &faulty.b,
        succession(&faulty.a, &faulty.b, 2000)?,
        2000,
    )
}

/// Everything an activation whose governing commit outcome is unknown
/// leaves on its handle: the outcome reported unknown, the outgoing
/// authority still installed, the handle unresolved, a further rotation
/// refused before commit naming A, the control namespace fenced, and
/// published history still admitted. The handle drops with the fault
/// armed; the fault is disarmed for the reopen.
fn rotate_into_unknown_outcome(
    faulty: Faulty,
    fault: Fault,
) -> Result<Unknown, Box<dyn std::error::Error>> {
    faulty.governing_db.arm(fault);
    let outcome = rotate_ab(&faulty)?;
    let trace = faulty.governing_db.trace();
    assert!(
        matches!(outcome, Err(AuthorityRotationError::Indeterminate(_))),
        "a failed governing commit must report an unknown outcome, got {outcome:?}"
    );
    assert_eq!(
        &faulty.store.node_anchor(),
        faulty.a.anchor(),
        "an activation of unknown outcome installed its candidate"
    );
    assert!(
        faulty.store.authority_unresolved(),
        "unknown outcome not recorded"
    );
    let c = authority(3)?;
    let second = rotation(
        &faulty.store,
        &faulty.governing,
        &c,
        succession(&faulty.a, &c, 2500)?,
        2500,
    )?;
    assert!(
        matches!(
            &second,
            Err(AuthorityRotationError::NotCommitted(
                StoreError::AuthorityUnresolved { outgoing }
            )) if outgoing.as_ref() == faulty.a.anchor()
        ),
        "a rotation on an unresolved handle must be refused before commit: {second:?}"
    );
    assert!(
        matches!(
            faulty
                .store
                .begin_execution(&faulty.governing, &clock_at(ClockMs::from_raw(2600))?),
            Err(StoreError::Conflict(_))
        ),
        "the control namespace of an unknown governing outcome admitted an execution"
    );
    authenticated_replay_matches(&faulty.store, &faulty.ns)?;
    let Faulty {
        spec,
        governing_db,
        store,
        ns,
        a,
        b,
        ..
    } = faulty;
    drop(store);
    governing_db.disarm();
    Ok(Unknown {
        spec,
        ns,
        a,
        b,
        trace,
    })
}

/// What an activation of unknown outcome leaves for the reopen: the store
/// spec, the published namespace, both authorities and the governing
/// database's operation trace.
struct Unknown {
    spec: PersistentSpec,
    ns: NamespaceRef,
    a: SigningAuthority,
    b: SigningAuthority,
    trace: Vec<(StorageOp, OpOutcome)>,
}

/// Reopen and require the recovered authority to be `head`, with `rows`
/// history rows and no pending intent, the other key refused by a typed
/// mismatch naming `head`, the authority resolved, and the published
/// namespace still admitted.
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
        !reopened.activation_intent_pending()?,
        "reopening resolves the activation intent"
    );
    assert!(
        !reopened.authority_unresolved(),
        "reopening resolves the authority"
    );
    authenticated_replay_matches(&reopened, ns)?;
    Ok(reopened)
}

/// The governing epoch is refused at the last point before its commit: a
/// known noncommit after signing. The outgoing authority stays installed,
/// the intent and incoming capability stay owned, and resolution publishes
/// the retained governing epoch before B starts ordinary publication.
#[test]
fn a_refused_governing_commit_keeps_the_outgoing_authority() -> TestResult {
    let faulty = faulty()?;
    let head_before = faulty.store.epoch_current(&faulty.governing)?;
    faulty.store.hooks.refuse_activation_commit(true);
    let outcome = rotate_ab(&faulty)?;
    faulty.store.hooks.refuse_activation_commit(false);
    assert!(
        matches!(
            outcome,
            Err(AuthorityRotationError::Retained(
                StoreError::PublicationRetained(_)
            ))
        ),
        "{outcome:?}"
    );
    assert_eq!(&faulty.store.node_anchor(), faulty.a.anchor());
    assert!(faulty.store.authority_unresolved());
    assert!(faulty.store.activation_intent_pending()?);
    assert_eq!(faulty.store.persisted_authority_rows()?, 1);
    assert_eq!(faulty.store.epoch_current(&faulty.governing)?, head_before);
    let resolution = ExecutionStore::resolve_publication(
        &faulty.store,
        &faulty.governing,
        &clock_at(ClockMs::from_raw(2500))?,
        &mut kappa_store::work::WorkMeter::new(faulty.store.step_limit),
    )?;
    assert!(matches!(
        resolution,
        kappa_store::PublicationResolution::Published(_)
    ));
    assert_eq!(&faulty.store.node_anchor(), faulty.b.anchor());
    assert!(!faulty.store.authority_unresolved());
    assert!(!faulty.store.activation_intent_pending()?);
    let next = faulty.store.epoch_get(&publish_tag(
        &faulty.store,
        &faulty.ns,
        2500,
        false,
        "after",
    )?)?;
    assert_eq!(next.signer_anchor(), faulty.b.anchor());
    let Faulty {
        spec,
        store,
        ns,
        a,
        b,
        ..
    } = faulty;
    drop(store);
    let reopened = reopens_to(&spec, &ns, &b, &a, 2)?;
    assert_eq!(reopened.retired_authorities(), vec![a.anchor().clone()]);
    Ok(())
}

/// Writes of the governing commit refused before they reach the file: its
/// epoch never lands. Reopen keeps A installed and B in custody; resolving
/// that exact governing candidate installs B without another rotation.
#[test]
fn refused_governing_writes_reopen_under_the_outgoing_authority() -> TestResult {
    let Unknown {
        spec,
        ns,
        a,
        b,
        trace,
    } = rotate_into_unknown_outcome(faulty()?, Fault::RefuseWrites)?;
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
    let reopened = spec
        .authority(a.clone())
        .alternates(vec![b.clone()])
        .acquire()?
        .into_store();
    assert_eq!(&reopened.node_anchor(), a.anchor());
    assert!(reopened.activation_intent_pending()?);
    assert!(reopened.authority_unresolved());
    assert!(reopened.retired_authorities().is_empty());
    let resolution = ExecutionStore::resolve_publication(
        &reopened,
        &NamespaceRef::deterministic("activation-control"),
        &clock_at(ClockMs::from_raw(3000))?,
        &mut kappa_store::work::WorkMeter::new(reopened.step_limit),
    )?;
    assert!(matches!(
        resolution,
        kappa_store::PublicationResolution::Published(_)
    ));
    assert_eq!(&reopened.node_anchor(), b.anchor());
    publish_tag(&reopened, &ns, 3000, false, "after")?;
    Ok(())
}

/// Synchronized, then reported failed: the governing epoch is durable
/// although its activation was told otherwise, so the store reopens under
/// B only, with A retired and the history row projected from the evidence.
#[test]
fn an_unacknowledged_durable_governing_epoch_reopens_under_the_incoming_authority() -> TestResult {
    let Unknown {
        spec,
        ns,
        a,
        b,
        trace,
    } = rotate_into_unknown_outcome(faulty()?, Fault::FailSyncAfter)?;
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

/// Synchronization refused after the governing commit's writes reached the
/// file: without a crash the written header stays in the file and redb's
/// one-phase recovery selects it, so the store reopens under B.
#[test]
fn refused_sync_after_governing_writes_reopens_under_the_incoming_authority() -> TestResult {
    let Unknown {
        spec,
        ns,
        a,
        b,
        trace,
    } = rotate_into_unknown_outcome(faulty()?, Fault::FailSyncBefore)?;
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

/// The registry refuses the activation's intent: nothing is published and
/// nothing changes, on the handle or after reopening.
#[test]
fn a_refused_intent_record_commits_nothing() -> TestResult {
    let faulty = faulty()?;
    let head_before = faulty.store.epoch_current(&faulty.governing)?;
    faulty.registry.arm(Fault::RefuseWrites);
    let outcome = rotate_ab(&faulty)?;
    assert!(
        matches!(outcome, Err(AuthorityRotationError::NotCommitted(_))),
        "{outcome:?}"
    );
    assert_eq!(&faulty.store.node_anchor(), faulty.a.anchor());
    assert!(!faulty.store.authority_unresolved());
    assert_eq!(faulty.store.epoch_current(&faulty.governing)?, head_before);
    let Faulty {
        spec,
        registry,
        store,
        ns,
        a,
        b,
        ..
    } = faulty;
    drop(store);
    registry.disarm();
    reopens_to(&spec, &ns, &a, &b, 1)?;
    Ok(())
}

/// The registry fails after the governing epoch committed: the activation
/// stands, B is installed, and the history row its projection could not
/// write is derived from the evidence when the store reopens.
#[test]
fn a_projection_lost_after_the_governing_commit_is_derived_at_reopen() -> TestResult {
    let faulty = faulty()?;
    let registry = faulty.registry.clone();
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let once = Arc::clone(&armed);
    faulty
        .store
        .hooks
        .install(Point::AfterEpochCommit, move || {
            if !once.swap(true, Ordering::SeqCst) {
                registry.arm(Fault::RefuseWrites);
            }
        });
    let outcome = rotate_ab(&faulty)?;
    faulty.store.hooks.clear(Point::AfterEpochCommit);
    assert!(
        armed.load(Ordering::SeqCst),
        "the governing epoch never committed"
    );
    outcome?;
    assert_eq!(&faulty.store.node_anchor(), faulty.b.anchor());
    assert_eq!(
        faulty.store.persisted_authority_rows()?,
        1,
        "control: the projection did not land"
    );
    assert!(faulty.store.activation_intent_pending()?);
    let Faulty {
        spec,
        registry,
        store,
        ns,
        a,
        b,
        ..
    } = faulty;
    drop(store);
    registry.disarm();
    let reopened = reopens_to(&spec, &ns, &b, &a, 2)?;
    assert_eq!(reopened.retired_authorities(), vec![a.anchor().clone()]);
    Ok(())
}

/// A rotation refused before its governing epoch is sealed leaves A
/// committed, installed and operational: nothing persisted, nothing
/// unresolved, and A keeps sealing.
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
    assert!(!store.activation_intent_pending()?);
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

/// A publication holds the shared activation gate from its seal until it
/// has raised the published-time bound. A rotation holding its control
/// namespace's writer must wait at the gate, and then sees the bound: a
/// succession effective at the committed epoch's time is rejected. The
/// interleaving is forced by the store's pause points.
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
    // The rotation holds its control namespace's writer and is about to
    // request the gate the publication still holds shared.
    let writer_held = writer_rx.recv_timeout(DEADLINE);
    // Release the publication whatever happened, so a failure below does
    // not also leave it parked.
    proceed_tx.send(())?;
    writer_held.map_err(|_| "rotation never obtained its control namespace's writer")?;

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
