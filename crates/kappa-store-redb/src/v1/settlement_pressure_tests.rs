//! Settlement driven by admission pressure, against real gates, grants,
//! cursors and registry transactions: sustained publication across the
//! epoch ceiling, prompt typed deferral on every unavailable resource with
//! nothing settled or released, recovery ownership refused before pressure
//! work, an unknown settlement commit keeping its ownership, the common
//! compaction body, and a committed epoch that completes whatever its
//! assignment refresh does.

use std::sync::{mpsc, Arc};
use std::time::Duration;

use kappa_handler::clock_at;
use kappa_store::work::{Dimension, WorkLimit, WorkMeter};
use kappa_store::{
    Axis, ClockMs, EpochStore, Kappa, NamespaceRef, StoreError, TagUpdate, VerifiedContent,
};

use super::{Origin, SettlementAttempt, SettlementStop};
use crate::control_plane::{AssignmentRecord, Guarantee, Guarantees};
use crate::projection_compact::PressureFold;
use crate::registry::Standing;
use crate::storage::NamespaceController;
use crate::test_hooks::CommitFault;
use crate::{PersistentStore, PersistentStoreConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const WATCHDOG: Duration = Duration::from_secs(10);

fn open(
    root: &std::path::Path,
    configure: impl FnOnce(&mut PersistentStoreConfig),
) -> TestResult<PersistentStore> {
    let mut config = PersistentStoreConfig::new(
        root.join("blobs"),
        root.join("store.redb"),
        kappa_crypto::testing::fixture_authority(1)?,
    );
    configure(&mut config);
    Ok(PersistentStore::new(config)?)
}

fn create(store: &PersistentStore, name: &str) -> Result<NamespaceRef, StoreError> {
    store.create_for_test(
        name,
        None,
        Guarantees::NONE
            .with(Guarantee::TotalOrder)
            .with(Guarantee::LinearizableReads),
    )
}

/// Publish one epoch of `ns` at `time` setting `tag`.
fn write(
    store: &PersistentStore,
    ns: &NamespaceRef,
    tag: &str,
    time: i64,
) -> Result<(), StoreError> {
    let clock = clock_at(ClockMs::from_raw(time))?;
    let mut execution = store.begin_epoch_execution(ns, &clock, None)?;
    execution.tag_put(
        tag,
        &TagUpdate::Set {
            kappa: Kappa::sha256(tag.as_bytes()),
        },
    )?;
    execution.publish()?;
    Ok(())
}

fn controller(store: &PersistentStore, ns: &NamespaceRef) -> TestResult<Arc<NamespaceController>> {
    Ok(Arc::clone(store.namespace_snapshot(ns)?.controller()))
}

fn checkpoint(store: &PersistentStore, ns: &NamespaceRef) -> TestResult<u64> {
    let instance = controller(store, ns)?.instance;
    Ok(store
        .established_checkpoint(&instance)?
        .map_or(0, |(epoch, _)| epoch))
}

fn parked(controller: &NamespaceController) -> TestResult<usize> {
    Ok(controller
        .pending_pins
        .lock()
        .map_err(|_| "pending pins poisoned")?
        .len())
}

/// A namespace with `epochs` committed and none settled.
fn at_backlog(store: &PersistentStore, name: &str, epochs: i64) -> TestResult<NamespaceRef> {
    let ns = create(store, name)?;
    for index in 1..epochs {
        write(store, &ns, &format!("fill-{index}"), 1000 + index)?;
    }
    assert_eq!(store.epoch_current(&ns)?.0, u64::try_from(epochs)?);
    assert_eq!(checkpoint(store, &ns)?, 0);
    Ok(ns)
}

/// Run `publication` on a worker while `blocker` is held, failing instead
/// of hanging when the publication waits on it: the completion is observed
/// with a timeout while the blocker is held, the blocker is released before
/// the worker is joined, and a timeout fails the test even when the release
/// then lets the worker finish.
fn promptly<B, T: Send>(blocker: B, publication: impl FnOnce() -> T + Send) -> TestResult<T> {
    std::thread::scope(|scope| {
        let (done, completion) = mpsc::channel();
        let worker = scope.spawn(move || {
            let outcome = publication();
            // Ignored: a receiver gone after the timeout already failed.
            let _ = done.send(());
            outcome
        });
        let completed = completion.recv_timeout(WATCHDOG);
        drop(blocker);
        let outcome = worker.join().map_err(|_| "publication worker panicked")?;
        completed.map_err(|_| "publication waited on a holder elsewhere")?;
        Ok(outcome)
    })
}

const fn refused_at_capacity(outcome: &Result<(), StoreError>) -> bool {
    matches!(outcome, Err(StoreError::CapacityExceeded(_)))
}

/// Sustained publication with no maintenance crosses the epoch ceiling
/// again and again: every publication is admitted, epochs stay dense, the
/// established backlog never exceeds the ceiling, and replay holds every
/// tag.
#[test]
fn sustained_publication_crosses_the_epoch_ceiling_repeatedly() -> TestResult {
    const CEILING: u64 = 3;
    const WRITES: u64 = 40;
    let root = tempfile::tempdir()?;
    let store = open(root.path(), |config| {
        config.max_unsettled_epochs = usize::try_from(CEILING).unwrap_or(usize::MAX);
    })?;
    let ns = create(&store, "sustained")?;
    for index in 0..WRITES {
        write(
            &store,
            &ns,
            &format!("tag-{index}"),
            2000 + i64::try_from(index)?,
        )?;
        let head = store.epoch_current(&ns)?.0;
        assert_eq!(head, index + 2, "epochs are dense");
        assert!(
            head - checkpoint(&store, &ns)? <= CEILING,
            "the established backlog stays at most the ceiling"
        );
    }
    let state = kappa_store::replay::replay_to(&store, &ns, WRITES + 1)?;
    for index in 0..WRITES {
        let tag = format!("tag-{index}");
        assert_eq!(state.tags.get(&tag), Some(&Kappa::sha256(tag.as_bytes())));
    }
    Ok(())
}

/// A registry writer held elsewhere: admission at the ceiling is refused
/// without waiting, nothing is settled or released; once the writer is
/// free the next admission settles and is admitted.
#[test]
fn a_held_registry_writer_defers_pressure_promptly() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open(root.path(), |config| config.max_unsettled_epochs = 2)?;
    let ns = at_backlog(&store, "registry-held", 2)?;
    let controller = controller(&store, &ns)?;
    let parked_before = parked(&controller)?;
    let blocker = store.registry.begin_write()?;
    let outcome = promptly(blocker, || write(&store, &ns, "blocked", 3000))?;
    assert!(refused_at_capacity(&outcome), "{outcome:?}");
    assert_eq!(checkpoint(&store, &ns)?, 0, "nothing settled");
    assert_eq!(parked(&controller)?, parked_before, "nothing released");
    write(&store, &ns, "free", 3001)?;
    assert_eq!(store.epoch_current(&ns)?.0, 3);
    assert!(checkpoint(&store, &ns)? >= 1);
    Ok(())
}

/// Another settlement attempt holding the namespace: admission at the
/// ceiling is refused without waiting and changes nothing; released, the
/// next admission settles.
#[test]
fn a_held_settlement_attempt_defers_pressure_promptly() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open(root.path(), |config| config.max_unsettled_epochs = 2)?;
    let ns = at_backlog(&store, "attempt-held", 2)?;
    let controller = controller(&store, &ns)?;
    let attempt =
        SettlementAttempt::try_acquire(&controller).ok_or("the attempt is free before the test")?;
    assert!(
        SettlementAttempt::try_acquire(&controller).is_none(),
        "one attempt per instance"
    );
    let outcome = promptly(attempt, || write(&store, &ns, "blocked", 3000))?;
    assert!(refused_at_capacity(&outcome), "{outcome:?}");
    assert_eq!(checkpoint(&store, &ns)?, 0);
    write(&store, &ns, "free", 3001)?;
    assert_eq!(store.epoch_current(&ns)?.0, 3);
    Ok(())
}

/// A namespace whose instance holds a recovery obligation is refused
/// before any pressure work: its checkpoint does not move.
#[test]
fn a_recovery_obligation_is_refused_before_pressure_work() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open(root.path(), |config| config.max_unsettled_epochs = 2)?;
    let ns = at_backlog(&store, "obligated", 2)?;
    let instance = controller(&store, &ns)?.instance;
    store.record_unresolved(&instance, Origin::Marker, "held by the test".into())?;
    assert!(refused_at_capacity(&write(&store, &ns, "refused", 3000)));
    assert_eq!(checkpoint(&store, &ns)?, 0, "no pressure work ran");
    Ok(())
}

/// Every namespace activity held: admission at the ceiling is refused,
/// and recovery visiting the instance defers, neither recording an
/// obligation; once an activity ends, recovery settles and admission is
/// admitted.
#[test]
fn exhausted_activity_defers_without_an_obligation() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open(root.path(), |config| {
        config.max_unsettled_epochs = 2;
        config.max_active_namespaces = 2;
        config.max_epoch_cursors = 1;
    })?;
    let other = create(&store, "activity-other")?;
    let ns = at_backlog(&store, "activity-full", 2)?;
    let instance = controller(&store, &ns)?.instance;
    let held = store.namespaces.admit_read(other.id())?;
    assert!(refused_at_capacity(&write(&store, &ns, "refused", 3000)));
    assert!(!store.obligation_held(&instance), "capacity is not storage");
    assert_eq!(checkpoint(&store, &ns)?, 0);
    // Recovery visiting the marker while the publisher's place is taken by
    // a reader of the namespace itself: deferred, nothing recorded.
    let reader = store.namespaces.admit_read(ns.id())?;
    store.settlement_step(64)?;
    assert!(!store.obligation_held(&instance));
    assert_eq!(checkpoint(&store, &ns)?, 0);
    drop(reader);
    drop(held);
    store.settlement_step(64)?;
    assert!(
        checkpoint(&store, &ns)? >= 1,
        "progress once capacity frees"
    );
    write(&store, &ns, "admitted", 3001)?;
    Ok(())
}

/// Publish `count` distinct records of `ns` in one epoch.
fn publish_many(store: &PersistentStore, ns: &NamespaceRef, count: u32, time: i64) -> TestResult {
    let clock = clock_at(ClockMs::from_raw(time))?;
    let mut execution = store.begin_epoch_execution(ns, &clock, None)?;
    for index in 0..count {
        execution.blob_put(&VerifiedContent::compute(
            Axis::Sha256,
            &index.to_be_bytes(),
        )?)?;
    }
    execution.publish()?;
    Ok(())
}

/// Every settlement cursor held by another namespace's partly read epoch:
/// admission at the ceiling is refused without an obligation and without
/// disturbing that cursor; once it completes, admission settles.
#[test]
fn exhausted_cursors_defer_without_an_obligation() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open(root.path(), |config| {
        config.max_unsettled_epochs = 2;
        config.max_epoch_cursors = 1;
    })?;
    let other = create(&store, "cursor-other")?;
    publish_many(&store, &other, 24, 1500)?;
    let other_controller = controller(&store, &other)?;
    let signatures = super::work::EPOCH_SIGNATURES;
    let limit = WorkLimit::unbounded()
        .with(Dimension::Entries, 3)
        .with(Dimension::Signatures, signatures);
    let opening_started = std::time::Instant::now();
    while store.cursors_in_progress() == 0 {
        assert!(
            opening_started.elapsed() < WATCHDOG,
            "three-entry settlement steps never retained a cursor"
        );
        let settled = store.settle_namespace(&other_controller, &mut WorkMeter::new(limit))?;
        if settled.reached {
            return Err("control: the other epoch settled in one step".into());
        }
    }
    let ns = at_backlog(&store, "cursor-full", 2)?;
    let instance = controller(&store, &ns)?.instance;
    assert!(refused_at_capacity(&write(&store, &ns, "refused", 3000)));
    assert!(!store.obligation_held(&instance));
    assert_eq!(store.cursors_in_progress(), 1, "the held cursor is kept");
    let completion_started = std::time::Instant::now();
    loop {
        let settled = store.settle_namespace(&other_controller, &mut WorkMeter::new(limit))?;
        if settled.reached {
            break;
        }
        assert!(
            completion_started.elapsed() < WATCHDOG,
            "three-entry settlement steps did not complete the retained epoch: {settled:?}; cursors: {:?}",
            store.cursor_diagnostics()
        );
    }
    write(&store, &ns, "admitted", 3001)?;
    Ok(())
}

/// A settlement commit whose outcome is unknown, driven by pressure, in
/// both schedules: the admission is refused as unavailable (only a reopen
/// decides), the epoch's parked ownership stays, no namespace obligation is
/// recorded, the registry is recovery-required so the next admission is
/// refused the same way and no established read is taken. A plain read of
/// the live handle shows whatever this handle holds, before close; the
/// reopen establishes exactly what persisted.
#[test]
fn an_unknown_pressure_commit_keeps_ownership_until_reopen() -> TestResult {
    for (fault, persisted) in [
        (CommitFault::PersistedUnknown, true),
        (CommitFault::AbortedUnknown, false),
    ] {
        let root = tempfile::tempdir()?;
        let ns = {
            let store = open(root.path(), |config| config.max_unsettled_epochs = 2)?;
            let ns = at_backlog(&store, "unknown-commit", 2)?;
            let controller = controller(&store, &ns)?;
            let parked_before = parked(&controller)?;
            store.registry.inject_commit_fault(fault);
            let refused = write(&store, &ns, "uncertain", 3000);
            assert!(
                matches!(refused, Err(StoreError::Unavailable(_))),
                "{fault:?}: {refused:?}"
            );
            assert!(store.registry.recovery_required());
            assert_eq!(
                parked(&controller)?,
                parked_before,
                "{fault:?}: ownership kept"
            );
            assert!(
                !store.obligation_held(&controller.instance),
                "{fault:?}: registry recovery is not namespace debt"
            );
            assert!(matches!(
                store.established_checkpoint(&controller.instance),
                Err(StoreError::Unavailable(_))
            ));
            let shown = store
                .settled_epoch(&controller.instance)?
                .map_or(0, |(epoch, _)| epoch);
            assert_eq!(
                shown >= 1,
                persisted,
                "{fault:?}: a plain read of the live handle shows what it holds"
            );
            let after = write(&store, &ns, "after", 3001);
            assert!(
                matches!(after, Err(StoreError::Unavailable(_))),
                "{fault:?}: pressure is refused while recovery is required: {after:?}"
            );
            ns
        };
        let store = open(root.path(), |config| config.max_unsettled_epochs = 2)?;
        assert_eq!(
            checkpoint(&store, &ns)? >= 1,
            persisted,
            "{fault:?}: the reopen establishes what persisted"
        );
        write(&store, &ns, "recovered", 4000)?;
    }
    Ok(())
}

/// The common folding body: a compaction whose commit outcome is unknown
/// leaves the cursor where it was, while the same bounded step that
/// commits advances it; pressure's folding takes nothing held elsewhere.
#[test]
fn compaction_installs_its_cursor_only_after_commit() -> TestResult {
    let step = || WorkMeter::new(WorkLimit::unbounded().with(Dimension::Entries, 2));
    let settled = |name: &str| -> TestResult<(tempfile::TempDir, PersistentStore)> {
        let root = tempfile::tempdir()?;
        let store = open(root.path(), |_| {})?;
        let ns = create(&store, name)?;
        for index in 0..4 {
            write(&store, &ns, &format!("tag-{index}"), 2000 + index)?;
        }
        // Settled by the traversal alone: a recovery step would also
        // compact what this test compacts.
        let controller = controller(&store, &ns)?;
        if !store
            .settle_namespace(&controller, &mut WorkMeter::unbounded())?
            .reached
        {
            return Err("control: the namespace did not settle".into());
        }
        Ok((root, store))
    };
    let cursor = |store: &PersistentStore| {
        store
            .compaction_cursor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    };

    let (_control_root, control) = settled("compaction-control")?;
    let staged = control.projection_staged()?.bytes;
    assert!(staged > 0, "control: settlement staged versions");
    let Standing::Ready(_) = control.compact_projection(&mut step())? else {
        return Err("control: the registry is recovery-required".into());
    };
    assert!(
        !cursor(&control).at_start(),
        "control: a bounded step advances"
    );

    let (_faulted_root, faulted) = settled("compaction-faulted")?;
    faulted
        .registry
        .inject_commit_fault(CommitFault::AbortedUnknown);
    assert!(matches!(
        faulted.compact_projection(&mut step())?,
        Standing::RecoveryRequired
    ));
    assert!(
        cursor(&faulted).at_start(),
        "an unknown outcome keeps the cursor"
    );
    assert!(
        matches!(
            faulted.compact_for_pressure(&mut step())?,
            PressureFold::Deferred(SettlementStop::RegistryRecoveryRequired)
        ),
        "pressure on a recovery-required registry defers with that reason"
    );

    let (_pressure_root, pressure) = settled("compaction-pressure")?;
    let blocker = pressure.registry.begin_write()?;
    assert!(
        matches!(
            pressure.compact_for_pressure(&mut step())?,
            PressureFold::Deferred(SettlementStop::RegistryBusy)
        ),
        "a held writer defers"
    );
    drop(blocker);
    let held = pressure
        .compaction_cursor
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        matches!(
            pressure.compact_for_pressure(&mut step())?,
            PressureFold::Deferred(SettlementStop::CompactionBusy)
        ),
        "a held cursor defers"
    );
    drop(held);
    let before = pressure.projection_staged()?.bytes;
    let PressureFold::Committed(outcome) = pressure.compact_for_pressure(&mut step())? else {
        return Err("free resources fold".into());
    };
    assert!(outcome.released_bytes > 0, "{outcome:?}");
    assert_eq!(
        pressure.projection_staged()?.bytes,
        before - outcome.released_bytes,
        "the reported release is the staging counter's"
    );
    Ok(())
}

/// An epoch whose settlement commits completes even when the assignment it
/// admitted cannot be installed: its ownership is released, the
/// checkpoint advances, and the controller is left stale for admission to
/// refresh.
#[test]
fn a_committed_epoch_completes_when_its_assignment_refresh_fails() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open(root.path(), |_| {})?;
    let ns = create(&store, "assignment-refresh")?;
    let plane = Arc::clone(store.namespaces.planes().local());
    let reassignment = AssignmentRecord {
        namespace_id: ns.id().to_vec(),
        plane: plane.id.0.to_vec(),
        generation: 1,
        requires: Guarantees::NONE
            .with(Guarantee::TotalOrder)
            .with(Guarantee::LinearizableReads),
    };
    let clock = clock_at(ClockMs::from_raw(2000))?;
    let mut execution = store.begin_epoch_execution(&ns, &clock, None)?;
    execution.assign_control_plane(&reassignment)?;
    execution.publish()?;
    let controller = controller(&store, &ns)?;
    assert!(!controller.assignment_is_stale());
    store.hooks.refuse_assignment_refresh(true);
    let settled = store.settle_namespace(&controller, &mut WorkMeter::unbounded())?;
    store.hooks.refuse_assignment_refresh(false);
    assert!(
        controller.assignment_is_stale(),
        "control: the settled reassignment could not be installed"
    );
    assert!(settled.reached, "every committed epoch is settled");
    assert_eq!(checkpoint(&store, &ns)?, 2);
    assert_eq!(parked(&controller)?, 0, "the settled ownership is released");
    write(&store, &ns, "refreshed", 3000)?;
    assert!(!controller.assignment_is_stale(), "admission refreshed it");
    Ok(())
}
