//! The registry writer slot over a real registry: exclusion and its
//! release on every exit, reads beside a held writer, both schedules of a
//! commit whose outcome is unknown, each run through the production
//! classification, refusing writers and established reads until a reopen
//! decides from what persisted, and the interval between the registry being
//! marked recovery-required and the slot being released.

use std::sync::mpsc;
use std::time::Duration;

use kappa_store::{Kappa, StoreError};

use super::{Attempt, Registry, Standing};
use crate::PersistentStore;
use crate::error::CommitFailure;
use crate::storage_instance::{Incarnation, StorageInstance};
use crate::tables::SETTLED;
use crate::test_hooks::CommitFault;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const WATCHDOG: Duration = Duration::from_secs(10);

fn instance() -> StorageInstance {
    StorageInstance::new([7; 16], Incarnation::Known([7; 16]))
}

/// The checkpoint value of `epoch` (`settlement_pending::checkpoint`).
fn checkpoint_value(epoch: u64) -> Vec<u8> {
    let mut value = epoch.to_be_bytes().to_vec();
    value.extend_from_slice(&Kappa::sha256(&epoch.to_be_bytes()).key_bytes());
    value
}

fn slot_held(registry: &Registry) -> bool {
    *registry
        .gate
        .held
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn spec(root: &kappa_fixture::FixtureRoot) -> crate::test_support::PersistentSpec {
    crate::test_support::PersistentSpec::new()
        .in_root(root)
        .db_file("db.redb")
}

/// A held writer excludes the other writer mode without waiting; reads
/// proceed beside it; an uncommitted writer dropped, a committed one and
/// an aborted one each release the slot.
#[test]
fn the_slot_excludes_writers_and_is_released_on_every_exit() -> TestResult {
    let store: PersistentStore = crate::test_support::persistent_store()?.into_store();
    let registry = &store.registry;
    let held = registry.begin_write()?;
    assert!(slot_held(registry));
    assert!(
        matches!(registry.try_begin_write()?, Attempt::Busy),
        "a held slot defers"
    );
    assert!(matches!(
        registry.try_begin_established_read()?,
        Attempt::Busy
    ));
    drop(registry.begin_read()?);
    drop(held);
    assert!(
        !slot_held(registry),
        "an uncommitted writer dropped releases"
    );
    let Attempt::Ready(committed) = registry.try_begin_write()? else {
        return Err("a free slot admits a writer".into());
    };
    committed
        .commit()
        .map_err(|failure| format!("commit failed: {failure}"))?;
    assert!(!slot_held(registry), "a commit releases");
    registry.begin_write()?.abort()?;
    assert!(!slot_held(registry), "an abort releases");
    assert!(matches!(
        registry.try_begin_established_read()?,
        Attempt::Ready(_)
    ));
    Ok(())
}

/// Both schedules of an unknown commit outcome: the caller is told Unknown,
/// the registry is recovery-required before the slot is free, no writer of
/// either mode and no established read is admitted, a plain read shows what
/// this handle holds, and a reopen establishes exactly what persisted.
#[test]
fn an_unknown_commit_outcome_refuses_writers_and_established_reads_until_reopen() -> TestResult {
    for (fault, persisted) in [
        (CommitFault::PersistedUnknown, true),
        (CommitFault::AbortedUnknown, false),
    ] {
        let root = kappa_fixture::FixtureRoot::temporary()?;
        {
            let store = spec(&root).acquire()?.into_store();
            let registry = &store.registry;
            let txn = registry.begin_write()?;
            txn.open_table(SETTLED)?
                .insert(instance().key().as_slice(), checkpoint_value(3).as_slice())?;
            registry.inject_commit_fault(fault);
            assert!(matches!(txn.commit(), Err(CommitFailure::Unknown(_))));
            assert!(registry.recovery_required());
            assert!(!slot_held(registry), "{fault:?}: the slot is released");
            assert!(matches!(
                registry.begin_write(),
                Err(StoreError::Unavailable(_))
            ));
            assert!(matches!(
                registry.write_standing()?,
                Standing::RecoveryRequired
            ));
            assert!(matches!(
                registry.try_begin_write()?,
                Attempt::RecoveryRequired
            ));
            assert!(!slot_held(registry), "a refused writer holds no slot");
            assert!(matches!(
                registry.try_begin_established_read()?,
                Attempt::RecoveryRequired
            ));
            assert!(matches!(
                store.established_checkpoint(&instance()),
                Err(StoreError::Unavailable(_))
            ));
            let shown = registry
                .begin_read()?
                .open_table(SETTLED)?
                .get(instance().key().as_slice())?
                .is_some();
            assert_eq!(shown, persisted, "{fault:?}: what this handle can read");
        }
        let store = spec(&root).acquire()?.into_store();
        assert!(!store.registry.recovery_required(), "a reopen recovers");
        assert_eq!(
            store
                .established_checkpoint(&instance())?
                .map(|(epoch, _)| epoch),
            persisted.then_some(3),
            "{fault:?}: the reopen establishes what persisted"
        );
        store.registry.begin_write()?.abort()?;
    }
    Ok(())
}

/// The committing thread paused after it marked the registry
/// recovery-required and before it released the slot: the slot is still
/// held, yet every acquisition mode already reports recovery rather than
/// a busy writer, and a writer and an established read that waited on the
/// slot meanwhile are refused once it is released. Nothing is admitted in
/// the interval between the mark and the release, nor after it.
#[test]
fn the_registry_is_fenced_before_the_slot_is_released() -> TestResult {
    let store: PersistentStore = crate::test_support::persistent_store()?.into_store();
    let registry = &store.registry;
    let (fenced, at_fence) = mpsc::channel();
    let (release, released) = mpsc::channel::<()>();
    registry.pause_when_fenced(move || {
        // Ignored: a test that already failed has dropped the receiver.
        let _ = fenced.send(());
        // Ignored: a dropped sender is the release.
        let _ = released.recv();
    });
    std::thread::scope(|scope| -> TestResult {
        let txn = registry.begin_write()?;
        let waiting_writer = scope.spawn(|| {
            registry
                .write_standing()
                .map(|standing| matches!(standing, Standing::RecoveryRequired))
        });
        let waiting_read = scope.spawn(|| {
            registry
                .established_read_standing()
                .map(|standing| matches!(standing, Standing::RecoveryRequired))
        });
        registry.inject_commit_fault(CommitFault::PersistedUnknown);
        let committer = scope.spawn(move || matches!(txn.commit(), Err(CommitFailure::Unknown(_))));
        let paused = at_fence.recv_timeout(WATCHDOG);
        // Observed while paused, before the release.
        let observed = paused.is_ok().then(|| -> Result<_, StoreError> {
            Ok((
                slot_held(registry),
                registry.recovery_required(),
                matches!(registry.try_begin_write()?, Attempt::RecoveryRequired),
                matches!(
                    registry.try_begin_established_read()?,
                    Attempt::RecoveryRequired
                ),
            ))
        });
        // Release before joining, whatever was observed, so a defect
        // fails the test instead of hanging it.
        drop(release);
        let unknown = committer.join().map_err(|_| "committer panicked")?;
        let writer_refused = waiting_writer.join().map_err(|_| "writer panicked")??;
        let read_refused = waiting_read.join().map_err(|_| "reader panicked")??;
        paused.map_err(|_| "the commit never reached the fence")?;
        let (held, marked, try_write, try_read) =
            observed.ok_or("no observation while paused")??;
        assert!(held, "the slot is held while paused");
        assert!(marked, "marked before the slot is released");
        assert!(
            try_write,
            "a non-waiting writer sees recovery, not a busy slot"
        );
        assert!(try_read, "a non-waiting established read sees recovery");
        assert!(unknown, "the committer is told the outcome is unknown");
        assert!(
            writer_refused,
            "a writer that waited on the slot is refused"
        );
        assert!(read_refused, "an established read that waited is refused");
        assert!(!slot_held(registry), "the slot is released after the pause");
        Ok(())
    })
}
