use super::*;
use kappa_fixture::FixtureRoot;
use kappa_store::{ClockMs, EpochStore, TagStore, TagUpdate};

use crate::test_support::{
    Fault, FaultBackend, FaultControl, OpOutcome, PersistentSpec, StorageOp,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// What a failed handle leaves to reopen: the store spec, the faulted
/// namespace, its baseline head and its storage directory.
type Reopen = (
    PersistentSpec,
    NamespaceRef,
    (u64, Kappa),
    std::path::PathBuf,
);

/// Time of the baseline epoch 1.
const NOW: ClockMs = ClockMs::from_raw(1000);
/// Time of the epoch-2 attempt whose commit is faulted. Distinct from
/// `NOW`, so the published-time bound shows whether the attempt raised it.
const ATTEMPT: ClockMs = ClockMs::from_raw(2000);
/// Time of publications after reopening, later than both.
const LATER: ClockMs = ClockMs::from_raw(3000);

fn bound(store: &PersistentStore) -> i64 {
    store
        .latest_epoch_ms
        .load(std::sync::atomic::Ordering::SeqCst)
}

/// A store whose namespace database for `ns` sits on a fault-injecting
/// backend, with `ns` published at epoch 1. The registry database is
/// ordinary: the faults land on the namespace's own commits.
struct Fixture {
    spec: PersistentSpec,
    control: FaultControl,
    store: PersistentStore,
    ns: NamespaceRef,
    baseline: (u64, Kappa),
    directory: std::path::PathBuf,
}

fn fixture(name: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = FixtureRoot::temporary()?;
    let spec = PersistentSpec::new().in_root(&root);
    let store = spec.clone().acquire()?.into_store();
    let ns = NamespaceRef::deterministic(name);
    let writer = store.test_writer(&ns)?;
    let baseline = store.publish_test_writer(writer, &ns, NOW)?;
    store.settle_all()?;
    drop(store);
    // Reopen with the namespace database behind the fault backend.
    let directory = crate::storage::NamespaceController::directory(
        &root.resolve(std::path::Path::new("."))?,
        ns.id(),
    );
    let (backend, control) = FaultBackend::factory(&directory.join("state.redb"))?;
    let spec = spec.namespace_backend(*ns.id(), backend);
    let store = spec.clone().acquire()?.into_store();
    Ok(Fixture {
        spec,
        control,
        store,
        ns,
        baseline,
        directory,
    })
}

/// Commit epoch 2 of `fixture.ns`, carrying tag `operation`, with `fault`
/// armed. Returns the epoch-2 root the publication error names, which must
/// carry the exact publication coordinates.
fn commit_under(fixture: &Fixture, fault: Fault) -> Result<Kappa, Box<dyn std::error::Error>> {
    let writer = fixture.store.test_writer(&fixture.ns)?;
    fixture.store.tag_put_in_txn(
        &writer.txn,
        &fixture.ns,
        "operation",
        &TagUpdate::Set {
            kappa: Kappa::sha256(b"operation"),
        },
        ATTEMPT,
        &mut kappa_store::work::WorkMeter::unbounded(),
    )?;
    let prepared = fixture
        .store
        .prepare_test_writer(writer, &fixture.ns, ATTEMPT)?;
    assert_eq!(
        bound(&fixture.store),
        NOW.as_i64(),
        "a prepared, unsigned epoch raised the bound"
    );
    fixture.control.arm(fault);
    let error = prepared
        .publish()
        .err()
        .ok_or("a failed commit reported success")?;
    match error {
        StoreError::PublicationIndeterminate {
            namespace,
            epoch_number,
            root,
            ..
        }
        | StoreError::PublicationRecoveryRequired {
            namespace,
            epoch_number,
            root,
            ..
        } => {
            assert_eq!(namespace, *fixture.ns.id());
            assert_eq!(epoch_number, 2);
            Ok(*root)
        }
        StoreError::PublicationRetained(retained) => {
            assert_eq!(retained.namespace, *fixture.ns.id());
            assert_eq!(retained.epoch_number, 2);
            retained
                .signed_root
                .ok_or_else(|| "commit failure lost its signed root".into())
        }
        other => Err(format!("lost exact publication identity: {other}").into()),
    }
}

/// The failed namespace is fenced: it refuses further executions, its
/// published-time bound is conservatively the attempt's time (the epoch's
/// outcome is unknown, so it must bound rotation as a committed one
/// would), and dropping the store with the fault still armed changes
/// nothing more on disk. Other namespaces are unaffected.
fn finish_failed_handle(fixture: Fixture) -> Result<Reopen, Box<dyn std::error::Error>> {
    let later = kappa_handler::clock_at(LATER)?;
    let refused = fixture
        .store
        .begin_epoch_execution(&fixture.ns, &later, None);
    assert!(
        matches!(refused, Err(StoreError::Conflict(_))),
        "a namespace whose commit failed admitted another execution"
    );
    // An execution borrows its store until it drops.
    drop(refused);
    let other = NamespaceRef::deterministic("unaffected");
    fixture
        .store
        .begin_epoch_execution(&other, &later, None)?
        .publish()?;
    assert_eq!(
        bound(&fixture.store),
        LATER.as_i64().max(ATTEMPT.as_i64()),
        "an epoch of unknown outcome does not bound rotation"
    );
    let Fixture {
        spec,
        control,
        store,
        ns,
        baseline,
        directory,
    } = fixture;
    drop(store);
    control.disarm();
    assert!(
        crate::storage::NamespaceController::fence_path(&directory).try_exists()?,
        "the fence of an unknown outcome is durable beyond its handle"
    );
    Ok((spec, ns, baseline, directory))
}

/// Publish an empty epoch of `ns` through the public execution path.
fn publish_empty(
    store: &PersistentStore,
    ns: &NamespaceRef,
    now: ClockMs,
) -> Result<(u64, Kappa), StoreError> {
    store
        .begin_epoch_execution(ns, &kappa_handler::clock_at(now)?, None)?
        .publish()
}

/// Writes refused before they reach the file: the epoch-2 header never
/// lands, so reopening finds epoch 1 exactly, without the tag.
#[test]
fn refused_commit_writes_leave_the_previous_epoch() -> TestResult {
    let fixture = fixture("refused-writes")?;
    let expected = commit_under(&fixture, Fault::RefuseWrites)?;
    let trace = fixture.control.trace();
    assert!(
        trace
            .iter()
            .any(|(op, outcome)| matches!(op, StorageOp::Write { .. })
                && *outcome == OpOutcome::Refused),
        "the commit wrote nothing it could refuse: {trace:?}"
    );
    assert!(
        !trace
            .iter()
            .any(|(op, outcome)| matches!(op, StorageOp::Write { .. })
                && *outcome != OpOutcome::Refused),
        "a write reached the file while refusal was armed: {trace:?}"
    );
    assert!(
        !trace.iter().any(|(op, _)| *op == StorageOp::Sync),
        "the commit synchronized after its writes were refused: {trace:?}"
    );
    let (spec, ns, baseline, _) = finish_failed_handle(fixture)?;
    // The old head proves noncommit, not permission to replace a signed
    // candidate. Custody must survive reopen and publish that exact root.
    let reopened = spec.acquire()?.into_store();
    reopened.settle_all()?;
    assert_eq!(reopened.epoch_current(&ns)?, baseline);
    assert!(matches!(
        reopened.tag_get_raw(&ns, "operation"),
        Err(StoreError::NotFound(_))
    ));
    assert_eq!(reopened.epoch_state(&ns)?.1, 0);
    assert!(
        matches!(
            publish_empty(&reopened, &ns, LATER),
            Err(StoreError::Conflict(_))
        ),
        "retained signing coordinate admitted a replacement"
    );
    let resolution = kappa_store::ExecutionStore::resolve_publication(
        &reopened,
        &ns,
        &kappa_handler::clock_at(LATER)?,
        &mut kappa_store::work::WorkMeter::new(reopened.publication_work),
    )?;
    let kappa_store::PublicationResolution::Published(resolved) = resolution else {
        return Err("retained signed publication did not resolve".into());
    };
    assert_eq!(resolved.epoch_number, 2);
    assert_eq!(resolved.root, expected);
    assert_eq!(reopened.epoch_current(&ns)?, (2, expected));
    assert_eq!(
        reopened.tag_get_raw(&ns, "operation")?.kappa,
        Kappa::sha256(b"operation")
    );
    let published = publish_empty(&reopened, &ns, LATER)?;
    assert_eq!(published.0, 3);
    assert_eq!(bound(&reopened), LATER.as_i64());
    Ok(())
}

/// Synchronized, then reported failed: epoch 2 is durable although its
/// writer was told otherwise, so reopening finds exactly epoch 2 with the
/// tag, and its recovery resolves the exact publication.
#[test]
fn unacknowledged_durable_commit_reopens_to_the_new_epoch() -> TestResult {
    let fixture = fixture("unacknowledged")?;
    let expected = commit_under(&fixture, Fault::FailSyncAfter)?;
    let trace = fixture.control.trace();
    assert_eq!(
        trace
            .iter()
            .filter(|(op, _)| *op == StorageOp::Sync)
            .map(|(_, outcome)| *outcome)
            .collect::<Vec<_>>(),
        vec![OpOutcome::PerformedThenFailed],
        "the one-phase commit synchronizes once, after switching the header"
    );
    let (spec, ns, _, _) = finish_failed_handle(fixture)?;
    let reopened = spec.acquire()?.into_store();
    assert_eq!(reopened.epoch_current(&ns)?, (2, expected.clone()));
    reopened.verify_committed_publication(&ns, 2, &expected)?;
    assert_eq!(
        reopened.tag_get_raw(&ns, "operation")?.kappa,
        Kappa::sha256(b"operation")
    );
    assert_eq!(reopened.epoch_state(&ns)?.1, 1);
    reopened.settle_all()?;
    let published = publish_empty(&reopened, &ns, LATER)?;
    assert_eq!(published.0, 3);
    assert!(bound(&reopened) >= ATTEMPT.as_i64());
    Ok(())
}

/// Synchronization refused after the commit's writes reached the file.
/// Without a crash the written pages stay in the file, and redb's
/// one-phase recovery selects the valid newer header slot, so reopening in
/// this process finds exactly epoch 2. Whether the same holds after power
/// loss depends on the filesystem and is not observable here; what this
/// asserts is that an unsynchronized but written commit is not mistaken
/// for one that never happened, and that every epoch it holds is admitted.
#[test]
fn refused_sync_after_writes_reopens_to_the_written_epoch() -> TestResult {
    let fixture = fixture("refused-sync")?;
    let expected = commit_under(&fixture, Fault::FailSyncBefore)?;
    let trace = fixture.control.trace();
    assert!(
        trace
            .iter()
            .any(|(op, outcome)| matches!(op, StorageOp::Write { .. })
                && *outcome == OpOutcome::Performed),
        "the commit's writes did not reach the file: {trace:?}"
    );
    assert_eq!(
        trace.iter().find(|(op, _)| *op == StorageOp::Sync),
        Some(&(StorageOp::Sync, OpOutcome::Refused))
    );
    let (spec, ns, _, _) = finish_failed_handle(fixture)?;
    let reopened = spec.acquire()?.into_store();
    assert_eq!(reopened.epoch_current(&ns)?, (2, expected.clone()));
    reopened.verify_committed_publication(&ns, 2, &expected)?;
    reopened.settle_all()?;
    for number in 1..=2 {
        reopened.epoch_get(&reopened.epoch_get_by_number(&ns, number)?)?;
    }
    Ok(())
}
