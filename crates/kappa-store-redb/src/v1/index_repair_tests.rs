//! Repair of derived indexes through a private generation: reconstruction
//! from committed state, recorded divergence, fencing while a repair
//! builds, bounded resumable steps that cover concurrent writes, scoped
//! continuations, and resumption after a restart.

use std::collections::BTreeSet;

use redb::{ReadableDatabase, ReadableMultimapTable};

use kappa_store::work::{Dimension, WorkLimit, WorkMeter};
use kappa_store::{
    BuiltinRelation, ClockMs, EdgeRelation, ExecutionStore, Kappa, MaintenanceStore, NamespaceRef,
    StoreError, TagUpdate,
};

use crate::PersistentStore;
use crate::derived_index::DerivedState;
use crate::referrers::Referrer;
use crate::tables::{DERIVED_STATE, INDEX_REPAIRS, REFERRERS};
use crate::transition_apply::TxnWriter;

type Snapshot = BTreeSet<(Vec<u8>, Vec<u8>)>;
type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Every entry of `ns`'s live referrer generation.
fn snapshot(
    store: &PersistentStore,
    ns: &NamespaceRef,
) -> Result<Snapshot, Box<dyn std::error::Error>> {
    let (db, _active) = store.namespace_db(ns)?;
    let txn = db.begin_read()?;
    let live = DerivedState::read(&txn.open_table(DERIVED_STATE)?)?.live;
    let table = txn.open_multimap_table(live.referrers())?;
    let mut entries = BTreeSet::new();
    for entry in table.iter()? {
        let (key, values) = entry?;
        for value in values {
            entries.insert((key.value().to_vec(), value?.value().to_vec()));
        }
    }
    Ok(entries)
}

/// Publish every referrer kind, preparing the composite through the same
/// verified resource lifecycle used by protocol consumers.
fn publish_every_kind(store: &PersistentStore, ns: &NamespaceRef, now: ClockMs) -> TestResult {
    use kappa_store::{
        Axis, ContentIdentity, ContentPreparation, PreparationBounds, ResourceKind, resource,
    };
    let clock = kappa_handler::clock_at(now)?;
    let asserter = Kappa::sha256(b"referrer fixture");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut execution = store.begin_execution(ns, &clock)?;
    if execution.namespace_info()?.is_none() {
        execution.namespace_create(None, None)?;
    }
    let id = resource::open(
        &mut *execution,
        &asserter,
        ResourceKind::Sequential,
        11,
        now.add_physical_ms(60_000),
        None,
    )?
    .id();
    execution.publish()?;
    for (position, part) in [(0, &b"hello "[..]), (6, &b"world"[..])] {
        let prepared = store.prepare_content(
            ContentIdentity::Computed(Axis::Sha256),
            &mut &part[..],
            PreparationBounds {
                maximum: 11,
                deadline,
            },
        )?;
        let mut execution = store.begin_execution(ns, &clock)?;
        resource::stage(&mut *execution, &asserter, &id, prepared, position, None)?;
        execution.publish()?;
    }
    let mut execution = store.begin_execution(ns, &clock)?;
    let generation = resource::prepare(
        &mut *execution,
        &asserter,
        &id,
        &Kappa::sha256(b"complete fixture"),
        &[],
    )?
    .generation;
    execution.publish()?;
    let evidence =
        resource::prepare_composition(store, ns, &id, &generation, Axis::Sha256, deadline)?;
    let mut execution = store.begin_execution(ns, &clock)?;
    resource::complete(&mut *execution, &asserter, &id, &evidence, None)?;
    let tagged = Kappa::sha256(b"tagged");
    execution.tag_put(
        "latest",
        &TagUpdate::Set {
            kappa: tagged.clone(),
        },
    )?;
    execution.edge_put(&kappa_store::EdgeInput {
        source: Kappa::sha256(b"source"),
        target: tagged,
        relation: EdgeRelation::Builtin(BuiltinRelation::Owns),
        asserter: Kappa::sha256(b"asserter"),
        created_at_ms: now.as_i64(),
        metadata: None,
    })?;
    let pinned = Kappa::sha256(b"pinned");
    execution.namespace_put_meta(&format!("_pin/{pinned}"), b"{}")?;
    execution.publish()?;
    store.settle_all()?;
    Ok(())
}

/// Remove the live entry of tag `name` on `content`, then let a mutation
/// that relies on it find the divergence: the mutation refuses and the
/// divergence is recorded for the namespace.
fn diverge(
    store: &PersistentStore,
    ns: &NamespaceRef,
    name: &str,
    content: &Kappa,
    now: ClockMs,
) -> TestResult {
    {
        let (db, _active) = store.namespace_db(ns)?;
        let write = db.begin_write()?;
        {
            let mut table = write.open_multimap_table(REFERRERS)?;
            let entry = Referrer::tag(ns, name)?.encode();
            assert!(table.remove(content.key_bytes().as_slice(), entry.as_slice())?);
        }
        write.commit()?;
    }
    let writer = store.test_writer(ns)?;
    assert!(matches!(
        store.tag_delete_in_txn(&writer.txn, ns, name, now, &mut WorkMeter::unbounded()),
        Err(StoreError::Internal(_))
    ));
    drop(writer);
    assert!(store.divergence_recorded(ns.id()));
    Ok(())
}

/// Whether the registry lists `ns` under repair.
fn listed(store: &PersistentStore, ns: &NamespaceRef) -> Result<bool, Box<dyn std::error::Error>> {
    let txn = store.registry.begin_read()?;
    Ok(txn
        .open_table(INDEX_REPAIRS)?
        .get(ns.id().as_slice())?
        .is_some())
}

#[test]
fn rebuild_reproduces_the_incremental_index_and_repairs_divergence() -> TestResult {
    let store = crate::test_support::persistent_store()?.into_store();
    let ns = NamespaceRef::deterministic("referrer-rebuild");
    publish_every_kind(&store, &ns, ClockMs::from_raw(1000))?;
    // A second epoch moves the head: the rebuild must index the current
    // root, not the first.
    publish_every_kind(&store, &ns, ClockMs::from_raw(2000))?;
    let incremental = snapshot(&store, &ns)?;
    let kinds: BTreeSet<u8> = incremental.iter().map(|(_, value)| value[16]).collect();
    assert_eq!(kinds, BTreeSet::from([0, 1, 2, 3, 4, 5]), "{incremental:?}");

    let count = store.rebuild_referrers(&ns)?;
    assert_eq!(snapshot(&store, &ns)?, incremental);
    assert_eq!(count, incremental.len() as u64);

    // Divergence in both directions: an entry the state implies is missing
    // and an entry nothing implies is present. The rebuild, into the other
    // generation, has neither.
    let (missing_key, missing_value) =
        incremental.iter().next().cloned().ok_or("index is empty")?;
    {
        let (db, _active) = store.namespace_db(&ns)?;
        let live = {
            let txn = db.begin_read()?;
            DerivedState::read(&txn.open_table(DERIVED_STATE)?)?.live
        };
        let write = db.begin_write()?;
        {
            let mut table = write.open_multimap_table(live.referrers())?;
            assert!(table.remove(missing_key.as_slice(), missing_value.as_slice())?);
            let stray = Referrer::pin(&NamespaceRef::deterministic("stray")).encode();
            let content = Kappa::sha256(b"unreferenced").key_bytes();
            assert!(!table.insert(content.as_slice(), stray.as_slice())?);
        }
        write.commit()?;
    }
    assert_ne!(snapshot(&store, &ns)?, incremental);
    store.rebuild_referrers(&ns)?;
    assert_eq!(snapshot(&store, &ns)?, incremental);
    Ok(())
}

/// A mutation that finds `REFERRERS` diverged refuses to commit and
/// records it; maintenance repairs the index and the retried mutation
/// commits. A healthy store repairs nothing.
#[test]
fn a_referrer_divergence_is_recorded_repaired_and_the_mutation_retried() -> TestResult {
    let store = crate::test_support::persistent_store()?.into_store();
    let ns = NamespaceRef::deterministic("referrer-repair");
    let now = ClockMs::from_raw(1000);
    publish_every_kind(&store, &ns, now)?;
    let incremental = snapshot(&store, &ns)?;
    let healthy = store.repair_indexes(&WorkLimit::unbounded(), None)?;
    assert_eq!(healthy.outcome, kappa_store::IndexRepair::default());
    assert!(
        healthy.complete(),
        "no divergence recorded, nothing rebuilt"
    );

    diverge(&store, &ns, "latest", &Kappa::sha256(b"tagged"), now)?;
    let repair = store.repair_indexes(&WorkLimit::unbounded(), None)?;
    assert!(repair.outcome.diverged);
    assert!(repair.complete());
    assert!(!store.divergence_recorded(ns.id()));
    assert!(!listed(&store, &ns)?);
    assert_eq!(snapshot(&store, &ns)?, incremental);

    let writer = store.test_writer(&ns)?;
    store.tag_delete_in_txn(&writer.txn, &ns, "latest", now, &mut WorkMeter::unbounded())?;
    store.publish_test_writer(writer, &ns, now)?;
    Ok(())
}

/// A retirement that finds `ALLOCATIONS` diverged refuses to commit and
/// records it; the repair rebuilds ownership from `BLOB_INDEX` and the
/// retried retirement releases the allocation.
#[test]
fn an_allocation_divergence_is_recorded_repaired_and_the_retirement_retried() -> TestResult {
    let store = crate::test_support::persistent_store()?.into_store();
    let ns = NamespaceRef::deterministic("allocation-repair");
    let now = ClockMs::from_raw(1000);
    let size = usize::try_from(store.representation_limits.inline_limit)? + 1;
    let content = vec![0x6b; size];
    let prepared = store.prepare_representation(
        kappa_store::Axis::Sha256,
        None,
        &mut content.as_slice(),
        None,
        u64::try_from(size)?,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
    )?;
    let identity = prepared.identity().clone();
    let mut execution = store.begin_execution(&ns, &kappa_handler::clock_at(now)?)?;
    execution.namespace_create(None, None)?;
    execution.content_install(Box::new(prepared))?;
    execution.publish()?;
    store.settle_all()?;
    let allocation = match store
        .blob_record(&identity, &mut store.read_meter())?
        .representation()
    {
        crate::representation::Representation::External { allocation, .. } => *allocation,
        _ => return Err("content above the inline limit is not external".into()),
    };

    {
        let (db, _active) = store.namespace_db(&ns)?;
        let write = db.begin_write()?;
        assert!(
            write
                .open_table(crate::tables::ALLOCATIONS)?
                .remove(allocation.0.as_slice())?
                .is_some()
        );
        write.commit()?;
    }

    let writer = store.test_writer(&ns)?;
    assert!(matches!(
        crate::content_reclaim::retire_in_txn(
            &TxnWriter::new(&store, &writer.txn, &ns, now, &mut WorkMeter::unbounded())?,
            &identity
        ),
        Err(StoreError::Internal(_))
    ));
    drop(writer);
    assert!(store.divergence_recorded(ns.id()));

    let repair = store.repair_indexes(&WorkLimit::unbounded(), None)?;
    assert!(repair.outcome.diverged);
    assert!(!store.divergence_recorded(ns.id()));

    let writer = store.test_writer(&ns)?;
    assert_eq!(
        crate::content_reclaim::retire_in_txn(
            &TxnWriter::new(&store, &writer.txn, &ns, now, &mut WorkMeter::unbounded())?,
            &identity
        )?,
        crate::content_reclaim::Retired::Row(Some(allocation))
    );
    Ok(())
}

/// A repair advances in budgeted steps, each resuming from the progress
/// the previous one committed; writes committed between steps are covered
/// whether their source was traversed before or after them; while it
/// builds, the namespace's indexes authorize no retirement; the completed
/// generation equals an independent reconstruction of the final state.
#[test]
fn a_bounded_repair_resumes_and_covers_writes_between_its_steps() -> TestResult {
    let store = crate::test_support::persistent_store()?.into_store();
    let ns = NamespaceRef::deterministic("bounded-repair");
    let now = ClockMs::from_raw(1000);
    publish_every_kind(&store, &ns, now)?;
    diverge(&store, &ns, "latest", &Kappa::sha256(b"tagged"), now)?;

    let limit = WorkLimit::unbounded().with(Dimension::Entries, 3);
    let mut carried = None;
    let mut steps = 0u32;
    loop {
        let step = store.repair_indexes(&limit, carried)?;
        steps += 1;
        assert!(
            step.consumed.get(Dimension::Entries) <= 3,
            "within the limit"
        );
        let Some(continuation) = step.continuation else {
            break;
        };
        carried = Some(continuation);
        // A write between steps: tags sort first, so early writes land
        // after their source was traversed and late ones before.
        let writer = store.test_writer(&ns)?;
        store.tag_put_in_txn(
            &writer.txn,
            &ns,
            &format!("concurrent-{steps}"),
            &TagUpdate::Set {
                kappa: Kappa::sha256(format!("concurrent-{steps}").as_bytes()),
            },
            now,
            &mut WorkMeter::unbounded(),
        )?;
        // The fence holds while the repair builds.
        if store.divergence_recorded(ns.id()) {
            assert!(matches!(
                crate::content_reclaim::retire_in_txn(
                    &TxnWriter::new(&store, &writer.txn, &ns, now, &mut WorkMeter::unbounded())?,
                    &Kappa::sha256(b"hello world")
                ),
                Err(StoreError::Unavailable(_))
            ));
        }
        store.publish_test_writer(writer, &ns, now)?;
        assert!(steps < 10_000, "the repair makes progress");
    }
    assert!(steps > 2, "the budget split the repair into steps");
    assert!(!store.divergence_recorded(ns.id()));
    assert!(!listed(&store, &ns)?);
    let repaired = snapshot(&store, &ns)?;
    store.rebuild_referrers(&ns)?;
    assert_eq!(repaired, snapshot(&store, &ns)?);
    Ok(())
}

/// A continuation is refused by another store and by another operation of
/// the same store, before any work.
#[test]
fn another_stores_continuation_is_refused_before_any_work() -> TestResult {
    let first = crate::test_support::persistent_store()?.into_store();
    let second = crate::test_support::persistent_store()?.into_store();
    let paused = first.repair_indexes(&WorkLimit::unbounded().with(Dimension::Entries, 0), None)?;
    let continuation = paused.continuation.ok_or("a zero budget pauses the pass")?;
    assert!(matches!(
        second.repair_indexes(&WorkLimit::unbounded(), Some(continuation)),
        Err(StoreError::Rejected(_))
    ));
    let paused = first.repair_indexes(&WorkLimit::unbounded().with(Dimension::Entries, 0), None)?;
    let continuation = paused.continuation.ok_or("a zero budget pauses the pass")?;
    assert!(matches!(
        first.reclaim_unowned(&WorkLimit::unbounded(), Some(continuation)),
        Err(StoreError::Rejected(_))
    ));
    Ok(())
}

/// A repair a restart interrupted is fenced from the open on, found from
/// its listing, and completed by the next pass; nothing in memory survives
/// the restart.
#[test]
fn a_repair_interrupted_by_a_restart_resumes_from_its_listing() -> TestResult {
    let root = kappa_fixture::FixtureRoot::temporary()?;
    let spec = crate::test_support::PersistentSpec::new().in_root(&root);
    let ns = NamespaceRef::deterministic("restarted-repair");
    let now = ClockMs::from_raw(1000);
    {
        let store = spec.clone().acquire()?.into_store();
        publish_every_kind(&store, &ns, now)?;
        diverge(&store, &ns, "latest", &Kappa::sha256(b"tagged"), now)?;
        let step =
            store.repair_indexes(&WorkLimit::unbounded().with(Dimension::Entries, 3), None)?;
        assert!(step.continuation.is_some(), "the repair is left building");
        assert!(listed(&store, &ns)?);
    }
    let store = spec.acquire()?.into_store();
    assert!(
        !store.divergence_recorded(ns.id()),
        "memory did not survive"
    );
    assert!(matches!(
        store.referrers_of(&ns, &Kappa::sha256(b"tagged")),
        Err(StoreError::Unavailable(_))
    ));
    let repair = store.repair_indexes(&WorkLimit::unbounded(), None)?;
    assert!(repair.outcome.diverged);
    assert!(repair.complete());
    assert!(!listed(&store, &ns)?);
    let repaired = snapshot(&store, &ns)?;
    store.rebuild_referrers(&ns)?;
    assert_eq!(repaired, snapshot(&store, &ns)?);
    Ok(())
}
