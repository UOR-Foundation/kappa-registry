//! Settlement of epochs read across bounded steps: an epoch's projections
//! become visible whole when its attempt completes, never in part, and the
//! cursors holding partly read epochs stay within their capacity.

use kappa_handler::clock_at;
use kappa_store::{Axis, ClockMs, Kappa, NamespaceRef, StoreError, VerifiedContent};

use crate::control_plane::{Guarantee, Guarantees};
use crate::settlement::work::EPOCH_SIGNATURES;
use crate::{PersistentStore, PersistentStoreConfig};
use kappa_store::work::{Dimension, WorkLimit, WorkMeter};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const STEP_BYTES: u64 = 256 * 1024 * 1024;

fn meter(entries: u64, signatures: u64) -> WorkMeter {
    WorkMeter::new(
        WorkLimit::unbounded()
            .with(Dimension::Entries, entries)
            .with(Dimension::BytesRead, STEP_BYTES)
            .with(Dimension::BytesDecoded, STEP_BYTES)
            .with(Dimension::BytesAllocated, STEP_BYTES)
            .with(Dimension::BytesHashed, STEP_BYTES)
            .with(Dimension::Signatures, signatures),
    )
}

fn open(root: &std::path::Path, cursors: usize) -> TestResult<PersistentStore> {
    let mut config = PersistentStoreConfig::new(
        root.join("blobs"),
        root.join("store.redb"),
        kappa_crypto::testing::fixture_authority(1)?,
    );
    config.max_epoch_cursors = cursors;
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

/// Publish `count` distinct records of `ns` in one epoch; their identities.
fn publish_many(
    store: &PersistentStore,
    ns: &NamespaceRef,
    count: u32,
    time: i64,
) -> TestResult<Vec<Kappa>> {
    let clock = clock_at(ClockMs::from_raw(time))?;
    let mut execution = store.begin_epoch_execution(ns, &clock, None)?;
    let mut identities = Vec::new();
    for index in 0..count {
        let content = VerifiedContent::compute(Axis::Sha256, &index.to_be_bytes())?;
        execution.blob_put(&content)?;
        identities.push(content.kappa().clone());
    }
    execution.publish()?;
    Ok(identities)
}

/// How many of `identities` the completed catalog projects.
fn projected(store: &PersistentStore, identities: &[Kappa]) -> TestResult<usize> {
    let mut count = 0;
    for identity in identities {
        if !store
            .catalog_owners(identity, &mut kappa_store::work::WorkMeter::unbounded())?
            .is_empty()
        {
            count += 1;
        }
    }
    Ok(count)
}

/// One epoch of many mutations, settled a few mutations per call: after
/// every call its records are projected all or none, the epoch's cursor is
/// held while it is partly read and released once it completes.
#[test]
fn an_epoch_read_across_steps_is_projected_whole() -> TestResult {
    const RECORDS: u32 = 24;
    let root = tempfile::tempdir()?;
    let store = open(root.path(), 16)?;
    let ns = create(&store, "whole-epoch")?;
    let identities = publish_many(&store, &ns, RECORDS, 2000)?;
    let active = store.namespace_snapshot(&ns)?;
    let mut partly_read = false;
    for _ in 0..1024 {
        let mut work = meter(3, EPOCH_SIGNATURES);
        let settled = store.settle_namespace(active.controller(), &mut work)?;
        let seen = projected(&store, &identities)?;
        assert!(
            seen == 0 || seen == identities.len(),
            "{seen} of {} records projected: an epoch was exposed in part",
            identities.len()
        );
        if seen == 0 && store.cursors_in_progress() > 0 {
            partly_read = true;
        }
        if settled.reached {
            assert_eq!(seen, identities.len());
            assert!(partly_read, "control: the epoch was read across steps");
            assert_eq!(
                store.cursors_in_progress(),
                0,
                "the completed cursor is released"
            );
            return Ok(());
        }
    }
    Err(format!(
        "settlement did not reach the head: {:?}",
        store.cursor_diagnostics()
    )
    .into())
}

/// An epoch read is admitted only with the signatures it verifies: a step
/// with ample mutations and bytes but no signatures opens no read and
/// settles nothing; the same step with one read's signatures settles, and
/// spends exactly them.
#[test]
fn a_step_without_signatures_opens_no_epoch_read() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open(root.path(), 16)?;
    let ns = create(&store, "signature-bound")?;
    let identities = publish_many(&store, &ns, 2, 2000)?;
    let active = store.namespace_snapshot(&ns)?;
    let mut work = meter(1024, EPOCH_SIGNATURES - 1);
    let settled = store.settle_namespace(active.controller(), &mut work)?;
    assert_eq!(settled.examined, 0, "no epoch read opened");
    assert_eq!(store.cursors_in_progress(), 0);
    assert_eq!(projected(&store, &identities)?, 0);
    assert_eq!(
        work.used().get(Dimension::Signatures),
        0,
        "nothing was charged"
    );
    let mut reached = false;
    for _ in 0..64 {
        let mut work = meter(1024, EPOCH_SIGNATURES);
        let settled = store.settle_namespace(active.controller(), &mut work)?;
        assert!(
            settled.examined <= 1,
            "one read's signatures settle one epoch"
        );
        if settled.reached {
            reached = true;
            break;
        }
    }
    assert!(reached, "settlement reached the head");
    assert_eq!(projected(&store, &identities)?, identities.len());
    Ok(())
}

/// With room for one cursor, two namespaces each holding an epoch read
/// across steps never hold more than one cursor at a time, and both settle:
/// the second epoch waits for the first to complete.
#[test]
fn partly_read_epochs_stay_within_cursor_capacity() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open(root.path(), 1)?;
    let first = create(&store, "capacity-first")?;
    let second = create(&store, "capacity-second")?;
    let identities = [
        publish_many(&store, &first, 16, 2000)?,
        publish_many(&store, &second, 16, 2001)?,
    ];
    let actives = [
        store.namespace_snapshot(&first)?,
        store.namespace_snapshot(&second)?,
    ];
    let mut reached = [false, false];
    for _ in 0..2048 {
        for (index, active) in actives.iter().enumerate() {
            let mut work = meter(3, EPOCH_SIGNATURES);
            reached[index] = store
                .settle_namespace(active.controller(), &mut work)?
                .reached;
            assert!(store.cursors_in_progress() <= 1, "cursor capacity exceeded");
        }
        if reached == [true, true] {
            for records in &identities {
                assert_eq!(projected(&store, records)?, records.len());
            }
            return Ok(());
        }
    }
    Err(format!(
        "both namespaces did not settle: {:?}",
        store.cursor_diagnostics()
    )
    .into())
}
