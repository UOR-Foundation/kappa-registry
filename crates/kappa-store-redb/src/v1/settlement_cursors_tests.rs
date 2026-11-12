//! Cursor ownership across checkout, retention, invalidation and failure:
//! a checked-out owner an invalidation revoked is never retained, a
//! detached retained cursor is released, a failed restart releases what it
//! reserved, and the pool's use is exactly the owners at every point.

use std::cell::Cell;
use std::sync::atomic::Ordering;

use kappa_handler::clock_at;
use kappa_store::work::{Dimension, Meter, WorkLimit, WorkMeter};
use kappa_store::{Axis, ClockMs, NamespaceRef, StoreError, VerifiedContent};

use super::{EffectProgress, Element, EpochConsumer, EpochRead, Purpose};
use crate::control_plane::{Guarantee, Guarantees};
use crate::settlement::work::EPOCH_SIGNATURES;
use crate::settlement::SettlementStop;
use crate::{PersistentStore, PersistentStoreConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const STEP_BYTES: u64 = 256 * 1024 * 1024;

/// A meter of `entries` entries and one epoch read's signatures: an epoch
/// of many records is read across several of them.
fn meter(entries: u64) -> WorkMeter {
    WorkMeter::new(
        WorkLimit::unbounded()
            .with(Dimension::Entries, entries)
            .with(Dimension::BytesRead, STEP_BYTES)
            .with(Dimension::BytesDecoded, STEP_BYTES)
            .with(Dimension::BytesAllocated, STEP_BYTES)
            .with(Dimension::BytesHashed, STEP_BYTES)
            .with(Dimension::Signatures, EPOCH_SIGNATURES),
    )
}

/// A store holding namespace `name` whose epoch 2 admits 24 records.
fn store_with_epoch(
    root: &std::path::Path,
    name: &str,
) -> Result<(PersistentStore, NamespaceRef), Box<dyn std::error::Error>> {
    let mut config = PersistentStoreConfig::new(
        root.join("blobs"),
        root.join("store.redb"),
        kappa_crypto::testing::fixture_authority(1)?,
    );
    config.max_epoch_cursors = 4;
    let store = PersistentStore::new(config)?;
    let ns = store.create_for_test(
        name,
        None,
        Guarantees::NONE
            .with(Guarantee::TotalOrder)
            .with(Guarantee::LinearizableReads),
    )?;
    let clock = clock_at(ClockMs::from_raw(2000))?;
    let mut execution = store.begin_epoch_execution(&ns, &clock, None)?;
    for index in 0..24u32 {
        execution.blob_put(&VerifiedContent::compute(
            Axis::Sha256,
            &index.to_be_bytes(),
        )?)?;
    }
    execution.publish()?;
    Ok((store, ns))
}

/// The storage instance of `ns`, and its controller's activity count.
fn instance_and_activity(
    store: &PersistentStore,
    ns: &NamespaceRef,
) -> Result<(crate::storage_instance::StorageInstance, usize), Box<dyn std::error::Error>> {
    let controller = store
        .namespaces
        .open_controller(ns.id())
        .ok_or("namespace has no open controller")?;
    Ok((
        controller.instance,
        controller.active.load(Ordering::Acquire),
    ))
}

/// A consumer counting restarts that, on its first delivered element, runs
/// `during` while the read's cursor is checked out, and applies each element
/// inside a unit admitted for its finalization.
struct Consumer<'a> {
    restarts: Cell<u32>,
    during: Option<Box<dyn FnOnce() + 'a>>,
    refuse_restart: bool,
}

impl<'a> Consumer<'a> {
    fn new() -> Self {
        Self {
            restarts: Cell::new(0),
            during: None,
            refuse_restart: false,
        }
    }
}

impl EpochConsumer for Consumer<'_> {
    fn restart(&mut self, _: &mut dyn Meter) -> Result<(), StoreError> {
        if self.refuse_restart {
            return Err(StoreError::Internal(
                "restart refused by the schedule".into(),
            ));
        }
        self.restarts.set(self.restarts.get() + 1);
        Ok(())
    }

    fn apply(
        &mut self,
        mut element: Element<'_>,
        work: &mut dyn Meter,
    ) -> Result<EffectProgress, StoreError> {
        if let Some(during) = self.during.take() {
            during();
        }
        let Ok(mut unit) = work.admit(&element.finalization().as_bound()) else {
            return Ok(EffectProgress::Deferred(SettlementStop::Budget));
        };
        element.finish(&mut unit)?;
        Ok(EffectProgress::Applied)
    }
}

/// Checkout, invalidation while the read advances, the read stopping on its
/// meter: the revoked owner is not retained, no cursor returns to the map,
/// its activity grant and charge are released, and the next read opens the
/// epoch afresh and restarts its consumer.
#[test]
fn a_revoked_checkout_is_not_retained_and_releases_its_grant() -> TestResult {
    let root = tempfile::tempdir()?;
    let (store, ns) = store_with_epoch(root.path(), "revoked-checkout")?;
    let (instance, idle) = instance_and_activity(&store, &ns)?;
    let observed = Cell::new(None);
    let mut consumer = Consumer::new();
    consumer.during = Some(Box::new(|| {
        // Out under its lease: one checked-out owner, nothing in the map.
        let before = store.cursors_in_progress();
        store.forget_namespace_cursors(ns.id());
        observed.set(Some((before, store.cursors_in_progress())));
    }));
    let read = store.read_epoch(
        &instance,
        2,
        Purpose::Reconstruct,
        &mut meter(3),
        &mut consumer,
    )?;
    assert!(
        matches!(read.outcome(), EpochRead::Pending(SettlementStop::Budget)),
        "the meter stopped the read"
    );
    assert_eq!(
        observed.get(),
        Some((1, 1)),
        "the checked-out owner stays accounted, revoked, until it ends"
    );
    assert_eq!(
        store.cursors_in_progress(),
        0,
        "nothing retained, everything released"
    );
    assert_eq!(
        instance_and_activity(&store, &ns)?.1,
        idle,
        "the cursor's grant ended"
    );
    let mut next = Consumer::new();
    let read = store.read_epoch(&instance, 2, Purpose::Reconstruct, &mut meter(3), &mut next)?;
    assert!(matches!(
        read.outcome(),
        EpochRead::Pending(SettlementStop::Budget)
    ));
    assert_eq!(next.restarts.get(), 1, "the epoch is read afresh");
    Ok(())
}

/// A retained cursor detached by invalidation is released, and the next
/// read restarts; an unrevoked partial read is retained and resumed
/// without a restart.
#[test]
fn retained_cursors_resume_until_invalidated() -> TestResult {
    let root = tempfile::tempdir()?;
    let (store, ns) = store_with_epoch(root.path(), "retained-cursor")?;
    let (instance, idle) = instance_and_activity(&store, &ns)?;
    let mut consumer = Consumer::new();
    let read = store.read_epoch(
        &instance,
        2,
        Purpose::Reconstruct,
        &mut meter(3),
        &mut consumer,
    )?;
    assert!(matches!(
        read.outcome(),
        EpochRead::Pending(SettlementStop::Budget)
    ));
    assert_eq!(consumer.restarts.get(), 1);
    assert_eq!(
        store.cursors_in_progress(),
        1,
        "the partial read is retained"
    );
    let read = store.read_epoch(
        &instance,
        2,
        Purpose::Reconstruct,
        &mut meter(3),
        &mut consumer,
    )?;
    assert!(matches!(
        read.outcome(),
        EpochRead::Pending(SettlementStop::Budget)
    ));
    assert_eq!(
        consumer.restarts.get(),
        1,
        "a retained cursor resumes without a restart"
    );
    store.forget_namespace_cursors(ns.id());
    assert_eq!(store.cursors_in_progress(), 0);
    assert_eq!(instance_and_activity(&store, &ns)?.1, idle);
    let read = store.read_epoch(
        &instance,
        2,
        Purpose::Reconstruct,
        &mut meter(3),
        &mut consumer,
    )?;
    assert!(matches!(
        read.outcome(),
        EpochRead::Pending(SettlementStop::Budget)
    ));
    assert_eq!(
        consumer.restarts.get(),
        2,
        "a detached cursor is read again from its start"
    );
    Ok(())
}

/// A restart that fails after the cursor opened releases the cursor, its
/// grant and its charge.
#[test]
fn a_failed_restart_releases_what_it_reserved() -> TestResult {
    let root = tempfile::tempdir()?;
    let (store, ns) = store_with_epoch(root.path(), "failed-restart")?;
    let (instance, idle) = instance_and_activity(&store, &ns)?;
    let mut consumer = Consumer::new();
    consumer.refuse_restart = true;
    assert!(matches!(
        store.read_epoch(
            &instance,
            2,
            Purpose::Reconstruct,
            &mut meter(3),
            &mut consumer
        ),
        Err(StoreError::Internal(_))
    ));
    assert_eq!(store.cursors_in_progress(), 0);
    assert_eq!(instance_and_activity(&store, &ns)?.1, idle);
    Ok(())
}
