//! Reclamation of external allocations decided by the installing
//! instance's own committed rows: under unrelated backlog, under a fence,
//! with the owner's storage missing until its governed release is
//! recorded, and through a committed retirement of the content.
//!
//! The inventory counts every entry it examines once
//! (`kappa_store::Reclamation`), and an allocation has as many entries as
//! its layout keeps on disk, so the figures expected of an allocation are
//! its entries counted on disk, not a fixed number.

use std::collections::BTreeMap;
use std::time::Instant;

use kappa_handler::clock_at;
use kappa_store::{BlobStore, ClockMs, Kappa, MaintenanceStore, NamespaceRef, StoreError};

use super::{TestResult, WATCHDOG, create, create_owned, drain_settlement, open, publish_blob};
use crate::representation::AllocationId;
use crate::retirement_record::RetirementRecord;
use crate::test_support::retirement_principal;
use crate::unsettled::Parked;
use crate::{PersistentStore, PersistentStoreConfig};

/// One complete inventory pass; the accumulated figures.
fn inventory_pass(store: &PersistentStore) -> TestResult<kappa_store::Reclamation> {
    let mut total = kappa_store::Reclamation::default();
    for _ in 0..1024 {
        let step = store.reclaim_unowned(8)?;
        total.accumulate(&step);
        if step.complete {
            return Ok(total);
        }
    }
    Err("bounded inventory did not complete on a tiny fixture".into())
}

/// The inventory entries `allocation` has on disk: its payload, its
/// sidecar where the layout keeps one, and its owner marker once an
/// installation wrote it.
fn entries(store: &PersistentStore, allocation: &AllocationId) -> TestResult<u64> {
    let mut present = 0;
    for path in [
        crate::allocation::allocation_path(&store.blob_root, allocation),
        crate::allocation::chunk_list_path(&store.blob_root, allocation),
        crate::allocation::owner_path(&store.blob_root, allocation),
    ] {
        if path.try_exists()? {
            present += 1;
        }
    }
    Ok(present)
}

/// The allocation of the one pin `ns`'s committed epochs parked; with
/// `take`, every parked pin is dropped, as after a restart, so only
/// durable evidence protects what they held.
fn parked_allocation(
    store: &PersistentStore,
    ns: &NamespaceRef,
    take: bool,
) -> TestResult<AllocationId> {
    let active = store.namespace_snapshot(ns)?;
    let mut parked = active
        .controller()
        .pending_pins
        .lock()
        .map_err(|_| "pending pins poisoned")?;
    let mut allocations = parked
        .values()
        .flat_map(|parked| parked.pins.iter())
        .map(|pin| *pin.allocation());
    let allocation = allocations
        .next()
        .ok_or("the committed blob parked no pin")?;
    if allocations.next().is_some() {
        return Err("more than one parked pin".into());
    }
    if take {
        let released: BTreeMap<u64, Parked> = std::mem::take(&mut *parked);
        drop(parked);
        drop(released);
    }
    Ok(allocation)
}

/// A prepared external allocation that never installs: no owner marker.
fn orphan(store: &PersistentStore, fill: u8) -> TestResult<Kappa> {
    let bytes = vec![fill; 256 * 1024];
    let prepared = kappa_store::ContentPreparation::prepare_content(
        store,
        kappa_store::ContentIdentity::Verified(Kappa::sha256(&bytes)),
        &mut bytes.as_slice(),
        kappa_store::PreparationBounds {
            maximum: bytes.len() as u64,
            deadline: Instant::now() + WATCHDOG,
        },
    )?;
    drop(prepared);
    Ok(Kappa::sha256(&bytes))
}

/// Reclamation is decided by the installing namespace's committed rows,
/// not by the settled projection and not by the settlement state of any
/// other namespace: with namespace A committed but unsettled (its
/// projection names no owner) and its parked pins gone as after a
/// restart, A's allocation is kept by A's own row while an orphan and an
/// allocation whose installing execution aborted are reclaimed in the
/// same pass.
#[test]
fn reclamation_is_decided_by_the_installing_namespace_under_unrelated_backlog() -> TestResult {
    const BYTES: usize = 256 * 1024;
    let root = tempfile::tempdir()?;
    let store = open(root.path())?;
    let a = create(&store, "reclaim-owner")?;
    drain_settlement(&store, &a)?;
    publish_blob(&store, &a, 1, BYTES, 2000)?;
    let committed = Kappa::sha256(&vec![1u8; BYTES]);
    // An installation whose transaction aborted: the marker names A, A's
    // rows do not select the allocation.
    let aborted_bytes = vec![2u8; BYTES];
    let prepared = kappa_store::ContentPreparation::prepare_content(
        &store,
        kappa_store::ContentIdentity::Verified(Kappa::sha256(&aborted_bytes)),
        &mut aborted_bytes.as_slice(),
        kappa_store::PreparationBounds {
            maximum: BYTES as u64,
            deadline: Instant::now() + WATCHDOG,
        },
    )?;
    let clock = clock_at(ClockMs::from_raw(2001))?;
    let mut execution = store.begin_epoch_execution(&a, &clock, None)?;
    kappa_store::ExecutionWrites::content_install(&mut execution, prepared)?;
    execution.abort()?;
    orphan(&store, 3)?;
    // A is pending: nothing of epoch 2 is projected.
    assert!(store.pending_settlements()?.contains(a.id()));
    let allocation = parked_allocation(&store, &a, true)?;
    let owned = entries(&store, &allocation)?;
    let pass = inventory_pass(&store)?;
    assert_eq!(
        pass.files, 2,
        "the aborted install and the orphan: {pass:?}"
    );
    assert_eq!(pass.owned, owned, "the committed allocation: {pass:?}");
    assert_eq!(pass.protected, 0, "nothing waited on settlement: {pass:?}");
    assert_eq!(entries(&store, &allocation)?, owned, "the owned files stay");
    assert_eq!(store.blob_get_in(&a, &committed)?, vec![1u8; BYTES]);
    assert!(
        store.pending_settlements()?.contains(a.id()),
        "reclamation did not settle anything itself"
    );
    // Settling changes no decision: the row is the authority before and
    // after the projection catches up.
    drain_settlement(&store, &a)?;
    let pass = inventory_pass(&store)?;
    assert_eq!(pass.files, 0, "{pass:?}");
    assert_eq!(pass.owned, owned, "{pass:?}");
    assert_eq!(store.blob_get_in(&a, &committed)?, vec![1u8; BYTES]);
    Ok(())
}

/// An installer whose commit outcome is unknown protects exactly its own
/// allocations: under its fence the committed-but-unprojected allocation
/// is reported protected, while an orphan is reclaimed in the same pass.
#[test]
fn a_fenced_installer_protects_only_its_own_allocations() -> TestResult {
    const BYTES: usize = 256 * 1024;
    let root = tempfile::tempdir()?;
    let store = open(root.path())?;
    let a = create(&store, "reclaim-fenced")?;
    drain_settlement(&store, &a)?;
    publish_blob(&store, &a, 4, BYTES, 2000)?;
    let committed = Kappa::sha256(&vec![4u8; BYTES]);
    orphan(&store, 5)?;
    let allocation = parked_allocation(&store, &a, true)?;
    let held = entries(&store, &allocation)?;
    let active = store.namespace_snapshot(&a)?;
    active.controller().fence()?;
    let pass = inventory_pass(&store)?;
    assert_eq!(pass.files, 1, "the orphan: {pass:?}");
    assert_eq!(
        pass.protected, held,
        "the fenced installer's allocation: {pass:?}"
    );
    assert_eq!(pass.owned, 0, "nothing decided under the fence: {pass:?}");
    active.controller().unfence()?;
    let pass = inventory_pass(&store)?;
    assert_eq!(pass.owned, held, "{pass:?}");
    assert_eq!(pass.files, 0, "{pass:?}");
    assert_eq!(store.blob_get_in(&a, &committed)?, vec![4u8; BYTES]);
    Ok(())
}

/// An owner instance whose storage is missing releases nothing unless the
/// registry records an authorized retirement of exactly that instance:
/// unexplained absence protects the allocation; the owner's governed
/// release of the instance releases it; and a release recorded before a
/// crash removed the directory is completed by recovery at the next open,
/// against storage recording that same instance, once its decision
/// verifies again from the governing namespace's evidence.
#[test]
fn missing_owner_storage_protects_until_retirement_is_recorded() -> TestResult {
    const BYTES: usize = 256 * 1024;
    let root = tempfile::tempdir()?;
    let mut config = PersistentStoreConfig::new(
        root.path().join("blobs"),
        root.path().join("store.redb"),
        kappa_crypto::testing::fixture_authority(1)?,
    );
    config.max_idle_namespaces = 0;
    let store = PersistentStore::new(config)?;
    let (_, principal) = retirement_principal()?;
    let governing = create(&store, "reclaim-governing")?;
    let a = create_owned(&store, "reclaim-missing", Some(&principal))?;
    let instance = store.namespace_snapshot(&a)?.controller().instance;
    drain_settlement(&store, &a)?;
    publish_blob(&store, &a, 7, BYTES, 2000)?;
    let allocation = parked_allocation(&store, &a, true)?;
    let held = entries(&store, &allocation)?;
    // Unsettled: the projection names no owner. Idle controllers are
    // evicted (max_idle 0), so the directory can be removed underneath.
    assert!(
        store.namespaces.open_controller(a.id()).is_none(),
        "controller not evicted"
    );
    let directory = crate::storage::NamespaceController::directory(store.namespaces.root(), a.id());
    std::fs::rename(&directory, root.path().join("displaced"))?;
    let pass = inventory_pass(&store)?;
    assert_eq!(
        pass.protected, held,
        "unexplained absence must protect: {pass:?}"
    );
    assert_eq!(pass.files, 0, "{pass:?}");
    assert!(crate::allocation::allocation_path(&store.blob_root, &allocation).exists());
    // The owner's governed release decides. No restart found the loss, so
    // no obligation closes the pool and the decision publishes as any
    // operation. The directory is already gone, so the removal is a no-op.
    let released = store.release_lost_for_test(&governing, &instance, ClockMs::from_raw(3000))?;
    assert_eq!(
        store.retirement_record(&instance)?,
        Some(RetirementRecord::Released {
            governing: *governing.id(),
            decision: released.record().clone(),
        })
    );
    let pass = inventory_pass(&store)?;
    assert_eq!(pass.files, 1, "recorded retirement releases: {pass:?}");
    assert_eq!(entries(&store, &allocation)?, 0, "every entry went with it");
    // A crash between the record and the removal: put the directory back
    // and reopen; recovery at open completes the retirement, because the
    // storage records exactly the retired instance.
    drop(store);
    std::fs::rename(root.path().join("displaced"), &directory)?;
    assert!(directory.exists());
    let reopened = open(root.path())?;
    assert!(
        !directory.exists(),
        "recorded retirement not completed at open"
    );
    assert!(
        reopened.pending_settlements()?.is_empty(),
        "the retired instance's pending marker was discharged"
    );
    assert!(matches!(
        reopened.namespace_snapshot(&a),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

/// The owner marker is written at installation, before the row, and the
/// settled projection is never the sole deletion authority: a retirement
/// that committed releases the allocation through the namespace's row,
/// and the marker goes with the files.
#[test]
fn retirement_releases_through_the_installers_row_and_removes_the_marker() -> TestResult {
    const BYTES: usize = 256 * 1024;
    let root = tempfile::tempdir()?;
    let store = open(root.path())?;
    let a = create(&store, "reclaim-retire")?;
    drain_settlement(&store, &a)?;
    publish_blob(&store, &a, 6, BYTES, 2000)?;
    let identity = Kappa::sha256(&vec![6u8; BYTES]);
    let allocation = parked_allocation(&store, &a, false)?;
    assert_eq!(
        crate::allocation::read_owner_marker(&store.blob_root, &allocation)?,
        Some(crate::allocation::Owner {
            instance: store.namespace_snapshot(&a)?.controller().instance,
            identity: identity.clone(),
        })
    );
    let held = entries(&store, &allocation)?;
    drain_settlement(&store, &a)?;
    let clock = clock_at(ClockMs::from_raw(3000))?;
    let mut execution = store.begin_epoch_execution(&a, &clock, None)?;
    execution.tag_delete("item-6")?;
    assert_eq!(
        kappa_store::ExecutionWrites::content_retire(&mut execution, &identity)?,
        kappa_store::execution::Retirement::Retired
    );
    execution.publish()?;
    // Before settlement the projection still names A as owner: kept.
    let pass = inventory_pass(&store)?;
    assert_eq!(pass.owned, held, "{pass:?}");
    assert!(crate::allocation::owner_path(&store.blob_root, &allocation).exists());
    drain_settlement(&store, &a)?;
    assert!(
        !crate::allocation::allocation_path(&store.blob_root, &allocation).exists(),
        "settlement of the retirement did not reclaim the allocation"
    );
    assert!(!crate::allocation::owner_path(&store.blob_root, &allocation).exists());
    let pass = inventory_pass(&store)?;
    assert_eq!(pass.files, 0, "{pass:?}");
    assert_eq!(pass.owned, 0, "{pass:?}");
    Ok(())
}
