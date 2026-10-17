//! Governed retirement of present storage, driven through the store: the
//! owner's release removes exactly its instance; a refused decision leaves
//! the namespace serving every purpose; a release held back by a reader
//! keeps its intent across a restart, and recovery completes it from the
//! published decision.

use std::path::Path;

use kappa_handler::clock_at;
use kappa_store::{ClockMs, EpochStore, Kappa, NamespaceRef, StoreError, TagUpdate};

use crate::control_plane::{Guarantee, Guarantees};
use crate::retirement_record::RetirementRecord;
use crate::storage::NamespaceController;
use crate::storage_instance::StorageInstance;
use crate::test_support::retirement_principal;
use crate::{PersistentStore, PersistentStoreConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn open(root: &Path) -> Result<PersistentStore, Box<dyn std::error::Error>> {
    Ok(PersistentStore::new(PersistentStoreConfig::new(
        root.join("blobs"),
        root.join("store.redb"),
        kappa_crypto::testing::fixture_authority(1)?,
    ))?)
}

fn create(
    store: &PersistentStore,
    name: &str,
    owner: Option<&Kappa>,
) -> Result<NamespaceRef, StoreError> {
    store.create_for_test(
        name,
        owner,
        Guarantees::NONE
            .with(Guarantee::TotalOrder)
            .with(Guarantee::LinearizableReads),
    )
}

/// Publish one tag of `ns` at `time`.
fn publish(store: &PersistentStore, ns: &NamespaceRef, time: i64) -> Result<(), StoreError> {
    let mut execution =
        store.begin_epoch_execution(ns, &clock_at(ClockMs::from_raw(time))?, None)?;
    execution.tag_put(
        "head",
        &TagUpdate::Set {
            kappa: Kappa::sha256(&time.to_be_bytes()),
        },
    )?;
    execution.publish()?;
    Ok(())
}

/// A governing namespace and a target the retirement principal owns, with
/// one epoch past its creation; the target's instance.
fn owned_target(
    store: &PersistentStore,
) -> Result<(NamespaceRef, NamespaceRef, StorageInstance), Box<dyn std::error::Error>> {
    let (_, principal) = retirement_principal()?;
    let governing = create(store, "retiring-governing", None)?;
    let target = create(store, "retiring-target", Some(&principal))?;
    publish(store, &target, 2000)?;
    let instance = store.namespace_snapshot(&target)?.controller().instance;
    Ok((governing, target, instance))
}

/// The record of `instance` is the release of the decision `decision`.
fn released(
    store: &PersistentStore,
    governing: &NamespaceRef,
    instance: &StorageInstance,
    decision: &Kappa,
) -> TestResult {
    assert_eq!(
        store.retirement_record(instance)?,
        Some(RetirementRecord::Released {
            governing: *governing.id(),
            decision: decision.clone(),
        })
    );
    Ok(())
}

/// The owner's release at the current head removes exactly its instance:
/// the record names the published decision, which verifies, and the
/// namespace has no storage.
#[test]
fn the_owners_release_removes_its_present_storage() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open(root.path())?;
    let (governing, target, instance) = owned_target(&store)?;
    let retired = store.retire_present_for_test(&governing, &instance, ClockMs::from_raw(3000))?;
    released(&store, &governing, &instance, retired.record())?;
    let record = store.retirement_record(&instance)?.ok_or("no record")?;
    assert!(store.release_verified(&instance, &record)?);
    assert!(!NamespaceController::directory(root.path(), target.id()).exists());
    assert!(matches!(
        store.namespace_snapshot(&target),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

/// A decision `authorize` refuses publishes nothing: the intent is given
/// up and the namespace publishes again. Both refusals are the principal's
/// own request: signed for a head the target has moved past, and signed by
/// a principal that does not own the target.
#[test]
fn a_refused_decision_gives_the_intent_up() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open(root.path())?;
    let (governing, target, instance) = owned_target(&store)?;
    let (number, head) = store.epoch_current(&target)?;
    let stale = Some(kappa_store::ObservedHead {
        epoch_number: number,
        root: head,
    });
    publish(&store, &target, 2500)?;
    let refused = store.retire_for_test(
        &governing,
        &instance,
        kappa_store::Disposition::RetirePresent,
        stale,
        ClockMs::from_raw(3000),
    );
    assert!(
        matches!(refused, Err(StoreError::Rejected(_))),
        "{refused:?}"
    );
    assert!(store.retirement_record(&instance)?.is_none());
    publish(&store, &target, 3500)?;

    let unowned = create(&store, "retiring-unowned", None)?;
    let unowned_instance = store.namespace_snapshot(&unowned)?.controller().instance;
    let refused =
        store.retire_present_for_test(&governing, &unowned_instance, ClockMs::from_raw(4000));
    assert!(
        matches!(refused, Err(StoreError::Rejected(_))),
        "{refused:?}"
    );
    assert!(store.retirement_record(&unowned_instance)?.is_none());
    publish(&store, &unowned, 4500)?;
    Ok(())
}

/// A reader holding the namespace when the decision publishes keeps its
/// storage: the release is refused, the intent stays and fences the
/// storage across a restart, and recovery at the next open releases it
/// from the decision the governing namespace published.
#[test]
fn a_release_held_back_by_a_reader_completes_after_restart() -> TestResult {
    let root = tempfile::tempdir()?;
    let (governing, target, instance) = {
        let store = open(root.path())?;
        let (governing, target, instance) = owned_target(&store)?;
        let reader = store.namespace_snapshot(&target)?;
        let held = store.retire_present_for_test(&governing, &instance, ClockMs::from_raw(3000));
        assert!(matches!(held, Err(StoreError::Conflict(_))), "{held:?}");
        assert!(matches!(
            store.retirement_record(&instance)?,
            Some(RetirementRecord::Intent { .. })
        ));
        assert!(
            matches!(publish(&store, &target, 3500), Err(StoreError::Conflict(_))),
            "a retiring namespace published"
        );
        assert_eq!(
            reader.controller().instance,
            instance,
            "the reader's storage is intact"
        );
        drop(reader);
        (governing, target, instance)
    };
    assert!(NamespaceController::directory(root.path(), target.id()).exists());
    let reopened = open(root.path())?;
    assert!(
        !NamespaceController::directory(root.path(), target.id()).exists(),
        "recovery at open did not complete the published release"
    );
    let record = reopened.retirement_record(&instance)?.ok_or("no record")?;
    assert!(matches!(record, RetirementRecord::Released { .. }));
    assert!(reopened.release_verified(&instance, &record)?);
    assert_eq!(
        reopened.epoch_current(&governing)?.0,
        2,
        "the decision published once, before the restart"
    );
    Ok(())
}
