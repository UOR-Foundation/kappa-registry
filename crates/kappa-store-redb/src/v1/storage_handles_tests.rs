use std::sync::atomic::Ordering;
use std::sync::{Arc, Barrier};

use super::ActivityReservation;
use crate::storage::fixture::{create, storage};
use crate::storage::{Opening, Recording};
use kappa_store::StoreError;

#[test]
fn concurrent_reservations_cannot_exceed_capacity() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let storage = storage(root.path(), 0, 1);
    let start = Barrier::new(8);
    let acquired = Barrier::new(8);
    let successes = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    let reservation = ActivityReservation::acquire(&storage.inner);
                    // Every attempt finishes before any successful reservation drops.
                    acquired.wait();
                    usize::from(reservation.is_ok())
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().map_err(|_| "reservation worker panicked"))
            .collect::<Result<Vec<_>, _>>()
    })?;
    assert_eq!(successes.iter().sum::<usize>(), 1);
    assert_eq!(storage.inner.active_total.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn failed_open_releases_capacity_and_does_not_leave_an_unbounded_slot()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let storage = storage(root.path(), 0, 1);
    for byte in 0..32 {
        assert!(matches!(
            storage.admit_read(&[byte; 16]),
            Err(StoreError::NotFound(_))
        ));
        assert_eq!(storage.inner.active_total.load(Ordering::Acquire), 0);
        assert!(storage.inner.open.is_empty());
    }
    Ok(())
}

#[test]
fn concurrent_first_access_shares_one_controller_and_last_release_evicts()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let storage = storage(root.path(), 0, 8);
    let start = Barrier::new(8);
    let admitted = Barrier::new(8);
    let outcomes = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    let activity = storage.admit_publish(&[1; 16], &create(&storage));
                    admitted.wait();
                    // Keep activities alive through join so pointer identity is not
                    // confused with an allocator reusing a dropped controller's address.
                    activity.map_err(|error| error.to_string())
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .map_err(|_| "open worker panicked".to_owned())?
            })
            .collect::<Result<Vec<_>, String>>()
    })?;
    assert_eq!(outcomes.len(), 8);
    for activity in &outcomes {
        assert!(Arc::ptr_eq(activity.controller(), outcomes[0].controller()));
    }
    assert_eq!(storage.inner.active_total.load(Ordering::Acquire), 8);
    assert!(matches!(
        storage.remove_recorded(&[1; 16], |_| Ok(())),
        Err(StoreError::Conflict(_))
    ));
    drop(outcomes);
    assert_eq!(storage.inner.active_total.load(Ordering::Acquire), 0);
    assert!(storage.inner.open.is_empty());
    Ok(())
}

#[test]
fn dropping_one_of_two_activities_releases_only_its_grant() -> Result<(), Box<dyn std::error::Error>>
{
    let root = tempfile::tempdir()?;
    let storage = storage(root.path(), 0, 2);
    let opening = create(&storage);
    let first = storage.admit_publish(&[1; 16], &opening)?;
    let second = storage.admit_publish(&[1; 16], &opening)?;
    assert!(matches!(
        storage.admit_publish(&[2; 16], &opening),
        Err(StoreError::CapacityExceeded(_))
    ));
    drop(first);
    assert_eq!(second.controller().active.load(Ordering::Acquire), 1);
    assert_eq!(storage.inner.active_total.load(Ordering::Acquire), 1);
    assert!(storage.open_controller(&[1; 16]).is_some());
    let unrelated = storage.admit_publish(&[2; 16], &opening)?;
    drop(unrelated);
    assert!(storage.open_controller(&[2; 16]).is_none());
    assert!(storage.open_controller(&[1; 16]).is_some());
    drop(second);
    assert_eq!(storage.inner.active_total.load(Ordering::Acquire), 0);
    // In particular, the capacity grant's eviction must run after Active
    // releases its controller Arc, not before it.
    assert!(storage.inner.open.is_empty());
    Ok(())
}

#[test]
fn retained_controller_prevents_eviction_and_removal() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let storage = storage(root.path(), 0, 1);
    let activity = storage.admit_publish(&[1; 16], &create(&storage))?;
    let retained = Arc::clone(activity.controller());
    drop(activity);
    assert_eq!(storage.inner.active_total.load(Ordering::Acquire), 0);
    storage.evict_idle();
    assert!(storage.open_controller(&[1; 16]).is_some());
    assert!(matches!(
        storage.remove_recorded(&[1; 16], |_| Ok(())),
        Err(StoreError::Conflict(_))
    ));
    drop(retained);
    storage.evict_idle();
    assert!(storage.inner.open.is_empty());
    Ok(())
}

#[test]
fn unsettled_dependencies_survive_last_activity_release() -> Result<(), Box<dyn std::error::Error>>
{
    let root = tempfile::tempdir()?;
    let storage = storage(root.path(), 0, 1);
    let activity = storage.admit_publish(&[1; 16], &create(&storage))?;
    let protection = Arc::new(crate::allocation::Protection::default());
    let allocation = crate::representation::AllocationId::generate()?;
    activity.controller().park_until_settled(
        7,
        crate::unsettled::Parked::uncharged(vec![protection.pin(allocation)?]),
    );
    drop(activity);
    storage.evict_idle();
    assert!(
        protection.claim(allocation)?.is_none(),
        "eviction released unsettled content"
    );
    let controller = storage
        .open_controller(&[1; 16])
        .ok_or("unsettled controller evicted")?;
    controller.release_settled(6);
    assert!(
        protection.claim(allocation)?.is_none(),
        "earlier settlement released later content"
    );
    controller.release_settled(7);
    assert!(protection.claim(allocation)?.is_some());
    drop(controller);
    storage.evict_idle();
    assert!(storage.inner.open.is_empty());
    Ok(())
}

#[test]
fn settlement_does_not_release_unknown_commit_dependencies()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let storage = storage(root.path(), 0, 1);
    let activity = storage.admit_publish(&[1; 16], &create(&storage))?;
    let protection = Arc::new(crate::allocation::Protection::default());
    let pending = crate::representation::AllocationId::generate()?;
    let unknown = crate::representation::AllocationId::generate()?;
    activity.controller().park_until_settled(
        7,
        crate::unsettled::Parked::uncharged(vec![protection.pin(pending)?]),
    );
    activity
        .controller()
        .unresolved_content
        .lock()
        .map_err(|_| "pins poisoned")?
        .append(crate::unsettled::Parked::uncharged(vec![
            protection.pin(unknown)?,
        ]));
    activity.controller().fence()?;
    activity.controller().release_settled(u64::MAX);
    assert!(protection.claim(pending)?.is_some());
    assert!(
        protection.claim(unknown)?.is_none(),
        "settlement resolved an unknown commit"
    );
    drop(activity);
    storage.evict_idle();
    assert!(storage.open_controller(&[1; 16]).is_some());
    assert!(matches!(
        storage.remove_recorded(&[1; 16], |_| Ok(())),
        Err(StoreError::Conflict(_))
    ));
    assert!(protection.claim(unknown)?.is_none());
    Ok(())
}

#[test]
fn a_refused_removal_record_leaves_the_namespace_live() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let storage = storage(root.path(), 1, 1);
    drop(storage.admit_publish(&[1; 16], &create(&storage))?);
    let directory = crate::storage::NamespaceController::directory(root.path(), &[1; 16]);
    assert!(directory.exists());
    assert!(matches!(
        storage.remove_recorded(&[1; 16], |_| Err(Recording::Refused(StoreError::Internal(
            "record refused".into()
        )))),
        Err(StoreError::Internal(_))
    ));
    assert!(directory.exists(), "storage removed without its record");
    assert!(
        storage.admit_read(&[1; 16]).is_ok(),
        "namespace left retired after the record was refused"
    );
    storage.remove_recorded(&[1; 16], |_| Ok(()))?;
    assert!(!directory.exists());
    assert!(matches!(
        storage.admit_read(&[1; 16]),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

/// A removal record whose commit outcome is unknown may be durable: the
/// storage is kept, and nothing of the namespace is admitted, eviction
/// included, until the store is reopened and the record decides.
#[test]
fn an_unknown_removal_record_outcome_leaves_the_namespace_unresolved()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let storage = storage(root.path(), 0, 1);
    drop(storage.admit_publish(&[1; 16], &create(&storage))?);
    let directory = crate::storage::NamespaceController::directory(root.path(), &[1; 16]);
    assert!(matches!(
        storage.remove_recorded(&[1; 16], |_| Err(Recording::Unknown(StoreError::Internal(
            "commit outcome unknown".into()
        )))),
        Err(StoreError::Internal(_))
    ));
    assert!(
        directory.exists(),
        "storage removed on an unknown record outcome"
    );
    storage.evict_idle();
    assert!(matches!(
        storage.admit_read(&[1; 16]),
        Err(StoreError::Unavailable(_))
    ));
    assert!(matches!(
        storage.admit_publish(&[1; 16], &Opening::Existing),
        Err(StoreError::Unavailable(_))
    ));
    assert!(matches!(
        storage.try_maintain(&[1; 16]),
        Err(StoreError::Unavailable(_))
    ));
    assert!(matches!(
        storage.remove_recorded(&[1; 16], |_| Ok(())),
        Err(StoreError::Unavailable(_))
    ));
    assert!(directory.exists());
    Ok(())
}

#[test]
fn fence_survives_handle_reconstruction_and_does_not_fence_other_namespaces()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    {
        let storage = storage(root.path(), 0, 2);
        let opening = create(&storage);
        let affected = storage.admit_publish(&[1; 16], &opening)?;
        let unrelated = storage.admit_publish(&[2; 16], &opening)?;
        affected.controller().fence()?;
        assert!(!unrelated.controller().fenced());
    }
    // All in-process flags and pins are gone. Read the persisted fence.
    let storage = storage(root.path(), 0, 2);
    let affected = storage.admit_read(&[1; 16])?;
    let unrelated = storage.admit_read(&[2; 16])?;
    assert!(affected.controller().fenced());
    assert!(!unrelated.controller().fenced());
    // Opening an existing database cannot recover provisional creation
    // authority when no assignment was ever admitted.
    assert!(affected.controller().plane().is_err());
    assert!(unrelated.controller().plane().is_err());
    Ok(())
}

#[test]
fn settlement_releases_only_covered_epochs_even_when_parking_is_out_of_order()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let storage = storage(root.path(), 0, 1);
    let activity = storage.admit_publish(&[1; 16], &create(&storage))?;
    let protection = Arc::new(crate::allocation::Protection::default());
    let older = crate::representation::AllocationId::generate()?;
    let newer = crate::representation::AllocationId::generate()?;
    activity.controller().park_until_settled(
        9,
        crate::unsettled::Parked::uncharged(vec![protection.pin(newer)?]),
    );
    activity.controller().park_until_settled(
        7,
        crate::unsettled::Parked::uncharged(vec![protection.pin(older)?]),
    );
    activity.controller().release_settled(7);
    assert!(protection.claim(older)?.is_some());
    assert!(protection.claim(newer)?.is_none());
    activity.controller().release_settled(6);
    assert!(protection.claim(newer)?.is_none());
    activity.controller().release_settled(9);
    assert!(protection.claim(newer)?.is_some());
    Ok(())
}
