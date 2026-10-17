//! Release grants against a store's own recovery obligations: who may hold
//! one, what it admits while the pool is closed, and that it never takes a
//! charge.

use kappa_store::StoreError;

use crate::PersistentStore;
use crate::settlement::Origin;
use crate::storage_instance::StorageInstance;
use crate::unsettled::{Class, Closure};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn store() -> Result<PersistentStore, kappa_fixture::SetupError> {
    Ok(crate::test_support::persistent_store()?.into_store())
}

/// A store holding an unresolved obligation for a lost instance, recorded
/// the way recovery records it.
fn closed_by_a_lost_instance()
-> Result<(PersistentStore, StorageInstance), Box<dyn std::error::Error>> {
    let store = store()?;
    assert!(
        store.unsettled.closures().is_empty(),
        "control: the startup closure ended with the enumeration at open"
    );
    let lost = StorageInstance::generate([5; 16])?;
    store.record_unresolved(&lost, Origin::Marker, "storage missing".into())?;
    Ok((store, lost))
}

/// No obligation, no grant: the release is admitted as any publication.
#[test]
fn an_instance_without_an_obligation_gets_no_grant() -> TestResult {
    let store = store()?;
    assert!(
        store
            .release_grant(&StorageInstance::generate([6; 16])?)?
            .is_none()
    );
    Ok(())
}

/// While the obligation closes the pool, an ordinary admission is refused,
/// an empty one included; the grant admits a publication that takes
/// nothing and refuses one that would take anything.
#[test]
fn a_grant_admits_only_a_publication_that_takes_no_charge() -> TestResult {
    let (store, lost) = closed_by_a_lost_instance()?;
    assert_eq!(store.unsettled.closures(), vec![Closure::Obligation(lost)]);
    assert!(matches!(
        store.unsettled.admit(Class::Ordinary, 0, 0),
        Err(StoreError::CapacityExceeded(_))
    ));
    let grant = store
        .release_grant(&lost)?
        .ok_or("no grant for a held obligation")?;
    let admitted = store.unsettled.admit(Class::Resolving(&grant), 0, 0)?;
    assert_eq!((admitted.entries(), admitted.bytes()), (0, 0));
    for (entries, bytes) in [(1, 0), (0, 1), (1, 1)] {
        assert!(
            matches!(
                store
                    .unsettled
                    .admit(Class::Resolving(&grant), entries, bytes),
                Err(StoreError::CapacityExceeded(_))
            ),
            "a resolving admission took {entries} entries and {bytes} bytes"
        );
    }
    assert_eq!(store.unsettled.charged(), (0, 0));
    Ok(())
}

/// One release of an instance at a time: a second grant is refused while
/// the first exists, and granted once it drops.
#[test]
fn one_grant_per_obligation_until_it_drops() -> TestResult {
    let (store, lost) = closed_by_a_lost_instance()?;
    let first = store
        .release_grant(&lost)?
        .ok_or("no grant for a held obligation")?;
    assert!(matches!(
        store.release_grant(&lost),
        Err(StoreError::Conflict(_))
    ));
    drop(first);
    let again = store.release_grant(&lost)?;
    assert!(again.is_some(), "the mark outlived its grant");
    Ok(())
}

/// The obligation discharged while a grant exists: the grant's drop finds
/// nothing to clear, the pool reopens with the obligation, and no grant is
/// minted afterwards.
#[test]
fn a_discharged_obligation_outlives_no_grant() -> TestResult {
    let (store, lost) = closed_by_a_lost_instance()?;
    let grant = store
        .release_grant(&lost)?
        .ok_or("no grant for a held obligation")?;
    store.discharge(&lost, "its release is recorded");
    assert!(store.unsettled.closures().is_empty());
    drop(grant);
    assert!(store.release_grant(&lost)?.is_none());
    assert!(store.unsettled.admit(Class::Ordinary, 1, 1).is_ok());
    Ok(())
}
