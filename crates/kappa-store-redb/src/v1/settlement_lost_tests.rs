//! Storage lost before a restart: its obligation closes the unsettled pool,
//! and its owner's governed release, publishing through the obligation's
//! release grant, is the exit that closure does not block.

use kappa_store::{BlobStore, ClockMs, Disposition, EpochStore, Kappa, StoreError};

use super::{TestResult, create, create_owned, instance_of, open, publish, refused, write};
use crate::retirement_record::RetirementRecord;
use crate::storage::NamespaceController;
use crate::store_access::Coverage;
use crate::test_support::retirement_principal;
use crate::unsettled::Closure;
use crate::{PersistentStore, PersistentStoreConfig};

/// A committed but unsettled namespace whose storage disappears before a
/// restart stays an unresolved obligation: the store opens, its marker and
/// claim are kept, identity misses are unavailable and the pool is closed,
/// naming the lost instance, while a readable sibling recovers in the same
/// pass. The owner's governed release of exactly the missing instance
/// publishes while the pool is closed, through the obligation's release
/// grant, and resolves it.
#[test]
fn storage_lost_before_restart_stays_unresolved_while_its_sibling_recovers() -> TestResult {
    let root = tempfile::tempdir()?;
    let (_, principal) = retirement_principal()?;
    let (lost, sibling, governing, instance) = {
        let store = open(root.path())?;
        let governing = create(&store, "lost-governing")?;
        let lost = create_owned(&store, "lost", Some(&principal))?;
        let sibling = create(&store, "sibling")?;
        // The owner record is projected: the release's authority evidence.
        store.settlement_step(u64::MAX)?;
        publish(&store, &lost, b"committed, then lost", 2000)?;
        write(&store, &sibling, 2001)?;
        let instance = instance_of(&store, &lost)?;
        (lost, sibling, governing, instance)
    };
    let directory = NamespaceController::directory(root.path(), lost.id());
    std::fs::rename(&directory, root.path().join("displaced"))?;
    let store = open(root.path())?;
    assert!(store.settlement_pass_complete()?, "enumeration finished");
    assert_eq!(
        store.discovery_coverage(),
        Coverage::Incomplete {
            unregistered: 1,
            enumerating: false
        }
    );
    let absent = Kappa::sha256(b"never published");
    assert!(matches!(
        store.blob_get(&absent),
        Err(StoreError::Unavailable(_))
    ));
    assert_eq!(store.pending_settlements()?, vec![*lost.id()]);
    assert!(store.directory_knows(&lost)?, "the claim is kept");
    assert!(
        refused(&write(&store, &sibling, 3000)),
        "the pool is closed"
    );
    assert_eq!(
        store.unsettled.closures(),
        vec![Closure::Obligation(instance)]
    );
    let released = store.release_lost_for_test(&governing, &instance, ClockMs::from_raw(3000))?;
    assert_eq!(released.decision().disposition(), Disposition::ReleaseLost);
    assert_eq!(
        store.retirement_record(&instance)?,
        Some(RetirementRecord::Released {
            governing: *governing.id(),
            decision: released.record().clone(),
        })
    );
    assert!(
        store.release_grant(&instance)?.is_some(),
        "the release's grant outlived its publication"
    );
    store.settlement_step(u64::MAX)?;
    assert_eq!(store.discovery_coverage(), Coverage::Complete);
    assert!(store.pending_settlements()?.is_empty());
    assert!(store.unsettled.closures().is_empty());
    assert!(matches!(
        store.blob_get(&absent),
        Err(StoreError::NotFound(_))
    ));
    write(&store, &sibling, 3001)?;
    Ok(())
}

/// The decision a release publishes while the pool is closed must take no
/// charge. With an inline limit below the size of its records they are
/// prepared externally, which is new allocation ownership: the release is
/// refused before anything publishes, and the instance stays obligated
/// and releasable once its records fit.
#[test]
fn a_release_that_would_take_a_charge_is_refused_while_closed() -> TestResult {
    let root = tempfile::tempdir()?;
    let (_, principal) = retirement_principal()?;
    let narrow = |root: &std::path::Path| -> TestResult<PersistentStore> {
        let mut config = PersistentStoreConfig::new(
            root.join("blobs"),
            root.join("store.redb"),
            kappa_crypto::testing::fixture_authority(1)?,
        );
        config.inline_limit = 64;
        Ok(PersistentStore::new(config)?)
    };
    let (governing, instance) = {
        let store = narrow(root.path())?;
        let governing = create(&store, "narrow-governing")?;
        let lost = create_owned(&store, "narrow-lost", Some(&principal))?;
        store.settlement_step(u64::MAX)?;
        publish(&store, &lost, b"committed, then lost", 2000)?;
        let instance = instance_of(&store, &lost)?;
        std::fs::rename(
            NamespaceController::directory(root.path(), lost.id()),
            root.path().join("displaced"),
        )?;
        (governing, instance)
    };
    let store = narrow(root.path())?;
    assert_eq!(
        store.unsettled.closures(),
        vec![Closure::Obligation(instance)]
    );
    let head = store.epoch_current(&governing)?;
    let refused = store.release_lost_for_test(&governing, &instance, ClockMs::from_raw(3000));
    assert!(
        matches!(refused, Err(StoreError::CapacityExceeded(_))),
        "{refused:?}"
    );
    assert_eq!(
        store.epoch_current(&governing)?,
        head,
        "a refused release published"
    );
    assert!(store.retirement_record(&instance)?.is_none());
    assert_eq!(
        store.unsettled.closures(),
        vec![Closure::Obligation(instance)]
    );
    assert!(
        store.release_grant(&instance)?.is_some(),
        "the refused release's grant outlived it"
    );
    drop(store);
    // The same instance, its records inline: released.
    let store = open(root.path())?;
    store.release_lost_for_test(&governing, &instance, ClockMs::from_raw(4000))?;
    store.settlement_step(u64::MAX)?;
    assert!(store.unsettled.closures().is_empty());
    Ok(())
}
