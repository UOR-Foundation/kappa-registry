//! The completed-generation boundary over a real registry: what a reader
//! selects before and after completion, across restarted attempts and
//! tombstones, and that compaction changes none of it.

use redb::{ReadableDatabase, ReadableTableMetadata};

use kappa_store::Kappa;

use super::{Family, Version, VersionKey, logical, version_key};
use crate::PersistentStore;
use crate::projection_stage::{ProjectionStage, begin_attempt};
use crate::storage_instance::{Incarnation, StorageInstance};
use crate::tables::{PROJECTION_COMPLETED, PROJECTION_LOG, SETTLED};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// One staged write: family, key, member of a membership family, version.
type Write<'k> = (Family, &'k [u8], Option<&'k [u8]>, Version);

fn store() -> Result<PersistentStore, Box<dyn std::error::Error>> {
    Ok(crate::test_support::PersistentSpec::new()
        .in_root(&kappa_fixture::FixtureRoot::temporary()?)
        .db_file("db.redb")
        .acquire()?
        .into_store())
}

fn instance(byte: u8) -> StorageInstance {
    StorageInstance::new([byte; 16], Incarnation::Known([byte; 16]))
}

/// Stage `writes` under a new attempt of `epoch` of `instance`, completing
/// it (and advancing `SETTLED`) when `complete`.
fn settle(
    store: &PersistentStore,
    instance: StorageInstance,
    epoch: u64,
    writes: &[Write<'_>],
    complete: bool,
) -> TestResult {
    let txn = store.registry.begin_write()?;
    let attempt = begin_attempt(&txn, &instance, epoch)?;
    {
        let mut stage = ProjectionStage::open(&txn, instance, epoch, attempt, u64::MAX)?;
        for (family, key, member, version) in writes {
            stage.write(*family, key, *member, version)?;
        }
        if complete {
            stage.complete()?;
        }
    }
    if complete {
        let mut checkpoint = epoch.to_be_bytes().to_vec();
        checkpoint.extend_from_slice(&Kappa::sha256(&epoch.to_be_bytes()).key_bytes());
        txn.open_table(SETTLED)?
            .insert(instance.key().as_slice(), checkpoint.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

fn catalog(
    store: &PersistentStore,
    key: &[u8],
) -> Result<Vec<StorageInstance>, Box<dyn std::error::Error>> {
    Ok(store
        .projection()?
        .get(Family::Catalog, key)?
        .into_iter()
        .map(|visible| visible.instance)
        .collect())
}

/// Keys holding zero bytes keep their byte order through the encoding, a
/// key's members are never confused with a longer key, and version keys
/// decode to what encoded them.
#[test]
fn encoding_preserves_order_and_separates_members() -> TestResult {
    let keys: [&[u8]; 5] = [b"a", b"a\0", b"a\0\0", b"a\x01", b"b"];
    let encoded: Vec<Vec<u8>> = keys
        .iter()
        .map(|key| logical(Family::Catalog, key, None))
        .collect();
    let mut sorted = encoded.clone();
    sorted.sort();
    assert_eq!(sorted, encoded, "escaped keys sort as their bytes do");
    let member = logical(Family::AllocationOwner, b"a", Some(b"m"));
    let longer = logical(Family::AllocationOwner, b"a\x00\x01", None);
    assert_ne!(member, longer, "a member is not a longer key");
    let physical = version_key(&member, &instance(3), 7, 2, 9);
    let decoded = VersionKey::decode(&physical)?;
    assert_eq!(decoded.logical, member);
    assert_eq!(decoded.instance, instance(3));
    assert_eq!(
        (decoded.epoch, decoded.attempt, decoded.sequence),
        (7, 2, 9)
    );
    Ok(())
}

/// A staged version is invisible until its attempt completes; a restarted
/// attempt's predecessor never becomes visible, even after the epoch
/// completes; a completed tombstone hides the older completed put.
#[test]
fn only_completed_attempts_are_visible() -> TestResult {
    let store = store()?;
    let owner = instance(1);
    settle(
        &store,
        owner,
        1,
        &[(
            Family::Catalog,
            b"abandoned",
            None,
            Version::Put(Vec::new()),
        )],
        false,
    )?;
    assert!(
        catalog(&store, b"abandoned")?.is_empty(),
        "staged, not completed"
    );
    settle(
        &store,
        owner,
        1,
        &[(Family::Catalog, b"kept\0x", None, Version::Put(Vec::new()))],
        true,
    )?;
    assert_eq!(catalog(&store, b"kept\0x")?, vec![owner]);
    assert!(
        catalog(&store, b"abandoned")?.is_empty(),
        "the restarted attempt's predecessor never completes"
    );
    settle(
        &store,
        owner,
        2,
        &[(Family::Catalog, b"kept\0x", None, Version::Tombstone)],
        true,
    )?;
    assert!(
        catalog(&store, b"kept\0x")?.is_empty(),
        "the tombstone hides the put"
    );
    Ok(())
}

/// Compaction folds completed versions and removes abandoned ones without
/// changing any read; the staging counters return to zero and the
/// completed rows go once their epochs hold nothing but folded versions.
#[test]
fn compaction_changes_no_read_and_releases_staging() -> TestResult {
    let store = store()?;
    let (first, second) = (instance(1), instance(2));
    settle(
        &store,
        first,
        1,
        &[(Family::Catalog, b"gone", None, Version::Put(Vec::new()))],
        false,
    )?;
    settle(
        &store,
        first,
        1,
        &[
            (Family::Catalog, b"shared", None, Version::Put(Vec::new())),
            (
                Family::AllocationOwner,
                b"0123456789abcdef",
                Some(b"member"),
                Version::Put(Vec::new()),
            ),
        ],
        true,
    )?;
    settle(
        &store,
        second,
        1,
        &[(Family::Catalog, b"shared", None, Version::Put(Vec::new()))],
        true,
    )?;
    settle(
        &store,
        first,
        2,
        &[(
            Family::AllocationOwner,
            b"0123456789abcdef",
            Some(b"member"),
            Version::Tombstone,
        )],
        true,
    )?;
    let before_shared = catalog(&store, b"shared")?;
    assert_eq!(before_shared.len(), 2);
    assert!(store.projection_staged()?.bytes > 0);
    loop {
        if store.compact_projection(2)?.complete {
            break;
        }
    }
    assert_eq!(
        catalog(&store, b"shared")?,
        before_shared,
        "folding changed a read"
    );
    assert!(catalog(&store, b"gone")?.is_empty());
    assert!(
        store
            .projection()?
            .members(Family::AllocationOwner, b"0123456789abcdef")?
            .is_empty(),
        "the folded tombstone still hides the owner"
    );
    let staged = store.projection_staged()?;
    assert_eq!((staged.bytes, staged.entries), (0, 0));
    let read = store.registry.begin_read()?;
    assert_eq!(read.open_table(PROJECTION_LOG)?.len()?, 0);
    assert_eq!(read.open_table(PROJECTION_COMPLETED)?.len()?, 0);
    Ok(())
}
