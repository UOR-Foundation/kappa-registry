//! The completed-generation boundary over a real registry: what a reader
//! selects before and after completion, across restarted attempts and
//! tombstones, that compaction changes none of it, and the one reduction's
//! selection order, stops and resumption.

use std::ops::ControlFlow;

use redb::ReadableTableMetadata;

use kappa_store::Kappa;
use kappa_store::work::{Dimension, Meter, WorkLimit, WorkMeter, reserve_charged};

use super::reduce::{Reduced, Reduction, reduce_groups, undelivered};
use super::{
    Family, Version, VersionKey, VersionRef, key_prefix, key_prefix_len, logical, logical_len,
    prefixed, prefixed_cost, version_key,
};
use crate::PersistentStore;
use crate::projection_stage::{ProjectionStage, begin_attempt};
use crate::storage_instance::{Incarnation, StorageInstance};
use crate::tables::{PROJECTION_COMPLETED, PROJECTION_LOG, PROJECTION_VERSIONS, SETTLED};

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
    let attempt = begin_attempt(&txn, &instance, epoch, &mut WorkMeter::unbounded())?;
    {
        let mut stage = ProjectionStage::open(
            &txn,
            instance,
            epoch,
            attempt,
            u64::MAX,
            store.settlement_limits,
            &mut store.read_meter(),
        )?;
        for (family, key, member, version) in writes {
            stage.write(
                *family,
                key,
                *member,
                version.as_ref(),
                &mut WorkMeter::unbounded(),
            )?;
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
        .get(Family::Catalog, key, &mut store.read_meter())?
        .into_iter()
        .map(|visible| visible.instance)
        .collect())
}

/// Keys holding zero bytes keep their byte order through the encoding, a
/// key's members are never confused with a longer key, version keys decode
/// to what encoded them, and every constructor fills exactly the length its
/// length function reports.
#[test]
fn encoding_preserves_order_and_separates_members() -> TestResult {
    let keys: [&[u8]; 5] = [b"a", b"a\0", b"a\0\0", b"a\x01", b"b"];
    let mut encoded = Vec::new();
    for key in keys {
        let logical = logical(Family::Catalog, key, None, &[])?;
        assert_eq!(logical.len() as u64, logical_len(key, None, 0)?);
        encoded.push(logical);
    }
    let mut sorted = encoded.clone();
    sorted.sort();
    assert_eq!(sorted, encoded, "escaped keys sort as their bytes do");
    let member = logical(Family::AllocationOwner, b"a", Some(b"m\0"), &[])?;
    assert_eq!(member.len() as u64, logical_len(b"a", Some(b"m\0"), 0)?);
    let longer = logical(Family::AllocationOwner, b"a\x00\x01", None, &[])?;
    assert_ne!(member, longer, "a member is not a longer key");
    let prefix = key_prefix(&member, &instance(3))?;
    assert_eq!(prefix.len() as u64, key_prefix_len(&member, &instance(3))?);
    let physical = version_key(&member, &instance(3), 7, 2, 9)?;
    assert!(physical.starts_with(&prefix), "a version extends its group");
    let decoded = VersionKey::decode(&physical)?;
    assert_eq!(decoded.logical, member);
    assert_eq!(decoded.instance, instance(3));
    assert_eq!(
        (decoded.epoch, decoded.attempt, decoded.sequence),
        (7, 2, 9)
    );
    Ok(())
}

/// Insert a put of `payload` at the version coordinates given, directly.
fn insert_version(
    txn: &redb::WriteTransaction,
    logical: &[u8],
    owner: &StorageInstance,
    (epoch, attempt, sequence): (u64, u32, u64),
    payload: u8,
) -> TestResult {
    let key = version_key(logical, owner, epoch, attempt, sequence)?;
    txn.open_table(PROJECTION_VERSIONS)?.insert(
        key.as_slice(),
        {
            let framed = VersionRef::Put(&[payload]);
            let mut bytes = crate::projection::zeroed(framed.encoded_len()?)?;
            framed.encode_into(&mut bytes)?;
            bytes
        }
        .as_slice(),
    )?;
    Ok(())
}

/// One reduction step over the catalog's versions after `state`'s
/// position, every version eligible, deliveries appended to `out` as
/// (logical key, payload) once room for them is secured.
fn reduce_catalog(
    store: &PersistentStore,
    txn: &redb::WriteTransaction,
    state: &mut Reduction,
    work: &mut dyn Meter,
    out: &mut Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<Reduced, Box<dyn std::error::Error>> {
    let table = txn.open_table(PROJECTION_VERSIONS)?;
    let prefix = [Family::Catalog as u8];
    let mut setup = WorkMeter::unbounded();
    let mut versions = {
        let after = state.position().map(<[u8]>::to_vec);
        let mut unit = setup.admit(&[(
            Dimension::BytesAllocated,
            prefixed_cost(&prefix, after.as_deref())?,
        )])?;
        prefixed(&table, &prefix, after.as_deref(), &mut unit)?
    };
    let limits = store.settlement_limits;
    Ok(reduce_groups(
        state,
        &mut versions,
        &limits.versions(),
        &limits.selection_unit(),
        work,
        &mut |version: &VersionKey, _: &mut dyn Meter| Ok(Some(version.epoch)),
        &mut |offered, work| {
            reserve_charged(work, out)?;
            let delivery = offered.take().ok_or_else(undelivered)?;
            let Version::Put(payload) = delivery.version else {
                return Err(kappa_store::StoreError::Internal("a tombstone".into()));
            };
            out.push((delivery.logical, payload));
            Ok(ControlFlow::Continue(()))
        },
    )?)
}

/// A group's selection is its eligible version greatest in (epoch,
/// sequence), not the last eligible one in physical (epoch, attempt,
/// sequence) order: here attempt 0's sequence 5 sorts before attempt 1's
/// sequence 0 and is still selected.
#[test]
fn the_greatest_epoch_and_sequence_is_selected() -> TestResult {
    let store = store()?;
    let owner = instance(1);
    let key = logical(Family::Catalog, b"k", None, &[])?;
    let txn = store.registry.begin_write()?;
    insert_version(&txn, &key, &owner, (1, 0, 5), 50)?;
    insert_version(&txn, &key, &owner, (1, 1, 0), 10)?;
    let mut out = Vec::new();
    let reduced = reduce_catalog(
        &store,
        &txn,
        &mut Reduction::default(),
        &mut WorkMeter::unbounded(),
        &mut out,
    )?;
    assert!(matches!(reduced, Reduced::Exhausted));
    assert_eq!(out, vec![(key, vec![50])]);
    txn.abort()?;
    Ok(())
}

/// A meter that refuses inside a group leaves everything processed in the
/// reduction's state: resumed after its position on a fresh meter, the
/// reduction delivers exactly what one unrefused reduction delivers, each
/// group once, the refused group's earlier versions included in its
/// selection and the next group's first row never skipped.
#[test]
fn a_refusal_inside_a_group_resumes_without_loss() -> TestResult {
    let store = store()?;
    let owner = instance(1);
    let first = logical(Family::Catalog, b"k", None, &[])?;
    let second = logical(Family::Catalog, b"l", None, &[])?;
    let txn = store.registry.begin_write()?;
    insert_version(&txn, &first, &owner, (3, 0, 0), 30)?;
    insert_version(&txn, &first, &owner, (1, 0, 0), 10)?;
    insert_version(&txn, &first, &owner, (2, 0, 0), 20)?;
    insert_version(&txn, &second, &owner, (1, 0, 0), 11)?;
    let mut whole = Vec::new();
    reduce_catalog(
        &store,
        &txn,
        &mut Reduction::default(),
        &mut WorkMeter::unbounded(),
        &mut whole,
    )?;
    assert_eq!(whole, vec![(first.clone(), vec![30]), (second, vec![11])]);

    let mut state = Reduction::default();
    let mut resumed = Vec::new();
    let mut steps = 0;
    // An examination is admitted at a whole selection unit's entries and
    // consumes one, so a step limited to that unit plus one admits two
    // examinations: five (four rows and the end) finish in three steps.
    let unit = store
        .settlement_limits
        .selection_unit()
        .get(Dimension::Entries);
    let quantum = WorkLimit::unbounded().with(Dimension::Entries, unit + 1);
    loop {
        steps += 1;
        assert!(steps <= 3, "the reduction stopped advancing");
        let mut work = WorkMeter::new(quantum);
        let before = state.position().map(<[u8]>::to_vec);
        match reduce_catalog(&store, &txn, &mut state, &mut work, &mut resumed)? {
            Reduced::Exhausted => break,
            Reduced::Refused(_) => {
                assert_ne!(
                    state.position().map(<[u8]>::to_vec),
                    before,
                    "a refused step processed nothing"
                );
            }
            Reduced::Stopped => return Err("the caller never stops this reduction".into()),
        }
    }
    assert_eq!(resumed, whole, "the resumed reduction differs");
    txn.abort()?;
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

/// A read whose meter cannot admit one version is refused, never answered
/// as absence.
#[test]
fn a_refused_read_is_not_absence() -> TestResult {
    let store = store()?;
    let owner = instance(1);
    settle(
        &store,
        owner,
        1,
        &[(Family::Catalog, b"held", None, Version::Put(Vec::new()))],
        true,
    )?;
    let mut starved = WorkMeter::new(WorkLimit::unbounded().with(Dimension::Entries, 0));
    let refused = store
        .projection()?
        .get(Family::Catalog, b"held", &mut starved);
    assert!(
        matches!(refused, Err(kappa_store::StoreError::WorkRefused(_))),
        "{refused:?}"
    );
    assert_eq!(catalog(&store, b"held")?, vec![owner]);
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
    // Steps of one compaction unit each: every step either reaches the end
    // of the log or leaves a continuation, so a bounded number of them
    // finishes (`COMPACTION_UNIT`).
    let mut finished = false;
    for _ in 0..64 {
        let mut work = WorkMeter::new(WorkLimit::unbounded().with(Dimension::Entries, 2));
        let progress = store.compact_projection(&mut work)?.or_unavailable()?;
        assert!(work.used().get(Dimension::Entries) <= 2);
        if progress.complete {
            finished = true;
            break;
        }
    }
    assert!(finished, "compaction made no progress within 64 unit steps");
    assert_eq!(
        catalog(&store, b"shared")?,
        before_shared,
        "folding changed a read"
    );
    assert!(catalog(&store, b"gone")?.is_empty());
    assert!(
        store
            .projection()?
            .members(
                Family::AllocationOwner,
                b"0123456789abcdef",
                &mut store.read_meter()
            )?
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

/// A single key can exceed a compaction step. The committed cursor must
/// retain the position inside that key, rather than replaying its prefix.
#[test]
fn compaction_resumes_inside_one_large_key() -> TestResult {
    let store = store()?;
    let owner = instance(1);
    let writes: Vec<Write<'_>> = (0..32)
        .map(|value| {
            (
                Family::Catalog,
                &b"long-group"[..],
                None,
                Version::Put(vec![value]),
            )
        })
        .collect();
    settle(&store, owner, 1, &writes, true)?;
    let before = catalog(&store, b"long-group")?;
    let quantum = WorkLimit::unbounded().with(Dimension::Entries, 8);
    let mut work = WorkMeter::new(quantum);
    let first = store.compact_projection(&mut work)?.or_unavailable()?;
    assert!(!first.complete);
    assert!(store.compaction_cursor.lock().unwrap().within_key());
    let position = store.compaction_cursor.lock().unwrap().clone();
    let mut work = WorkMeter::new(quantum);
    let second = store.compact_projection(&mut work)?.or_unavailable()?;
    assert!(!second.complete);
    assert!(store.compaction_cursor.lock().unwrap().within_key());
    assert_ne!(
        *store.compaction_cursor.lock().unwrap(),
        position,
        "the next committed step must advance within the same key"
    );
    assert!(work.used().get(Dimension::Entries) <= 8);
    assert_eq!(catalog(&store, b"long-group")?, before);
    store
        .compact_projection(&mut WorkMeter::unbounded())?
        .or_unavailable()?;
    assert!(store.compaction_cursor.lock().unwrap().at_start());
    assert_eq!(catalog(&store, b"long-group")?, before);
    assert_eq!(store.projection_staged()?.entries, 0);
    Ok(())
}
