//! Publication binding: a sealed root commits only with the transaction that
//! sealed it, recovery revalidates evidence, and erasure revokes reads.
//!
//! In `src` because these tests drive crate-private seams the public
//! contract never exposes: the namespace writer (`test_writer`),
//! `epoch_cache`, `seal_epoch_in_txn`, `commit_epoch_transaction`,
//! `resolve_epoch_publication`, `tag_put_in_txn`, `tag_delete_in_txn`,
//! `tag_state_in_txn`, `edge_mutation_put_in_txn`, and `BLOB_INDEX`.

use super::*;
use crate::epoch_execution::PreparedEpochPublication;
use kappa_store::{EpochStore, TagStore, TagUpdate};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn spec() -> crate::test_support::PersistentSpec {
    crate::test_support::PersistentSpec::new().db_file("state.redb")
}

/// A store retaining its own scope.
fn store() -> Result<PersistentStore, kappa_fixture::SetupError> {
    Ok(spec().acquire()?.into_store())
}

/// Seal `writer`'s transaction and return the root, keeping the writer.
fn seal(
    store: &PersistentStore,
    writer: &crate::test_support::TestWriter,
    ns: &NamespaceRef,
    now: ClockMs,
) -> Result<EpochRoot, StoreError> {
    Ok(store
        .seal_epoch_in_txn(&writer.txn, writer.active.controller(), ns, now, None)?
        .root)
}

#[test]
fn commit_rejects_a_root_from_an_aborted_transaction() -> TestResult {
    let store = store()?;
    let ns = NamespaceRef::deterministic("transaction-binding");
    let now = ClockMs::from_raw(1000);
    let abandoned = store.test_writer(&ns)?;
    let root = seal(&store, &abandoned, &ns, now)?;
    abandoned.txn.abort()?;
    drop(abandoned.writer);
    drop(abandoned.active);
    let unrelated = store.test_writer(&ns)?;
    store.tag_put_in_txn(
        &unrelated.txn,
        &ns,
        "unrelated",
        &TagUpdate::Set {
            kappa: Kappa::sha256(b"unrelated"),
        },
        now,
    )?;
    assert!(matches!(
        PreparedEpochPublication::commit_test_transaction(&store, unrelated, &ns, root),
        Err(StoreError::Conflict(_))
    ));
    assert!(matches!(
        store.tag_get_raw(&ns, "unrelated"),
        Err(StoreError::NotFound(_))
    ));
    assert!(matches!(
        store.epoch_current(&ns),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

#[test]
fn recovery_revalidates_ledger_even_with_a_cached_root() -> TestResult {
    let store = store()?;
    let ns = NamespaceRef::deterministic("uncached-recovery");
    let now = ClockMs::from_raw(1000);
    let writer = store.test_writer(&ns)?;
    let (_, identity) = store.publish_test_writer(writer, &ns, now)?;
    let root = store.epoch_get(&identity)?;
    let ledger = root.ledger_root().key_bytes();
    assert!(store.epoch_cache.contains_key(&identity));
    store.resolve_publication(&ns, 1, &identity)?;
    let (db, _active) = store.namespace_db(&ns)?;
    let corrupt = db.begin_write()?;
    {
        let mut index = corrupt.open_table(BLOB_INDEX)?;
        index.remove(ledger.as_slice())?;
    }
    corrupt.commit()?;
    assert!(matches!(
        store.resolve_publication(&ns, 1, &identity),
        Err(StoreError::NotFound(_))
    ));
    store.epoch_cache.remove(&identity);
    assert!(store.epoch_get(&identity).is_err());
    assert!(store.epoch_current(&ns).is_err());
    assert!(store.epoch_get_by_number(&ns, 1).is_err());
    Ok(())
}

#[test]
fn encryption_erasure_revokes_previously_admitted_epoch_reads()
-> Result<(), Box<dyn std::error::Error>> {
    let store = spec().encryption_key([47; 32]).acquire()?.into_store();
    let ns = NamespaceRef::deterministic("erased-epoch");
    let (number, identity) = store
        .begin_epoch_execution(
            &ns,
            &kappa_handler::clock_at(ClockMs::from_raw(1000))?,
            None,
        )?
        .publish()?;
    store.settle_all()?;
    store.epoch_get(&identity)?;
    store.epoch_current(&ns)?;
    store.epoch_get_by_number(&ns, number)?;
    store.erase_blob_encryption()?;
    store.epoch_cache.clear();
    assert!(store.epoch_get(&identity).is_err());
    assert!(store.epoch_current(&ns).is_err());
    assert!(store.epoch_get_by_number(&ns, number).is_err());
    Ok(())
}

#[test]
fn restoring_tag_state_after_sealing_does_not_restore_ledger_correspondence() -> TestResult {
    let store = store()?;
    let ns = NamespaceRef::deterministic("post-seal-restoration");
    let now = ClockMs::from_raw(1000);
    let writer = store.test_writer(&ns)?;
    let root = seal(&store, &writer, &ns, now)?;
    let before = store.tag_state_in_txn(&writer.txn, &ns)?;
    store.tag_put_in_txn(
        &writer.txn,
        &ns,
        "temporary",
        &TagUpdate::Set {
            kappa: Kappa::sha256(b"temporary"),
        },
        now,
    )?;
    store.tag_delete_in_txn(&writer.txn, &ns, "temporary", now)?;
    assert_eq!(store.tag_state_in_txn(&writer.txn, &ns)?, before);
    assert!(matches!(
        PreparedEpochPublication::commit_test_transaction(&store, writer, &ns, root),
        Err(StoreError::Conflict(_))
    ));
    assert!(matches!(
        store.epoch_current(&ns),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

#[test]
fn edge_mutation_after_sealing_invalidates_publication_without_changing_tags() -> TestResult {
    let store = store()?;
    let ns = NamespaceRef::deterministic("post-seal-edge");
    let now = ClockMs::from_raw(1000);
    let writer = store.test_writer(&ns)?;
    let root = seal(&store, &writer, &ns, now)?;
    let edge = kappa_store::EdgeInput {
        source: Kappa::sha256(b"source"),
        target: Kappa::sha256(b"target"),
        relation: kappa_store::EdgeRelation::Builtin(kappa_store::BuiltinRelation::Owns),
        asserter: Kappa::sha256(b"asserter"),
        created_at_ms: now.as_i64(),
        metadata: None,
    };
    store.edge_mutation_put_in_txn(&writer.txn, &ns, &edge, now)?;
    assert!(matches!(
        PreparedEpochPublication::commit_test_transaction(&store, writer, &ns, root),
        Err(StoreError::Conflict(_))
    ));
    assert!(matches!(
        store.epoch_current(&ns),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}
