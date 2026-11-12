//! Publication binding: a sealed root commits only with the transaction that
//! sealed it, recovery revalidates evidence, and erasure revokes reads.
//!
//! In `src` because these tests drive crate-private seams the public
//! contract never exposes: the namespace writer (`test_writer`),
//! `epoch_cache`, the seal (`sign_test_writer`), `commit_epoch_transaction`,
//! `resolve_epoch_publication`, `tag_put_in_txn`, `tag_delete_in_txn`,
//! `tag_state_in_txn`, `edge_mutation_put_in_txn`, and `BLOB_INDEX`.

use super::*;
use crate::epoch_execution::PreparedEpochPublication;
use crate::tables::BLOB_INDEX;
use kappa_store::{ClockMs, EpochStore, TagStore, TagUpdate};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn committed_epoch_discovery_does_not_depend_on_cache_membership() -> TestResult {
    let store = store()?;
    let ns = NamespaceRef::deterministic("uncached-unsettled-root");
    let writer = store.test_writer(&ns)?;
    let (number, identity) = store.publish_test_writer(writer, &ns, ClockMs::from_raw(1000))?;
    let expected = store.epoch_get(&identity)?;
    store.epoch_cache.clear();
    let discovered = store.epoch_get(&identity)?;
    assert_eq!(discovered.kappa(), &identity);
    assert_eq!(discovered.epoch_number(), number);
    assert_eq!(discovered.to_bytes(), expected.to_bytes());
    store.settle_all()?;
    store.epoch_cache.clear();
    assert_eq!(store.epoch_get(&identity)?.to_bytes(), expected.to_bytes());
    Ok(())
}

#[test]
fn signed_unpublished_root_stays_private_until_custody_resolution() -> TestResult {
    let store = store()?;
    let ns = store.create_for_test(
        "signed-custody-visibility",
        None,
        store.control_planes().local().agreement.guarantees(),
    )?;
    let previous = store.epoch_current(&ns)?;
    let writer = store.test_writer(&ns)?;
    let now = ClockMs::from_raw(2000);
    let target = Kappa::sha256(b"retained-tag-target");
    store.tag_put_in_txn(
        &writer.txn,
        &ns,
        "retained",
        &TagUpdate::Set {
            kappa: target.clone(),
        },
        now,
        &mut kappa_store::work::WorkMeter::unbounded(),
    )?;
    let signed = seal(&store, &writer, &ns, now)?;
    assert_eq!(store.epoch_current(&ns)?, previous);
    assert!(matches!(
        store.tag_get_raw(&ns, "retained"),
        Err(StoreError::NotFound(_))
    ));
    assert!(store.epoch_get(signed.kappa()).is_err());
    drop(writer);
    assert_eq!(store.epoch_current(&ns)?, previous);
    assert!(store.epoch_get(signed.kappa()).is_err());

    let outcome = kappa_store::ExecutionStore::resolve_publication(
        &store,
        &ns,
        &kappa_handler::clock_at(ClockMs::from_raw(3000))?,
        &mut kappa_store::work::WorkMeter::new(store.publication_work),
    )?;
    let kappa_store::PublicationResolution::Published(published) = outcome else {
        return Err("signed candidate did not resolve".into());
    };
    assert_eq!(published.root, *signed.kappa());
    assert_eq!(published.epoch_number, signed.epoch_number());
    assert_eq!(
        store.epoch_current(&ns)?,
        (published.epoch_number, published.root)
    );
    assert_eq!(
        store.epoch_get(signed.kappa())?.cose_signature(),
        signed.cose_signature()
    );
    assert_eq!(store.tag_get_raw(&ns, "retained")?.kappa, target);
    Ok(())
}

fn spec() -> crate::test_support::PersistentSpec {
    crate::test_support::PersistentSpec::new().db_file("state.redb")
}

/// A store retaining its own scope.
fn store() -> Result<PersistentStore, kappa_fixture::SetupError> {
    Ok(spec().acquire()?.into_store())
}

/// Seal and sign `writer`'s transaction and return the root, keeping the
/// writer.
fn seal(
    store: &PersistentStore,
    writer: &crate::test_support::TestWriter,
    ns: &NamespaceRef,
    now: ClockMs,
) -> Result<EpochRoot, StoreError> {
    store.sign_test_writer(writer, ns, now)
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
        &mut kappa_store::work::WorkMeter::unbounded(),
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
    store.verify_committed_publication(&ns, 1, &identity)?;
    let (db, _active) = store.namespace_db(&ns)?;
    let corrupt = db.begin_write()?;
    {
        let mut index = corrupt.open_table(BLOB_INDEX)?;
        index.remove(ledger.as_slice())?;
    }
    corrupt.commit()?;
    assert!(matches!(
        store.verify_committed_publication(&ns, 1, &identity),
        Err(StoreError::NotFound(_))
    ));
    store.epoch_cache.remove(&identity);
    assert!(store.epoch_get(&identity).is_err());
    assert!(store.epoch_current(&ns).is_err());
    assert!(store.epoch_get_by_number(&ns, 1).is_err());
    Ok(())
}

#[test]
fn encryption_erasure_revokes_previously_admitted_epoch_reads(
) -> Result<(), Box<dyn std::error::Error>> {
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
    let meter = &mut kappa_store::work::WorkMeter::unbounded();
    store.tag_put_in_txn(
        &writer.txn,
        &ns,
        "temporary",
        &TagUpdate::Set {
            kappa: Kappa::sha256(b"temporary"),
        },
        now,
        meter,
    )?;
    store.tag_delete_in_txn(&writer.txn, &ns, "temporary", now, meter)?;
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
    store.edge_mutation_put_in_txn(
        &writer.txn,
        &ns,
        &edge,
        now,
        &mut kappa_store::work::WorkMeter::unbounded(),
    )?;
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
