//! Ledger and completion atomicity contract, exercised identically against
//! every backend through `ExecutionStore` and the boxed `dyn Execution`.
//!
//! - Namespace metadata changes are committed by the epoch ledger as
//!   `MetadataUpdate` records and reconstructed by replay.
//! - Completion of a staged resource installs its composite privately and
//!   transitions the head only when the execution publishes; an aborted or
//!   dropped completion leaves the frozen generation completable.

mod support;

use std::collections::BTreeMap;

use kappa_handler::clock_at;
use kappa_store::canonical::from_canonical;
use kappa_store::epoch::{EpochMutation, MetadataRecord};
use kappa_store::resource;
use kappa_store::{
    Axis, Kappa, MutationOp, NamespaceRef, Published, ResourceKind, ResourcePhase, StoreError,
};
use kappa_store_memory::test_support;

use support::{Staging, T0, TestResult, at, computed, create, publish};

/// Metadata key to committed value; `None` records a deletion.
type MetadataRecords = BTreeMap<String, Option<Vec<u8>>>;

/// Metadata records committed by a published epoch, keyed by metadata key.
fn metadata_records(
    store: &(impl Staging + ?Sized),
    published: &Published,
) -> Result<MetadataRecords, Box<dyn std::error::Error>> {
    let root = store.epoch_get(&published.root)?;
    let ledger: Vec<EpochMutation> = from_canonical(&store.blob_get(root.ledger_root())?)?;
    let mut records = BTreeMap::new();
    for mutation in ledger
        .iter()
        .filter(|mutation| mutation.op == MutationOp::MetadataUpdate)
    {
        let record: MetadataRecord = from_canonical(&store.blob_get(&mutation.kappa)?)?;
        assert_eq!(mutation.context.as_deref(), Some(record.key.as_str()));
        assert_eq!(record.namespace_id, root.namespace_id().to_vec());
        records.insert(record.key, record.value);
    }
    Ok(records)
}

fn metadata_is_committed_by_the_ledger_and_replayed(store: &(impl Staging + ?Sized)) -> TestResult {
    // Created at `T0`; every later epoch of the chain is issued after it.
    let ns = create(store, "metadata-ledger")?;
    let mut execution = store.begin_execution(&ns, &clock_at(at(T0 + 1))?)?;
    execution.namespace_put_meta("versioning", b"enabled")?;
    execution.namespace_put_meta("policy", b"allow")?;
    execution.namespace_delete_meta("absent")?;
    let first = execution.publish()?;
    assert_eq!(
        metadata_records(store, &first)?,
        BTreeMap::from([
            ("policy".to_string(), Some(b"allow".to_vec())),
            ("versioning".to_string(), Some(b"enabled".to_vec())),
        ]),
        "deleting an absent key records nothing"
    );

    let mut execution = store.begin_execution(&ns, &clock_at(at(T0 + 2))?)?;
    execution.namespace_delete_meta("policy")?;
    let second = execution.publish()?;
    assert_eq!(
        metadata_records(store, &second)?,
        BTreeMap::from([("policy".to_string(), None)])
    );

    let mut execution = store.begin_execution(&ns, &clock_at(at(T0 + 3))?)?;
    execution.namespace_delete_meta("policy")?;
    let third = execution.publish()?;
    assert!(metadata_records(store, &third)?.is_empty());

    let replayed = kappa_store::replay_to(store, &ns, third.epoch_number)?;
    assert_eq!(
        replayed.metadata,
        BTreeMap::from([("versioning".to_string(), b"enabled".to_vec())])
    );
    assert_eq!(store.namespace_get_meta(&ns, "versioning")?, b"enabled");
    assert!(matches!(
        store.namespace_get_meta(&ns, "policy"),
        Err(StoreError::NotFound(_))
    ));
    let at_first = kappa_store::replay_to(store, &ns, first.epoch_number)?;
    assert_eq!(
        at_first.metadata.get("policy").map(Vec::as_slice),
        Some(&b"allow"[..])
    );
    Ok(())
}

fn asserter() -> Kappa {
    Kappa::sha256(b"ledger contract")
}

fn head(
    store: &(impl Staging + ?Sized),
    ns: &NamespaceRef,
    id: &str,
) -> Result<ResourcePhase, StoreError> {
    Ok(resource::resolve(store, ns, id)?
        .ok_or_else(|| StoreError::NotFound(format!("resource {id}")))?
        .head
        .phase)
}

fn completion_is_atomic_with_publication(store: &(impl Staging + ?Sized)) -> TestResult {
    let ns = create(store, "completion-atomicity")?;
    let now = at(T0 + 10);
    let expires_at = now.add_physical_ms(60_000);
    let id = publish(store, &ns, now, |e| {
        Ok(resource::open(
            e,
            &asserter(),
            ResourceKind::Sequential,
            1024,
            expires_at,
            None,
        )?
        .id())
    })?;
    let payload = b"atomic payload";
    let prepared = computed(store, payload)?;
    publish(store, &ns, now, |e| {
        resource::stage(e, &asserter(), &id, prepared, 0, None).map(|_| ())
    })?;
    let request = Kappa::sha256(b"complete");
    let generation = publish(store, &ns, now, |e| {
        Ok(resource::prepare(e, &asserter(), &id, &request, &[])?.generation)
    })?;
    let evidence = resource::prepare_composition(
        store,
        &ns,
        &id,
        &generation,
        Axis::Sha256,
        support::bounds().deadline,
    )?;
    let assembled = Kappa::sha256(payload);
    assert_eq!(evidence.identity(), &assembled);

    // Abort leaves the frozen generation completable; the composite was
    // installed privately only.
    let mut execution = store.begin_execution(&ns, &clock_at(now)?)?;
    let staged = resource::complete(&mut *execution, &asserter(), &id, &evidence, None)?;
    assert!(!staged.replayed);
    assert_eq!(staged.installed.kappa, assembled);
    assert!(!store.blob_exists(&assembled)?);
    execution.abort()?;
    assert!(!store.blob_exists(&assembled)?);
    assert_eq!(head(store, &ns, &id)?, ResourcePhase::Prepared);

    // Dropping the execution does the same.
    {
        let mut execution = store.begin_execution(&ns, &clock_at(now)?)?;
        resource::complete(&mut *execution, &asserter(), &id, &evidence, None)?;
    }
    assert!(!store.blob_exists(&assembled)?);
    assert_eq!(head(store, &ns, &id)?, ResourcePhase::Prepared);

    // Publication installs the composite together with the head
    // transition and the writes that name the object.
    let mut execution = store.begin_execution(&ns, &clock_at(now)?)?;
    let completed = resource::complete(&mut *execution, &asserter(), &id, &evidence, None)?;
    assert!(!completed.replayed);
    assert_eq!(completed.installed.kappa, assembled);
    execution.tag_put(
        "object",
        &kappa_store::TagUpdate::Set {
            kappa: completed.installed.kappa,
        },
    )?;
    execution.publish()?;
    assert_eq!(store.blob_get(&assembled)?, payload);
    assert_eq!(store.tag_get(&ns, "object")?.kappa, assembled);
    assert_eq!(head(store, &ns, &id)?, ResourcePhase::Completed);

    // The same evidence replays, marked as a replay that wrote nothing; a
    // different request conflicts.
    let replayed = publish(store, &ns, now, |e| {
        let completed = resource::complete(e, &asserter(), &id, &evidence, None)?;
        Ok((completed.replayed, completed.installed.newly_stored))
    })?;
    assert_eq!(replayed, (true, false));
    match resource::resolve_completion(store, &ns, &id, &Kappa::sha256(b"another")) {
        Err(StoreError::Conflict(_)) => {}
        other => return Err(format!("expected a conflict, got {other:?}").into()),
    }
    Ok(())
}

fn contract(store: &(impl Staging + ?Sized)) -> TestResult {
    metadata_is_committed_by_the_ledger_and_replayed(store)?;
    completion_is_atomic_with_publication(store)
}

#[test]
fn memory_backend_meets_the_ledger_contract() -> TestResult {
    contract(test_support::test_store()?.store())
}

#[test]
fn persistent_backend_meets_the_ledger_contract() -> TestResult {
    contract(kappa_store_redb::test_support::persistent_store()?.store())
}
