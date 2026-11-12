//! Operation-owned execution contract, exercised identically against every
//! backend through `ExecutionStore` and the boxed `dyn Execution`, exactly as
//! production callers drive it.

use kappa_handler::clock_at;
use kappa_store::edge::{BuiltinRelation, EdgeRelation};
use kappa_store::{
    Axis, BlobStore, ClockMs, EdgeInput, EpochStore, ExecutionStore, Kappa, NamespaceRef,
    NamespaceStore, OperationAdmission, StoreError, TagStore, TagUpdate, VerifiedContent,
};
use kappa_store_memory::test_support;

type TestResult = Result<(), Box<dyn std::error::Error>>;

trait Contract: ExecutionStore + TagStore + BlobStore + EpochStore + NamespaceStore {}
impl<S: ExecutionStore + TagStore + BlobStore + EpochStore + NamespaceStore> Contract for S {}

fn set(seed: &[u8]) -> TagUpdate {
    TagUpdate::Set {
        kappa: Kappa::sha256(seed),
    }
}

fn writes_are_private_until_publication(store: &impl Contract) -> TestResult {
    let namespace = NamespaceRef::deterministic("private");
    let content = VerifiedContent::compute(Axis::Sha256, b"private bytes")?;
    let mut execution = store.begin_execution(&namespace, &clock_at(ClockMs::from_raw(1000))?)?;
    execution.tag_put("head", &set(b"one"))?;
    execution.blob_put(&content)?;
    assert_eq!(
        execution.tag_get("head")?.map(|entry| entry.kappa),
        Some(Kappa::sha256(b"one"))
    );
    assert!(execution.tag_get("absent")?.is_none());
    assert!(matches!(
        store.tag_get(&namespace, "head"),
        Err(StoreError::NotFound(_))
    ));
    assert!(!store.blob_exists(content.kappa())?);
    assert!(matches!(
        store.epoch_current(&namespace),
        Err(StoreError::NotFound(_))
    ));
    let published = execution.publish()?;
    assert_eq!(published.epoch_number, 1);
    assert_eq!(
        store.tag_get(&namespace, "head")?.kappa,
        Kappa::sha256(b"one")
    );
    assert!(store.blob_exists(content.kappa())?);
    assert_eq!(
        store.epoch_current(&namespace)?,
        (published.epoch_number, published.root.clone())
    );
    let root = store.epoch_get(&published.root)?;
    let (digest, count) = store.epoch_state(&namespace)?;
    assert_eq!(root.tag_count(), 1);
    assert_eq!(count, 1);
    assert_eq!(root.state_digest(), digest.as_slice());
    Ok(())
}

fn abort_and_drop_discard_every_write(store: &impl Contract) -> TestResult {
    let namespace = NamespaceRef::deterministic("aborted");
    let content = VerifiedContent::compute(Axis::Sha256, b"discarded")?;
    let edge = EdgeInput {
        source: Kappa::sha256(b"source"),
        target: Kappa::sha256(b"target"),
        relation: EdgeRelation::Builtin(BuiltinRelation::Owns),
        asserter: Kappa::sha256(b"source"),
        created_at_ms: 1,
        metadata: None,
    };
    let mut execution = store.begin_execution(&namespace, &clock_at(ClockMs::from_raw(1000))?)?;
    execution.tag_put("head", &set(b"one"))?;
    let identity = execution.edge_put(&edge)?;
    execution.blob_put(&content)?;
    execution.abort()?;
    let mut dropped = store.begin_execution(&namespace, &clock_at(ClockMs::from_raw(1001))?)?;
    dropped.sequence_next("counter")?;
    drop(dropped);
    assert!(matches!(
        store.tag_get(&namespace, "head"),
        Err(StoreError::NotFound(_))
    ));
    assert!(!store.blob_exists(&identity)?);
    assert!(!store.blob_exists(content.kappa())?);
    assert!(matches!(
        store.epoch_current(&namespace),
        Err(StoreError::NotFound(_))
    ));
    let published = store
        .begin_execution(&namespace, &clock_at(ClockMs::from_raw(1002))?)?
        .publish()?;
    assert_eq!(published.epoch_number, 1);
    Ok(())
}

fn a_failed_write_latches_and_publishes_nothing(store: &impl Contract) -> TestResult {
    let namespace = NamespaceRef::deterministic("latched");
    let mut execution = store.begin_execution(&namespace, &clock_at(ClockMs::from_raw(1000))?)?;
    execution.tag_put("kept", &set(b"kept"))?;
    assert!(matches!(
        execution.tag_delete("missing"),
        Err(StoreError::NotFound(_))
    ));
    assert!(matches!(
        execution.tag_put("after", &set(b"after")),
        Err(StoreError::Conflict(_))
    ));
    assert!(matches!(execution.publish(), Err(StoreError::Conflict(_))));
    assert!(matches!(
        store.tag_get(&namespace, "kept"),
        Err(StoreError::NotFound(_))
    ));
    assert!(matches!(
        store.epoch_current(&namespace),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

fn operation_replays_original_result_and_rejects_reuse(store: &impl Contract) -> TestResult {
    let namespace = NamespaceRef::deterministic("operation");
    let request = Kappa::sha256(b"request");
    let OperationAdmission::Execute(mut execution) = store.begin_operation(
        &namespace,
        [7; 32],
        request.clone(),
        &clock_at(ClockMs::from_raw(1000))?,
    )?
    else {
        panic!("first admission must execute");
    };
    execution.tag_put("head", &set(b"first"))?;
    let original = execution.publish_result(b"original".to_vec())?;
    let mut later = store.begin_execution(&namespace, &clock_at(ClockMs::from_raw(1001))?)?;
    later.tag_put("head", &set(b"second"))?;
    later.publish()?;
    let OperationAdmission::Replay { epoch, receipt } = store.begin_operation(
        &namespace,
        [7; 32],
        request,
        &clock_at(ClockMs::from_raw(1002))?,
    )?
    else {
        panic!("retry must not execute again");
    };
    assert_eq!(
        (epoch.epoch_number(), epoch.kappa().clone()),
        (original.epoch_number, original.root)
    );
    assert_eq!(receipt.result(), b"original");
    assert_eq!(
        store.tag_get(&namespace, "head")?.kappa,
        Kappa::sha256(b"second")
    );
    assert!(matches!(
        store.begin_operation(
            &namespace,
            [7; 32],
            Kappa::sha256(b"different"),
            &clock_at(ClockMs::from_raw(1003))?,
        ),
        Err(StoreError::Conflict(_))
    ));
    Ok(())
}

fn publication_mode_must_match_operation_identity(store: &impl Contract) -> TestResult {
    let namespace = NamespaceRef::deterministic("mode");
    let OperationAdmission::Execute(execution) = store.begin_operation(
        &namespace,
        [1; 32],
        Kappa::sha256(b"request"),
        &clock_at(ClockMs::from_raw(1000))?,
    )?
    else {
        panic!("first admission must execute");
    };
    assert!(matches!(execution.publish(), Err(StoreError::Conflict(_))));
    let plain = store.begin_execution(&namespace, &clock_at(ClockMs::from_raw(1001))?)?;
    assert!(matches!(
        plain.publish_result(b"result".to_vec()),
        Err(StoreError::Conflict(_))
    ));
    assert!(matches!(
        store.epoch_current(&namespace),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

fn abort_does_not_reserve_an_operation_identity(store: &impl Contract) -> TestResult {
    let namespace = NamespaceRef::deterministic("unreserved");
    let request = Kappa::sha256(b"request");
    drop(store.begin_operation(
        &namespace,
        [9; 32],
        request.clone(),
        &clock_at(ClockMs::from_raw(1000))?,
    )?);
    assert!(
        store
            .resolve_operation(&namespace, &[9; 32], &request)?
            .is_none()
    );
    assert!(matches!(
        store.begin_operation(
            &namespace,
            [9; 32],
            request,
            &clock_at(ClockMs::from_raw(1001))?
        )?,
        OperationAdmission::Execute(_)
    ));
    Ok(())
}

fn replay_is_not_blocked_by_a_held_writer(store: &impl Contract) -> TestResult {
    let namespace = NamespaceRef::deterministic("replay-under-writer");
    let request = Kappa::sha256(b"request");
    let OperationAdmission::Execute(mut execution) = store.begin_operation(
        &namespace,
        [3; 32],
        request.clone(),
        &clock_at(ClockMs::from_raw(1000))?,
    )?
    else {
        panic!("first admission must execute");
    };
    execution.tag_put("head", &set(b"value"))?;
    execution.publish_result(b"done".to_vec())?;
    let holder = store.begin_execution(&namespace, &clock_at(ClockMs::from_raw(1001))?)?;
    let replay_clock = clock_at(ClockMs::from_raw(1002))?;
    let resolved = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                store
                    .begin_operation(&namespace, [3; 32], request, &replay_clock)
                    .map(|admission| matches!(admission, OperationAdmission::Replay { .. }))
            })
            .join()
    });
    holder.abort()?;
    assert!(matches!(resolved, Ok(Ok(true))));
    Ok(())
}

fn namespace_creation_publishes_with_its_first_write(store: &impl Contract) -> TestResult {
    let now = ClockMs::from_raw(1000);
    let namespace = NamespaceRef::generate("created-in-execution", now)?;
    let owner = Kappa::sha256(b"owner");
    let mut execution = store.begin_execution(&namespace, &clock_at(now)?)?;
    assert!(execution.namespace_info()?.is_none());
    execution.namespace_create(Some(&owner), None)?;
    execution.tag_put("head", &set(b"first"))?;
    assert_eq!(
        execution.namespace_info()?.map(|info| info.owner_anchor),
        Some(Some(owner.clone()))
    );
    assert!(matches!(
        store.namespace_resolve("created-in-execution", None),
        Err(StoreError::NotFound(_))
    ));
    execution.publish()?;
    assert_eq!(
        store.namespace_resolve("created-in-execution", None)?.id(),
        namespace.id()
    );
    assert_eq!(store.namespace_info(&namespace)?.owner_anchor, Some(owner));
    assert_eq!(
        store.tag_get(&namespace, "head")?.kappa,
        Kappa::sha256(b"first")
    );
    let rival = NamespaceRef::generate("created-in-execution", ClockMs::from_raw(1001))?;
    let mut contender = store.begin_execution(&rival, &clock_at(ClockMs::from_raw(1001))?)?;
    assert!(matches!(
        contender.namespace_create(None, None),
        Err(StoreError::Conflict(_))
    ));
    assert!(matches!(contender.publish(), Err(StoreError::Conflict(_))));
    assert!(matches!(
        store.namespace_info(&rival),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

fn blob_metadata_is_private_until_publication(store: &impl Contract) -> TestResult {
    let namespace = NamespaceRef::deterministic("blob-metadata");
    let content = VerifiedContent::compute(Axis::Sha256, b"typed content")?;
    let mut aborted = store.begin_execution(&namespace, &clock_at(ClockMs::from_raw(1000))?)?;
    aborted.blob_put(&content)?;
    aborted.blob_meta_put(content.kappa(), "content-type", b"text/plain")?;
    assert_eq!(
        aborted.blob_meta_get(content.kappa(), "content-type")?,
        Some(b"text/plain".to_vec())
    );
    aborted.abort()?;
    assert!(matches!(
        store.blob_meta_get(content.kappa(), "content-type"),
        Err(StoreError::NotFound(_))
    ));
    let mut execution = store.begin_execution(&namespace, &clock_at(ClockMs::from_raw(1001))?)?;
    execution.blob_put(&content)?;
    execution.blob_meta_put(content.kappa(), "content-type", b"text/plain")?;
    execution.publish()?;
    assert_eq!(
        store.blob_meta_get(content.kappa(), "content-type")?,
        b"text/plain"
    );
    let mut removal = store.begin_execution(&namespace, &clock_at(ClockMs::from_raw(1002))?)?;
    removal.blob_meta_delete(content.kappa(), "content-type")?;
    assert!(
        removal
            .blob_meta_get(content.kappa(), "content-type")?
            .is_none()
    );
    removal.publish()?;
    assert!(matches!(
        store.blob_meta_get(content.kappa(), "content-type"),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

fn an_expired_deadline_publishes_nothing(store: &impl Contract) -> TestResult {
    let namespace = NamespaceRef::deterministic("deadline");
    let mut execution = store.begin_execution(&namespace, &clock_at(ClockMs::from_raw(1000))?)?;
    execution.tag_put("head", &set(b"late"))?;
    execution.set_deadline(
        std::time::Instant::now()
            .checked_sub(std::time::Duration::from_millis(5))
            .ok_or("monotonic clock is within 5ms of its origin")?,
    );
    match execution.publish() {
        Err(StoreError::DeadlineExceeded {
            namespace: rejected,
            overrun_ms,
        }) => {
            assert_eq!(&rejected, namespace.id());
            assert!(overrun_ms >= 5);
        }
        other => panic!("expected DeadlineExceeded, got {other:?}"),
    }
    assert!(matches!(
        store.tag_get(&namespace, "head"),
        Err(StoreError::NotFound(_))
    ));
    assert!(matches!(
        store.epoch_current(&namespace),
        Err(StoreError::NotFound(_))
    ));
    let mut retry = store.begin_execution(&namespace, &clock_at(ClockMs::from_raw(1001))?)?;
    retry.tag_put("head", &set(b"on time"))?;
    retry.set_deadline(std::time::Instant::now() + std::time::Duration::from_secs(60));
    assert_eq!(retry.publish()?.epoch_number, 1);
    Ok(())
}

fn contract(store: &impl Contract) -> TestResult {
    writes_are_private_until_publication(store)?;
    abort_and_drop_discard_every_write(store)?;
    a_failed_write_latches_and_publishes_nothing(store)?;
    operation_replays_original_result_and_rejects_reuse(store)?;
    publication_mode_must_match_operation_identity(store)?;
    abort_does_not_reserve_an_operation_identity(store)?;
    replay_is_not_blocked_by_a_held_writer(store)?;
    namespace_creation_publishes_with_its_first_write(store)?;
    blob_metadata_is_private_until_publication(store)?;
    an_expired_deadline_publishes_nothing(store)
}

#[test]
fn memory_backend_meets_the_execution_contract() -> TestResult {
    contract(test_support::test_store()?.store())
}

#[test]
fn persistent_backend_meets_the_execution_contract() -> TestResult {
    contract(kappa_store_redb::test_support::persistent_store()?.store())
}

#[test]
fn sequences_edges_and_versions_survive_restart_together() -> TestResult {
    use kappa_store::traits::sequence::SequenceStore;
    use kappa_store::version_ops::{
        version_delete_with_marker, version_get_by_id, version_list_entries, version_put_entry,
        versioning_put,
    };
    use kappa_store::versioning::VersioningState;
    use kappa_store::{EdgeStore, PageRequest};
    let spec = kappa_store_redb::test_support::PersistentSpec::new()
        .in_root(&kappa_fixture::FixtureRoot::temporary()?);
    let ns = NamespaceRef::deterministic("restart-capabilities");
    let content = VerifiedContent::compute(Axis::Sha256, b"versioned persistent bytes")?;
    let owner = Kappa::sha256(b"owner");
    let edge = EdgeInput {
        source: owner.clone(),
        target: content.kappa().clone(),
        relation: EdgeRelation::Builtin(BuiltinRelation::Owns),
        asserter: owner.clone(),
        created_at_ms: 1000,
        metadata: None,
    };
    let (version, root);
    {
        let store = spec.clone().acquire()?;
        let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(1000))?)?;
        execution.namespace_create(Some(&owner), None)?;
        execution.blob_put(&content)?;
        versioning_put(&mut *execution, VersioningState::Enabled)?;
        version = version_put_entry(
            store.store(),
            &mut *execution,
            "object",
            content.kappa(),
            &owner,
        )?;
        for value in 1..=5 {
            assert_eq!(execution.sequence_next("counter")?, value);
        }
        execution.edge_put_batch(&[edge.clone()])?;
        root = execution.publish()?.root;
    }
    let store = spec.acquire()?;
    assert_eq!(
        store.namespace_resolve("restart-capabilities", None)?.id(),
        ns.id()
    );
    assert_eq!(store.epoch_current(&ns)?.1, root);
    assert_eq!(store.sequence_current(&ns, "counter")?, 5);
    assert_eq!(
        version_get_by_id(store.store(), &ns, "object", &version)?.kappa,
        *content.kappa()
    );
    assert_eq!(store.blob_get(content.kappa())?, content.content());
    for (anchor, direction) in [
        (edge.source.clone(), kappa_store::edge::Direction::Outbound),
        (edge.target.clone(), kappa_store::edge::Direction::Inbound),
    ] {
        let page = store.edge_query(
            &ns,
            &kappa_store::edge::EdgeQuery {
                anchor,
                direction,
                relation: Some(edge.relation.clone()),
                asserter: Some(owner.clone()),
            },
            &PageRequest::first(10),
        )?;
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].target(), &edge.target);
    }
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2000))?)?;
    assert_eq!(execution.sequence_next("counter")?, 6);
    execution.publish()?;
    assert_eq!(store.sequence_current(&ns, "counter")?, 6);
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(3000))?)?;
    let marker = version_delete_with_marker(store.store(), &mut *execution, "object", None)?;
    assert!(marker.is_delete_marker);
    execution.publish()?;
    assert!(matches!(
        store.tag_get(&ns, "object"),
        Err(StoreError::NotFound(_))
    ));
    let versions = version_list_entries(store.store(), &ns, "object")?;
    assert_eq!(versions.len(), 2);
    assert!(versions[0].is_delete_marker);
    assert_eq!(versions[1].version_id, version);
    let marker_id = marker.version_id.ok_or("marker omitted its version")?;
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(4000))?)?;
    let removed =
        version_delete_with_marker(store.store(), &mut *execution, "object", Some(&marker_id))?;
    assert!(removed.is_delete_marker);
    execution.publish()?;
    assert_eq!(version_list_entries(store.store(), &ns, "object")?.len(), 1);
    Ok(())
}
