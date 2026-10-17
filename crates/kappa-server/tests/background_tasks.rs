//! Background task passes publish one execution per namespace, and publish
//! nothing when there is nothing to change.

use kappa_fixture::SetupError;
use kappa_handler::StagingBudget;
use kappa_handler::clock_at;
use kappa_server::tasks::federation::publish_trust_position;
use kappa_server::tasks::handle_verify::attest_handle;
use kappa_server::tasks::lifecycle::evaluate_lifecycles;
use kappa_store::canonical::from_canonical;
use kappa_store::epoch::EpochMutation;
use kappa_store::identity::HandleRecord;
use kappa_store::namespace::ProtocolId;
use kappa_store::resource;
use kappa_store::{
    Axis, BlobStore, ClockMs, ContentPreparation, EpochStore, ExecutionStore, IdentityStore, Kappa,
    MutationOp, NamespaceRef, PageRequest, ResourceKind, StoreError, TagStore, TagUpdate,
    VerifiedContent, namespace_ensure,
};
use kappa_store_redb::PersistentStore;
use kappa_store_redb::test_support::PersistentSpec;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DAY_MS: i64 = 86_400_000;
const CREATED_MS: i64 = 1_700_000_000_000;

fn at(physical_ms: i64) -> ClockMs {
    ClockMs::from_raw(physical_ms << 16)
}

fn budget() -> StagingBudget {
    StagingBudget::new(0, 0)
}

/// The server's store layout, retaining its own scope.
fn store() -> Result<PersistentStore, SetupError> {
    Ok(PersistentSpec::new()
        .db_file("state.redb")
        .acquire()?
        .into_store())
}

fn epoch(store: &PersistentStore, ns: &NamespaceRef) -> Result<u64, StoreError> {
    Ok(store.epoch_current(ns)?.0)
}

fn ledger(
    store: &PersistentStore,
    ns: &NamespaceRef,
) -> Result<Vec<EpochMutation>, Box<dyn std::error::Error>> {
    let root = store.epoch_get(&store.epoch_current(ns)?.1)?;
    Ok(from_canonical(&store.blob_get(root.ledger_root())?)?)
}

/// A bucket expiring objects after one day, holding `objects` as
/// (name, creation time) pairs. Two epochs: creation and seeding.
fn bucket(store: &PersistentStore, objects: &[(&str, i64)]) -> Result<NamespaceRef, StoreError> {
    let ns = namespace_ensure(store, "bucket", None, None, &clock_at(at(CREATED_MS))?)?;
    let mut execution = store.begin_execution(&ns, &clock_at(at(CREATED_MS + 1))?)?;
    execution.namespace_put_meta("lifecycle", br#"{"expiration_days":1}"#)?;
    for (name, created_ms) in objects {
        let content = VerifiedContent::compute(Axis::Sha256, format!("{name}-object").as_bytes())?;
        execution.blob_put(&content)?;
        execution.blob_meta_put(
            content.kappa(),
            "_s3_created_ms",
            created_ms.to_string().as_bytes(),
        )?;
        execution.tag_put(
            name,
            &TagUpdate::Set {
                kappa: content.kappa().clone(),
            },
        )?;
    }
    execution.publish()?;
    Ok(ns)
}

#[test]
fn a_lifecycle_pass_with_nothing_expired_publishes_no_epoch() -> TestResult {
    let store = store()?;
    let ns = bucket(&store, &[("a", CREATED_MS), ("b", CREATED_MS)])?;
    assert_eq!(epoch(&store, &ns)?, 2);

    evaluate_lifecycles(&store, &clock_at(at(CREATED_MS + DAY_MS / 2))?, &budget())?;

    assert_eq!(epoch(&store, &ns)?, 2);
    assert_eq!(store.tag_list(&ns, None, &PageRequest::first(10))?.len(), 2);
    Ok(())
}

/// Incomplete uploads older than the configured age are discarded in one
/// epoch, guarded by the revision observed; a fresh upload and one that
/// progressed since stay.
#[test]
fn incomplete_uploads_older_than_the_policy_are_abandoned_in_one_epoch() -> TestResult {
    let store = store()?;
    let ns = namespace_ensure(&store, "uploads", None, None, &clock_at(at(CREATED_MS))?)?;
    let asserter = Kappa::sha256(b"lifecycle");
    let open = |at_ms: i64| -> Result<String, StoreError> {
        let mut execution = store.begin_execution(&ns, &clock_at(at(at_ms))?)?;
        execution.namespace_put_meta("lifecycle", br#"{"abort_incomplete_days":1}"#)?;
        let head = resource::open(
            &mut *execution,
            &asserter,
            ResourceKind::Numbered,
            0,
            at(at_ms + 30 * DAY_MS),
            Some(b"key".to_vec()),
        )?;
        execution.publish()?;
        Ok(head.id())
    };
    let stale = open(CREATED_MS)?;
    let fresh = open(CREATED_MS + DAY_MS)?;
    let budget = budget();

    evaluate_lifecycles(&store, &clock_at(at(CREATED_MS + DAY_MS + 1))?, &budget)?;
    assert!(resource::resolve(&store, &ns, &stale)?.is_none());
    assert!(resource::resolve(&store, &ns, &fresh)?.is_some());
    let discards: Vec<_> = ledger(&store, &ns)?
        .into_iter()
        .filter(|mutation| mutation.op == MutationOp::TagDelete)
        .map(|mutation| mutation.context)
        .collect();
    assert_eq!(discards, [Some(format!("_resource/{stale}"))]);
    assert_eq!(budget.open_count(), 0, "the budget followed the discard");

    let before = epoch(&store, &ns)?;
    evaluate_lifecycles(&store, &clock_at(at(CREATED_MS + DAY_MS + 2))?, &budget)?;
    assert_eq!(
        epoch(&store, &ns)?,
        before,
        "a converged pass publishes nothing"
    );
    Ok(())
}

/// The staging budget rebuilds from committed heads: open resources
/// count, completed and discarded ones do not, and `settle` rebuilds only
/// while the projection is unresolved, reopening admission without any
/// foreground publication.
#[test]
fn an_unresolved_budget_is_settled_from_committed_resources_by_maintenance() -> TestResult {
    let store = store()?;
    let ns = namespace_ensure(&store, "staging", None, None, &clock_at(at(CREATED_MS))?)?;
    let asserter = Kappa::sha256(b"settle");
    let now = at(CREATED_MS + 1);
    let open = |bytes: usize| -> Result<String, Box<dyn std::error::Error>> {
        let mut execution = store.begin_execution(&ns, &clock_at(now)?)?;
        let head = resource::open(
            &mut *execution,
            &asserter,
            ResourceKind::Sequential,
            0,
            now.add_physical_ms(60_000),
            None,
        )?;
        if bytes > 0 {
            let content = vec![9u8; bytes];
            let prepared = store.prepare_content(
                kappa_store::ContentIdentity::Computed(Axis::Sha256),
                &mut content.as_slice(),
                kappa_store::PreparationBounds {
                    maximum: u64::MAX,
                    deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
                },
            )?;
            resource::stage(&mut *execution, &asserter, &head.id(), prepared, 0, None)?;
        }
        execution.publish()?;
        Ok(head.id())
    };
    open(5)?;
    open(11)?;
    let discarded = open(3)?;
    let mut execution = store.begin_execution(&ns, &clock_at(now)?)?;
    assert!(resource::discard(&mut *execution, &asserter, &discarded)?);
    execution.publish()?;

    let budget = StagingBudget::new(3, 0);
    budget.invalidate("test");
    assert!(budget.unresolved());
    assert_eq!(budget.settle(&store)?, Some(2));
    assert!(!budget.unresolved());
    assert_eq!((budget.open_count(), budget.staged_bytes()), (2, 16));
    assert_eq!(
        budget.settle(&store)?,
        None,
        "a resolved projection is not rebuilt"
    );
    assert_eq!(budget.rebuild(&store)?, 2);
    Ok(())
}

#[test]
fn every_expired_object_of_a_namespace_is_deleted_in_exactly_one_epoch() -> TestResult {
    let store = store()?;
    let fresh_ms = CREATED_MS + 2 * DAY_MS;
    let ns = bucket(
        &store,
        &[
            ("a", CREATED_MS),
            ("b", CREATED_MS),
            ("c", CREATED_MS),
            ("keep", fresh_ms),
        ],
    )?;

    evaluate_lifecycles(&store, &clock_at(at(fresh_ms + 3_600_000))?, &budget())?;

    assert_eq!(epoch(&store, &ns)?, 3);
    let deletions: Vec<_> = ledger(&store, &ns)?
        .into_iter()
        .map(|mutation| (mutation.op, mutation.context))
        .collect();
    assert_eq!(
        deletions,
        ["a", "b", "c"]
            .map(|name| (MutationOp::TagDelete, Some(name.to_string())))
            .to_vec()
    );
    for name in ["a", "b", "c"] {
        assert!(matches!(
            store.tag_get(&ns, name),
            Err(StoreError::NotFound(_))
        ));
    }
    assert_eq!(store.tag_get(&ns, "keep")?.version, 1);

    evaluate_lifecycles(&store, &clock_at(at(fresh_ms + 7_200_000))?, &budget())?;
    assert_eq!(epoch(&store, &ns)?, 3, "a converged pass publishes nothing");
    Ok(())
}

#[test]
fn a_stale_handle_probe_publishes_nothing() -> TestResult {
    let store = store()?;
    let handles = namespace_ensure(&store, "_handles", None, None, &clock_at(at(CREATED_MS))?)?;
    let record = HandleRecord {
        anchor: Kappa::sha256(b"alice"),
        handle: "alice.example".into(),
        protocol: ProtocolId::new("atproto")?,
        claimed_at_ms: CREATED_MS,
        attested_at_ms: None,
    };
    let mut execution = store.begin_execution(&handles, &clock_at(at(CREATED_MS + 1))?)?;
    execution.handle_put(&record)?;
    execution.publish()?;
    let before = epoch(&store, &handles)?;
    let stale = HandleRecord {
        claimed_at_ms: CREATED_MS - 1,
        ..record.clone()
    };

    assert_eq!(
        attest_handle(&store, &handles, &stale, &clock_at(at(CREATED_MS + 2))?)?,
        None
    );
    assert_eq!(epoch(&store, &handles)?, before);
    let stored = store.handle_get(record.protocol.clone(), &record.handle)?;
    assert_eq!(stored.attested_at_ms, None);

    let now = at(CREATED_MS + 3);
    assert_eq!(
        attest_handle(&store, &handles, &record, &clock_at(now)?)?,
        Some(before + 1)
    );
    let stored = store.handle_get(record.protocol.clone(), &record.handle)?;
    assert_eq!(stored.attested_at_ms, Some(now.as_i64()));
    Ok(())
}

#[test]
fn an_unchanged_trust_position_publishes_nothing() -> TestResult {
    let store = store()?;
    let system = namespace_ensure(&store, "_system", None, None, &clock_at(at(CREATED_MS))?)?;
    let anchor = Kappa::sha256(b"node");

    let first =
        publish_trust_position(&store, &anchor, "verified", &clock_at(at(CREATED_MS + 1))?)?;
    let again =
        publish_trust_position(&store, &anchor, "verified", &clock_at(at(CREATED_MS + 2))?)?;

    assert_eq!(first, Some(2));
    assert_eq!(again, None);
    assert_eq!(epoch(&store, &system)?, 2);
    assert_eq!(
        store
            .tag_get(&system, &format!("trust/position/{anchor}"))?
            .kappa,
        Kappa::sha256(b"verified")
    );
    Ok(())
}
