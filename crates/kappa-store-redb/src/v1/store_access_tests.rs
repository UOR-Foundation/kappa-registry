//! Identity-only reads locate committed content from its commit, not from
//! its settlement: before any settlement step and after one, the same
//! identities resolve to the same bytes and owners. Candidates come from
//! the identity's own registrations, and an owner whose evidence is
//! missing makes the read unavailable, never absent.

use kappa_handler::clock_at;
use kappa_store::canonical::from_canonical;
use kappa_store::epoch::EpochMutation;
use kappa_store::{
    Axis, BlobStore, ClockMs, Disposition, EpochStore, Kappa, NamespaceRef, ObservedHead,
    StoreError, VerifiedContent,
};

use super::Coverage;
use crate::control_plane::{Guarantee, Guarantees};
use crate::settlement::Origin;
use crate::storage::NamespaceController;
use crate::test_support::retirement_principal;
use crate::unsettled_index::DiscoveryKey;
use crate::{PersistentStore, PersistentStoreConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn store() -> Result<PersistentStore, kappa_fixture::SetupError> {
    Ok(crate::test_support::PersistentSpec::new()
        .acquire()?
        .into_store())
}

fn create(store: &PersistentStore, name: &str) -> Result<NamespaceRef, StoreError> {
    create_owned(store, name, None)
}

/// Create `name` owned by `owner`, totally ordered with linearizable reads.
fn create_owned(
    store: &PersistentStore,
    name: &str,
    owner: Option<&Kappa>,
) -> Result<NamespaceRef, StoreError> {
    store.create_for_test(
        name,
        owner,
        Guarantees::NONE
            .with(Guarantee::TotalOrder)
            .with(Guarantee::LinearizableReads),
    )
}

/// Every identity-only read of `content` and of the ledger of `ns`'s head
/// resolves, with `ns` as the one owner.
fn assert_located(
    store: &PersistentStore,
    ns: &NamespaceRef,
    content: &VerifiedContent,
    bytes: &[u8],
) -> TestResult {
    assert_eq!(store.blob_get(content.kappa())?, bytes);
    assert!(store.blob_exists(content.kappa())?);
    assert_eq!(store.blob_size(content.kappa())?, bytes.len() as u64);
    assert_eq!(
        store
            .blob_owners(content.kappa())?
            .iter()
            .map(|owner| *owner.id())
            .collect::<Vec<_>>(),
        vec![*ns.id()]
    );
    let root = store.epoch_get(&store.epoch_current(ns)?.1)?;
    let ledger: Vec<EpochMutation> = from_canonical(&store.blob_get(root.ledger_root())?)?;
    // Ledger identities name transition evidence, not its admitted payload.
    // Resolve that evidence through the same public identity-only boundary
    // and independently verify its address and namespace/content binding.
    let mut admitted = false;
    for mutation in ledger
        .iter()
        .filter(|mutation| mutation.op == kappa_store::epoch::MutationOp::RecordPublish)
    {
        let evidence = store.blob_get(&mutation.kappa)?;
        let verified = VerifiedContent::verify(&mutation.kappa, &evidence)?;
        let record: kappa_types::content::ContentAdmissionRecord =
            from_canonical(verified.content())?;
        if record.admission().identity() == content.kappa() {
            assert_eq!(record.admission().namespace(), ns.id());
            assert_eq!(record.admission().logical_size(), bytes.len() as u64);
            assert!(matches!(
                record.evidence(),
                kappa_types::content::ContentAdmissionEvidence::VerifiedBytes
            ));
            admitted = true;
        }
    }
    assert!(
        admitted,
        "the head's ledger must authenticate the published record's admission"
    );
    Ok(())
}

#[test]
fn committed_content_is_located_before_and_after_settlement() -> TestResult {
    let store = store()?;
    let ns = create(&store, "located-before-settlement")?;
    let bytes = b"committed, not yet settled".to_vec();
    let content = VerifiedContent::compute(Axis::Sha256, &bytes)?;
    let clock = clock_at(ClockMs::from_raw(2000))?;
    let mut execution = store.begin_epoch_execution(&ns, &clock, None)?;
    execution.blob_put(&content)?;
    execution.publish()?;
    assert!(
        store.pending_settlements()?.contains(ns.id()),
        "control: the publication is not yet settled"
    );
    assert_located(&store, &ns, &content, &bytes)?;
    store.settlement_step(u64::MAX)?;
    assert!(!store.pending_settlements()?.contains(ns.id()));
    assert_located(&store, &ns, &content, &bytes)?;
    Ok(())
}

#[test]
fn absent_content_is_absent_with_pending_and_settled_namespaces() -> TestResult {
    let store = store()?;
    let ns = create(&store, "absent-identity")?;
    let absent = VerifiedContent::compute(Axis::Sha256, b"never published")?;
    assert!(store.pending_settlements()?.contains(ns.id()));
    assert!(matches!(
        store.blob_get(absent.kappa()),
        Err(StoreError::NotFound(_))
    ));
    assert!(!store.blob_exists(absent.kappa())?);
    assert!(store.blob_owners(absent.kappa())?.is_empty());
    store.settlement_step(u64::MAX)?;
    assert!(!store.blob_exists(absent.kappa())?);
    Ok(())
}

/// Publish `bytes` as a record of `ns`.
fn publish(store: &PersistentStore, ns: &NamespaceRef, bytes: &[u8]) -> TestResult {
    publish_at(store, ns, bytes, 2000)
}

/// Publish `bytes` as a record of `ns` in an epoch at `time`.
fn publish_at(store: &PersistentStore, ns: &NamespaceRef, bytes: &[u8], time: i64) -> TestResult {
    let content = VerifiedContent::compute(Axis::Sha256, bytes)?;
    let clock = clock_at(ClockMs::from_raw(time))?;
    let mut execution = store.begin_epoch_execution(ns, &clock, None)?;
    execution.blob_put(&content)?;
    execution.publish()?;
    Ok(())
}

/// The candidates an identity-only read probes beyond the catalog come
/// from the identity's own registrations, not from the pending
/// population: an absent identity probes no namespace however many are
/// unsettled, a published one probes only the namespace that registered
/// it, and settlement hands it to the catalog.
#[test]
fn unsettled_candidates_do_not_grow_with_the_pending_population() -> TestResult {
    let store = store()?;
    let namespaces = (0..16)
        .map(|index| create(&store, &format!("pending-{index}")))
        .collect::<Result<Vec<_>, _>>()?;
    let holder = &namespaces[7];
    let holder_instance = store.namespace_snapshot(holder)?.controller().instance;
    let bytes = b"registered under one namespace".to_vec();
    publish(&store, holder, &bytes)?;
    let content = VerifiedContent::compute(Axis::Sha256, &bytes)?;
    let absent = VerifiedContent::compute(Axis::Sha256, b"never published anywhere")?;
    assert!(
        store.pending_settlements()?.len() >= namespaces.len(),
        "control: every namespace is unsettled"
    );
    assert!(store
        .unsettled_candidates(
            &DiscoveryKey::Content(absent.kappa().clone()),
            &mut kappa_store::work::WorkMeter::unbounded(),
        )?
        .is_empty());
    assert_eq!(
        store.unsettled_candidates(
            &DiscoveryKey::Content(content.kappa().clone()),
            &mut kappa_store::work::WorkMeter::unbounded(),
        )?,
        vec![holder_instance]
    );
    assert!(store
        .catalog_owners(
            content.kappa(),
            &mut kappa_store::work::WorkMeter::unbounded()
        )?
        .is_empty());
    assert_eq!(store.blob_get(content.kappa())?, bytes);
    assert!(matches!(
        store.blob_get(absent.kappa()),
        Err(StoreError::NotFound(_))
    ));
    store.settlement_step(u64::MAX)?;
    assert!(
        store
            .unsettled_candidates(
                &DiscoveryKey::Content(content.kappa().clone()),
                &mut kappa_store::work::WorkMeter::unbounded(),
            )?
            .is_empty(),
        "settlement released the registration"
    );
    assert_eq!(
        store.catalog_owners(
            content.kappa(),
            &mut kappa_store::work::WorkMeter::unbounded()
        )?,
        vec![holder_instance]
    );
    assert_eq!(store.blob_get(content.kappa())?, bytes);
    Ok(())
}

/// An owner whose storage is missing without a recorded retirement makes
/// every identity-only read of its content unavailable, never absent; the
/// governed release of the lost instance turns the same read into an
/// authoritative absence. Missing storage is never retired as present.
#[test]
fn an_owner_with_missing_storage_is_unavailable_until_its_retirement_is_recorded() -> TestResult {
    let root = tempfile::tempdir()?;
    let mut config = PersistentStoreConfig::new(
        root.path().join("blobs"),
        root.path().join("store.redb"),
        kappa_crypto::testing::fixture_authority(1)?,
    );
    config.max_idle_namespaces = 0;
    let store = PersistentStore::new(config)?;
    let (_, principal) = retirement_principal()?;
    let governing = create(&store, "missing-owner-governing")?;
    let ns = create_owned(&store, "missing-owner", Some(&principal))?;
    let instance = store.namespace_snapshot(&ns)?.controller().instance;
    let bytes = b"held by storage that goes missing".to_vec();
    publish(&store, &ns, &bytes)?;
    let content = VerifiedContent::compute(Axis::Sha256, &bytes)?;
    store.settlement_step(u64::MAX)?;
    assert_eq!(
        store.catalog_owners(
            content.kappa(),
            &mut kappa_store::work::WorkMeter::unbounded()
        )?,
        vec![instance]
    );
    assert!(
        store.namespaces.open_controller(ns.id()).is_none(),
        "control: the settled, idle controller was evicted"
    );
    let directory = NamespaceController::directory(store.namespaces.root(), ns.id());
    std::fs::rename(&directory, root.path().join("displaced"))?;
    assert!(matches!(
        store.blob_get(content.kappa()),
        Err(StoreError::Unavailable(_))
    ));
    assert!(matches!(
        store.blob_exists(content.kappa()),
        Err(StoreError::Unavailable(_))
    ));
    assert!(matches!(
        store.blob_owners(content.kappa()),
        Err(StoreError::Unavailable(_))
    ));
    let settled = store
        .settled_epoch(&instance)?
        .map(|(epoch_number, root)| ObservedHead { epoch_number, root });
    let as_present = store.retire_for_test(
        &governing,
        &instance,
        Disposition::RetirePresent,
        settled,
        ClockMs::from_raw(3000),
    );
    assert!(
        matches!(as_present, Err(StoreError::NotFound(_))),
        "missing storage retired as present: {as_present:?}"
    );
    assert!(matches!(
        store.blob_get(content.kappa()),
        Err(StoreError::Unavailable(_))
    ));
    assert!(
        store.release_grant(&instance)?.is_none(),
        "no restart found the loss: no obligation closes the pool, and the release is ordinary"
    );
    let released = store.release_lost_for_test(&governing, &instance, ClockMs::from_raw(3001))?;
    assert_eq!(released.decision().target(), ns.id());
    assert_eq!(released.decision().disposition(), Disposition::ReleaseLost);
    assert!(matches!(
        store.blob_get(content.kappa()),
        Err(StoreError::NotFound(_))
    ));
    assert!(!store.blob_exists(content.kappa())?);
    assert!(store.blob_owners(content.kappa())?.is_empty());
    Ok(())
}

/// An unresolved recovery obligation leaves discovery incomplete. A
/// positive read still answers from a holder; a miss is unavailable, not
/// absent; a list of holders is refused; the obligation's closing charge
/// closes admission. Settlement reaching the obligated instance's head
/// discharges it and restores authoritative absence and admission.
#[test]
fn incomplete_discovery_makes_a_miss_unavailable_not_absent() -> TestResult {
    let store = store()?;
    let holder = create(&store, "coverage-holder")?;
    let failed = create(&store, "coverage-failed")?;
    let failed_instance = store.namespace_snapshot(&failed)?.controller().instance;
    let bytes = b"held while discovery is incomplete".to_vec();
    publish(&store, &holder, &bytes)?;
    let content = VerifiedContent::compute(Axis::Sha256, &bytes)?;
    let absent = VerifiedContent::compute(Axis::Sha256, b"never published while incomplete")?;
    assert_eq!(store.discovery_coverage(), Coverage::Complete);
    // Recorded the way recovery records an instance whose effects it cannot
    // read.
    store.record_unresolved(
        &failed_instance,
        Origin::Marker,
        "effects unreadable".into(),
    )?;
    assert_eq!(
        store.discovery_coverage(),
        Coverage::Incomplete {
            unregistered: 1,
            enumerating: false
        }
    );
    assert_eq!(store.blob_get(content.kappa())?, bytes);
    assert!(store.blob_exists(content.kappa())?);
    assert!(matches!(
        store.blob_get(absent.kappa()),
        Err(StoreError::Unavailable(_))
    ));
    assert!(matches!(
        store.blob_exists(absent.kappa()),
        Err(StoreError::Unavailable(_))
    ));
    assert!(matches!(
        store.blob_owners(content.kappa()),
        Err(StoreError::Unavailable(_))
    ));
    assert!(matches!(
        publish_at(&store, &holder, b"refused while unmeasured", 3000),
        Err(error) if matches!(
            error.downcast_ref::<StoreError>(),
            Some(StoreError::CapacityExceeded(_))
        )
    ));
    store.settlement_step(u64::MAX)?;
    assert_eq!(store.discovery_coverage(), Coverage::Complete);
    assert!(matches!(
        store.blob_get(absent.kappa()),
        Err(StoreError::NotFound(_))
    ));
    assert!(!store.blob_exists(absent.kappa())?);
    publish_at(&store, &holder, b"admitted once settled", 4000)?;
    Ok(())
}
