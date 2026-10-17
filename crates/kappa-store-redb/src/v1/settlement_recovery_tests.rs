//! Recovery schedules: abandoned creations, instance-bound retirement,
//! bounded opening, reconstruction split across steps, and creation residue
//! that cannot be read. Storage lost before a restart is `lost`.

use std::sync::Arc;

use kappa_handler::clock_at;
use kappa_store::{
    Axis, BlobStore, ClockMs, EpochStore, Kappa, NamespaceRef, StoreError, TagUpdate,
    VerifiedContent,
};

use super::StepBudget;
use crate::control_plane::{Guarantee, Guarantees};
use crate::retirement_record::RetirementRecord;
use crate::settlement::Work;
use crate::storage::NamespaceController;
use crate::storage_instance::StorageInstance;
use crate::store_access::Coverage;
use crate::{PersistentStore, PersistentStoreConfig, creation_intent};

#[path = "settlement_lost_tests.rs"]
mod lost;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The default step byte budget (`PersistentStoreConfig`).
const STEP_BYTES: u64 = 256 * 1024 * 1024;

/// A step of `entries` records and `mutations` epoch examinations.
const fn budget(entries: u64, mutations: u64) -> StepBudget {
    StepBudget {
        entries,
        work: Work {
            mutations,
            bytes: if mutations == 0 { 0 } else { STEP_BYTES },
        },
    }
}

fn open_with(root: &std::path::Path, entries: u64, mutations: u64) -> TestResult<PersistentStore> {
    let mut config = PersistentStoreConfig::new(
        root.join("blobs"),
        root.join("store.redb"),
        kappa_crypto::testing::fixture_authority(1)?,
    );
    config.recovery_step_entries = entries;
    config.recovery_step_mutations = mutations;
    Ok(PersistentStore::new(config)?)
}

fn open(root: &std::path::Path) -> TestResult<PersistentStore> {
    open_with(root, 4096, 4096)
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

fn write(store: &PersistentStore, ns: &NamespaceRef, time: i64) -> Result<(), StoreError> {
    let clock = clock_at(ClockMs::from_raw(time))?;
    let mut execution = store.begin_epoch_execution(ns, &clock, None)?;
    execution.tag_put(
        "head",
        &TagUpdate::Set {
            kappa: Kappa::sha256(&time.to_be_bytes()),
        },
    )?;
    execution.publish()?;
    Ok(())
}

fn publish(store: &PersistentStore, ns: &NamespaceRef, bytes: &[u8], time: i64) -> TestResult {
    let content = VerifiedContent::compute(Axis::Sha256, bytes)?;
    let clock = clock_at(ClockMs::from_raw(time))?;
    let mut execution = store.begin_epoch_execution(ns, &clock, None)?;
    execution.blob_put(&content)?;
    execution.publish()?;
    Ok(())
}

fn instance_of(store: &PersistentStore, ns: &NamespaceRef) -> TestResult<StorageInstance> {
    Ok(store.namespace_snapshot(ns)?.controller().instance)
}

const fn refused(result: &Result<(), StoreError>) -> bool {
    matches!(result, Err(StoreError::CapacityExceeded(_)))
}

fn intents(store: &PersistentStore) -> TestResult<usize> {
    Ok(creation_intent::traversal(store.namespaces.root())?.map_or(0, Iterator::count))
}

/// A creation that never committed leaves a claim, a marker and empty
/// storage; recovery proves it never committed and releases all three,
/// retiring exactly its instance. A recreation of the name is a new
/// instance, settled from no checkpoint, and survives a reopen although the
/// earlier instance's retirement record remains.
#[test]
fn a_proven_uncommitted_creation_is_cleaned_up_and_its_recreation_survives() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open(root.path())?;
    let ns = NamespaceRef::deterministic("abandoned");
    let clock = clock_at(ClockMs::from_raw(1000))?;
    let plane = Arc::clone(store.namespaces.planes().local());
    let mut execution = store.begin_creation_execution(&ns, plane, &clock, None)?;
    execution.namespace_create(None, None)?;
    let abandoned = execution.controller().instance;
    execution.abort()?;
    assert!(store.pending_settlements()?.contains(ns.id()));
    assert!(store.directory_knows(&ns)?, "control: the claim is held");
    store.settlement_step(u64::MAX)?;
    assert!(!store.directory_knows(&ns)?, "the claim was released");
    assert!(store.pending_settlements()?.is_empty());
    assert_eq!(
        store.retirement_record(&abandoned)?,
        Some(RetirementRecord::NeverCommitted)
    );
    assert_eq!(intents(&store)?, 0, "the intent went with the storage");
    assert!(matches!(
        store.namespace_snapshot(&ns),
        Err(StoreError::NotFound(_))
    ));
    create(&store, "abandoned")?;
    let recreated = instance_of(&store, &ns)?;
    assert_ne!(recreated, abandoned, "a recreation is a new instance");
    store.settlement_step(u64::MAX)?;
    assert!(store.directory_knows(&ns)?);
    assert_eq!(
        store.settled_epoch(&recreated)?.map(|(epoch, _)| epoch),
        Some(1)
    );
    drop(store);
    let reopened = open(root.path())?;
    assert_eq!(reopened.epoch_current(&ns)?.0, 1, "the recreation survived");
    assert_eq!(instance_of(&reopened, &ns)?, recreated);
    assert_eq!(
        reopened.retirement_record(&abandoned)?,
        Some(RetirementRecord::NeverCommitted),
        "old evidence is retained"
    );
    assert_eq!(reopened.discovery_coverage(), Coverage::Complete);
    Ok(())
}

/// Completing a retirement of instance A never removes instance B, whether
/// the completion runs before B is created or after.
#[test]
fn an_old_retirement_never_touches_its_replacement_in_either_order() -> TestResult {
    use crate::storage_retirement::RetirementCompletion;
    let root = tempfile::tempdir()?;
    let store = open(root.path())?;
    let ns = NamespaceRef::deterministic("replaced");
    let clock = clock_at(ClockMs::from_raw(1000))?;
    let plane = Arc::clone(store.namespaces.planes().local());
    let mut execution = store.begin_creation_execution(&ns, Arc::clone(&plane), &clock, None)?;
    execution.namespace_create(None, None)?;
    let old = execution.controller().instance;
    execution.abort()?;
    store.settlement_step(u64::MAX)?;
    assert_eq!(
        store.retirement_record(&old)?,
        Some(RetirementRecord::NeverCommitted),
        "control: A is retired"
    );
    // Completion before the replacement exists: nothing of A remains.
    assert_eq!(
        store.complete_retirement(&old)?,
        RetirementCompletion::Complete
    );
    create(&store, "replaced")?;
    let new = instance_of(&store, &ns)?;
    // Completion after: the storage present is B, which is kept.
    assert_eq!(
        store.complete_retirement(&old)?,
        RetirementCompletion::Retained
    );
    let directory = NamespaceController::directory(store.namespaces.root(), ns.id());
    assert!(directory.exists());
    store.settlement_step(u64::MAX)?;
    drop(store);
    let reopened = open(root.path())?;
    assert!(
        directory.exists(),
        "recovery at open removed the replacement"
    );
    assert_eq!(instance_of(&reopened, &ns)?, new);
    assert_eq!(reopened.epoch_current(&ns)?.0, 1);
    Ok(())
}

/// Opening a store with a large pending population does one bounded step
/// and returns with recovery in progress: misses are unavailable and the
/// pool is closed until later steps finish the enumeration, which examine
/// each pending entry once.
#[test]
fn a_bounded_open_examines_its_budget_and_steps_finish_without_rescanning() -> TestResult {
    const POPULATION: u64 = 40;
    const BUDGET: u64 = 8;
    let root = tempfile::tempdir()?;
    let namespaces = {
        let store = open(root.path())?;
        (0..POPULATION)
            .map(|index| create(&store, &format!("population-{index}")))
            .collect::<Result<Vec<_>, _>>()?
    };
    let store = open_with(root.path(), BUDGET, 1024)?;
    assert_eq!(store.recovery_examined()?, BUDGET, "one open step");
    assert!(!store.settlement_pass_complete()?);
    assert!(matches!(
        store.discovery_coverage(),
        Coverage::Incomplete {
            enumerating: true,
            ..
        }
    ));
    assert!(matches!(
        store.blob_get(&Kappa::sha256(b"never published")),
        Err(StoreError::Unavailable(_))
    ));
    assert!(refused(&write(&store, &namespaces[0], 2000)));
    let mut steps = 0;
    while store.discovery_coverage() != Coverage::Complete {
        store.recovery_step(budget(BUDGET, 1024))?;
        steps += 1;
        assert!(
            steps <= POPULATION / BUDGET + 2,
            "recovery made no progress"
        );
    }
    assert_eq!(
        store.recovery_examined()?,
        POPULATION,
        "each pending entry was examined once"
    );
    assert!(store.settlement_pass_complete()?);
    assert!(store.pending_settlements()?.is_empty());
    write(&store, &namespaces[0], 2001)?;
    Ok(())
}

/// An instance whose unsettled backlog exceeds one step's work is
/// reconstructed across steps, each epoch itself read across several
/// steps. After every step its ownership is held either by its closing
/// charge with discovery incomplete, or by measured debt with its
/// identities registered: never by nothing.
#[test]
fn a_reconstruction_split_across_steps_never_leaves_ownership_unaccounted() -> TestResult {
    let root = tempfile::tempdir()?;
    let ns = {
        let store = open(root.path())?;
        let ns = create(&store, "backlog")?;
        for time in 2000..2006 {
            write(&store, &ns, time)?;
        }
        ns
    };
    let store = open_with(root.path(), 64, 2)?;
    let instance = instance_of(&store, &ns)?;
    assert!(
        store.obligation_held(&instance),
        "control: a backlog remains"
    );
    for _ in 0..512 {
        let registered = store.obligation_registered(&instance);
        let coverage = store.discovery_coverage();
        assert!(
            !(registered == Some(false) && coverage == Coverage::Complete),
            "an unregistered obligation with complete discovery"
        );
        if registered.is_none() && coverage == Coverage::Complete {
            break;
        }
        store.recovery_step(budget(64, 2))?;
    }
    assert!(
        !store.obligation_held(&instance),
        "settlement discharged it"
    );
    assert_eq!(store.discovery_coverage(), Coverage::Complete);
    assert_eq!(store.unsettled.charged(), (0, 0));
    write(&store, &ns, 3000)?;
    Ok(())
}

/// A permanently unreadable obligation in the queue does not starve
/// discovery, even when each step has a single entry to spend: the unit
/// alternates between the queue and the traversal, so the readable markers
/// behind it are found and settled and the enumeration finishes.
#[test]
fn an_unreadable_obligation_does_not_starve_discovery_under_a_one_entry_budget() -> TestResult {
    const READABLE: u64 = 6;
    let root = tempfile::tempdir()?;
    let (stuck, readable) = {
        let store = open(root.path())?;
        let stuck = create(&store, "stuck")?;
        let readable = (0..READABLE)
            .map(|index| create(&store, &format!("readable-{index}")))
            .collect::<Result<Vec<_>, _>>()?;
        (stuck, readable)
    };
    let database = NamespaceController::database_path(&NamespaceController::directory(
        root.path(),
        stuck.id(),
    ));
    std::fs::File::create(&database)?;
    // One entry per step is what the schedule is about; the epoch work
    // each visit may do is ample, so a visit settles its marker.
    let store = open_with(root.path(), 1, 4096)?;
    let bound = 4 * (READABLE + 1) + 8;
    let mut steps = 0;
    while store.discovery_coverage()
        != (Coverage::Incomplete {
            unregistered: 1,
            enumerating: false,
        })
    {
        store.recovery_step(budget(1, 4096))?;
        steps += 1;
        assert!(
            steps <= bound,
            "discovery starved behind the unreadable obligation"
        );
    }
    let pending = store.pending_settlements()?;
    assert_eq!(
        pending,
        vec![*stuck.id()],
        "every readable marker was settled"
    );
    for ns in &readable {
        assert_eq!(store.epoch_current(ns)?.0, 1);
    }
    Ok(())
}

/// An unresolved creation intent whose committed storage becomes readable
/// again is handed to its marker in place: right after the step that writes
/// the marker, an identity miss is still unavailable, because the
/// obligation keeps its gap until registration or settlement establishes
/// discovery.
#[test]
fn an_intent_handed_to_its_marker_keeps_discovery_incomplete_until_settled() -> TestResult {
    let root = tempfile::tempdir()?;
    let (ns, instance) = {
        let store = open(root.path())?;
        let ns = create(&store, "handed")?;
        publish(&store, &ns, b"committed under an intent", 2000)?;
        let instance = instance_of(&store, &ns)?;
        creation_intent::record(store.namespaces.root(), &instance)?;
        (ns, instance)
    };
    let marker = root
        .path()
        .join("settlement")
        .join("pending")
        .join(instance.hex());
    std::fs::remove_file(&marker)?;
    let directory = NamespaceController::directory(root.path(), ns.id());
    let displaced = root.path().join("displaced");
    std::fs::rename(&directory, &displaced)?;
    std::fs::create_dir_all(&directory)?;
    std::fs::File::create(NamespaceController::database_path(&directory))?;
    let store = open(root.path())?;
    assert_eq!(
        store.discovery_coverage(),
        Coverage::Incomplete {
            unregistered: 1,
            enumerating: false
        },
        "control: the unreadable intent is an unresolved obligation"
    );
    std::fs::remove_dir_all(&directory)?;
    std::fs::rename(&displaced, &directory)?;
    store.recovery_step(budget(2, 0))?;
    assert!(
        marker.exists(),
        "control: the intent was handed to a marker"
    );
    assert_eq!(intents(&store)?, 0);
    assert!(store.obligation_held(&instance));
    assert!(matches!(
        store.blob_get(&Kappa::sha256(b"never published")),
        Err(StoreError::Unavailable(_))
    ));
    for _ in 0..8 {
        if store.discovery_coverage() == Coverage::Complete && !store.obligation_held(&instance) {
            break;
        }
        store.settlement_step(64)?;
    }
    assert_eq!(store.discovery_coverage(), Coverage::Complete);
    assert!(matches!(
        store.blob_get(&Kappa::sha256(b"never published")),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

/// Storage a failed creation left that cannot be read is an unresolved
/// obligation whatever its size: a zero-length database is not proof that
/// nothing committed, and it is never removed for being empty.
#[test]
fn unreadable_creation_residue_stays_unresolved_and_is_never_removed() -> TestResult {
    let root = tempfile::tempdir()?;
    let ns = NamespaceRef::deterministic("residue");
    let instance = StorageInstance::generate(*ns.id())?;
    let directory = NamespaceController::directory(root.path(), ns.id());
    let database = NamespaceController::database_path(&directory);
    {
        let store = open(root.path())?;
        creation_intent::record(store.namespaces.root(), &instance)?;
    }
    std::fs::create_dir_all(&directory)?;
    std::fs::File::create(&database)?;
    let store = open(root.path())?;
    assert_eq!(
        store.discovery_coverage(),
        Coverage::Incomplete {
            unregistered: 1,
            enumerating: false
        }
    );
    assert!(database.exists(), "an unreadable database is never removed");
    assert_eq!(intents(&store)?, 1, "the intent still owns the residue");
    // The operator removes the residue. A creation intent claims storage a
    // creation may have left, not committed ownership: with no storage of
    // the instance left, recovery completes the intent and discharges its
    // obligation (`visit_intent`), with no retirement to record.
    std::fs::remove_dir_all(&directory)?;
    assert!(store.retirement_record(&instance)?.is_none());
    store.settlement_step(u64::MAX)?;
    assert_eq!(store.discovery_coverage(), Coverage::Complete);
    assert_eq!(intents(&store)?, 0);
    Ok(())
}
