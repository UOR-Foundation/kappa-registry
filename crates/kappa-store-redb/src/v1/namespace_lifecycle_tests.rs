//! Real namespace transactions under process death and forced overlap.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use kappa_cursor::FallibleCursor;
use kappa_handler::clock_at;
use kappa_store::{
    BlobStore, ClockMs, EpochStore, Kappa, MaintenanceStore, NamespaceRef, StoreError, TagStore,
    TagUpdate,
};

use super::{ACTIVITY_RELEASE, Point};
use crate::control_plane::{AssignmentRecord, Guarantee, Guarantees};
use crate::referrers::{Referrer, Source};
use crate::{PersistentStore, PersistentStoreConfig};

#[path = "namespace_backpressure_tests.rs"]
mod backpressure;
#[path = "namespace_reclaim_tests.rs"]
mod reclaim;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const WATCHDOG: Duration = Duration::from_secs(10);

fn open(root: &std::path::Path) -> Result<PersistentStore, Box<dyn std::error::Error>> {
    Ok(PersistentStore::new(PersistentStoreConfig::new(
        root.join("blobs"),
        root.join("store.redb"),
        kappa_crypto::testing::fixture_authority(1)?,
    ))?)
}

fn create(store: &PersistentStore, name: &str) -> Result<NamespaceRef, StoreError> {
    create_owned(store, name, None)
}

/// Create `name` owned by `owner`, totally ordered, fenced, with
/// linearizable reads.
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
            .with(Guarantee::Fenced)
            .with(Guarantee::LinearizableReads),
    )
}

fn write(store: &PersistentStore, ns: &NamespaceRef, time: i64) -> Result<(), StoreError> {
    let clock = clock_at(ClockMs::from_raw(time))?;
    let mut execution = store.begin_epoch_execution(ns, &clock, None)?;
    execution.tag_put(
        "head",
        &TagUpdate::Set {
            kappa: Kappa::sha256(b"new"),
        },
    )?;
    execution.publish()?;
    Ok(())
}

fn drain_settlement(store: &PersistentStore, ns: &NamespaceRef) -> TestResult {
    const MUTATIONS: u64 = 16;
    let active = store.namespace_snapshot(ns)?;
    for _ in 0..64 {
        let mut work = crate::settlement::Work {
            mutations: MUTATIONS,
            bytes: 256 * 1024 * 1024,
        };
        let settled = store.settle_namespace(active.controller(), &mut work)?;
        assert!(
            settled.examined <= MUTATIONS && settled.applied <= settled.examined,
            "settlement completed more epochs than its work admits"
        );
        if settled.reached {
            assert!(
                active
                    .controller()
                    .pending_pins
                    .lock()
                    .map_err(|_| "pending pins poisoned")?
                    .is_empty(),
                "settled fixture still has pins that could mask missing reader ownership"
            );
            // A maintenance step compacts after it settles: completed
            // retirements release their allocations there.
            for _ in 0..64 {
                if store.compact_projection(64)?.complete {
                    return Ok(());
                }
            }
            return Err("tiny fixture did not compact within 64 bounded steps".into());
        }
    }
    Err("tiny fixture did not settle within 64 bounded steps".into())
}

#[test]
fn process_death_after_commit_before_settlement_recovers_content() -> TestResult {
    const CHILD_ROOT: &str = "KAPPA_NAMESPACE_COMMIT_CRASH_ROOT";
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let store = open(std::path::Path::new(&root))?;
        let ns = create(&store, "commit-crash")?;
        let bytes = vec![73; 256 * 1024];
        let prepared = kappa_store::ContentPreparation::prepare_content(
            &store,
            kappa_store::ContentIdentity::Verified(Kappa::sha256(&bytes)),
            &mut bytes.as_slice(),
            kappa_store::PreparationBounds {
                maximum: bytes.len() as u64,
                deadline: Instant::now() + WATCHDOG,
            },
        )?;
        // exit skips every Rust destructor: no parking, settlement, or
        // graceful database shutdown can repair the deliberately stale index.
        store
            .hooks
            .install(Point::AfterEpochCommit, || std::process::exit(73));
        let clock = clock_at(ClockMs::from_raw(2000))?;
        let mut execution = store.begin_epoch_execution(&ns, &clock, None)?;
        kappa_store::ExecutionWrites::content_install(&mut execution, prepared)?;
        execution.tag_put(
            "payload",
            &TagUpdate::Set {
                kappa: Kappa::sha256(&bytes),
            },
        )?;
        execution.publish()?;
        return Err("crash hook was not reached".into());
    }
    let root = tempfile::tempdir()?;
    let test_name = format!(
        "{}::process_death_after_commit_before_settlement_recovers_content",
        module_path!()
    );
    // module_path includes the crate, whereas libtest names do not.
    let exact = test_name
        .split_once("::")
        .ok_or("test module has no crate prefix")?
        .1;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", exact, "--nocapture"])
        .env(CHILD_ROOT, root.path())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err("crash child failed to reach committed boundary".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(
        status.code(),
        Some(73),
        "child must exit at the commit hook"
    );
    let store = open(root.path())?;
    let ns = NamespaceRef::deterministic("commit-crash");
    assert_eq!(store.epoch_current(&ns)?.0, 2);
    let bytes = vec![73; 256 * 1024];
    let identity = Kappa::sha256(&bytes);
    assert_eq!(store.tag_get_raw(&ns, "payload")?.kappa, identity);
    // Reclamation must not trust projection absence left by the dead child.
    assert_eq!(store.blob_get_in(&ns, &identity)?, bytes);
    let mut completed = false;
    for _ in 0..1024 {
        if store.reclaim_unowned(8)?.complete {
            completed = true;
            break;
        }
    }
    assert!(
        completed,
        "bounded inventory failed to complete on the tiny crash fixture"
    );
    assert_eq!(store.blob_get_in(&ns, &identity)?, bytes);
    drain_settlement(&store, &ns)?;
    assert_eq!(store.blob_get_in(&ns, &identity)?, bytes);
    write(&store, &ns, 3000)?;
    assert_eq!(store.epoch_current(&ns)?.0, 3);
    Ok(())
}

#[test]
fn recovery_overlap_never_regresses_the_published_head() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open(root.path())?;
    let ns = create(&store, "recovery-overlap")?;
    let active = store.namespace_snapshot(&ns)?;
    active
        .controller()
        .head_recovered
        .store(false, Ordering::Release);
    let (arrived, arrival) = mpsc::channel::<()>();
    let (release, released) = mpsc::channel::<()>();
    let released = Mutex::new(released);
    let first = AtomicBool::new(true);
    store.hooks.install(Point::RecoveryHeadRead, move || {
        if first.swap(false, Ordering::AcqRel) {
            let _ = arrived.send(());
            if let Ok(receiver) = released.lock() {
                let _ = receiver.recv_timeout(WATCHDOG);
            }
        }
    });
    let result = std::thread::scope(|scope| -> TestResult {
        let recovery = scope.spawn(|| -> Result<(), StoreError> {
            let clock = clock_at(ClockMs::from_raw(2000))?;
            store.begin_epoch_execution(&ns, &clock, None)?.abort()
        });
        let reached = arrival.recv_timeout(WATCHDOG);
        let publisher = scope.spawn(|| write(&store, &ns, 3000));
        drop(release);
        recovery.join().map_err(|_| "recovery panicked")??;
        publisher.join().map_err(|_| "publisher panicked")??;
        reached?;
        Ok(())
    });
    store.hooks.clear(Point::RecoveryHeadRead);
    result?;
    assert_eq!(store.epoch_current(&ns)?.0, 2);
    assert_eq!(active.controller().epoch_number.load(Ordering::Acquire), 2);
    write(&store, &ns, 4000)?;
    assert_eq!(store.epoch_current(&ns)?.0, 3);
    Ok(())
}

#[test]
fn activity_release_occurs_after_transaction_abort() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open(root.path())?;
    let ns = create(&store, "drop-order")?;
    let active = store.namespace_snapshot(&ns)?;
    let database = Arc::clone(&active.controller().db);
    let clock = clock_at(ClockMs::from_raw(2000))?;
    let (observed, observation) = mpsc::channel();
    std::thread::scope(|scope| {
        let (probe, requested) = mpsc::channel();
        let (acquired, acquisition) = mpsc::channel();
        let worker = scope.spawn(move || -> Result<(), String> {
            requested.recv().map_err(|e| e.to_string())?;
            let transaction = database.begin_write().map_err(|e| e.to_string())?;
            let _ = acquired.send(());
            drop(transaction);
            Ok(())
        });
        let mut execution = store.begin_epoch_execution(&ns, &clock, None)?;
        execution.tag_put(
            "aborted",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"private"),
            },
        )?;
        ACTIVITY_RELEASE.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                let _ = probe.send(());
                let _ = observed.send(acquisition.recv_timeout(WATCHDOG).is_ok());
            }));
        });
        drop(execution);
        worker.join().map_err(|_| "writer probe panicked")??;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    assert!(
        observation.recv_timeout(WATCHDOG)?,
        "activity released while transaction still held writer"
    );
    assert!(matches!(
        store.tag_get_raw(&ns, "aborted"),
        Err(StoreError::NotFound(_))
    ));
    assert_eq!(store.epoch_current(&ns)?.0, 1);
    Ok(())
}

/// Publish one external blob of `fill` bytes in `ns`; the committed
/// epoch's pins are parked until settlement.
fn publish_blob(
    store: &PersistentStore,
    ns: &NamespaceRef,
    fill: u8,
    size: usize,
    time: i64,
) -> Result<(), StoreError> {
    let bytes = vec![fill; size];
    let prepared = kappa_store::ContentPreparation::prepare_content(
        store,
        kappa_store::ContentIdentity::Verified(Kappa::sha256(&bytes)),
        &mut bytes.as_slice(),
        kappa_store::PreparationBounds {
            maximum: size as u64,
            deadline: Instant::now() + WATCHDOG,
        },
    )?;
    let clock = clock_at(ClockMs::from_raw(time))?;
    let mut execution = store.begin_epoch_execution(ns, &clock, None)?;
    kappa_store::ExecutionWrites::content_install(&mut execution, prepared)?;
    execution.tag_put(
        &format!("item-{fill}"),
        &TagUpdate::Set {
            kappa: Kappa::sha256(&bytes),
        },
    )?;
    execution.publish()?;
    Ok(())
}

/// A committed reassignment whose installation on the open controller
/// fails leaves the publication committed and the controller stale: no
/// execution is admitted under the previous authority, and the next
/// admission refreshes the controller from the admitted record.
#[test]
fn stale_assignment_authority_is_refused_until_refreshed() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = open(root.path())?;
    let ns = create(&store, "stale-assignment")?;
    let plane = Arc::clone(store.namespaces.planes().local());
    let reassignment = AssignmentRecord {
        namespace_id: ns.id().to_vec(),
        plane: plane.id.0.to_vec(),
        generation: 1,
        requires: Guarantees::NONE
            .with(Guarantee::TotalOrder)
            .with(Guarantee::LinearizableReads),
    };
    store.hooks.refuse_assignment_refresh(true);
    let clock = clock_at(ClockMs::from_raw(2000))?;
    let mut execution = store.begin_epoch_execution(&ns, &clock, None)?;
    execution.assign_control_plane(&reassignment)?;
    let published = execution.publish()?;
    assert_eq!(published.0, 2, "the reassignment epoch is committed");
    assert_eq!(store.epoch_current(&ns)?, published);
    let controller = Arc::clone(store.namespace_snapshot(&ns)?.controller());
    assert!(controller.assignment_is_stale());
    assert_eq!(
        controller.plane()?.1,
        0,
        "the stale controller still holds generation 0"
    );
    // Refresh still refused: nothing is admitted under the stale authority.
    let clock = clock_at(ClockMs::from_raw(3000))?;
    assert!(matches!(
        store.begin_epoch_execution(&ns, &clock, None),
        Err(StoreError::Internal(_))
    ));
    assert!(controller.assignment_is_stale());
    store.hooks.refuse_assignment_refresh(false);
    write(&store, &ns, 4000)?;
    assert!(!controller.assignment_is_stale());
    assert_eq!(
        controller.plane()?.1,
        1,
        "admission refreshed the admitted generation"
    );
    assert_eq!(store.epoch_current(&ns)?.0, 3);
    Ok(())
}

#[test]
fn referrer_cursor_retains_its_snapshot_through_eviction_and_replacement() -> TestResult {
    let root = tempfile::tempdir()?;
    let mut config = PersistentStoreConfig::new(
        root.path().join("blobs"),
        root.path().join("store.redb"),
        kappa_crypto::testing::fixture_authority(1)?,
    );
    config.max_idle_namespaces = 0;
    let store = PersistentStore::new(config)?;
    let ns = create(&store, "retained-referrers")?;
    let content = Kappa::sha256(b"referenced");
    let clock = clock_at(ClockMs::from_raw(2000))?;
    let mut execution = store.begin_epoch_execution(&ns, &clock, None)?;
    for name in ["a", "b", "c"] {
        execution.tag_put(
            name,
            &TagUpdate::Set {
                kappa: content.clone(),
            },
        )?;
    }
    execution.publish()?;

    drain_settlement(&store, &ns)?;
    assert!(
        store.namespaces.open_controller(ns.id()).is_none(),
        "control failed: settled namespace without a reader was not evicted"
    );
    // No separate Active or controller Arc is retained by this test.
    // Only the escaping production cursor can keep the database open.
    let mut cursor = store.referrers_of(&ns, &content)?;
    assert!(matches!(cursor.referrer()?.map(Referrer::source),
        Some(Source::Tag { name }) if name == "a"));
    for index in 0..4 {
        let other = create(&store, &format!("eviction-pressure-{index}"))?;
        write(&store, &other, 2000)?;
        drain_settlement(&store, &other)?;
        assert!(
            store.namespaces.open_controller(other.id()).is_none(),
            "control failed: idle namespace survived eviction pressure"
        );
    }
    assert!(
        store.namespaces.open_controller(ns.id()).is_some(),
        "escaping cursor did not retain its namespace controller"
    );
    // Reading the already decoded head is insufficient: advance must
    // actually access retained redb pages after eviction pressure.
    cursor.advance()?;
    assert!(matches!(cursor.referrer()?.map(Referrer::source),
        Some(Source::Tag { name }) if name == "b"));

    let clock = clock_at(ClockMs::from_raw(3000))?;
    let mut execution = store.begin_epoch_execution(&ns, &clock, None)?;
    execution.tag_delete("b")?;
    execution.tag_delete("c")?;
    execution.tag_put(
        "d",
        &TagUpdate::Set {
            kappa: content.clone(),
        },
    )?;
    execution.publish()?;
    drain_settlement(&store, &ns)?;
    cursor.advance()?;
    assert!(matches!(cursor.referrer()?.map(Referrer::source),
        Some(Source::Tag { name }) if name == "c"));
    assert!(cursor.advance()?.is_none());
    assert!(cursor.advance()?.is_none());
    drop(cursor);
    assert!(
        store.namespaces.open_controller(ns.id()).is_none(),
        "dropping the last cursor did not release the namespace for eviction"
    );

    // A fresh view must see the replacement, not the retained old snapshot.
    let mut fresh = store.referrers_of(&ns, &content)?;
    let mut names = Vec::new();
    while let Some(entry) = fresh.referrer()? {
        match entry.source() {
            Source::Tag { name } => names.push(name.clone()),
            other => return Err(format!("unexpected referrer: {other:?}").into()),
        }
        fresh.advance()?;
    }
    assert_eq!(names, ["a", "d"]);
    Ok(())
}
