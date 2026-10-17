//! Forced admission schedules. Hooks only pause the real admission path;
//! they do not replace transactions, controller state, or mutation logic.
use std::cell::RefCell;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use kappa_handler::clock_at;
use kappa_store::{ClockMs, EpochStore, Kappa, NamespaceRef, StoreError, TagStore, TagUpdate};

use crate::PersistentStore;
use crate::control_plane::{ASSIGNMENT_KEY, AssignmentRecord, Guarantee, Guarantees};
use crate::storage::Opening;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Pause = (mpsc::Sender<()>, mpsc::Receiver<()>);

thread_local! {
    static BEFORE_WRITER: RefCell<Option<Pause>> = const { RefCell::new(None) };
}

pub(super) fn before_writer() {
    BEFORE_WRITER.with(|slot| {
        if let Some((arrived, resume)) = slot.borrow_mut().take() {
            // A disconnected test driver releases the worker during unwinding.
            let _ = arrived.send(());
            let _ = resume.recv_timeout(Duration::from_secs(10));
        }
    });
}

fn store() -> Result<PersistentStore, kappa_fixture::SetupError> {
    Ok(crate::test_support::PersistentSpec::new()
        .acquire()?
        .into_store())
}

#[test]
fn fence_between_precheck_and_writer_rejects_without_releasing_dependencies() -> TestResult {
    let store = store()?;
    let ns = NamespaceRef::deterministic("fence-after-precheck");
    let active = store.namespaces.admit_publish(
        ns.id(),
        &Opening::Create {
            plane: Arc::clone(store.namespaces.planes().local()),
        },
    )?;
    let controller = Arc::clone(active.controller());
    let allocation = crate::representation::AllocationId::generate()?;
    let protection = Arc::new(crate::allocation::Protection::default());
    controller
        .writer_pins
        .lock()
        .map_err(|_| "pins poisoned")?
        .push(protection.pin(allocation)?);
    let clock = clock_at(ClockMs::from_raw(1000))?;
    let (arrived, arrival) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    let outcome = std::thread::scope(|scope| -> Result<_, Box<dyn std::error::Error>> {
        let (store, ns, clock) = (&store, &ns, &clock);
        let worker = scope.spawn(move || {
            BEFORE_WRITER.with(|slot| *slot.borrow_mut() = Some((arrived, resumed)));
            match store.begin_epoch_execution(ns, clock, None) {
                Ok(execution) => {
                    drop(execution);
                    Ok(())
                }
                Err(error) => Err(error),
            }
        });
        let reached = arrival.recv_timeout(Duration::from_secs(10));
        // Always release before joining, including when the precheck fails.
        let fenced = controller.fence();
        drop(resume);
        let result = worker.join().map_err(|_| "admission worker panicked")?;
        reached?;
        fenced?;
        Ok(result)
    })?;
    assert!(
        matches!(outcome, Err(StoreError::Conflict(_))),
        "a fence installed after the early check must reject admission"
    );
    assert!(
        protection.claim(allocation)?.is_none(),
        "rejected admission released a dependency before recovery"
    );
    Ok(())
}

#[test]
fn withdrawn_assignment_between_precheck_and_writer_rejects_admission() -> TestResult {
    let store = store()?;
    let ns = NamespaceRef::deterministic("assignment-after-precheck");
    let active = store.namespaces.admit_publish(
        ns.id(),
        &Opening::Create {
            plane: Arc::clone(store.namespaces.planes().local()),
        },
    )?;
    let controller = Arc::clone(active.controller());
    let clock = clock_at(ClockMs::from_raw(1000))?;
    let (arrived, arrival) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    let outcome = std::thread::scope(|scope| -> Result<_, Box<dyn std::error::Error>> {
        let (store, ns, clock) = (&store, &ns, &clock);
        let worker = scope.spawn(move || {
            BEFORE_WRITER.with(|slot| *slot.borrow_mut() = Some((arrived, resumed)));
            match store.begin_epoch_execution(ns, clock, None) {
                Ok(execution) => {
                    drop(execution);
                    Ok(())
                }
                Err(error) => Err(error),
            }
        });
        let reached = arrival.recv_timeout(Duration::from_secs(10));
        *controller.plane.lock().map_err(|_| "plane poisoned")? = None;
        drop(resume);
        let result = worker.join().map_err(|_| "admission worker panicked")?;
        reached?;
        Ok(result)
    })?;
    assert!(
        matches!(outcome, Err(StoreError::Rejected(_))),
        "admission used authority that disappeared while acquiring the writer"
    );
    Ok(())
}

#[test]
fn creation_without_an_assignment_cannot_publish() -> TestResult {
    let store = store()?;
    let ns = NamespaceRef::deterministic("unassigned-creation");
    let clock = clock_at(ClockMs::from_raw(1000))?;
    let mut execution = store.begin_creation_execution(
        &ns,
        Arc::clone(store.namespaces.planes().local()),
        &clock,
        None,
    )?;
    execution.namespace_create(None, None)?;
    assert!(
        execution.publish().is_err(),
        "creation admitted no assignment but published"
    );
    assert!(matches!(
        store.epoch_current(&ns),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

#[test]
fn published_result_returns_while_the_shared_projection_writer_is_held() -> TestResult {
    let store = store()?;
    let ns = NamespaceRef::deterministic("blocked-settlement");
    let plane = Arc::clone(store.namespaces.planes().local());
    let clock = clock_at(ClockMs::from_raw(1000))?;
    let assignment = AssignmentRecord {
        namespace_id: ns.id().to_vec(),
        plane: plane.id.0.to_vec(),
        generation: 0,
        requires: Guarantees::NONE
            .with(Guarantee::TotalOrder)
            .with(Guarantee::Fenced)
            .with(Guarantee::LinearizableReads),
    };
    let mut creation = store.begin_creation_execution(&ns, plane, &clock, None)?;
    creation.namespace_create(None, None)?;
    creation.namespace_put_meta(
        ASSIGNMENT_KEY,
        &kappa_store::canonical::canonical_bytes(&assignment),
    )?;
    creation.publish()?;
    let before = store.epoch_current(&ns)?.0;
    let registry_writer = store.registry.begin_write()?;
    let (finished, completion) = mpsc::channel();
    let (early, outcome) = std::thread::scope(|scope| {
        let worker = scope.spawn(|| -> Result<(), String> {
            let result = (|| -> Result<(), StoreError> {
                let clock = clock_at(ClockMs::from_raw(1001))?;
                let mut execution = store.begin_epoch_execution(&ns, &clock, None)?;
                execution.tag_put(
                    "head",
                    &TagUpdate::Set {
                        kappa: Kappa::sha256(b"published"),
                    },
                )?;
                execution.publish()?;
                Ok(())
            })()
            .map_err(|error| error.to_string());
            let _ = finished.send(result.clone());
            result
        });
        // Watchdog only. Release the blocker before joining on both paths,
        // so a serialization regression terminates with an assertion.
        let early = completion.recv_timeout(Duration::from_secs(10));
        drop(registry_writer);
        (early, worker.join())
    });
    outcome.map_err(|_| "publication worker panicked")??;
    early.map_err(|_| "publication waited for the shared projection writer")??;
    assert_eq!(store.epoch_current(&ns)?.0, before + 1);
    assert_eq!(
        store.tag_get_raw(&ns, "head")?.kappa,
        Kappa::sha256(b"published")
    );
    Ok(())
}
