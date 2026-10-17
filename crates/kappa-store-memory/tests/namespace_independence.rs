//! Namespaces publish independently: each has its own view, writer and
//! publication point, so one namespace's open execution never delays
//! another's publication. What spans namespaces is coordinated by the
//! constraint it belongs to: exclusive keys by claims, authorization rows
//! other executions decided under by revisioned dependencies, content by
//! namespace-local admission over shared physical allocations.
//!
//! Every schedule that would block under a shared-writer regression runs
//! its worker under a watchdog that releases what the test holds, so a
//! regression fails instead of hanging.

use std::sync::{Arc, mpsc};
use std::time::Duration;

use kappa_handler::clock_at;
use kappa_store::execution::Retirement;
use kappa_store::identity::HandleRecord;
use kappa_store::namespace::ProtocolId;
use kappa_store::{
    Axis, BlobStore, ClockMs, EpochStore, Execution, ExecutionStore, IdentityStore, Kappa,
    NamespaceRef, NamespaceStore, StoreError, TagStore, TagUpdate, VerifiedContent,
};
use kappa_store_memory::InMemoryStore;
use kappa_store_memory::test_support::test_store;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const WATCHDOG: Duration = Duration::from_secs(10);

fn create(store: &InMemoryStore, name: &str) -> Result<NamespaceRef, Box<dyn std::error::Error>> {
    let ns = NamespaceRef::generate(name, ClockMs::from_raw(1000))?;
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(1000))?)?;
    execution.namespace_create(None, None)?;
    execution.publish()?;
    Ok(ns)
}

/// Run `work` on a worker while the test keeps whatever it holds. If the
/// worker has not finished within the watchdog, `release` gives up the
/// held state first and then the worker is joined, so a regression that
/// blocks the worker on the held state fails instead of hanging.
fn while_holding<T: Send + 'static>(
    release: impl FnOnce(),
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Box<dyn std::error::Error>> {
    let (done, completion) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let outcome = work();
        // The receiver outlives the worker unless the test already failed.
        done.send(()).ok();
        outcome
    });
    let finished = completion.recv_timeout(WATCHDOG);
    if finished.is_err() {
        release();
    }
    let outcome = worker.join().map_err(|_| "worker panicked")?;
    finished.map_err(|_| "worker waited on state held by the test")?;
    Ok(outcome)
}

/// Publish `write` in `ns` on a worker under the watchdog while the test
/// holds `held`.
fn publish_beside(
    store: &Arc<InMemoryStore>,
    ns: &NamespaceRef,
    at: i64,
    held: &std::cell::RefCell<Option<Box<dyn Execution + '_>>>,
    write: impl FnOnce(&mut dyn Execution) -> Result<(), StoreError> + Send + 'static,
) -> Result<Result<(), String>, Box<dyn std::error::Error>> {
    let (store, ns) = (Arc::clone(store), ns.clone());
    while_holding(
        || drop(held.borrow_mut().take()),
        move || -> Result<(), String> {
            let clock = clock_at(ClockMs::from_raw(at)).map_err(|error| error.to_string())?;
            let mut execution = store
                .begin_execution(&ns, &clock)
                .map_err(|error| error.to_string())?;
            write(&mut *execution).map_err(|error| error.to_string())?;
            execution
                .publish()
                .map(drop)
                .map_err(|error| error.to_string())
        },
    )
}

#[test]
fn an_open_execution_of_one_namespace_does_not_block_another() -> TestResult {
    let store = Arc::new(test_store()?.into_store());
    let a = create(&store, "independent-a")?;
    let b = create(&store, "independent-b")?;
    let shared = VerifiedContent::compute(Axis::Sha256, b"shared content")?;
    let kappa = shared.kappa().clone();

    let mut execution = store.begin_execution(&a, &clock_at(ClockMs::from_raw(2000))?)?;
    execution.blob_put(&shared)?;
    execution.tag_put(
        "a",
        &TagUpdate::Set {
            kappa: kappa.clone(),
        },
    )?;
    let held = std::cell::RefCell::new(Some(execution));
    publish_beside(&store, &b, 2001, &held, move |execution| {
        let worker_shared = VerifiedContent::compute(Axis::Sha256, b"shared content")?;
        execution.blob_put(&worker_shared)?;
        execution.tag_put(
            "b",
            &TagUpdate::Set {
                kappa: worker_shared.kappa().clone(),
            },
        )
    })??;
    // B's publication is found by identity as soon as it returned.
    assert_eq!(store.epoch_current(&b)?.0, 2);
    assert_eq!(store.blob_get(&kappa)?, b"shared content");
    assert!(
        !store.blob_exists_in(&a, &kappa)?,
        "A's private admission is visible"
    );

    held.borrow_mut()
        .take()
        .ok_or("the watchdog released A although B finished")?
        .publish()?;
    assert_eq!(store.tag_get(&a, "a")?.kappa, kappa);
    assert_eq!(store.tag_get(&b, "b")?.kappa, kappa);

    // A releases its admission; B's admission of the same bytes stands.
    let mut execution = store.begin_execution(&a, &clock_at(ClockMs::from_raw(3000))?)?;
    execution.tag_delete("a")?;
    let identities = store.blob_owners(&kappa)?;
    assert_eq!(identities.len(), 2, "both namespaces admit the content");
    // The identity and its digest aliases in A go together.
    assert_eq!(execution.content_retire(&kappa)?, Retirement::Retired);
    execution.publish()?;
    let aliases: Vec<Kappa> = [Axis::Sha256, Axis::Sha512, Axis::Blake3]
        .into_iter()
        .map(|axis| Kappa::compute(axis, b"shared content"))
        .collect::<Result<_, _>>()?;
    for identity in &aliases {
        assert!(
            !store.blob_exists_in(&a, identity)?,
            "{identity} is still admitted by A"
        );
    }
    assert_eq!(store.blob_get_in(&b, &kappa)?, b"shared content");
    assert_eq!(store.blob_owners(&kappa)?.len(), 1);
    Ok(())
}

#[test]
fn a_reserved_alias_excludes_a_concurrent_creation_until_it_aborts() -> TestResult {
    let store = Arc::new(test_store()?.into_store());
    let first = NamespaceRef::generate("contested", ClockMs::from_raw(1000))?;
    let second = NamespaceRef::generate("contested", ClockMs::from_raw(1001))?;
    assert_ne!(first.id(), second.id());
    let mut execution = store.begin_execution(&first, &clock_at(ClockMs::from_raw(1000))?)?;
    execution.namespace_create(None, None)?;
    let held = std::cell::RefCell::new(Some(execution));
    // The second creation runs while the first is open: its reservation
    // conflicts at once instead of waiting or publishing a duplicate.
    let outcome = publish_beside(&store, &second, 1001, &held, |execution| {
        execution.namespace_create(None, None)
    })?;
    assert!(
        outcome.is_err(),
        "the second claim of the alias was admitted"
    );
    assert!(
        held.borrow().is_some(),
        "the second creation waited on the first's open execution"
    );
    // The first aborts: its reservation is released and the alias is free.
    drop(held.borrow_mut().take());
    let mut retry = store.begin_execution(&second, &clock_at(ClockMs::from_raw(1002))?)?;
    retry.namespace_create(None, None)?;
    retry.publish()?;
    assert_eq!(store.namespace_resolve("contested", None)?, second);
    Ok(())
}

/// A session removed and recreated with an equal value is still a change:
/// an execution of another namespace that decided under the first value
/// does not publish.
#[test]
fn an_authorization_changed_and_restored_still_refuses_the_dependent_publication() -> TestResult {
    let store = Arc::new(test_store()?.into_store());
    let issuer = create(&store, "issuer")?;
    let dependent = create(&store, "dependent")?;
    let anchor = Kappa::sha256(b"principal");
    let mut grant = store.begin_execution(&issuer, &clock_at(ClockMs::from_raw(2000))?)?;
    grant.session_put("token", &anchor, i64::MAX, b"meta")?;
    grant.publish()?;

    let mut decided = store.begin_execution(&dependent, &clock_at(ClockMs::from_raw(2001))?)?;
    assert_eq!(
        decided.session_get("token")?,
        Some((anchor.clone(), b"meta".to_vec()))
    );
    decided.tag_put(
        "authorized",
        &TagUpdate::Set {
            kappa: anchor.clone(),
        },
    )?;
    let held = std::cell::RefCell::new(Some(decided));
    let restored = anchor;
    publish_beside(&store, &issuer, 2002, &held, move |execution| {
        execution.session_delete("token")?;
        execution.session_put("token", &restored, i64::MAX, b"meta")
    })??;
    let decided = held
        .borrow_mut()
        .take()
        .ok_or("the watchdog released the dependent execution")?;
    assert!(
        matches!(decided.publish(), Err(StoreError::Conflict(_))),
        "an execution authorized under a replaced session published"
    );
    assert!(matches!(
        store.tag_get(&dependent, "authorized"),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

/// A credential observed absent and created by another namespace before
/// the observing execution publishes refuses that publication.
#[test]
fn an_absence_observed_then_filled_refuses_the_dependent_publication() -> TestResult {
    let store = Arc::new(test_store()?.into_store());
    let issuer = create(&store, "credential-issuer")?;
    let registrar = create(&store, "registrar")?;
    let mut decided = store.begin_execution(&registrar, &clock_at(ClockMs::from_raw(2000))?)?;
    assert_eq!(decided.credential_get("KEY1")?, None);
    decided.tag_put(
        "registered",
        &TagUpdate::Set {
            kappa: Kappa::sha256(b"KEY1"),
        },
    )?;
    let held = std::cell::RefCell::new(Some(decided));
    publish_beside(&store, &issuer, 2001, &held, |execution| {
        execution.credential_put("KEY1", &Kappa::sha256(b"owner"), b"secret")
    })??;
    let decided = held
        .borrow_mut()
        .take()
        .ok_or("the watchdog released the registrar")?;
    assert!(
        matches!(decided.publish(), Err(StoreError::Conflict(_))),
        "a create-if-absent decided under a stale absence published"
    );
    Ok(())
}

#[test]
fn one_handle_is_held_by_one_namespace() -> TestResult {
    let store = Arc::new(test_store()?.into_store());
    let first = create(&store, "handle-first")?;
    let second = create(&store, "handle-second")?;
    let protocol = ProtocolId::new("atproto")?;
    let record = |anchor: &[u8]| HandleRecord {
        protocol: protocol.clone(),
        handle: "alice".into(),
        anchor: Kappa::sha256(anchor),
        claimed_at_ms: 2000,
        attested_at_ms: None,
    };
    let mut claim = store.begin_execution(&first, &clock_at(ClockMs::from_raw(2000))?)?;
    claim.handle_put(&record(b"one"))?;
    let held = std::cell::RefCell::new(Some(claim));
    let contender = record(b"two");
    let outcome = publish_beside(&store, &second, 2001, &held, move |execution| {
        execution.handle_put(&contender)
    })?;
    assert!(
        outcome.is_err(),
        "a second namespace took a reserved handle"
    );
    held.borrow_mut()
        .take()
        .ok_or("the watchdog released the claim")?
        .publish()?;
    assert_eq!(
        IdentityStore::handle_get(&*store, protocol.clone(), "alice")?.anchor,
        Kappa::sha256(b"one")
    );
    Ok(())
}
