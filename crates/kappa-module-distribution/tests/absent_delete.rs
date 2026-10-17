//! Deleting state that does not exist publishes no epoch. An absent filter
//! is `NotFound`; an absent edge succeeds without publishing.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kappa_fixture::FixtureRoot;
use kappa_handler::{HandlerError, Outcome, Prepared, clock_at};
use kappa_module_distribution::edge::remove_edge;
use kappa_module_distribution::filter::{install_filter, remove_filter};
use kappa_store::{
    Axis, ClockMs, ContentIdentity, EpochStore, Execution, Kappa, KappaStore, NamespaceRef,
    PreparationBounds, StoreError,
};
use kappa_store_memory::InMemoryStore;
use kappa_store_memory::test_support::StoreSpec;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Filter content prepared through the store, as the handler hands it to
/// `install_filter`.
fn prepared(store: &dyn KappaStore, content: &[u8]) -> Result<Prepared, StoreError> {
    let prepared = store.prepare_content(
        ContentIdentity::Computed(Axis::Sha256),
        &mut &content[..],
        PreparationBounds {
            maximum: 256 * 1024,
            deadline: Instant::now() + Duration::from_secs(30),
        },
    )?;
    Ok(Arc::new(Mutex::new(Some(prepared))))
}

/// Run `work` in one execution; publish or abort as it decides. The inner
/// result is the work's own outcome: whether it published, or its error,
/// after which the dropped execution publishes nothing.
fn run<T>(
    store: &dyn KappaStore,
    namespace: &NamespaceRef,
    now: ClockMs,
    mut work: impl FnMut(&mut dyn Execution) -> Result<Outcome<T>, HandlerError>,
) -> Result<Result<bool, HandlerError>, StoreError> {
    let mut execution = store.begin_execution(namespace, &clock_at(now)?)?;
    match work(&mut *execution) {
        Ok(Outcome::Publish(_)) => {
            execution.publish()?;
            Ok(Ok(true))
        }
        Ok(Outcome::Discard(_)) => {
            execution.abort()?;
            Ok(Ok(false))
        }
        Err(error) => Ok(Err(error)),
    }
}

/// A shared store in its own scope. The caller drops every store handle and
/// then closes the scope, which fails while any handle (for example one an
/// operation captured) is still alive.
fn memory_store() -> Result<(Arc<InMemoryStore>, FixtureRoot), Box<dyn std::error::Error>> {
    let acquired = StoreSpec::new().acquire()?;
    let root = acquired.root().clone();
    Ok((Arc::new(acquired.into_store()), root))
}

#[test]
fn absent_filter_delete_is_not_found_and_publishes_no_epoch() -> TestResult {
    let (store, root) = memory_store()?;
    let namespace = NamespaceRef::deterministic("filters");

    assert!(matches!(
        run(
            &*store,
            &namespace,
            ClockMs::from_raw(1000),
            remove_filter("absent".into())
        )?,
        Err(HandlerError::NotFound { .. })
    ));
    assert!(matches!(
        store.epoch_current(&namespace),
        Err(StoreError::NotFound(_))
    ));

    assert!(run(
        &*store,
        &namespace,
        ClockMs::from_raw(2000),
        install_filter("present".into(), prepared(&*store, b"filter body")?)
    )??);
    assert!(run(
        &*store,
        &namespace,
        ClockMs::from_raw(3000),
        remove_filter("present".into())
    )??);
    let after_delete = store.epoch_current(&namespace)?;

    assert!(matches!(
        run(
            &*store,
            &namespace,
            ClockMs::from_raw(4000),
            remove_filter("present".into())
        )?,
        Err(HandlerError::NotFound { .. })
    ));
    assert_eq!(store.epoch_current(&namespace)?, after_delete);
    drop(store);
    root.close()?;
    Ok(())
}

#[test]
fn absent_edge_delete_publishes_no_epoch() -> TestResult {
    let (store, root) = memory_store()?;
    let namespace = NamespaceRef::deterministic("edges");
    let never_stored = Kappa::sha256(b"no such edge");

    assert!(!run(
        &*store,
        &namespace,
        ClockMs::from_raw(1000),
        remove_edge(store.clone(), never_stored)
    )??);
    assert!(matches!(
        store.epoch_current(&namespace),
        Err(StoreError::NotFound(_))
    ));
    drop(store);
    root.close()?;
    Ok(())
}
