use super::*;

use kappa_handler::clock_at;
use kappa_store::axis::Axis;
use kappa_store::clock::ClockMs;
use kappa_store::{Execution, ExecutionStore, VerifiedContent};
use kappa_store_memory::{InMemoryStore, test_support};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn test_store() -> Result<InMemoryStore, Box<dyn std::error::Error>> {
    Ok(test_support::test_store()?.into_store())
}

/// Install `content` as an object in the execution and return its identity.
fn object(execution: &mut dyn Execution, content: &[u8]) -> Result<Kappa, RefError> {
    let verified = VerifiedContent::compute(Axis::Sha256, content).map_err(StoreError::from)?;
    execution.blob_put(&verified)?;
    Ok(verified.kappa().clone())
}

/// Run one execution against `ns` and publish it, returning `write`'s value.
fn publish<T>(
    store: &InMemoryStore,
    ns: &NamespaceRef,
    at: i64,
    write: impl FnOnce(&mut dyn Execution) -> Result<T, RefError>,
) -> Result<T, Box<dyn std::error::Error>> {
    let mut execution = store.begin_execution(ns, &clock_at(ClockMs::from_raw(at))?)?;
    let value = write(&mut *execution)?;
    execution.publish()?;
    Ok(value)
}

#[test]
fn create_and_resolve_ref() -> TestResult {
    let store = test_store()?;
    let ns = NamespaceRef::deterministic("repo");
    let k = publish(&store, &ns, 1, |e| {
        let k = object(e, b"commit-aaa")?;
        update_ref(e, "refs/heads/main", &k, None)?;
        Ok(k)
    })?;
    assert_eq!(resolve_ref(&store, &ns, "refs/heads/main")?, Some(k));
    Ok(())
}

#[test]
fn cas_update_ref() -> TestResult {
    let store = test_store()?;
    let ns = NamespaceRef::deterministic("repo");
    let k1 = publish(&store, &ns, 1, |e| {
        let k1 = object(e, b"commit-1")?;
        update_ref(e, "refs/heads/main", &k1, None)?;
        Ok(k1)
    })?;
    let k2 = publish(&store, &ns, 2, |e| {
        let k2 = object(e, b"commit-2")?;
        update_ref(e, "refs/heads/main", &k2, Some(&k1))?;
        Ok(k2)
    })?;
    assert_eq!(resolve_ref(&store, &ns, "refs/heads/main")?, Some(k2));
    Ok(())
}

#[test]
fn rejection_leaves_the_execution_usable() -> TestResult {
    let store = test_store()?;
    let ns = NamespaceRef::deterministic("repo");
    let wrong = Kappa::sha256(b"wrong");
    let k1 = publish(&store, &ns, 1, |e| {
        let k1 = object(e, b"commit-1")?;
        update_ref(e, "refs/heads/main", &k1, None)?;
        Ok(k1)
    })?;

    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2))?)?;
    let k2 = object(&mut *execution, b"commit-2")?;
    let stale = update_ref(&mut *execution, "refs/heads/main", &k2, Some(&wrong));
    assert!(matches!(stale, Err(RefError::UpdateRejected { .. })));
    let duplicate = update_ref(&mut *execution, "refs/heads/main", &k2, None);
    assert!(matches!(duplicate, Err(RefError::UpdateRejected { .. })));
    let missing = delete_ref(&mut *execution, "refs/heads/absent", None);
    assert!(matches!(missing, Err(RefError::NotFound(_))));
    update_ref(&mut *execution, "refs/heads/dev", &k2, None)?;
    execution.publish()?;

    assert_eq!(resolve_ref(&store, &ns, "refs/heads/main")?, Some(k1));
    assert_eq!(resolve_ref(&store, &ns, "refs/heads/dev")?, Some(k2));
    Ok(())
}

#[test]
fn symbolic_ref_resolution() -> TestResult {
    let store = test_store()?;
    let ns = NamespaceRef::deterministic("repo");
    let k = publish(&store, &ns, 1, |e| {
        let k = object(e, b"commit-sym")?;
        update_ref(e, "refs/heads/main", &k, None)?;
        set_symbolic_ref(e, "HEAD", "refs/heads/main")?;
        Ok(k)
    })?;
    assert_eq!(resolve_ref(&store, &ns, "HEAD")?, Some(k));
    Ok(())
}

#[test]
fn resolve_missing_returns_none() -> TestResult {
    let store = test_store()?;
    let ns = NamespaceRef::deterministic("repo");
    assert_eq!(resolve_ref(&store, &ns, "refs/heads/nonexistent")?, None);
    Ok(())
}

#[test]
fn list_refs_by_prefix() -> TestResult {
    let store = test_store()?;
    let ns = NamespaceRef::deterministic("repo");
    publish(&store, &ns, 1, |e| {
        let k1 = object(e, b"c1")?;
        let k2 = object(e, b"c2")?;
        let k3 = object(e, b"c3")?;
        update_ref(e, "refs/heads/main", &k1, None)?;
        update_ref(e, "refs/heads/dev", &k2, None)?;
        update_ref(e, "refs/tags/v1.0", &k3, None)
    })?;
    assert_eq!(list_refs(&store, &ns, "refs/heads/")?.len(), 2);
    assert_eq!(list_refs(&store, &ns, "refs/tags/")?.len(), 1);
    Ok(())
}

#[test]
fn delete_ref_checks_expected_value() -> TestResult {
    let store = test_store()?;
    let ns = NamespaceRef::deterministic("repo");
    let other = Kappa::sha256(b"other");
    let k = publish(&store, &ns, 1, |e| {
        let k = object(e, b"c-del")?;
        update_ref(e, "refs/heads/main", &k, None)?;
        Ok(k)
    })?;

    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2))?)?;
    let stale = delete_ref(&mut *execution, "refs/heads/main", Some(&other));
    assert!(matches!(stale, Err(RefError::UpdateRejected { .. })));
    delete_ref(&mut *execution, "refs/heads/main", Some(&k))?;
    execution.publish()?;

    assert_eq!(resolve_ref(&store, &ns, "refs/heads/main")?, None);
    Ok(())
}
