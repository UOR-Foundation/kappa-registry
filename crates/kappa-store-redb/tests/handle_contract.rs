use kappa_handler::clock_at;
use kappa_store::{Execution, KappaStore};
use kappa_store_memory::test_support;
use kappa_types::page::PageRequest;
use kappa_types::{ClockMs, HandleRecord, Kappa, NamespaceRef, ProtocolId, StoreError};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn handles(records: &kappa_types::Page<HandleRecord>) -> Vec<&str> {
    records.items.iter().map(|r| r.handle.as_str()).collect()
}

/// Publish one execution against `ns` at `at`.
fn publish(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    at: i64,
    write: impl FnOnce(&mut dyn Execution) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let mut execution = store.begin_execution(ns, &clock_at(ClockMs::from_raw(at))?)?;
    write(&mut *execution)?;
    execution.publish()?;
    Ok(())
}

/// Attest in its own execution; a stale or absent record publishes nothing.
fn attest(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    expected: &HandleRecord,
    at: i64,
) -> Result<bool, StoreError> {
    let mut execution = store.begin_execution(ns, &clock_at(ClockMs::from_raw(at))?)?;
    if execution.handle_attest(expected)? {
        execution.publish()?;
        Ok(true)
    } else {
        execution.abort()?;
        Ok(false)
    }
}

/// A rotation whose grace deadline is unrepresentable is refused inside
/// its execution, which then publishes nothing.
fn exercise_credential_overflow(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    owner: &Kappa,
) -> TestResult {
    publish(store, ns, 4, |execution| {
        execution.credential_put("overflow", owner, b"original")
    })?;
    let mut execution = store.begin_execution(ns, &clock_at(ClockMs::from_raw(5))?)?;
    assert!(
        execution
            .credential_rotate("overflow", owner, b"replacement", u64::MAX)
            .is_err()
    );
    execution.abort()?;
    let (_, secret, grace) = store.credential_get("overflow", ClockMs::from_raw(6))?;
    assert_eq!(secret, b"original");
    assert!(grace.is_none());
    Ok(())
}

fn exercise_paging(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    owner: &Kappa,
    protocol: &ProtocolId,
) -> TestResult {
    // Each publication advances the namespace epoch, whose timestamps must
    // not regress.
    for (at, handle) in (1..).zip(["z", "a", "m"]) {
        let record = HandleRecord {
            anchor: owner.clone(),
            handle: handle.into(),
            protocol: protocol.clone(),
            claimed_at_ms: 1,
            attested_at_ms: None,
        };
        // Rewriting the same record is idempotent for the index.
        publish(store, ns, at, |execution| {
            execution.handle_put(&record)?;
            execution.handle_put(&record)
        })?;
    }
    let first = store.handle_list_by_anchor(owner, &PageRequest::first(2))?;
    assert_eq!(handles(&first), ["a", "m"]);
    let second = store.handle_list_by_anchor(owner, &PageRequest::new(2, first.next_after))?;
    assert_eq!(handles(&second), ["z"]);
    assert!(second.next_after.is_none());
    let first = store.handle_list(&PageRequest::first(2))?;
    assert_eq!(handles(&first), ["a", "m"]);
    let second = store.handle_list(&PageRequest::new(2, first.next_after))?;
    assert_eq!(handles(&second), ["z"]);
    assert!(second.next_after.is_none());
    assert!(store.handle_list(&PageRequest::first(0))?.is_empty());
    assert!(
        store
            .handle_list_by_anchor(owner, &PageRequest::first(0))?
            .is_empty()
    );
    Ok(())
}

fn exercise(store: &dyn KappaStore) -> TestResult {
    let ns = NamespaceRef::deterministic("handles");
    let owner = Kappa::sha256(b"owner");
    let replacement = Kappa::sha256(b"replacement");
    let protocol = ProtocolId::new("test")?;
    exercise_paging(store, &ns, &owner, &protocol)?;
    exercise_credential_overflow(store, &ns, &owner)?;
    let mut record = store.handle_get(protocol.clone(), "a")?;
    let probed = record.clone();
    record.attested_at_ms = Some(42);
    publish(store, &ns, 10, |execution| execution.handle_put(&record))?;
    assert_eq!(
        store.handle_get(protocol.clone(), "a")?.attested_at_ms,
        Some(42)
    );
    record.anchor = replacement.clone();
    publish(store, &ns, 11, |execution| execution.handle_put(&record))?;
    assert!(!attest(store, &ns, &probed, 99)?);
    assert_eq!(store.handle_get(protocol.clone(), "a")?.anchor, replacement);
    assert!(attest(store, &ns, &record, 100)?);
    assert_eq!(
        store.handle_get(protocol.clone(), "a")?.attested_at_ms,
        Some(100)
    );
    assert_eq!(
        store
            .handle_list_by_anchor(&owner, &PageRequest::first(10))?
            .len(),
        2
    );
    assert_eq!(
        store
            .handle_list_by_anchor(&replacement, &PageRequest::first(10))?
            .len(),
        1
    );
    publish(store, &ns, 101, |execution| {
        execution.handle_delete(&protocol, "a")
    })?;
    assert!(!attest(store, &ns, &record, 102)?);
    assert!(store.handle_get(protocol, "a").is_err());
    assert!(
        store
            .handle_list_by_anchor(&replacement, &PageRequest::first(10))?
            .is_empty()
    );
    assert_eq!(store.handle_list(&PageRequest::first(10))?.len(), 2);
    Ok(())
}

#[test]
fn memory_handles_preserve_order_ownership_and_attestation() -> TestResult {
    let store = test_support::test_store()?.into_store();
    exercise(&store)
}

#[test]
fn persistent_handles_preserve_order_ownership_and_attestation() -> TestResult {
    exercise(kappa_store_redb::test_support::persistent_store()?.store())
}
