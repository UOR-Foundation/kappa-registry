use kappa_handler::clock_at;
use kappa_store::{Execution, IdentityStore, KappaStore};
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
    assert_eq!(first.next_after, Some(format!("{protocol}:m")));
    let second = store.handle_list_by_anchor(owner, &PageRequest::new(2, first.next_after))?;
    assert_eq!(handles(&second), ["z"]);
    assert!(second.next_after.is_none());
    let first = store.handle_list(&PageRequest::first(2))?;
    assert_eq!(handles(&first), ["a", "m"]);
    assert_eq!(first.next_after, Some(format!("{protocol}:m")));
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

#[test]
fn persistent_handle_discovery_survives_reopen() -> TestResult {
    let root = kappa_fixture::FixtureRoot::temporary()?;
    let spec = kappa_store_redb::test_support::PersistentSpec::new().in_root(&root);
    {
        let store = spec.clone().acquire()?;
        exercise(store.store())?;
    }
    let store = spec.acquire()?;
    let protocol = ProtocolId::new("test")?;
    let owner = Kappa::sha256(b"owner");
    assert!(matches!(
        store.handle_get(protocol.clone(), "a"),
        Err(StoreError::NotFound(_))
    ));
    assert_eq!(store.handle_get(protocol, "m")?.anchor, owner);
    let first = store.handle_list_by_anchor(&owner, &PageRequest::first(1))?;
    assert_eq!(handles(&first), ["m"]);
    assert_eq!(first.next_after.as_deref(), Some("test:m"));
    let last = store.handle_list_by_anchor(&owner, &PageRequest::new(1, first.next_after))?;
    assert_eq!(handles(&last), ["z"]);
    assert!(last.next_after.is_none());
    assert_eq!(
        handles(&store.handle_list(&PageRequest::first(10))?),
        ["m", "z"]
    );
    assert!(
        store
            .handle_list_by_anchor(&Kappa::sha256(b"replacement"), &PageRequest::first(1),)?
            .is_empty()
    );
    Ok(())
}

fn access_keys(store: &(impl KappaStore + kappa_crypto::sigv4::CredentialLookup)) -> TestResult {
    use kappa_store::identity_ops::{access_key_create, access_key_lookup, access_key_rotate};
    let ns = NamespaceRef::deterministic("access-keys");
    let owner = Kappa::sha256(b"access-key-owner");
    let (id, secret) = kappa_crypto::sigv4::generate_access_key()?;
    assert!(id.starts_with("KAPPA"));
    assert!(access_key_lookup(store, &id, ClockMs::from_raw(0)).is_err());
    assert!(matches!(
        store.lookup_credential(&id, ClockMs::from_raw(0)),
        Err(StoreError::NotFound(_))
    ));
    publish(store, &ns, 1, |execution| {
        access_key_create(execution, &owner, id.clone(), secret.clone()).map(|_| ())
    })?;
    let current = access_key_lookup(store, &id, ClockMs::from_raw(2))?;
    assert_eq!(current.current_secret.as_str(), secret);
    assert_eq!(current.principal_anchor, owner);
    assert_eq!(
        store
            .lookup_credential(&id, ClockMs::from_raw(2))?
            .current_secret
            .as_str(),
        secret
    );
    assert!(current.previous_secret.is_none());
    let mut duplicate = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(3))?)?;
    assert!(matches!(
        access_key_create(&mut *duplicate, &owner, id.clone(), "overwrite".into()),
        Err(StoreError::AlreadyExists(_))
    ));
    duplicate.abort()?;
    publish(store, &ns, 4, |execution| {
        access_key_rotate(execution, &id, &owner, "replacement".into(), 50).map(|_| ())
    })?;
    let rotated = access_key_lookup(store, &id, ClockMs::from_raw(5))?;
    assert_eq!(rotated.current_secret.as_str(), "replacement");
    assert_eq!(
        rotated.previous_secret.as_ref().map(|s| s.as_str()),
        Some(secret.as_str())
    );
    let (_, _, grace) = store.credential_get(&id, ClockMs::from_raw(5))?;
    let deadline = grace.ok_or("rotation omitted grace")?.1;
    assert!(
        access_key_lookup(store, &id, ClockMs::from_raw(deadline))?
            .previous_secret
            .is_none()
    );
    publish(store, &ns, 6, |execution| execution.credential_delete(&id))?;
    assert!(access_key_lookup(store, &id, ClockMs::from_raw(7)).is_err());
    publish(store, &ns, 8, |execution| {
        execution.credential_put("malformed-access-key", &owner, b"invalid credential")
    })?;
    let failure = store.lookup_credential("malformed-access-key", ClockMs::from_raw(9));
    assert!(failure.is_err());
    assert!(
        !matches!(failure, Err(StoreError::NotFound(_))),
        "corruption must not become an absent credential"
    );
    Ok(())
}

#[test]
fn access_key_lifecycle_uses_governed_credentials_on_both_backends() -> TestResult {
    access_keys(&test_support::test_store()?.into_store())?;
    access_keys(kappa_store_redb::test_support::persistent_store()?.store())
}

fn private_authorization_reads(store: &dyn KappaStore) -> TestResult {
    use kappa_store::identity_ops::{access_key_create, access_key_lookup, access_key_rotate};
    let clock = clock_at(ClockMs::from_raw(1))?;
    let owner = Kappa::sha256(b"private-owner");
    let ns =
        kappa_store::namespace_ensure(store, "private-authorization", Some(&owner), None, &clock)?;
    let mut execution = store.begin_execution(&ns, &clock)?;
    execution.session_put("private-token", &owner, i64::MAX, b"first")?;
    assert_eq!(
        execution.session_get("private-token")?,
        Some((owner.clone(), b"first".to_vec()))
    );
    execution.session_put("private-token", &owner, i64::MAX, b"replacement")?;
    assert_eq!(
        execution.session_get("private-token")?,
        Some((owner.clone(), b"replacement".to_vec()))
    );
    execution.session_delete("private-token")?;
    assert!(execution.session_get("private-token")?.is_none());
    access_key_create(
        &mut *execution,
        &owner,
        "private-access".into(),
        "first-secret".into(),
    )?;
    access_key_rotate(
        &mut *execution,
        "private-access",
        &owner,
        "second-secret".into(),
        50,
    )?;
    let (_, bytes, grace) = execution
        .credential_get("private-access")?
        .ok_or("missing private credential")?;
    let credential: kappa_types::authorization::AccessCredential =
        kappa_types::canonical::from_canonical(&bytes)?;
    assert_eq!(credential.secret_access_key, "second-secret");
    assert!(grace.is_some());
    execution.publish()?;
    let credential = access_key_lookup(store, "private-access", ClockMs::from_raw(2))?;
    assert_eq!(credential.current_secret.as_str(), "second-secret");
    assert_eq!(
        credential
            .previous_secret
            .as_deref()
            .map(|secret| secret.as_str()),
        Some("first-secret")
    );
    assert!(
        store
            .session_get("private-token", ClockMs::from_raw(2))
            .is_err()
    );
    Ok(())
}

#[test]
fn authorization_reads_observe_private_writes_on_both_backends() -> TestResult {
    private_authorization_reads(&test_support::test_store()?.into_store())?;
    private_authorization_reads(kappa_store_redb::test_support::persistent_store()?.store())
}
