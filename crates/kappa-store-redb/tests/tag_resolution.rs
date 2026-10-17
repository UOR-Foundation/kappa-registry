use kappa_handler::clock_at;
use kappa_store::{Execution, KappaStore, NamespaceRef};
use kappa_store_memory::test_support;
use kappa_types::{ClockMs, Kappa, StoreError, TagUpdate};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Publish one execution against `ns`.
fn publish(
    store: &impl KappaStore,
    ns: &NamespaceRef,
    write: impl FnOnce(&mut dyn Execution) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let mut execution = store.begin_execution(ns, &clock_at(ClockMs::from_raw(1000))?)?;
    write(&mut *execution)?;
    execution.publish()?;
    Ok(())
}

fn exercise(store: &impl KappaStore) -> TestResult {
    let ns = NamespaceRef::generate("refs", ClockMs::from_raw(1000))?;
    let target = Kappa::sha256(b"target content");
    publish(store, &ns, |execution| {
        execution.namespace_create(None, None)?;
        execution.tag_put(
            "refs/heads/main",
            &TagUpdate::Set {
                kappa: target.clone(),
            },
        )?;
        execution.tag_put(
            "HEAD",
            &TagUpdate::SetSymref {
                target: "refs/heads/main".into(),
            },
        )
    })?;
    let resolved = store.tag_get(&ns, "HEAD")?;
    assert_eq!(resolved.name, "HEAD");
    assert_eq!(resolved.kappa, target);
    assert!(resolved.symref.is_none());
    rejected_batch(store, &ns, &target)?;
    broken_references(store, &ns)
}

/// A batch with a rejected member publishes nothing: no tag changes, no
/// state change, and no epoch.
fn rejected_batch(store: &impl KappaStore, ns: &NamespaceRef, target: &Kappa) -> TestResult {
    let before = store.epoch_state(ns)?;
    let baseline = store.epoch_current(ns)?;
    let original = kappa_store::canonical::canonical_bytes(&store.tag_get_raw(ns, "HEAD")?);
    let mut execution = store.begin_execution(ns, &clock_at(ClockMs::from_raw(1001))?)?;
    let failure = execution.tag_batch_update(&[
        (
            "HEAD".into(),
            TagUpdate::Set {
                kappa: Kappa::sha256(b"replacement"),
            },
        ),
        (
            "refs/heads/main".into(),
            TagUpdate::CompareAndSwap {
                kappa: Kappa::sha256(b"rejected"),
                expected_version: 999,
            },
        ),
    ]);
    assert!(matches!(
        failure,
        Err(StoreError::VersionMismatch {
            expected: 999,
            found: 1,
            ..
        })
    ));
    // The failed member latches the execution; it cannot publish.
    assert!(execution.publish().is_err());
    assert_eq!(store.epoch_state(ns)?, before);
    assert_eq!(store.epoch_current(ns)?, baseline);
    assert_eq!(
        kappa_store::canonical::canonical_bytes(&store.tag_get_raw(ns, "HEAD")?),
        original
    );
    assert_eq!(&store.tag_get(ns, "HEAD")?.kappa, target);
    assert_eq!(
        store.tag_get_raw(ns, "HEAD")?.symref.as_deref(),
        Some("refs/heads/main")
    );
    Ok(())
}

fn broken_references(store: &impl KappaStore, ns: &NamespaceRef) -> TestResult {
    publish(store, ns, |execution| {
        execution.tag_put(
            "refs/heads/main",
            &TagUpdate::SetSymref {
                target: "HEAD".into(),
            },
        )
    })?;
    assert!(matches!(
        store.tag_get(ns, "HEAD"),
        Err(StoreError::Rejected(_))
    ));
    publish(store, ns, |execution| {
        execution.tag_delete("refs/heads/main")
    })?;
    assert!(matches!(
        store.tag_get(ns, "HEAD"),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

#[test]
fn memory_uses_shared_resolution_contract() -> TestResult {
    let store = test_support::test_store()?.into_store();
    exercise(&store)
}

#[test]
fn redb_uses_shared_resolution_contract() -> TestResult {
    exercise(kappa_store_redb::test_support::persistent_store()?.store())
}
