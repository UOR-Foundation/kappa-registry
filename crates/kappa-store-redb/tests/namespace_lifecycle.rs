//! Namespace lifecycle through the public contract: creation and alias
//! admission, resolution, rename, transfer, aliases and the alias cap,
//! deletion, listing, and metadata.

use kappa_fixture::SetupError;
use kappa_handler::clock_at;
use kappa_store::clock::ClockMs;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::{NamespaceRef, ProtocolId};
use kappa_store::page::{MAX_ALIASES_PER_NAMESPACE, NamespaceFilter, PageRequest};
use kappa_store::{Execution, ExecutionStore, NamespaceStore, StoreError, namespace_ensure};
use kappa_store_redb::PersistentStore;
use kappa_store_redb::test_support::PersistentSpec;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A store retaining its own scope.
fn test_store() -> Result<PersistentStore, SetupError> {
    Ok(PersistentSpec::new()
        .db_file("test.redb")
        .acquire()?
        .into_store())
}

const fn test_now() -> ClockMs {
    ClockMs::from_raw(1000)
}

fn pid(s: &str) -> Result<ProtocolId, kappa_store::namespace::InvalidProtocolId> {
    ProtocolId::new(s)
}

/// Create `name` within `protocol` in its own published execution.
fn create(
    store: &PersistentStore,
    name: &str,
    owner: Option<&Kappa>,
    protocol: Option<&ProtocolId>,
) -> Result<NamespaceRef, StoreError> {
    let generated = NamespaceRef::generate(name, test_now())?;
    let ns = match protocol {
        Some(protocol) => generated.with_protocol(protocol.clone()),
        None => generated,
    };
    let mut execution = store.begin_execution(&ns, &clock_at(test_now())?)?;
    execution.namespace_create(owner, protocol)?;
    execution.publish()?;
    Ok(ns)
}

/// Publish one execution against `ns`.
fn publish(
    store: &PersistentStore,
    ns: &NamespaceRef,
    write: impl FnOnce(&mut dyn Execution) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let mut execution = store.begin_execution(ns, &clock_at(test_now())?)?;
    write(&mut *execution)?;
    execution.publish()?;
    Ok(())
}

const fn everything() -> PageRequest {
    PageRequest {
        limit: 100,
        after: None,
    }
}

#[test]
fn create_and_resolve() -> TestResult {
    let store = test_store()?;
    let git = pid("git")?;
    let ns = create(&store, "myorg/repo", None, Some(&git))?;
    let resolved = store.namespace_resolve("myorg/repo", Some(&git))?;
    assert_eq!(ns, resolved);
    assert_eq!(resolved.display_name(), "myorg/repo");
    Ok(())
}

#[test]
fn create_conflict() -> TestResult {
    let store = test_store()?;
    let oci = pid("oci")?;
    create(&store, "repo", None, Some(&oci))?;
    let result = create(&store, "repo", None, Some(&oci));
    assert!(matches!(result, Err(StoreError::Conflict(_))));
    Ok(())
}

#[test]
fn cross_protocol_collision_global_blocks_scoped() -> TestResult {
    let store = test_store()?;
    let git = pid("git")?;
    create(&store, "shared", None, None)?;
    let result = create(&store, "shared", None, Some(&git));
    assert!(matches!(result, Err(StoreError::Conflict(_))));
    Ok(())
}

#[test]
fn different_protocols_no_collision() -> TestResult {
    let store = test_store()?;
    let git = pid("git")?;
    let oci = pid("oci")?;
    create(&store, "repo", None, Some(&git))?;
    create(&store, "repo", None, Some(&oci))?;
    Ok(())
}

#[test]
fn ensure_resolves_an_existing_namespace() -> TestResult {
    let store = test_store()?;
    let ns1 = create(&store, "repo", None, None)?;
    let ns2 = namespace_ensure(&store, "repo", None, None, &clock_at(test_now())?)?;
    assert_eq!(ns1, ns2);
    Ok(())
}

#[test]
fn ensure_creates_and_publishes_a_missing_namespace() -> TestResult {
    let store = test_store()?;
    let ns = namespace_ensure(&store, "new", None, None, &clock_at(test_now())?)?;
    assert_eq!(ns.display_name(), "new");
    assert_eq!(store.namespace_resolve("new", None)?, ns);
    assert_eq!(kappa_store::EpochStore::epoch_current(&store, &ns)?.0, 1);
    Ok(())
}

#[test]
fn exists_true_and_false() -> TestResult {
    let store = test_store()?;
    assert!(!store.namespace_exists("repo", None)?);
    create(&store, "repo", None, None)?;
    assert!(store.namespace_exists("repo", None)?);
    Ok(())
}

#[test]
fn delete_removes_aliases() -> TestResult {
    let store = test_store()?;
    let ns = create(&store, "repo", None, None)?;
    publish(&store, &ns, |execution| execution.namespace_delete())?;
    assert!(store.namespace_resolve("repo", None).is_err());
    let list = store.namespace_list(&NamespaceFilter::default(), &everything())?;
    assert!(list.items.is_empty());
    Ok(())
}

#[test]
fn rename_updates_all_tables() -> TestResult {
    let store = test_store()?;
    create(&store, "old", None, None)?;
    let ns = store.namespace_resolve("old", None)?;
    publish(&store, &ns, |execution| execution.namespace_rename("new"))?;
    assert!(store.namespace_resolve("old", None).is_err());
    let ns = store.namespace_resolve("new", None)?;
    let info = store.namespace_info(&ns)?;
    assert_eq!(info.name, "new");
    assert!(info.aliases.contains(&"new".to_string()));
    assert!(!info.aliases.contains(&"old".to_string()));
    Ok(())
}

#[test]
fn transfer_updates_owner() -> TestResult {
    let store = test_store()?;
    let owner = Kappa::sha256(b"owner1");
    let ns = create(&store, "repo", Some(&owner), None)?;
    let new_owner = Kappa::sha256(b"owner2");
    publish(&store, &ns, |execution| {
        execution.namespace_transfer(&new_owner)
    })?;
    let info = store.namespace_info(&ns)?;
    assert_eq!(info.owner_anchor, Some(new_owner));
    Ok(())
}

#[test]
fn add_alias_creates_secondary_name() -> TestResult {
    let store = test_store()?;
    let ns = create(&store, "primary", None, None)?;
    publish(&store, &ns, |execution| {
        execution.namespace_add_alias("secondary", None)
    })?;
    let resolved = store.namespace_resolve("secondary", None)?;
    assert_eq!(ns, resolved);
    Ok(())
}

#[test]
fn alias_cap_rejects_the_alias_beyond_the_limit() -> TestResult {
    let store = test_store()?;
    let ns = create(&store, "capped", None, None)?;
    // The primary name is the first alias.
    publish(&store, &ns, |execution| {
        for index in 1..MAX_ALIASES_PER_NAMESPACE {
            execution.namespace_add_alias(&format!("alias-{index}"), None)?;
        }
        Ok(())
    })?;
    assert_eq!(
        store.namespace_info(&ns)?.aliases.len(),
        MAX_ALIASES_PER_NAMESPACE
    );
    let mut execution = store.begin_execution(&ns, &clock_at(test_now())?)?;
    assert!(matches!(
        execution.namespace_add_alias("one-too-many", None),
        Err(StoreError::Rejected(_))
    ));
    execution.abort()?;
    assert!(store.namespace_resolve("one-too-many", None).is_err());
    Ok(())
}

#[test]
fn list_ordered_by_name() -> TestResult {
    let store = test_store()?;
    for name in ["charlie", "alpha", "bravo"] {
        create(&store, name, None, None)?;
    }
    let list = store.namespace_list(&NamespaceFilter::default(), &everything())?;
    let names: Vec<&str> = list.items.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, vec!["alpha", "bravo", "charlie"]);
    Ok(())
}

#[test]
fn list_with_limit() -> TestResult {
    let store = test_store()?;
    for name in ["a", "b", "c"] {
        create(&store, name, None, None)?;
    }
    let list = store.namespace_list(
        &NamespaceFilter::default(),
        &PageRequest {
            limit: 2,
            after: None,
        },
    )?;
    assert_eq!(list.items.len(), 2);
    assert!(list.next_after.is_some());
    Ok(())
}

#[test]
fn list_with_protocol_filter() -> TestResult {
    let store = test_store()?;
    let git = pid("git")?;
    let oci = pid("oci")?;
    create(&store, "git-repo", None, Some(&git))?;
    create(&store, "oci-repo", None, Some(&oci))?;
    let list = store.namespace_list(
        &NamespaceFilter {
            protocol: Some(git),
            ..Default::default()
        },
        &everything(),
    )?;
    assert_eq!(list.items.len(), 1);
    assert_eq!(list.items[0].name, "git-repo");
    Ok(())
}

#[test]
fn list_excludes_tombstoned() -> TestResult {
    let store = test_store()?;
    let ns = create(&store, "gone", None, None)?;
    create(&store, "alive", None, None)?;
    publish(&store, &ns, |execution| execution.namespace_delete())?;
    let list = store.namespace_list(&NamespaceFilter::default(), &everything())?;
    assert_eq!(list.items.len(), 1);
    assert_eq!(list.items[0].name, "alive");
    Ok(())
}

#[test]
fn list_pagination_cursor() -> TestResult {
    let store = test_store()?;
    for name in ["a", "b", "c"] {
        create(&store, name, None, None)?;
    }
    let page1 = store.namespace_list(
        &NamespaceFilter::default(),
        &PageRequest {
            limit: 2,
            after: None,
        },
    )?;
    assert_eq!(page1.items.len(), 2);
    let page2 = store.namespace_list(
        &NamespaceFilter::default(),
        &PageRequest {
            limit: 2,
            after: page1.next_after,
        },
    )?;
    assert_eq!(page2.items.len(), 1);
    assert_eq!(page2.items[0].name, "c");
    assert!(page2.next_after.is_none());
    Ok(())
}

#[test]
fn config_roundtrip() -> TestResult {
    let store = test_store()?;
    let ns = create(&store, "repo", None, None)?;
    publish(&store, &ns, |execution| {
        execution.namespace_put_meta("policy", b"allow-all")
    })?;
    let val = store.namespace_get_meta(&ns, "policy")?;
    assert_eq!(val, b"allow-all");
    Ok(())
}

#[test]
fn config_not_found() -> TestResult {
    let store = test_store()?;
    let ns = create(&store, "repo", None, None)?;
    assert!(matches!(
        store.namespace_get_meta(&ns, "missing"),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

#[test]
fn creation_record_precedes_its_publishing_epoch() -> TestResult {
    let store = test_store()?;
    let ns = create(&store, "repo", None, None)?;
    // The namespace record is ledger evidence committed by the epoch that
    // publishes it, so it cannot name that epoch: it carries 0 while the
    // epoch chain reports the creating publication as epoch 1.
    assert_eq!(store.namespace_info(&ns)?.last_epoch, 0);
    assert_eq!(kappa_store::EpochStore::epoch_current(&store, &ns)?.0, 1);
    Ok(())
}
