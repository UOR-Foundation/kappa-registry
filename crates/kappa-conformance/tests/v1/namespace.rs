//! Namespace conformance: create/resolve/delete/rename/transfer
//! through executions, protocol isolation, alias cap, pagination,
//! tombstone filtering, metadata CRUD, namespace_ensure.

use kappa_handler::clock_at;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::{NamespaceRef, ProtocolId};
use kappa_store::page::{MAX_ALIASES_PER_NAMESPACE, NamespaceFilter, PageRequest};
use kappa_store::{Execution, ExecutionStore, NamespaceStore, namespace_ensure};

use super::support::{MemoryFixture, TestResult, create_ns, publish, test_now};

fn pid(s: &str) -> Result<ProtocolId, kappa_store::namespace::InvalidProtocolId> {
    ProtocolId::new(s)
}

fn create_with_protocol(
    f: &MemoryFixture,
    name: &str,
    protocol: &ProtocolId,
) -> Result<NamespaceRef, kappa_store::StoreError> {
    let ns = NamespaceRef::generate(name, test_now())?.with_protocol(protocol.clone());
    let mut execution = f.store.begin_execution(&ns, &clock_at(test_now())?)?;
    execution.namespace_create(None, Some(protocol))?;
    execution.publish()?;
    Ok(ns)
}

fn everything() -> PageRequest {
    PageRequest {
        limit: 100,
        after: None,
    }
}

#[test]
fn create_and_resolve() -> TestResult {
    let f = MemoryFixture::new()?;
    let oci = pid("oci")?;
    let ns = create_with_protocol(&f, "myrepo", &oci)?;
    let resolved = f.store.namespace_resolve("myrepo", Some(&oci))?;
    assert_eq!(ns, resolved);
    Ok(())
}

#[test]
fn resolve_not_found() -> TestResult {
    let f = MemoryFixture::new()?;
    assert!(f.store.namespace_resolve("missing", None).is_err());
    Ok(())
}

#[test]
fn ensure_creates_missing() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = namespace_ensure(&f.store, "new", None, None, &clock_at(test_now())?)?;
    assert_eq!(ns.display_name(), "new");
    assert_eq!(f.store.namespace_resolve("new", None)?, ns);
    Ok(())
}

#[test]
fn ensure_resolves_existing() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns1 = create_ns(&f.store, "repo")?;
    let ns2 = namespace_ensure(&f.store, "repo", None, None, &clock_at(test_now())?)?;
    assert_eq!(ns1, ns2);
    Ok(())
}

#[test]
fn exists_true_after_create() -> TestResult {
    let f = MemoryFixture::new()?;
    create_ns(&f.store, "test")?;
    assert!(f.store.namespace_exists("test", None)?);
    Ok(())
}

#[test]
fn exists_false_before_create() -> TestResult {
    let f = MemoryFixture::new()?;
    assert!(!f.store.namespace_exists("missing", None)?);
    Ok(())
}

#[test]
fn protocol_isolation() -> TestResult {
    let f = MemoryFixture::new()?;
    let oci = pid("oci")?;
    let s3 = pid("s3")?;
    create_with_protocol(&f, "shared", &oci)?;
    create_with_protocol(&f, "shared", &s3)?;
    let oci_ns = f.store.namespace_resolve("shared", Some(&oci))?;
    let s3_ns = f.store.namespace_resolve("shared", Some(&s3))?;
    assert_ne!(oci_ns, s3_ns);
    Ok(())
}

#[test]
fn info_returns_metadata() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "infotest")?;
    let info = f.store.namespace_info(&ns)?;
    assert_eq!(info.name, "infotest");
    assert!(!info.tombstoned);
    assert_eq!(info.last_epoch, 0);
    Ok(())
}

#[test]
fn list_returns_all() -> TestResult {
    let f = MemoryFixture::new()?;
    create_ns(&f.store, "a")?;
    create_ns(&f.store, "b")?;
    let page = f
        .store
        .namespace_list(&NamespaceFilter::default(), &everything())?;
    assert!(page.items.len() >= 2);
    Ok(())
}

#[test]
fn list_filters_by_protocol() -> TestResult {
    let f = MemoryFixture::new()?;
    let oci = pid("oci")?;
    let git = pid("git")?;
    create_with_protocol(&f, "oci-only", &oci)?;
    create_with_protocol(&f, "git-only", &git)?;
    let page = f.store.namespace_list(
        &NamespaceFilter {
            protocol: Some(oci.clone()),
            ..Default::default()
        },
        &everything(),
    )?;
    assert!(page.items.iter().all(|i| i.protocol.as_ref() == Some(&oci)));
    Ok(())
}

#[test]
fn delete_tombstones() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "delme")?;
    publish(&f.store, &ns, |ex| ex.namespace_delete())?;
    assert!(!f.store.namespace_exists("delme", None)?);
    Ok(())
}

#[test]
fn list_excludes_tombstoned() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "gone")?;
    create_ns(&f.store, "alive")?;
    publish(&f.store, &ns, |ex| ex.namespace_delete())?;
    let page = f
        .store
        .namespace_list(&NamespaceFilter::default(), &everything())?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].name, "alive");
    Ok(())
}

#[test]
fn namespace_meta_roundtrip() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "metameta")?;
    publish(&f.store, &ns, |ex| {
        ex.namespace_put_meta("policy", b"{\"allow\": true}")
    })?;
    let data = f.store.namespace_get_meta(&ns, "policy")?;
    assert_eq!(data, b"{\"allow\": true}");
    Ok(())
}

#[test]
fn namespace_meta_not_found() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "nometa")?;
    assert!(f.store.namespace_get_meta(&ns, "missing").is_err());
    Ok(())
}

#[test]
fn deterministic_produces_same_uuid() {
    let a = NamespaceRef::deterministic("_root");
    let b = NamespaceRef::deterministic("_root");
    assert_eq!(a, b);
    assert_eq!(a.uuid_hex(), b.uuid_hex());
}

#[test]
fn deterministic_different_names_different_uuids() {
    let a = NamespaceRef::deterministic("_root");
    let b = NamespaceRef::deterministic("_nix");
    assert_ne!(a, b);
}

#[test]
fn last_epoch_initialized_zero() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "epoch-test")?;
    let info = f.store.namespace_info(&ns)?;
    assert_eq!(info.last_epoch, 0);
    Ok(())
}

#[test]
fn alias_cap_enforced() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "capped")?;
    // The primary name is the first alias.
    publish(&f.store, &ns, |ex| {
        for index in 1..MAX_ALIASES_PER_NAMESPACE {
            ex.namespace_add_alias(&format!("alias-{index}"), None)?;
        }
        Ok(())
    })?;
    let mut execution: Box<dyn Execution + '_> =
        f.store.begin_execution(&ns, &clock_at(test_now())?)?;
    let result = execution.namespace_add_alias("one-too-many", None);
    assert!(result.is_err());
    execution.abort()?;
    Ok(())
}

#[test]
fn list_pagination_cursor() -> TestResult {
    let f = MemoryFixture::new()?;
    for name in ["alpha", "bravo", "charlie", "delta", "echo"] {
        create_ns(&f.store, name)?;
    }
    let page1 = f.store.namespace_list(
        &NamespaceFilter::default(),
        &PageRequest {
            limit: 2,
            after: None,
        },
    )?;
    assert_eq!(page1.items.len(), 2);
    assert!(page1.next_after.is_some());
    let page2 = f.store.namespace_list(
        &NamespaceFilter::default(),
        &PageRequest {
            limit: 2,
            after: page1.next_after.clone(),
        },
    )?;
    assert_eq!(page2.items.len(), 2);
    let page3 = f.store.namespace_list(
        &NamespaceFilter::default(),
        &PageRequest {
            limit: 2,
            after: page2.next_after.clone(),
        },
    )?;
    assert_eq!(page3.items.len(), 1);
    assert!(page3.next_after.is_none());
    let all_names: Vec<&str> = page1
        .items
        .iter()
        .chain(page2.items.iter())
        .chain(page3.items.iter())
        .map(|i| i.name.as_str())
        .collect();
    assert_eq!(
        all_names,
        vec!["alpha", "bravo", "charlie", "delta", "echo"]
    );
    Ok(())
}

#[test]
fn create_with_owner_preserves_anchor() -> TestResult {
    let f = MemoryFixture::new()?;
    let owner = Kappa::sha256(b"owner-key");
    let ns = NamespaceRef::generate("owned", test_now())?;
    let mut execution = f.store.begin_execution(&ns, &clock_at(test_now())?)?;
    execution.namespace_create(Some(&owner), None)?;
    execution.publish()?;
    let info = f.store.namespace_info(&ns)?;
    assert_eq!(info.owner_anchor, Some(owner));
    Ok(())
}
