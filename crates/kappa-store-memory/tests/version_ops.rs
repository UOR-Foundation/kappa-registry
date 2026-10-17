//! Versioning composed over executions on the memory backend.

use kappa_handler::clock_at;
use kappa_store::traits::{edge::EdgeStore, epoch::EpochStore, tag::TagStore};
use kappa_store::version_ops::{
    version_delete_with_marker, version_evict_old, version_get_by_id, version_get_latest,
    version_list_entries, version_put_entry, versioning_get, versioning_put,
};
use kappa_store::{Execution, ExecutionStore, namespace_ensure};
use kappa_store_memory::{InMemoryStore, test_support};
use kappa_types::clock::ClockMs;
use kappa_types::edge::{Direction, EdgeQuery, EdgeRelation, SemanticRelation, semantic};
use kappa_types::tag::TagUpdate;
use kappa_types::versioning::VersioningState;
use kappa_types::{Kappa, NamespaceRef, PageRequest, StoreError, VerifiedContent};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    store: InMemoryStore,
    ns: NamespaceRef,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let store = test_support::test_store()?.into_store();
        let ns = namespace_ensure(&store, "version-ops-test", None, None, &clock_at(at(1000))?)?;
        Ok(Self { store, ns })
    }

    /// Run `write` in one execution at `now` and publish it.
    fn publish<T>(
        &self,
        now: ClockMs,
        write: impl FnOnce(&InMemoryStore, &mut dyn Execution) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut execution = self.store.begin_execution(&self.ns, &clock_at(now)?)?;
        let value = write(&self.store, &mut *execution)?;
        execution.publish()?;
        Ok(value)
    }

    fn enable(&self, state: VersioningState) -> Result<(), StoreError> {
        self.publish(at(1500), |_, execution| versioning_put(execution, state))
    }

    /// Install content and record it as the next version of `key`, in one
    /// published execution.
    fn put(&self, key: &str, content: &[u8], now: ClockMs) -> Result<(Kappa, String), StoreError> {
        let verified = VerifiedContent::compute(kappa_types::Axis::Sha256, content)?;
        let kappa = verified.kappa().clone();
        let asserter = Kappa::sha256(b"test-asserter");
        let version = self.publish(now, |store, execution| {
            execution.blob_put(&verified)?;
            version_put_entry(store, execution, key, &kappa, &asserter)
        })?;
        Ok((kappa, version))
    }
}

const fn at(ms: i64) -> ClockMs {
    ClockMs::from_raw(ms)
}

#[test]
fn disabled_stores_tag_only() -> TestResult {
    let f = Fixture::new()?;
    let (kappa, vid) = f.put("my-key", b"content", at(2000))?;
    assert_eq!(vid, "null");
    assert_eq!(f.store.tag_get(&f.ns, "my-key")?.kappa, kappa);
    assert!(version_list_entries(&f.store, &f.ns, "my-key")?.is_empty());
    Ok(())
}

#[test]
fn versioning_state_publishes_and_reads_back() -> TestResult {
    let f = Fixture::new()?;
    assert_eq!(versioning_get(&f.store, &f.ns)?, VersioningState::Disabled);
    f.enable(VersioningState::Suspended)?;
    assert_eq!(versioning_get(&f.store, &f.ns)?, VersioningState::Suspended);
    Ok(())
}

#[test]
fn enabled_creates_entry_and_edge() -> TestResult {
    let f = Fixture::new()?;
    f.enable(VersioningState::Enabled)?;
    let (k1, vid1) = f.put("obj", b"version 1", at(3000))?;
    assert_ne!(vid1, "null");
    let (k2, vid2) = f.put("obj", b"version 2", at(4000))?;
    assert_ne!(vid2, vid1);

    let versions = version_list_entries(&f.store, &f.ns, "obj")?;
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].kappa, k2);
    assert_eq!(versions[1].kappa, k1);

    let edges = f.store.edge_query(
        &f.ns,
        &EdgeQuery {
            anchor: k2,
            direction: Direction::Outbound,
            relation: Some(EdgeRelation::Semantic(SemanticRelation(
                semantic::DERIVED_FROM.into(),
            ))),
            asserter: None,
        },
        &PageRequest::first(10),
    )?;
    assert_eq!(edges.items.len(), 1);
    assert_eq!(edges.items[0].input.target, k1);
    assert!(edges.next_after.is_none());
    Ok(())
}

#[test]
fn get_latest_skips_delete_markers() -> TestResult {
    let f = Fixture::new()?;
    f.enable(VersioningState::Enabled)?;
    let (kappa, _) = f.put("obj", b"content", at(5000))?;
    f.publish(at(6000), |store, execution| {
        version_delete_with_marker(store, execution, "obj", None)
    })?;

    let versions = version_list_entries(&f.store, &f.ns, "obj")?;
    assert_eq!(versions.len(), 2);
    assert!(versions[0].is_delete_marker);
    assert!(!versions[1].is_delete_marker);

    let latest = version_get_latest(&f.store, &f.ns, "obj")?;
    assert_eq!(latest.kappa, kappa);
    assert!(!latest.is_delete_marker);
    Ok(())
}

#[test]
fn get_latest_not_found_when_all_markers() -> TestResult {
    let f = Fixture::new()?;
    f.enable(VersioningState::Enabled)?;
    f.publish(at(7000), |store, execution| {
        version_delete_with_marker(store, execution, "obj", None)
    })?;
    let result = version_get_latest(&f.store, &f.ns, "obj");
    assert!(matches!(result, Err(StoreError::NotFound(msg)) if msg.contains("delete marker")));
    Ok(())
}

#[test]
fn get_by_id_finds_specific() -> TestResult {
    let f = Fixture::new()?;
    f.enable(VersioningState::Enabled)?;
    let (kappa, vid) = f.put("obj", b"specific", at(8000))?;
    let entry = version_get_by_id(&f.store, &f.ns, "obj", &vid)?;
    assert_eq!(entry.kappa, kappa);
    assert_eq!(entry.version_id, vid);
    Ok(())
}

#[test]
fn get_by_id_not_found() -> TestResult {
    let f = Fixture::new()?;
    f.enable(VersioningState::Enabled)?;
    let result = version_get_by_id(&f.store, &f.ns, "obj", "nonexistent");
    assert!(matches!(result, Err(StoreError::NotFound(_))));
    Ok(())
}

#[test]
fn delete_disabled_deletes_tag() -> TestResult {
    let f = Fixture::new()?;
    let kappa = Kappa::sha256(b"to-delete");
    f.publish(at(9000), |_, execution| {
        execution.blob_put(&VerifiedContent::verify(&kappa, b"to-delete")?)?;
        execution.tag_put("key", &TagUpdate::Set { kappa })
    })?;

    let result = f.publish(at(9000), |store, execution| {
        version_delete_with_marker(store, execution, "key", None)
    })?;
    assert!(!result.is_delete_marker);
    assert!(result.version_id.is_none());
    assert!(matches!(
        f.store.tag_get(&f.ns, "key"),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

#[test]
fn delete_disabled_of_absent_key_writes_nothing() -> TestResult {
    let f = Fixture::new()?;
    let before = f.store.epoch_state(&f.ns)?;
    let result = f.publish(at(9500), |store, execution| {
        version_delete_with_marker(store, execution, "absent", None)
    })?;
    assert!(!result.is_delete_marker);
    assert_eq!(f.store.epoch_state(&f.ns)?, before);
    Ok(())
}

#[test]
fn delete_enabled_creates_marker() -> TestResult {
    let f = Fixture::new()?;
    f.enable(VersioningState::Enabled)?;
    f.put("key", b"versioned", at(10_000))?;
    let result = f.publish(at(11_000), |store, execution| {
        version_delete_with_marker(store, execution, "key", None)
    })?;
    assert!(result.is_delete_marker);
    assert!(result.version_id.is_some());

    let versions = version_list_entries(&f.store, &f.ns, "key")?;
    assert_eq!(versions.len(), 2);
    assert!(versions[0].is_delete_marker);
    Ok(())
}

#[test]
fn delete_specific_version() -> TestResult {
    let f = Fixture::new()?;
    f.enable(VersioningState::Enabled)?;
    let result = f.publish(at(12_000), |store, execution| {
        version_delete_with_marker(store, execution, "key", None)
    })?;
    let marker_id = result
        .version_id
        .ok_or("delete marker missing version ID")?;
    assert_eq!(version_list_entries(&f.store, &f.ns, "key")?.len(), 1);

    let del = f.publish(at(13_000), |store, execution| {
        version_delete_with_marker(store, execution, "key", Some(&marker_id))
    })?;
    assert!(del.is_delete_marker);
    assert!(version_list_entries(&f.store, &f.ns, "key")?.is_empty());
    Ok(())
}

#[test]
fn evict_keeps_latest() -> TestResult {
    let f = Fixture::new()?;
    f.enable(VersioningState::Enabled)?;
    for i in 0..5u64 {
        let now = at(i64::try_from(20_000 + i * 1000)?);
        f.put("obj", format!("version {i}").as_bytes(), now)?;
    }
    assert_eq!(version_list_entries(&f.store, &f.ns, "obj")?.len(), 5);

    let evicted = f.publish(at(30_000), |store, execution| {
        version_evict_old(store, execution, "obj", 2)
    })?;
    assert_eq!(evicted, 3);
    assert_eq!(version_list_entries(&f.store, &f.ns, "obj")?.len(), 2);
    Ok(())
}

#[test]
fn evict_no_op_when_under_limit() -> TestResult {
    let f = Fixture::new()?;
    f.enable(VersioningState::Enabled)?;
    f.put("obj", b"only-one", at(40_000))?;
    let evicted = f.publish(at(40_000), |store, execution| {
        version_evict_old(store, execution, "obj", 5)
    })?;
    assert_eq!(evicted, 0);
    Ok(())
}

#[test]
fn list_newest_first() -> TestResult {
    let f = Fixture::new()?;
    f.enable(VersioningState::Enabled)?;
    let mut kappas = Vec::new();
    for i in 0..3u64 {
        let now = at(i64::try_from(50_000 + i * 1000)?);
        kappas.push(f.put("obj", format!("v{i}").as_bytes(), now)?.0);
    }
    let versions = version_list_entries(&f.store, &f.ns, "obj")?;
    let listed: Vec<&Kappa> = versions.iter().map(|entry| &entry.kappa).collect();
    assert_eq!(listed, [&kappas[2], &kappas[1], &kappas[0]]);
    Ok(())
}

#[test]
fn list_empty_when_disabled() -> TestResult {
    let f = Fixture::new()?;
    assert!(version_list_entries(&f.store, &f.ns, "anything")?.is_empty());
    Ok(())
}

#[test]
fn suspended_replaces_null_version() -> TestResult {
    let f = Fixture::new()?;
    f.enable(VersioningState::Suspended)?;
    let (k1, vid1) = f.put("obj", b"first", at(60_000))?;
    assert_eq!(vid1, "null");
    let versions = version_list_entries(&f.store, &f.ns, "obj")?;
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].version_id, "null");
    assert_eq!(versions[0].kappa, k1);

    let (k2, _) = f.put("obj", b"second", at(61_000))?;
    let versions = version_list_entries(&f.store, &f.ns, "obj")?;
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].kappa, k2);
    Ok(())
}
