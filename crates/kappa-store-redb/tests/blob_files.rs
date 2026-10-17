//! Content allocations: plaintext content is stored verbatim in one
//! read-only allocation whatever its axis, retirement returns the
//! allocation, preparation stages nothing beside the allocation, and the
//! allocation of an execution that never publishes is reclaimed when the
//! store opens.

mod support;

use kappa_fixture::FixtureRoot;
use kappa_handler::clock_at;
use kappa_store::{Axis, BlobStore, ContentIdentity, ExecutionStore, Kappa, Retirement, TagUpdate};
use kappa_store_redb::test_support::{PersistentSpec, TestPersistentStore};

use support::{
    T0, TestResult, at, computed, create, install, install_prepared, payload_files, retire,
    single_payload, staging_dirs,
};

/// The plaintext store in `root`, reopened by every call.
fn open(root: &FixtureRoot) -> Result<TestPersistentStore, Box<dyn std::error::Error>> {
    PersistentSpec::new().in_root(root).acquire()
}

#[test]
fn plaintext_content_is_stored_verbatim_on_every_axis() -> TestResult {
    let content = vec![91u8; 3 * 65_536 + 5];
    for axis in [Axis::Sha256, Axis::Sha512, Axis::Blake3] {
        let store = open(&FixtureRoot::temporary()?)?;
        let ns = create(store.store(), "axes")?;
        let installed = install_prepared(
            store.store(),
            &ns,
            ContentIdentity::Computed(axis),
            &content,
        )?;
        assert!(installed.newly_stored, "{axis:?}");
        assert_eq!(installed.kappa.axis(), axis);
        let path = single_payload(store.blob_root())?;
        let stored = std::fs::read(&path)?;
        assert_eq!(stored, content, "{axis:?}");
        assert!(
            std::fs::metadata(&path)?.permissions().readonly(),
            "{axis:?} content is writable"
        );
        assert_eq!(store.blob_get_verified(&installed.kappa)?, content);
        for alias in &installed.additional_kappas {
            assert_eq!(store.blob_get_verified(alias)?, content, "{axis:?} alias");
        }
        let again = install_prepared(
            store.store(),
            &ns,
            ContentIdentity::Computed(axis),
            &content,
        )?;
        assert!(!again.newly_stored, "{axis:?} stored twice");
        assert_eq!(payload_files(store.blob_root())?.len(), 1, "{axis:?}");
    }
    Ok(())
}

#[test]
fn retirement_removes_the_allocation() -> TestResult {
    let store = open(&FixtureRoot::temporary()?)?;
    let ns = create(store.store(), "retire")?;
    let installed = install(store.store(), &ns, &vec![3u8; 70_001])?;
    let path = single_payload(store.blob_root())?;
    assert!(path.exists());
    assert_eq!(
        retire(store.store(), &ns, &installed.kappa)?,
        Retirement::Retired
    );
    assert!(!path.exists());
    assert!(!store.blob_exists(&installed.kappa)?);
    assert!(payload_files(store.blob_root())?.is_empty());
    Ok(())
}

#[test]
fn preparation_stages_nothing_beside_the_allocation() -> TestResult {
    let store = open(&FixtureRoot::temporary()?)?;
    let ns = create(store.store(), "staging")?;
    let content = vec![5u8; 200_000];
    let installed = install(store.store(), &ns, &content)?;
    assert!(installed.newly_stored);
    assert_eq!(installed.kappa, Kappa::sha256(&content));
    assert_eq!(std::fs::read(single_payload(store.blob_root())?)?, content);
    assert_eq!(
        staging_dirs(store.blob_root())?,
        Vec::<std::path::PathBuf>::new()
    );
    Ok(())
}

#[test]
fn content_of_an_unpublished_execution_is_invisible_and_reclaimed_at_open() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let content = vec![42u8; 70_000];
    let kappa = Kappa::sha256(&content);
    let ns = {
        let store = open(&root)?;
        let ns = create(store.store(), "aborted")?;
        let mut execution = store.begin_execution(&ns, &clock_at(at(T0 + 1))?)?;
        execution.content_install(computed(store.store(), &content)?)?;
        execution.tag_put(
            "pending",
            &TagUpdate::Set {
                kappa: kappa.clone(),
            },
        )?;
        assert!(!store.blob_exists(&kappa)?, "private content visible");
        let path = single_payload(store.blob_root())?;
        execution.abort()?;
        assert!(!store.blob_exists(&kappa)?);
        assert!(
            path.exists(),
            "the allocation outlives the aborted execution until the sweep"
        );
        ns
    };
    // Residue of an execution that never committed, as a crash leaves it,
    // is reclaimed by the bounded inventory step that runs when the store
    // opens (one allocation is within any step's bound).
    {
        let store = open(&root)?;
        assert!(
            payload_files(store.blob_root())?.is_empty(),
            "open did not reclaim the unowned allocation"
        );
        assert!(!store.blob_exists(&kappa)?);
        let mut execution = store.begin_execution(&ns, &clock_at(at(T0 + 2))?)?;
        execution.content_install(computed(store.store(), &content)?)?;
        drop(execution);
        assert_eq!(payload_files(store.blob_root())?.len(), 1);
    }
    let store = open(&root)?;
    assert!(payload_files(store.blob_root())?.is_empty());
    assert!(!store.blob_exists(&kappa)?);
    Ok(())
}

#[test]
fn published_content_survives_restart() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let content = vec![9u8; 70_000];
    let kappa = Kappa::sha256(&content);
    {
        let store = open(&root)?;
        let ns = create(store.store(), "published")?;
        let mut execution = store.begin_execution(&ns, &clock_at(at(T0 + 1))?)?;
        execution.content_install(computed(store.store(), &content)?)?;
        execution.tag_put(
            "kept",
            &TagUpdate::Set {
                kappa: kappa.clone(),
            },
        )?;
        execution.publish()?;
    }
    let store = open(&root)?;
    assert_eq!(store.blob_get(&kappa)?, content);
    assert_eq!(std::fs::read(single_payload(store.blob_root())?)?, content);
    Ok(())
}
