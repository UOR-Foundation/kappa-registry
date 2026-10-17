//! Concurrent preparations of the same verified content install one
//! representation that survives restart; a failing source prepares
//! nothing, leaves no allocation, and a clean retry installs.

mod support;

use std::sync::Barrier;

use kappa_fixture::FixtureRoot;
use kappa_store::{
    BlobStore, ContentIdentity, ContentPreparation, Kappa, NamespaceStore, StoreError,
};
use kappa_store_redb::test_support::PersistentSpec;

use support::{T0, TestResult, at, create, install_prepared, payload_files, prepare, publish};

#[test]
fn concurrent_verified_preparations_install_once_and_reopen_with_exact_content() -> TestResult {
    let spec = PersistentSpec::new().in_root(&FixtureRoot::temporary()?);
    let content = vec![83u8; 196_609];
    let identity = Kappa::sha256(&content);
    let ns = {
        let store = spec.clone().acquire()?.into_store();
        let ns = create(&store, "publication")?;
        let barrier = Barrier::new(8);
        let installed: usize = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let (store, ns, barrier, content, identity) =
                        (&store, &ns, &barrier, &content, &identity);
                    scope.spawn(move || -> Result<bool, StoreError> {
                        let prepared =
                            prepare(store, ContentIdentity::Verified(identity.clone()), content)?;
                        barrier.wait();
                        publish(store, ns, at(T0 + 1), |e| {
                            Ok(e.content_install(prepared)?.newly_stored)
                        })
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .map_err(|_| StoreError::Internal("publication writer panicked".into()))
                        .and_then(|outcome| outcome)
                        .map(usize::from)
                })
                .sum::<Result<usize, StoreError>>()
        })?;
        assert_eq!(installed, 1);
        assert_eq!(store.blob_get(&identity)?, content);
        ns
    };
    let store = spec.acquire()?;
    assert_eq!(store.blob_get(&identity)?, content);
    assert_eq!(store.blob_size(&identity)?, content.len() as u64);
    // Exactly one allocation holds the content.
    assert_eq!(payload_files(store.blob_root())?.len(), 1);
    assert_eq!(
        store.namespace_resolve(ns.display_name(), None)?.id(),
        ns.id()
    );
    Ok(())
}

#[test]
fn source_failure_prepares_nothing_and_allows_a_clean_retry() -> TestResult {
    struct Failing {
        first: bool,
    }
    impl std::io::Read for Failing {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.first {
                self.first = false;
                buffer.fill(37);
                Ok(buffer.len())
            } else {
                Err(std::io::Error::from_raw_os_error(5))
            }
        }
    }
    let store = kappa_store_redb::test_support::persistent_store()?;
    let ns = create(store.store(), "retry")?;
    let content = vec![37u8; 65_537];
    let identity = Kappa::sha256(&content);
    assert!(matches!(
        store.prepare_content(
            ContentIdentity::Verified(identity.clone()),
            &mut Failing { first: true },
            support::bounds()
        ),
        Err(StoreError::Io(_))
    ));
    assert!(!store.blob_exists(&identity)?);
    assert!(
        payload_files(store.blob_root())?.is_empty(),
        "a failed preparation left an allocation"
    );
    let installed = install_prepared(
        store.store(),
        &ns,
        ContentIdentity::Verified(identity.clone()),
        &content,
    )?;
    assert!(installed.newly_stored);
    assert_eq!(store.blob_get(&identity)?, content);
    Ok(())
}
