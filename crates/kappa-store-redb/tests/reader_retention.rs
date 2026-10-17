//! Escaping handles keep the resources their later operations need.
//!
//! An encrypted reader consults the store's erasure state on every chunk
//! it delivers, so it retains the store's filesystem scope through its
//! encryption domain: the reader keeps working after the store and every
//! external scope handle are gone, the scope cannot be removed beneath it,
//! and durable erasure through any later store instance still revokes it.

mod support;

use std::io::Read;

use kappa_fixture::{CloseError, FixtureRoot};
use kappa_store::{BlobStore, Kappa, StoreError};
use kappa_store_redb::test_support::PersistentSpec;

use support::{TestResult, create, install};

/// Three chunks, so a reader must load chunks after the store is gone.
fn content() -> Vec<u8> {
    (0u8..=250).cycle().take(3 * 65_536 + 17).collect()
}

#[test]
fn encrypted_reader_outlives_its_store_and_still_honors_erasure() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let spec = PersistentSpec::new()
        .in_root(&root)
        .encryption_key([47; 32]);
    let bytes = content();
    let key = Kappa::sha256(&bytes);
    let (mut delivered, mut revoked) = {
        let store = spec.clone().acquire()?.into_store();
        let ns = create(&store, "retention")?;
        assert_eq!(install(&store, &ns, &bytes)?.kappa, key);
        (store.blob_open(&key)?, store.blob_open(&key)?)
    };

    // Only the readers hold the scope now: it cannot be removed.
    let root = match root.close() {
        Err(CloseError::InUse(root)) => root,
        Err(error) => return Err(error.into()),
        Ok(()) => return Err("scope removed beneath live encrypted readers".into()),
    };
    let mut read = Vec::new();
    delivered.read_to_end(&mut read)?;
    assert_eq!(read, bytes, "reader stopped working once its store dropped");

    // Erasure through another instance is durable and revokes the reader
    // that has not yet delivered anything.
    {
        let store = spec.acquire()?.into_store();
        store.erase_blob_encryption()?;
        assert!(matches!(store.blob_get(&key), Err(StoreError::Rejected(_))));
    }
    let mut chunk = [0u8; 16];
    let refused = revoked
        .read(&mut chunk)
        .err()
        .ok_or("erased domain still delivered plaintext")?;
    assert_eq!(
        refused.kind(),
        std::io::ErrorKind::PermissionDenied,
        "{refused}"
    );

    drop((delivered, revoked));
    let path = root.path().to_path_buf();
    root.close()?;
    assert!(!path.exists());
    Ok(())
}

#[test]
fn escaped_store_handle_keeps_its_scope_until_released() -> TestResult {
    let acquired = PersistentSpec::new().acquire()?;
    let root = acquired.root().clone();
    let blob_root = acquired.blob_root().to_path_buf();
    let store = std::sync::Arc::new(acquired.into_store());
    let root = match root.close() {
        Err(CloseError::InUse(root)) => root,
        Err(error) => return Err(error.into()),
        Ok(()) => return Err("scope removed beneath a live store".into()),
    };
    let ns = create(&*store, "escaped")?;
    assert!(install(&*store, &ns, b"after release")?.newly_stored);
    assert!(blob_root.is_dir());
    drop(store);
    root.close()?;
    assert!(!blob_root.exists());
    Ok(())
}
