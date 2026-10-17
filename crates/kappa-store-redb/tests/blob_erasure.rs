//! Durable erasure of the blob encryption domain revokes every retained
//! read, cached or not, and cannot be rederived after restart.

mod support;

use std::io::Read;

use kappa_fixture::FixtureRoot;
use kappa_store::{BlobStore, Kappa};
use kappa_store_redb::test_support::PersistentSpec;

use support::{TestResult, create, install};

#[test]
fn durable_domain_erasure_revokes_cached_and_unloaded_retained_reads() -> TestResult {
    let spec = PersistentSpec::new()
        .in_root(&FixtureRoot::temporary()?)
        .encryption_key([47; 32]);
    let content = vec![7; 65_537];
    let key = Kappa::sha256(&content);
    {
        let store = spec.clone().acquire()?;
        let ns = create(store.store(), "erasure")?;
        assert_eq!(install(store.store(), &ns, &content)?.kappa, key);
        let mut cached = store.blob_open(&key)?;
        let mut unloaded = store.blob_open(&key)?;
        cached.read_exact(&mut [0; 1])?;
        store.erase_blob_encryption()?;
        store.erase_blob_encryption()?;
        assert_eq!(
            cached
                .read(&mut [0; 1])
                .err()
                .ok_or("cached access was not revoked")?
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(unloaded.read(&mut [0; 1]).is_err());
        assert!(store.blob_get(&key).is_err());
        assert!(store.blob_size(&key).is_err());
        assert!(store.blob_open(&key).is_err());
    }
    assert!(
        spec.acquire().is_err(),
        "erased domain cannot be rederived after restart"
    );
    Ok(())
}
