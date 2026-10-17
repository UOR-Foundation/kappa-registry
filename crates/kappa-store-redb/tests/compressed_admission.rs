//! Compressed representations are proven before admission: the frame
//! must decode, the decoded bytes must have the declared size and hash to
//! the declared identity, and an identity that already has a committed
//! representation keeps it.

mod support;

use std::io::Read;

use kappa_fixture::FixtureRoot;
use kappa_store::{BlobStore, ContentIdentity, Kappa, StoreError};
use kappa_store_redb::test_support::{PersistentSpec, persistent_store};

use support::{TestResult, create, install, install_prepared, payload_files, prepare};

fn compressed(identity: &Kappa, algorithm: &str, uncompressed_size: u64) -> ContentIdentity {
    ContentIdentity::Compressed {
        identity: identity.clone(),
        algorithm: algorithm.to_string(),
        uncompressed_size,
    }
}

#[test]
fn zstd_admission_rejects_bad_frames_and_expansion_before_publication() -> TestResult {
    let spec = PersistentSpec::new().in_root(&FixtureRoot::temporary()?);
    let content = vec![71; 262_145];
    let key = Kappa::sha256(&content);
    let encoded = zstd::encode_all(content.as_slice(), 3)?;
    {
        let store = spec.clone().acquire()?;
        let ns = create(store.store(), "zstd")?;
        assert!(matches!(
            prepare(store.store(), compressed(&key, "zstd", 1), &encoded),
            Err(StoreError::Rejected(_))
        ));
        assert!(!store.blob_exists(&key)?);
        assert!(
            prepare(
                store.store(),
                compressed(&key, "zstd", content.len() as u64),
                &encoded[..encoded.len() - 1]
            )
            .is_err()
        );
        assert!(!store.blob_exists(&key)?);
        assert!(
            payload_files(store.blob_root())?.is_empty(),
            "a rejected preparation left an allocation"
        );
        let installed = install_prepared(
            store.store(),
            &ns,
            compressed(&key, "zstd", content.len() as u64),
            &encoded,
        )?;
        assert!(installed.newly_stored);
        assert_eq!(installed.kappa, key);
        assert_eq!(store.blob_get_compressed(&key)?, (encoded, "zstd".into()));
        assert_eq!(store.blob_get_decompressed(&key)?, content);
        assert_eq!(store.blob_size(&key)?, content.len() as u64);
    }
    let store = spec.acquire()?;
    assert_eq!(store.blob_get_decompressed(&key)?, content);
    Ok(())
}

#[test]
fn compressed_admission_verifies_identity_and_size_before_publication() -> TestResult {
    let spec = PersistentSpec::new().in_root(&FixtureRoot::temporary()?);
    let content = b"verified uncompressed content";
    let key = Kappa::sha256(content);
    {
        let store = spec.clone().acquire()?;
        let ns = create(store.store(), "none")?;
        assert!(matches!(
            prepare(
                store.store(),
                compressed(&key, "none", 17),
                b"different content"
            ),
            Err(StoreError::Rejected(_))
        ));
        assert!(!store.blob_exists(&key)?);
        assert!(matches!(
            prepare(store.store(), compressed(&key, "none", 0), content),
            Err(StoreError::Rejected(_))
        ));
        assert!(!store.blob_exists(&key)?);
        install_prepared(
            store.store(),
            &ns,
            compressed(&key, "none", content.len() as u64),
            content,
        )?;
        assert_eq!(store.blob_get_decompressed(&key)?, content);
    }
    let store = spec.acquire()?;
    assert_eq!(store.blob_get_decompressed(&key)?, content);
    assert_eq!(store.blob_size(&key)?, content.len() as u64);
    Ok(())
}

#[test]
fn compressed_dedup_cannot_replace_an_existing_immutable_blob() -> TestResult {
    let store = persistent_store()?;
    let ns = create(store.store(), "immutable")?;
    let content = vec![19; 65_537];
    let key = Kappa::sha256(&content);
    assert_eq!(install(store.store(), &ns, &content)?.kappa, key);
    let mut retained = store.blob_open(&key)?;
    let again = install_prepared(
        store.store(),
        &ns,
        compressed(&key, "none", content.len() as u64),
        &content,
    )?;
    assert!(!again.newly_stored);
    assert!(matches!(
        store.blob_get_compressed(&key),
        Err(StoreError::NotFound(_))
    ));
    assert_eq!(store.blob_get(&key)?, content);
    assert_eq!(payload_files(store.blob_root())?.len(), 1);
    let mut read = Vec::new();
    retained.read_to_end(&mut read)?;
    assert_eq!(read, content);
    Ok(())
}
