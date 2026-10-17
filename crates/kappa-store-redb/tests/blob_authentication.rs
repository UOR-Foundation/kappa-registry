//! Encrypted content files are authenticated chunk by chunk: a chunk bound
//! to an earlier publication, a chunk moved to another ordinal, a tampered
//! final chunk, and an index record moved to another identity are all
//! refused by every read path.

mod support;

use std::path::Path;

use kappa_fixture::FixtureRoot;
use kappa_store::{BlobStore, Kappa, NamespaceRef, Retirement};
use kappa_store_redb::test_support::PersistentSpec;
use kappa_store_redb::{PersistentStore, tables::BLOB_INDEX};
use redb::ReadableTable;

use support::{TestResult, create, install, retire, single_payload};

/// The encrypted store in `root`, reopened by every call.
fn open(root: &FixtureRoot, key: u8) -> Result<PersistentStore, Box<dyn std::error::Error>> {
    Ok(PersistentSpec::new()
        .in_root(root)
        .encryption_key([key; 32])
        .acquire()?
        .into_store())
}

fn blob_root(root: &FixtureRoot) -> std::path::PathBuf {
    root.path().join("blobs")
}

/// Replace a placed content file. Placed files are read-only and may be
/// fs-verity sealed, so the replacement is a rename, as an attacker with
/// write access to the directory would perform.
fn replace(path: &Path, bytes: &[u8]) -> TestResult {
    let staged = path.with_extension("tampered");
    std::fs::write(&staged, bytes)?;
    std::fs::rename(&staged, path)?;
    Ok(())
}

fn assert_unreadable(store: &PersistentStore, kappa: &Kappa) {
    assert!(store.blob_get(kappa).is_err(), "blob_get admitted {kappa}");
    assert!(
        store.blob_open(kappa).is_err(),
        "blob_open admitted {kappa}"
    );
    assert!(
        store.blob_get_range(kappa, 0, 0).is_err(),
        "empty range admitted {kappa}"
    );
    assert!(
        store.blob_get_range(kappa, u64::MAX, 1).is_err(),
        "range past the end admitted {kappa}"
    );
}

/// Install `content` in a fresh namespace of `store`.
fn installed(
    store: &PersistentStore,
    content: &[u8],
) -> Result<(NamespaceRef, Kappa), Box<dyn std::error::Error>> {
    let ns = create(store, "authentication")?;
    let kappa = install(store, &ns, content)?.kappa;
    Ok((ns, kappa))
}

#[test]
fn old_publication_cannot_be_spliced_into_republished_content() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let content = vec![17; 65_537];
    let (old, current, key, path) = {
        let store = open(&root, 31)?;
        let (ns, key) = installed(&store, &content)?;
        let first = single_payload(&blob_root(&root))?;
        let old = std::fs::read(&first)?;
        assert_eq!(retire(&store, &ns, &key)?, Retirement::Retired);
        assert!(!first.exists(), "retirement left the allocation");
        assert!(install(&store, &ns, &content)?.newly_stored);
        assert_eq!(store.blob_get(&key)?, content);
        let path = single_payload(&blob_root(&root))?;
        let current = std::fs::read(&path)?;
        (old, current, key, path)
    };
    assert_eq!(old.len(), current.len());
    assert_ne!(old, current, "a republication reuses no ciphertext");
    replace(&path, &old)?;
    assert_unreadable(&open(&root, 31)?, &key);
    Ok(())
}

#[test]
fn encrypted_storage_rejects_chunk_relocation_and_final_chunk_tampering() -> TestResult {
    for relocate in [true, false] {
        let root = FixtureRoot::temporary()?;
        // Two full chunks: equal stored lengths, so relocation keeps the
        // file length and only authentication can refuse it.
        let content = vec![43; 2 * 65_536];
        let (_, key) = installed(&open(&root, 19)?, &content)?;
        let path = single_payload(&blob_root(&root))?;
        let mut bytes = std::fs::read(&path)?;
        let stride = bytes.len() / 2;
        if relocate {
            let first = bytes[..stride].to_vec();
            bytes[stride..].copy_from_slice(&first);
        } else {
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
        }
        replace(&path, &bytes)?;
        assert_unreadable(&open(&root, 19)?, &key);
    }
    Ok(())
}

#[test]
fn truncated_or_extended_content_is_refused() -> TestResult {
    for extend in [true, false] {
        let root = FixtureRoot::temporary()?;
        let content = vec![7; 70_000];
        let (_, key) = installed(&open(&root, 23)?, &content)?;
        let path = single_payload(&blob_root(&root))?;
        let mut bytes = std::fs::read(&path)?;
        if extend {
            bytes.push(0);
        } else {
            bytes.pop();
        }
        replace(&path, &bytes)?;
        assert_unreadable(&open(&root, 23)?, &key);
    }
    Ok(())
}

#[test]
fn encrypted_index_cannot_be_relocated_to_another_identity() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let content = vec![11; 70_000];
    let second = Kappa::sha256(b"other");
    let (first, db_path) = {
        let store = PersistentSpec::new()
            .in_root(&root)
            .encryption_key([29; 32])
            .acquire()?;
        let (_, first) = installed(store.store(), &content)?;
        (first, store.db_path().to_path_buf())
    };
    {
        let database = redb::Database::open(&db_path)?;
        let write = database.begin_write()?;
        {
            let mut index = write.open_table(BLOB_INDEX)?;
            let bytes = index
                .get(first.key_bytes().as_slice())?
                .ok_or("missing published index record")?
                .value()
                .to_vec();
            index.insert(second.key_bytes().as_slice(), bytes.as_slice())?;
        }
        write.commit()?;
    }
    // The relocated record names the first content's allocation; every read
    // of the second identity is refused and the first stays readable.
    let store = open(&root, 29)?;
    assert!(store.blob_size(&second).is_err());
    assert!(store.blob_get_range(&second, 0, 0).is_err());
    assert!(store.blob_open(&second).is_err());
    assert!(store.blob_get(&second).is_err());
    assert_eq!(store.blob_get(&first)?, content);
    Ok(())
}
