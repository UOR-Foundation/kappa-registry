//! Streaming readers: seeks land on exact bytes across loaded and unloaded
//! chunks, a reader admitted before retirement keeps its allocation pinned
//! until it drops, and the allocation is reclaimed once no reader holds
//! it.

mod support;

use std::io::{Read, Seek, SeekFrom};

use kappa_fixture::FixtureRoot;
use kappa_store::{BlobStore, Kappa, Retirement};
use kappa_store_redb::BLOB_CHUNK_SIZE;
use kappa_store_redb::test_support::{PersistentSpec, persistent_store};

use support::{TestResult, create, install, payload_files, record, retire};

#[test]
fn seeked_reads_match_original_bytes_across_loaded_and_unloaded_chunks() -> TestResult {
    for encrypted in [false, true] {
        let root = FixtureRoot::temporary()?;
        let spec = PersistentSpec::new().in_root(&root);
        let spec = if encrypted {
            spec.encryption_key([7; 32])
        } else {
            spec
        };
        let store = spec.clone().acquire()?;
        let ns = create(store.store(), "reader")?;
        let content: Vec<_> = (0..BLOB_CHUNK_SIZE * 3 + 17)
            .map(|i| u8::try_from((i * 37 + i / 251) % 256))
            .collect::<Result<_, _>>()?;
        let kappa = Kappa::sha256(&content);
        assert_eq!(install(store.store(), &ns, &content)?.kappa, kappa);
        let mut reader = store.blob_open(&kappa)?;
        for position in [
            13,
            BLOB_CHUNK_SIZE + 29,
            BLOB_CHUNK_SIZE + 7,
            BLOB_CHUNK_SIZE - 11,
            0,
            content.len() - 9,
            content.len(),
        ] {
            assert_eq!(
                reader.seek(SeekFrom::Start(position as u64))?,
                position as u64
            );
            assert_eq!(reader.read(&mut [])?, 0);
            let length = 41.min(content.len() - position);
            let mut bytes = vec![0; length];
            reader.read_exact(&mut bytes)?;
            assert_eq!(bytes, content[position..position + length]);
        }
        reader.seek(SeekFrom::Start(9))?;
        assert_eq!(
            reader
                .seek(SeekFrom::Current(i64::MIN))
                .err()
                .ok_or("negative seek succeeded")?
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(reader.stream_position()?, 9);
        assert_eq!(
            reader
                .seek(SeekFrom::End(i64::MIN))
                .err()
                .ok_or("negative end seek succeeded")?
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        let mut byte = [0];
        reader.read_exact(&mut byte)?;
        assert_eq!(byte[0], content[9]);

        // The reader pins its allocation. Retirement commits logically and
        // leaves the pinned allocation in place; the admitted reader still
        // delivers every byte.
        assert_eq!(retire(store.store(), &ns, &kappa)?, Retirement::Retired);
        assert!(!store.blob_exists(&kappa)?);
        assert_eq!(
            payload_files(store.blob_root())?.len(),
            1,
            "pinned allocation reclaimed"
        );
        reader.seek(SeekFrom::Start(0))?;
        let mut retained = Vec::new();
        reader.read_to_end(&mut retained)?;
        assert_eq!(retained, content);
        drop(reader);
        drop(store);
        // With the pin released, the inventory at open reclaims it.
        let reopened = spec.acquire()?;
        assert!(
            payload_files(reopened.blob_root())?.is_empty(),
            "encrypted={encrypted}"
        );
        assert!(!reopened.blob_exists(&kappa)?);
    }
    Ok(())
}

#[test]
fn empty_blob_reader_is_exhausted_and_seekable() -> TestResult {
    let store = persistent_store()?;
    let ns = create(store.store(), "empty")?;
    let (kappa, newly) = record(store.store(), &ns, b"")?;
    assert!(newly);
    let mut reader = store.blob_open(&kappa)?;
    assert_eq!(reader.read(&mut [0; 1])?, 0);
    assert_eq!(reader.seek(SeekFrom::End(0))?, 0);
    assert_eq!(reader.read(&mut [0; 1])?, 0);
    Ok(())
}
