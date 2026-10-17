//! Computed and compressed representations reopen with stream and range
//! reads bound to the published bytes.

mod support;

use std::io::{Read, Seek, SeekFrom};

use kappa_fixture::FixtureRoot;
use kappa_store::{Axis, BlobStore, ContentIdentity, Kappa};
use kappa_store_redb::test_support::PersistentSpec;

use support::{TestResult, create, install_prepared};

#[test]
fn computed_and_compressed_publications_reopen_with_bound_stream_and_range_reads() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let spec = PersistentSpec::new()
        .in_root(&root)
        .encryption_key([61; 32]);
    let computed: Vec<_> = (0u8..251).cycle().take(131_079).collect();
    let decoded = vec![83; 262_145];
    let encoded = zstd::encode_all(decoded.as_slice(), 3)?;
    let computed_key = Kappa::sha256(&computed);
    let compressed_key = Kappa::sha256(&decoded);
    {
        let store = spec.clone().acquire()?;
        let ns = create(store.store(), "binding")?;
        let installed = install_prepared(
            store.store(),
            &ns,
            ContentIdentity::Computed(Axis::Sha256),
            &computed,
        )?;
        assert!(installed.newly_stored);
        assert_eq!(installed.kappa, computed_key);
        install_prepared(
            store.store(),
            &ns,
            ContentIdentity::Compressed {
                identity: compressed_key.clone(),
                algorithm: "zstd".into(),
                uncompressed_size: decoded.len() as u64,
            },
            &encoded,
        )?;
    }
    let store = spec.acquire()?;
    for (key, representation) in [
        (&computed_key, computed.as_slice()),
        (&compressed_key, encoded.as_slice()),
    ] {
        assert_eq!(store.blob_get(key)?, representation);
        let mut reader = store.blob_open(key)?;
        assert_eq!(reader.seek(SeekFrom::End(0))?, representation.len() as u64);
        reader.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        assert_eq!(bytes, representation);
        let offset = representation.len() / 2;
        assert_eq!(
            store.blob_get_range(key, offset as u64, u64::MAX)?,
            representation[offset..]
        );
    }
    assert_eq!(store.blob_size(&compressed_key)?, decoded.len() as u64);
    assert_eq!(store.blob_get_decompressed(&compressed_key)?, decoded);
    Ok(())
}
