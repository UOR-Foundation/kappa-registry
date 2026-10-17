//! Reads through the resolver: streamed compressed leaves, seeks, and the
//! segment check of every delivered byte.

use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{Duration, Instant};

use kappa_handler::clock_at;
use kappa_store::{
    Axis, BlobStore, ClockMs, ContentIdentity, ContentPreparation, ExecutionStore, NamespaceRef,
    PreparationBounds, StoreError, VerifiedContent,
};
use kappa_types::kappa::Kappa;

use super::super::InMemoryStore;
use super::super::segments::SEGMENT;
use super::super::view::Representation;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn bounds() -> PreparationBounds {
    PreparationBounds {
        maximum: 1 << 24,
        deadline: Instant::now() + Duration::from_secs(30),
    }
}

fn namespace(store: &InMemoryStore) -> Result<NamespaceRef, Box<dyn std::error::Error>> {
    let ns = NamespaceRef::generate("reads", ClockMs::from_raw(1))?;
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(1))?)?;
    execution.namespace_create(None, None)?;
    execution.publish()?;
    Ok(ns)
}

#[test]
fn a_compressed_leaf_streams_through_seeks_and_verifies_in_order() -> TestResult {
    let store = super::super::test_support::test_store()?.into_store();
    let ns = namespace(&store)?;
    let plain: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let mut compressed = Vec::new();
    {
        let mut encoder = zstd::Encoder::new(&mut compressed, 3)?;
        encoder.write_all(&plain)?;
        encoder.finish()?;
    }
    let identity = Kappa::sha256(&plain);
    let prepared = store.prepare_content(
        ContentIdentity::Compressed {
            identity: identity.clone(),
            algorithm: "zstd".into(),
            uncompressed_size: plain.len() as u64,
        },
        &mut compressed.as_slice(),
        bounds(),
    )?;
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2))?)?;
    execution.content_install(prepared)?;
    execution.publish()?;

    let mut whole = Vec::new();
    store
        .blob_open_in(&ns, &identity)?
        .read_to_end(&mut whole)?;
    assert_eq!(whole, plain, "an in-order read of a compressed leaf");

    let mut reader = store.blob_open_in(&ns, &identity)?;
    let mut window = [0u8; 64];
    reader.seek(SeekFrom::Start(150_000))?;
    reader.read_exact(&mut window)?;
    assert_eq!(
        window.as_slice(),
        &plain[150_000..150_064],
        "forward seek decodes forward"
    );
    reader.seek(SeekFrom::Start(10))?;
    reader.read_exact(&mut window)?;
    assert_eq!(
        window.as_slice(),
        &plain[10..74],
        "backward seek reopens the decoder"
    );
    assert_eq!(
        store.blob_get_range_in(&ns, &identity, 199_990, 100)?,
        &plain[199_990..]
    );
    Ok(())
}

/// The file path of the allocation `kappa` selects in `ns`.
fn file_of(
    store: &InMemoryStore,
    ns: &NamespaceRef,
    kappa: &Kappa,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let view = store.view(ns.id());
    match view
        .admitted
        .get(kappa)
        .map(|admission| &admission.representation)
    {
        Some(Representation::File(allocation)) => Ok(allocation.path().to_path_buf()),
        other => Err(format!("{kappa} selects {other:?}").into()),
    }
}

#[test]
fn a_read_of_altered_bytes_fails_before_delivering_them() -> TestResult {
    let store = super::super::test_support::test_store()?.into_store();
    let ns = namespace(&store)?;
    let content = VerifiedContent::compute(Axis::Sha256, &[7u8; 4096])?;
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2))?)?;
    execution.blob_put(&content)?;
    execution.publish()?;
    // Same length, different bytes: only a digest check can tell.
    std::fs::write(file_of(&store, &ns, content.kappa())?, [8u8; 4096])?;
    let mut read = Vec::new();
    let outcome = store
        .blob_open_in(&ns, content.kappa())?
        .read_to_end(&mut read);
    let error = outcome
        .err()
        .ok_or("altered bytes were delivered as the identity")?;
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData, "{error}");
    assert!(
        read.is_empty(),
        "{} altered bytes were delivered",
        read.len()
    );
    Ok(())
}

/// A range read after a seek is checked: the altered segment is refused
/// wherever the read starts, and the unaltered segments still serve.
#[test]
fn a_seeked_range_read_of_an_altered_segment_is_refused() -> TestResult {
    let store = super::super::test_support::test_store()?.into_store();
    let ns = namespace(&store)?;
    let segment = usize::try_from(SEGMENT)?;
    let plain = (0..segment * 3)
        .map(|i| u8::try_from(i % 241))
        .collect::<Result<Vec<u8>, _>>()?;
    let content = VerifiedContent::compute(Axis::Sha256, &plain)?;
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2))?)?;
    execution.blob_put(&content)?;
    execution.publish()?;
    let mut altered = plain.clone();
    altered[segment + 100] ^= 0xff;
    std::fs::write(file_of(&store, &ns, content.kappa())?, &altered)?;

    let refused = store.blob_get_range_in(&ns, content.kappa(), SEGMENT + 50, 10);
    match refused {
        Err(StoreError::Io(error)) => {
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData, "{error}");
        }
        other => return Err(format!("an altered segment was served: {other:?}").into()),
    }
    let mut reader = store.blob_open_in(&ns, content.kappa())?;
    reader.seek(SeekFrom::Start(SEGMENT * 2 + 7))?;
    let mut window = [0u8; 32];
    reader.read_exact(&mut window)?;
    assert_eq!(window.as_slice(), &plain[segment * 2 + 7..segment * 2 + 39]);
    reader.seek(SeekFrom::Start(SEGMENT + 99))?;
    let error = reader
        .read_exact(&mut window)
        .err()
        .ok_or("a backward seek into an altered segment was served")?;
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData, "{error}");
    assert_eq!(
        store.blob_get_range_in(&ns, content.kappa(), 3, 5)?,
        &plain[3..8]
    );
    Ok(())
}

/// A compressed leaf's decoded bytes are checked against the digests of
/// the bytes preparation proved.
#[test]
fn a_compressed_leaf_whose_storage_decodes_differently_is_refused() -> TestResult {
    let store = super::super::test_support::test_store()?.into_store();
    let ns = namespace(&store)?;
    let plain = vec![3u8; 100_000];
    let encode = |bytes: &[u8]| -> Result<Vec<u8>, std::io::Error> {
        let mut compressed = Vec::new();
        let mut encoder = zstd::Encoder::new(&mut compressed, 3)?;
        encoder.write_all(bytes)?;
        encoder.finish()?;
        Ok(compressed)
    };
    let identity = Kappa::sha256(&plain);
    let prepared = store.prepare_content(
        ContentIdentity::Compressed {
            identity: identity.clone(),
            algorithm: "zstd".into(),
            uncompressed_size: plain.len() as u64,
        },
        &mut encode(&plain)?.as_slice(),
        bounds(),
    )?;
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2))?)?;
    execution.content_install(prepared)?;
    execution.publish()?;
    let view = store.view(ns.id());
    let path = match view
        .admitted
        .get(&identity)
        .map(|admission| &admission.representation)
    {
        Some(Representation::Compressed { storage, .. }) => storage.path().to_path_buf(),
        other => return Err(format!("{identity} selects {other:?}").into()),
    };
    // A valid stream decoding to as many other bytes.
    std::fs::write(&path, encode(&vec![4u8; 100_000])?)?;
    let refused = store.blob_get_range_in(&ns, &identity, 70_000, 16);
    match refused {
        Err(StoreError::Io(error)) => {
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData, "{error}");
        }
        other => return Err(format!("altered decoded bytes were served: {other:?}").into()),
    }
    Ok(())
}

#[test]
fn empty_content_verifies() -> TestResult {
    let store = super::super::test_support::test_store()?.into_store();
    let ns = namespace(&store)?;
    let content = VerifiedContent::compute(Axis::Sha256, b"")?;
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2))?)?;
    execution.blob_put(&content)?;
    execution.publish()?;
    let mut read = Vec::new();
    store
        .blob_open_in(&ns, content.kappa())?
        .read_to_end(&mut read)?;
    assert!(read.is_empty());
    Ok(())
}
