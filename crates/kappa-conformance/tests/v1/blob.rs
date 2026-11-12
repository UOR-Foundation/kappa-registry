//! Blob store conformance: content addressing, idempotent install, range
//! reads, metadata CRUD, multi-axis preparation, retirement. Every write
//! goes through a published execution; reads are through the store.

use std::time::{Duration, Instant};

use kappa_store::axis::Axis;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::traits::blob::BlobStore;
use kappa_store::verified::VerifiedContent;
use kappa_store::{
    ContentIdentity, ContentPreparation, IngestResult, PreparationBounds, Retirement, StoreError,
    TagUpdate,
};

use super::support::{MemoryFixture, TestResult, create_ns, publish};

/// Install `content` as a verified record in one published execution of
/// a new namespace.
fn install(f: &MemoryFixture, content: &[u8]) -> Result<(Kappa, bool), StoreError> {
    install_in(f, &create_ns(&f.store, "blob")?, content)
}

/// Install `content` as a verified record in one published execution of
/// `ns`.
fn install_in(
    f: &MemoryFixture,
    ns: &NamespaceRef,
    content: &[u8],
) -> Result<(Kappa, bool), StoreError> {
    let verified = VerifiedContent::compute(Axis::Sha256, content)?;
    let kappa = verified.kappa().clone();
    let mut newly = false;
    publish(&f.store, ns, |e| {
        newly = e.blob_put(&verified)?;
        Ok(())
    })?;
    Ok((kappa, newly))
}

/// Prepare `content` under `identity` and install it in one published
/// execution.
fn prepare_install(
    f: &MemoryFixture,
    identity: ContentIdentity,
    content: &[u8],
) -> Result<IngestResult, StoreError> {
    let ns = create_ns(&f.store, "prepared")?;
    let prepared = f.store.prepare_content(
        identity,
        &mut &content[..],
        PreparationBounds {
            maximum: 1024 * 1024,
            deadline: Instant::now() + Duration::from_secs(30),
        },
    )?;
    let mut result = None;
    publish(&f.store, &ns, |e| {
        result = Some(e.content_install(prepared)?);
        Ok(())
    })?;
    result.ok_or_else(|| StoreError::Internal("installation produced no result".into()))
}

/// Retire `kappa` from `ns`, the namespace whose admission it releases.
fn retire(f: &MemoryFixture, ns: &NamespaceRef, kappa: &Kappa) -> Result<Retirement, StoreError> {
    let mut outcome = None;
    publish(&f.store, ns, |e| {
        outcome = Some(e.content_retire(kappa)?);
        Ok(())
    })?;
    outcome.ok_or_else(|| StoreError::Internal("retirement produced no result".into()))
}

#[test]
fn put_get_roundtrip() -> TestResult {
    let f = MemoryFixture::new()?;
    let (k, newly) = install(&f, b"hello")?;
    assert!(newly);
    assert_eq!(f.store.blob_get(&k)?, b"hello");
    Ok(())
}

#[test]
fn content_addressed_identity() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "blob")?;
    let v1 = VerifiedContent::compute(Axis::Sha256, b"same")?;
    let v2 = VerifiedContent::compute(Axis::Sha256, b"same")?;
    assert_eq!(*v1.kappa(), *v2.kappa());
    let (first_identity, first) = install_in(&f, &ns, b"same")?;
    let (second_identity, second) = install_in(&f, &ns, b"same")?;
    assert_eq!(&first_identity, v1.kappa());
    assert_eq!(first_identity, second_identity);
    assert!(first);
    assert!(!second, "the second install is idempotent");
    assert_eq!(f.store.blob_get(&first_identity)?, b"same");
    Ok(())
}

#[test]
fn different_content_different_kappa() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "blob")?;
    let (k1, first) = install_in(&f, &ns, b"aaa")?;
    let (k2, second) = install_in(&f, &ns, b"bbb")?;
    assert!(
        first && second,
        "distinct content receives distinct admissions"
    );
    assert_ne!(k1, k2);
    assert_eq!(f.store.blob_get(&k1)?, b"aaa");
    assert_eq!(f.store.blob_get(&k2)?, b"bbb");
    Ok(())
}

#[test]
fn exists_after_put() -> TestResult {
    let f = MemoryFixture::new()?;
    let (k, _) = install(&f, b"exists")?;
    assert!(f.store.blob_exists(&k)?);
    Ok(())
}

#[test]
fn not_exists_before_put() -> TestResult {
    let f = MemoryFixture::new()?;
    let k = Kappa::sha256(b"never stored");
    assert!(!f.store.blob_exists(&k)?);
    Ok(())
}

#[test]
fn retirement_removes_an_unreferenced_blob() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "retire")?;
    let (k, _) = install_in(&f, &ns, b"delete me")?;
    // Another namespace never admitted it: nothing to release there.
    let other = create_ns(&f.store, "other")?;
    assert_eq!(retire(&f, &other, &k)?, Retirement::Absent);
    assert_eq!(retire(&f, &ns, &k)?, Retirement::Retired);
    assert!(!f.store.blob_exists(&k)?);
    assert!(f.store.blob_get(&k).is_err());
    assert_eq!(retire(&f, &ns, &k)?, Retirement::Absent);
    Ok(())
}

#[test]
fn retirement_is_refused_while_a_tag_names_the_blob() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "retained")?;
    let verified = VerifiedContent::compute(Axis::Sha256, b"retained")?;
    let k = verified.kappa().clone();
    publish(&f.store, &ns, |e| {
        e.blob_put(&verified)?;
        e.tag_put("kept", &TagUpdate::Set { kappa: k.clone() })
    })?;
    assert_eq!(retire(&f, &ns, &k)?, Retirement::Retained);
    assert_eq!(f.store.blob_get(&k)?, b"retained");
    publish(&f.store, &ns, |e| e.tag_delete("kept"))?;
    assert_eq!(retire(&f, &ns, &k)?, Retirement::Retired);
    assert!(!f.store.blob_exists(&k)?);
    Ok(())
}

#[test]
fn size_matches_content() -> TestResult {
    let f = MemoryFixture::new()?;
    let data = b"twelve bytes";
    let (k, _) = install(&f, data)?;
    assert_eq!(f.store.blob_size(&k)?, data.len() as u64);
    Ok(())
}

#[test]
fn get_range_middle() -> TestResult {
    let f = MemoryFixture::new()?;
    let (k, _) = install(&f, b"0123456789")?;
    assert_eq!(f.store.blob_get_range(&k, 3, 4)?, b"3456");
    Ok(())
}

#[test]
fn get_range_past_end_truncates() -> TestResult {
    let f = MemoryFixture::new()?;
    let (k, _) = install(&f, b"short")?;
    assert_eq!(f.store.blob_get_range(&k, 3, 100)?, b"rt");
    Ok(())
}

#[test]
fn empty_blob() -> TestResult {
    let f = MemoryFixture::new()?;
    let (k, _) = install(&f, b"")?;
    assert_eq!(f.store.blob_get(&k)?, b"");
    assert_eq!(f.store.blob_size(&k)?, 0);
    Ok(())
}

#[test]
fn prepared_verified_rejects_mismatch() -> TestResult {
    let f = MemoryFixture::new()?;
    let wrong = Kappa::sha256(b"wrong content");
    assert!(matches!(
        prepare_install(
            &f,
            ContentIdentity::Verified(wrong.clone()),
            b"right content"
        ),
        Err(StoreError::Rejected(_))
    ));
    assert!(!f.store.blob_exists(&wrong)?);
    assert!(!f.store.blob_exists(&Kappa::sha256(b"right content"))?);
    Ok(())
}

#[test]
fn prepared_compute_sha256() -> TestResult {
    let f = MemoryFixture::new()?;
    let result = prepare_install(&f, ContentIdentity::Computed(Axis::Sha256), b"computed")?;
    assert_eq!(result.kappa, Kappa::sha256(b"computed"));
    assert!(result.newly_stored);
    assert_eq!(f.store.blob_get(&result.kappa)?, b"computed");
    Ok(())
}

#[test]
fn prepared_compute_blake3() -> TestResult {
    let f = MemoryFixture::new()?;
    let result = prepare_install(
        &f,
        ContentIdentity::Computed(Axis::Blake3),
        b"blake3 content",
    )?;
    assert_eq!(result.kappa, Kappa::blake3(b"blake3 content"));
    assert_eq!(f.store.blob_get(&result.kappa)?, b"blake3 content");
    // Mandatory SHA-256 secondary axis.
    let sha256_k = Kappa::sha256(b"blake3 content");
    assert_eq!(result.additional_kappas, std::slice::from_ref(&sha256_k));
    assert!(f.store.blob_exists(&sha256_k)?);
    assert_eq!(f.store.blob_get_verified(&sha256_k)?, b"blake3 content");
    Ok(())
}

#[test]
fn sha512_first_class() -> TestResult {
    let f = MemoryFixture::new()?;
    let data = b"sha512 is first class";
    let result = prepare_install(&f, ContentIdentity::Computed(Axis::Sha512), data)?;
    assert!(result.kappa.to_string().starts_with("sha512:"));
    assert_eq!(f.store.blob_get(&result.kappa)?, data);
    Ok(())
}

#[test]
fn blob_meta_roundtrip() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "meta")?;
    let verified = VerifiedContent::compute(Axis::Sha256, b"meta")?;
    let k = verified.kappa().clone();
    publish(&f.store, &ns, |e| {
        e.blob_put(&verified)?;
        e.blob_meta_put(&k, "content-type", b"text/plain")
    })?;
    assert_eq!(f.store.blob_meta_get(&k, "content-type")?, b"text/plain");
    Ok(())
}

#[test]
fn blob_meta_not_found() -> TestResult {
    let f = MemoryFixture::new()?;
    let (k, _) = install(&f, b"no meta")?;
    assert!(f.store.blob_meta_get(&k, "missing").is_err());
    Ok(())
}

#[test]
fn blob_meta_delete() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "meta-delete")?;
    let verified = VerifiedContent::compute(Axis::Sha256, b"del meta")?;
    let k = verified.kappa().clone();
    publish(&f.store, &ns, |e| {
        e.blob_put(&verified)?;
        e.blob_meta_put(&k, "key", b"val")
    })?;
    assert_eq!(f.store.blob_meta_get(&k, "key")?, b"val");
    publish(&f.store, &ns, |e| e.blob_meta_delete(&k, "key"))?;
    assert!(f.store.blob_meta_get(&k, "key").is_err());
    Ok(())
}
