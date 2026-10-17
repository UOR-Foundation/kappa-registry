//! Shared fixtures for the redb test register: namespaces created in their
//! own epoch, published executions, content prepared outside the writer
//! and installed inside one, retirement, and the physical allocation
//! inventory under `objects/`.
#![allow(dead_code)]

pub mod resource;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kappa_handler::clock_at;
use kappa_store::{
    Axis, ClockMs, ContentIdentity, ContentPreparation, Execution, IngestResult, Kappa, KappaStore,
    NamespaceRef, PreparationBounds, PreparedContent, Retirement, StoreError, VerifiedContent,
};

pub type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A backend that prepares content and runs executions.
pub trait Staging: KappaStore + ContentPreparation {}
impl<T: KappaStore + ContentPreparation + ?Sized> Staging for T {}

/// Wall-clock origin of the register (2023-11-14T22:13:20Z).
pub const T0: i64 = 1_700_000_000_000;

/// The HLC timestamp at physical millisecond `ms`.
pub const fn at(ms: i64) -> ClockMs {
    ClockMs::from_raw(ms << 16)
}

pub fn bounds() -> PreparationBounds {
    PreparationBounds {
        maximum: 64 * 1024 * 1024,
        deadline: Instant::now() + Duration::from_secs(30),
    }
}

pub fn prepare(
    store: &(impl Staging + ?Sized),
    identity: ContentIdentity,
    bytes: &[u8],
) -> Result<Box<dyn PreparedContent>, StoreError> {
    store.prepare_content(identity, &mut &bytes[..], bounds())
}

pub fn computed(
    store: &(impl Staging + ?Sized),
    bytes: &[u8],
) -> Result<Box<dyn PreparedContent>, StoreError> {
    prepare(store, ContentIdentity::Computed(Axis::Sha256), bytes)
}

/// A namespace created in its own published execution at `T0`.
pub fn create(store: &(impl Staging + ?Sized), name: &str) -> Result<NamespaceRef, StoreError> {
    let ns = NamespaceRef::generate(name, at(T0))?;
    let mut execution = store.begin_execution(&ns, &clock_at(at(T0))?)?;
    execution.namespace_create(None, None)?;
    execution.publish()?;
    Ok(ns)
}

/// Run `write` in one execution at `now` and publish it.
pub fn publish<T>(
    store: &(impl Staging + ?Sized),
    ns: &NamespaceRef,
    now: ClockMs,
    write: impl FnOnce(&mut dyn Execution) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    let mut execution = store.begin_execution(ns, &clock_at(now)?)?;
    let value = write(&mut *execution)?;
    execution.publish()?;
    Ok(value)
}

/// Prepare `bytes` under `identity` and install them in one published
/// execution.
pub fn install_prepared(
    store: &(impl Staging + ?Sized),
    ns: &NamespaceRef,
    identity: ContentIdentity,
    bytes: &[u8],
) -> Result<IngestResult, StoreError> {
    let prepared = prepare(store, identity, bytes)?;
    publish(store, ns, at(T0 + 1), |e| e.content_install(prepared))
}

/// Prepare `bytes` under a computed SHA-256 identity and install them.
pub fn install(
    store: &(impl Staging + ?Sized),
    ns: &NamespaceRef,
    bytes: &[u8],
) -> Result<IngestResult, StoreError> {
    install_prepared(store, ns, ContentIdentity::Computed(Axis::Sha256), bytes)
}

/// Install `bytes` as a verified record the execution holds (the path
/// records the execution produces take), in one published execution.
pub fn record(
    store: &(impl Staging + ?Sized),
    ns: &NamespaceRef,
    bytes: &[u8],
) -> Result<(Kappa, bool), StoreError> {
    let verified = VerifiedContent::compute(Axis::Sha256, bytes)?;
    let kappa = verified.kappa().clone();
    let newly = publish(store, ns, at(T0 + 1), |e| e.blob_put(&verified))?;
    Ok((kappa, newly))
}

/// Retire `kappa` in one published execution.
pub fn retire(
    store: &(impl Staging + ?Sized),
    ns: &NamespaceRef,
    kappa: &Kappa,
) -> Result<Retirement, StoreError> {
    publish(store, ns, at(T0 + 2), |e| e.content_retire(kappa))
}

/// Every payload allocation under `blob_root/objects`, sidecars excluded.
pub fn payload_files(blob_root: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut files = Vec::new();
    let objects = blob_root.join("objects");
    if !objects.exists() {
        return Ok(files);
    }
    for shard in std::fs::read_dir(&objects)? {
        let shard = shard?;
        if !shard.file_type()?.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(shard.path())? {
            let path = entry?.path();
            if path
                .extension()
                .is_none_or(|ext| ext != "chunks" && ext != "owner")
            {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

/// The one payload allocation a store holding a single external
/// representation has.
pub fn single_payload(blob_root: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let files = payload_files(blob_root)?;
    match files.as_slice() {
        [file] => Ok(file.clone()),
        other => Err(format!("expected one payload allocation, found {other:?}").into()),
    }
}

/// Every directory under `root` whose name marks staging or temporary
/// state. The replaced engines wrote `staging/`, `_staging/`, `_ingest/`
/// and `tmp/`; the preparation path has no such area.
pub fn staging_dirs(root: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if !path.is_dir() {
                continue;
            }
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            let marked = name
                .as_deref()
                .is_some_and(|n| n.contains("staging") || n.contains("ingest") || n == "tmp");
            if marked {
                found.push(path.clone());
            }
            pending.push(path);
        }
    }
    Ok(found)
}
