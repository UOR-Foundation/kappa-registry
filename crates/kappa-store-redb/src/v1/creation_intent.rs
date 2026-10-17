//! Durable intents of namespace storage creation.
//!
//! A creation writes `settlement/creating/{instance}` (file and directory
//! entry synced) before it creates the instance's storage
//! (`NamespaceController::open`). The intent owns the instance for recovery
//! until the instance's pending marker is durable: `mark_unsettled` removes
//! it after writing the marker, on every call, so a retried creation hands
//! over the intent an earlier attempt left. Every publication marks its
//! instance before it commits, so storage that an intent still owns never
//! held a publication this protocol committed. An intent that remains names
//! storage a creation may have left with no marker and no claim naming it.
//! Recovery visits every intent (`settlement_recovery`): a marker of the
//! instance completes the handoff; readable storage of exactly that
//! instance holding no epoch is retired under the namespace's exclusion;
//! no storage at all leaves nothing to clean; storage that cannot be read
//! is an unresolved obligation, never removed on its size or state alone.
//! Storage of another instance is never touched for an intent.

use std::path::{Path, PathBuf};

use kappa_store::StoreError;

use crate::storage_instance::StorageInstance;

/// The directory holding creation intents under the namespaces root.
pub fn directory(root: &Path) -> PathBuf {
    root.join("settlement").join("creating")
}

fn entry(root: &Path, instance: &StorageInstance) -> PathBuf {
    directory(root).join(instance.hex())
}

/// Record durably that `instance` is about to be created, or, for storage a
/// proven-empty creation leaves, that the intent owns it again until it is
/// retired. Idempotent.
pub fn record(root: &Path, instance: &StorageInstance) -> Result<(), StoreError> {
    let dir = directory(root);
    let mut missing = Vec::new();
    let mut probe = Some(dir.as_path());
    while let Some(path) = probe {
        if path.exists() || !path.starts_with(root) {
            break;
        }
        missing.push(path.to_path_buf());
        probe = path.parent();
    }
    std::fs::create_dir_all(&dir)?;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(entry(root, instance))?;
    file.sync_all()?;
    drop(file);
    std::fs::File::open(&dir)?.sync_all()?;
    // Every directory this call created has a new entry in its parent.
    for path in missing {
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
    }
    Ok(())
}

/// A traversal of the remaining intents, or `None` when there are none
/// (the directory was never created). Consumed incrementally by recovery.
pub fn traversal(root: &Path) -> Result<Option<std::fs::ReadDir>, StoreError> {
    match std::fs::read_dir(directory(root)) {
        Ok(entries) => Ok(Some(entries)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(StoreError::Io(error)),
    }
}

/// The instance an intent entry names.
pub fn instance(entry: &std::fs::DirEntry) -> Result<StorageInstance, StoreError> {
    let name = entry.file_name();
    let name = name.to_str().ok_or_else(|| {
        StoreError::Internal(format!(
            "creation intent {} is not a storage instance",
            entry.path().display()
        ))
    })?;
    StorageInstance::from_hex(name)
}

/// Remove the intent of `instance`: its storage is created and locatable,
/// or recovery resolved what it left. Removing an absent intent succeeds.
pub fn complete(root: &Path, instance: &StorageInstance) -> Result<(), StoreError> {
    match std::fs::remove_file(entry(root, instance)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(StoreError::Io(error)),
    }
    std::fs::File::open(directory(root))?.sync_all()?;
    Ok(())
}
