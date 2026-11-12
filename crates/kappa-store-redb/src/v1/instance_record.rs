//! Durable records recovery owns: one file per storage instance, named by
//! the instance, in the directory of its kind under the namespaces root.
//! A presence marker carries no data, its presence being the whole record;
//! a custody record carries the retained publication it answers for.
//!
//! - [`Kind::Creating`] (`settlement/creating/{instance}`): a creation
//!   intent. A creation writes it before it creates the instance's storage
//!   (`NamespaceController::open`). The intent owns the instance for
//!   recovery until the instance's pending marker is durable:
//!   `mark_unsettled` completes it after writing the marker, on every call,
//!   so a retried creation hands over the intent an earlier attempt left.
//!   Every publication marks its instance before it commits, so storage
//!   that an intent still owns never held a publication this protocol
//!   committed. An intent that remains names storage a creation may have
//!   left with no marker and no claim naming it. Recovery visits every
//!   intent (`settlement_visits::visit_intent`): a marker of the instance
//!   completes the handoff; readable storage of exactly that instance
//!   holding no epoch is retired under the namespace's exclusion; no
//!   storage at all leaves nothing to clean; storage that cannot be read is
//!   an unresolved obligation, never removed on its size or state alone.
//!   Storage of another instance is never touched for an intent.
//! - [`Kind::Pending`] (`settlement/pending/{instance}`): a pending marker.
//!   The instance has, or is about to have, epochs past its settlement
//!   checkpoint (`settlement_pending`).
//! - [`Kind::Custody`] (`settlement/custody/{instance}`): the custody record
//!   of a publication whose signing coordinate is consumed and which is not
//!   known to have committed (`custody`). Its bytes are written whole by
//!   [`Kind::store`], replacing any earlier record atomically, under the
//!   instance's writer gate; its directory also holds that store's
//!   transient staging files (`{instance}.staged.{random}`), which no
//!   traversal of the presence kinds meets.
//!
//! Durability, on every call whatever the filesystem shows: [`Kind::record`]
//! syncs the marker file and every directory from the kind's directory up
//! to and including the namespaces root, so the marker's entry and the
//! entry of every directory above it are durable when it returns, however
//! an earlier or concurrent call that created any of them ended.
//! [`Kind::complete`] syncs the kind's directory after the marker is gone,
//! including when an earlier call already removed it, so a removal whose
//! sync failed is durable once a later call returns. [`Kind::holds`]
//! reports an inspection failure as an error, never as absence.

use std::fs::{DirEntry, ReadDir};
use std::path::{Path, PathBuf};

use kappa_store::StoreError;

use crate::storage_instance::StorageInstance;

/// The infix of a staging file's name, between the instance it stages a
/// record of and its random suffix. An instance name holds only hex
/// digits, so no record is ever named like a staging file.
const STAGED: &str = ".staged.";

/// What a marker says about its instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A creation intent.
    Creating,
    /// A pending settlement marker.
    Pending,
    /// A retained publication's custody record.
    Custody,
}

impl Kind {
    const fn name(self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Pending => "pending",
            Self::Custody => "custody",
        }
    }

    /// Store `bytes` as this kind's record of `instance`, durably and
    /// whole: written to a staging file of its own beside it (created
    /// exclusively, owner-only, under a fresh random name) and synced,
    /// renamed over the record, and every directory from the kind's up to
    /// the namespaces root synced, so a crash leaves either the earlier
    /// record or this one. The caller holds the instance's writer gate, the
    /// one exclusion every writer of a data-bearing record takes; staging
    /// files an earlier, interrupted store left are removed under it.
    pub fn store(
        self,
        root: &Path,
        instance: &StorageInstance,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        let dir = self.directory(root);
        std::fs::create_dir_all(&dir)?;
        self.remove_staged(root, instance)?;
        let mut suffix = [0u8; 16];
        getrandom::fill(&mut suffix)
            .map_err(|error| StoreError::Internal(format!("staging name: {error}")))?;
        let staged = dir.join(format!("{}{STAGED}{}", instance.hex(), hex::encode(suffix)));
        let mut file = crate::allocation::private_create_new().open(&staged)?;
        std::io::Write::write_all(&mut file, bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&staged, self.entry(root, instance))?;
        sync_directories(&dir, root)
    }

    /// Remove every staging file of `instance`'s record in this kind's
    /// directory.
    fn remove_staged(self, root: &Path, instance: &StorageInstance) -> Result<(), StoreError> {
        let prefix = format!("{}{STAGED}", instance.hex());
        let Some(entries) = self.traversal(root)? else {
            return Ok(());
        };
        for entry in entries {
            let entry = entry?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(&prefix))
            {
                match std::fs::remove_file(entry.path()) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(StoreError::Io(error)),
                }
            }
        }
        Ok(())
    }

    /// This kind's record of `instance`, or `None` when none is held. A
    /// record longer than `limit` is refused before it is read, and a
    /// failure to read it is an error, never absence.
    pub fn load(
        self,
        root: &Path,
        instance: &StorageInstance,
        limit: u64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let file = match std::fs::File::open(self.entry(root, instance)) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(StoreError::Io(error)),
        };
        let length = file.metadata()?.len();
        if length > limit {
            return Err(StoreError::CapacityExceeded(format!(
                "{} record of {instance} holds {length} bytes, above its limit {limit}",
                self.name()
            )));
        }
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::Read::take(file, limit + 1), &mut bytes)?;
        if bytes.len() as u64 > limit {
            return Err(StoreError::CapacityExceeded(format!(
                "{} record of {instance} grew above its limit {limit} while read",
                self.name()
            )));
        }
        Ok(Some(bytes))
    }

    /// The directory holding this kind's markers under the namespaces root.
    pub fn directory(self, root: &Path) -> PathBuf {
        root.join("settlement").join(self.name())
    }

    fn entry(self, root: &Path, instance: &StorageInstance) -> PathBuf {
        self.directory(root).join(instance.hex())
    }

    /// Record durably this kind's fact about `instance` (see the module
    /// documentation). Idempotent.
    pub fn record(self, root: &Path, instance: &StorageInstance) -> Result<(), StoreError> {
        let dir = self.directory(root);
        std::fs::create_dir_all(&dir)?;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.entry(root, instance))?;
        file.sync_all()?;
        drop(file);
        sync_directories(&dir, root)
    }

    /// Remove this kind's marker of `instance` durably: what it answered
    /// for is resolved or owned by another record. The directory is synced
    /// whether this call or an earlier one removed the marker; a directory
    /// that does not exist never held one.
    pub fn complete(self, root: &Path, instance: &StorageInstance) -> Result<(), StoreError> {
        match std::fs::remove_file(self.entry(root, instance)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(StoreError::Io(error)),
        }
        match std::fs::File::open(self.directory(root)) {
            Ok(directory) => Ok(directory.sync_all()?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(StoreError::Io(error)),
        }
    }

    /// Whether this kind's marker of exactly `instance` exists. A failure to
    /// inspect it is an error: an undetermined marker is neither present nor
    /// absent.
    pub fn holds(self, root: &Path, instance: &StorageInstance) -> Result<bool, StoreError> {
        Ok(self.entry(root, instance).try_exists()?)
    }

    /// A traversal of this kind's markers, or `None` when there are none
    /// (the directory was never created). Consumed incrementally by
    /// recovery.
    pub fn traversal(self, root: &Path) -> Result<Option<ReadDir>, StoreError> {
        match std::fs::read_dir(self.directory(root)) {
            Ok(entries) => Ok(Some(entries)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(StoreError::Io(error)),
        }
    }
}

/// The instance a marker entry of any kind names.
pub fn is_staged(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .is_some_and(|name| name.contains(STAGED))
}

/// The instance a marker entry of any kind names.
pub fn instance(entry: &DirEntry) -> Result<StorageInstance, StoreError> {
    let name = entry.file_name();
    let name = name.to_str().ok_or_else(|| {
        StoreError::Internal(format!(
            "durable marker {} is not a storage instance",
            entry.path().display()
        ))
    })?;
    StorageInstance::from_hex(name)
}

/// Sync `directory` and every directory above it up to and including
/// `root`, so the entries made beneath `root` survive a crash.
pub fn sync_directories(directory: &Path, root: &Path) -> Result<(), StoreError> {
    let mut current = Some(directory);
    while let Some(path) = current {
        std::fs::File::open(path)?.sync_all()?;
        if path == root {
            break;
        }
        current = path.parent().filter(|parent| parent.starts_with(root));
    }
    Ok(())
}
