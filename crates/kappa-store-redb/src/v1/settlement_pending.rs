//! The durable pending set and checkpoint reads of settlement.
//!
//! `settlement/pending/{instance}` entries name the storage instances
//! whose head may be past the registry's checkpoint; `SETTLED` holds each
//! instance's checkpoint; `SETTLEMENT_PASS` records that the recovery
//! enumeration since open finished. Every entry and checkpoint names the
//! storage instance (`storage_instance`), so an obligation of one instance
//! is never discharged by, or applied to, another instance of the same
//! namespace. See `settlement.rs` and `settlement_recovery.rs` for how they
//! are used.

use std::fs::ReadDir;
use std::path::PathBuf;

use redb::ReadableDatabase;

use kappa_store::{Kappa, StoreError};

use crate::storage_instance::StorageInstance;
use crate::tables::{SETTLED, SETTLEMENT_PASS};
use crate::{PersistentStore, creation_intent};

const PASS_KEY: &[u8] = b"pass";

/// The checkpoint value: `[epoch_number:8 BE][root key_bytes]`.
pub(super) fn checkpoint(epoch_number: u64, root: &Kappa) -> Vec<u8> {
    let key = root.key_bytes();
    let mut value = Vec::with_capacity(8 + key.len());
    value.extend_from_slice(&epoch_number.to_be_bytes());
    value.extend_from_slice(&key);
    value
}

pub(super) fn decode_checkpoint(value: &[u8]) -> Result<(u64, Kappa), StoreError> {
    if value.len() < 9 {
        return Err(StoreError::Internal(
            "malformed settlement checkpoint".into(),
        ));
    }
    let number = u64::from_be_bytes(
        value[..8]
            .try_into()
            .map_err(|_| StoreError::Internal("settlement checkpoint number".into()))?,
    );
    Ok((number, Kappa::from_key_bytes(&value[8..])?))
}

/// The instance a pending entry names.
pub(super) fn marker_instance(entry: &std::fs::DirEntry) -> Result<StorageInstance, StoreError> {
    let name = entry.file_name();
    let name = name.to_str().ok_or_else(|| {
        StoreError::Internal(format!(
            "pending settlement entry {} is not a storage instance",
            entry.path().display()
        ))
    })?;
    StorageInstance::from_hex(name)
}

impl PersistentStore {
    fn pending_dir(&self) -> PathBuf {
        self.namespaces.root().join("settlement").join("pending")
    }

    fn pending_entry(&self, instance: &StorageInstance) -> PathBuf {
        self.pending_dir().join(instance.hex())
    }

    /// Record durably that `instance` has, or is about to have, epochs past
    /// its checkpoint. Called by the namespace's controller under its
    /// writer gate before the commit, and by a creation before it claims
    /// its alias. Idempotent.
    ///
    /// The marker takes over recovery ownership of the instance from its
    /// creation intent (`creation_intent`): the intent is removed only once
    /// the marker is durable, on every call, so a retried creation hands
    /// over the intent its earlier attempt left and no storage is ever
    /// owned by neither.
    pub(crate) fn mark_unsettled(&self, instance: &StorageInstance) -> Result<(), StoreError> {
        let dir = self.pending_dir();
        std::fs::create_dir_all(&dir)?;
        let entry = self.pending_entry(instance);
        if !entry.exists() {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(&entry)?;
            file.sync_all()?;
            drop(file);
            std::fs::File::open(&dir)?.sync_all()?;
        }
        creation_intent::complete(self.namespaces.root(), instance)
    }

    /// Remove the pending entry of `instance`, and no other instance's.
    /// Callers hold the evidence that discharges it: the instance settled
    /// to its head, or proven never committed, under its writer gate; or
    /// its storage absent under a matching recorded retirement.
    pub(super) fn clear_unsettled(&self, instance: &StorageInstance) -> Result<(), StoreError> {
        match std::fs::remove_file(self.pending_entry(instance)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(StoreError::Io(error)),
        }
        std::fs::File::open(self.pending_dir())?.sync_all()?;
        Ok(())
    }

    /// Whether a pending entry of exactly `instance` exists.
    pub(super) fn has_pending(&self, instance: &StorageInstance) -> bool {
        self.pending_entry(instance).exists()
    }

    /// A traversal of the pending entries, or `None` when there are none
    /// (the directory was never created). Consumed incrementally by the
    /// recovery driver (`settlement_recovery`).
    pub(super) fn pending_traversal(&self) -> Result<Option<ReadDir>, StoreError> {
        match std::fs::read_dir(self.pending_dir()) {
            Ok(entries) => Ok(Some(entries)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(StoreError::Io(error)),
        }
    }

    /// The namespaces with a pending entry, in identity order, each once.
    #[cfg(test)]
    pub(crate) fn pending_settlements(&self) -> Result<Vec<[u8; 16]>, StoreError> {
        let mut ids = Vec::new();
        if let Some(entries) = self.pending_traversal()? {
            for entry in entries {
                ids.push(*marker_instance(&entry?)?.namespace());
            }
        }
        ids.sort_unstable();
        ids.dedup();
        Ok(ids)
    }

    /// The settlement checkpoint of `instance`: the last epoch whose effects
    /// the registry holds, or `None` when none was settled.
    pub(crate) fn settled_epoch(
        &self,
        instance: &StorageInstance,
    ) -> Result<Option<(u64, Kappa)>, StoreError> {
        let txn = self.registry.begin_read().map_err(crate::error::redb)?;
        let table = txn.open_table(SETTLED).map_err(crate::error::redb)?;
        table
            .get(instance.key().as_slice())
            .map_err(crate::error::redb)?
            .map(|value| decode_checkpoint(value.value()))
            .transpose()
    }

    /// Whether the recovery enumeration since open finished: every pending
    /// entry present at open was visited and settled, classified, or handed
    /// to an owned obligation. Not a statement that discovery is complete
    /// (`discovery_coverage`); an operator signal.
    pub fn settlement_pass_complete(&self) -> Result<bool, StoreError> {
        let txn = self.registry.begin_read().map_err(crate::error::redb)?;
        let table = txn
            .open_table(SETTLEMENT_PASS)
            .map_err(crate::error::redb)?;
        let passed = table
            .get(PASS_KEY)
            .map_err(crate::error::redb)?
            .is_some_and(|value| value.value() == [1u8]);
        drop(txn);
        Ok(passed)
    }

    pub(crate) fn set_settlement_pass(&self, complete: bool) -> Result<(), StoreError> {
        let txn = self.registry.begin_write().map_err(crate::error::redb)?;
        txn.open_table(SETTLEMENT_PASS)
            .map_err(crate::error::redb)?
            .insert(PASS_KEY, &[u8::from(complete)][..])
            .map_err(crate::error::redb)?;
        txn.commit().map_err(crate::error::redb)
    }
}
