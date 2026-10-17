//! The epoch cursors settlement and recovery keep across steps
//! (`settlement_ledger`), at most one per storage instance and purpose and
//! at most `capacity` in all, each owning one activity grant of its
//! namespace until it is verified or discarded.
//!
//! Steps that read epochs run under the recovery lock, one at a time, so
//! the count checked before a cursor opens is the count when it is
//! inserted. A cursor is taken out of the map while it advances and put
//! back only when it stopped on its budget: an error drops it, and the
//! epoch is read again from its start, its consumer told to restart.

use std::collections::BTreeMap;
use std::sync::{MutexGuard, PoisonError};

use kappa_store::{EpochRoot, StoreError};

use super::ledger::{Advance, EpochCursor};
use super::stage::Staged;
use super::work::Work;
use crate::PersistentStore;
use crate::storage_instance::StorageInstance;

/// Why an epoch is being read: its consumers stage different things, so
/// each keeps its own cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Purpose {
    /// Projection into the registry, advancing `SETTLED`.
    Settle,
    /// Measurement and registration of pre-restart ownership.
    Reconstruct,
}

/// What an epoch's effects are delivered to.
pub trait EpochConsumer {
    /// The epoch is being read from its start: anything staged from an
    /// earlier read of it is stale.
    fn restart(&mut self) -> Result<(), StoreError>;

    /// One effect of the epoch, unadmitted until the read is verified.
    fn stage(&mut self, staged: Staged) -> Result<(), StoreError>;
}

/// The cursors in progress.
pub struct EpochCursors {
    by_key: BTreeMap<(StorageInstance, Purpose), EpochCursor>,
    capacity: usize,
}

impl EpochCursors {
    /// No cursor, room for `capacity`.
    pub(crate) const fn new(capacity: usize) -> Self {
        Self {
            by_key: BTreeMap::new(),
            capacity,
        }
    }
}

impl PersistentStore {
    fn cursors(&self) -> MutexGuard<'_, EpochCursors> {
        // Every update is one map insertion or removal under the lock; a
        // panic elsewhere cannot leave it half-written.
        self.epoch_cursors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Read epoch `epoch` of `instance` for `purpose` within `work`,
    /// delivering its effects to `consumer`. Returns the epoch's verified
    /// root once it is read and verified, `None` while it is not: the
    /// budget ran out, or no cursor could be opened because `capacity` are
    /// in progress or `work` does not admit one.
    pub(super) fn read_epoch(
        &self,
        instance: &StorageInstance,
        epoch: u64,
        purpose: Purpose,
        work: &mut Work,
        consumer: &mut dyn EpochConsumer,
    ) -> Result<Option<EpochRoot>, StoreError> {
        let key = (*instance, purpose);
        let held = self.cursors().by_key.remove(&key);
        let mut cursor = match held {
            Some(cursor) if cursor.epoch() == epoch => cursor,
            stale => {
                // A cursor of another epoch was overtaken; it is released
                // before another is opened.
                drop(stale);
                let full = {
                    let cursors = self.cursors();
                    cursors.by_key.len() >= cursors.capacity
                };
                if full {
                    return Ok(None);
                }
                let Some(cursor) =
                    EpochCursor::open(self, instance, epoch, self.settlement_limits, work)?
                else {
                    return Ok(None);
                };
                consumer.restart()?;
                cursor
            }
        };
        let authority = self.authority.load();
        let mut sink = |staged: Staged| consumer.stage(staged);
        match cursor.advance(self.settlement_limits, &authority, work, &mut sink)? {
            Advance::Pending => {
                self.cursors().by_key.insert(key, cursor);
                Ok(None)
            }
            Advance::Verified => Ok(Some(cursor.epoch_root().clone())),
        }
    }

    /// Discard the cursor of `instance` for `purpose`, releasing its
    /// activity grant: its position is no longer matched by what its
    /// consumer durably staged.
    pub(super) fn forget_cursor(&self, instance: &StorageInstance, purpose: Purpose) {
        let released = self.cursors().by_key.remove(&(*instance, purpose));
        // The grant ends outside the lock: ending it may evict the namespace.
        drop(released);
    }

    /// Discard every cursor of `instance`, releasing its activity grants:
    /// before its obligation is discharged, and before its storage is
    /// retired, which requires the namespace idle.
    pub(crate) fn forget_cursors(&self, instance: &StorageInstance) {
        let released: Vec<EpochCursor> = {
            let mut cursors = self.cursors();
            [Purpose::Settle, Purpose::Reconstruct]
                .into_iter()
                .filter_map(|purpose| cursors.by_key.remove(&(*instance, purpose)))
                .collect()
        };
        // Grants end outside the lock: ending one may evict the namespace.
        drop(released);
    }

    /// Discard every cursor of any instance of namespace `namespace`,
    /// releasing their activity grants, before its storage is retired:
    /// retirement requires the namespace idle, and a partly read epoch is
    /// read again from its start if the storage remains.
    pub(crate) fn forget_namespace_cursors(&self, namespace: &[u8; 16]) {
        // The guard is a temporary of this statement: the lock is released
        // once the cursors are taken out.
        let released: Vec<EpochCursor> = self
            .cursors()
            .by_key
            .extract_if(.., |(instance, _), _| instance.namespace() == namespace)
            .map(|(_, cursor)| cursor)
            .collect();
        // Grants end outside the lock: ending one may evict the namespace.
        drop(released);
    }

    /// Cursors in progress.
    #[cfg(test)]
    pub(crate) fn cursors_in_progress(&self) -> usize {
        self.cursors().by_key.len()
    }
}
