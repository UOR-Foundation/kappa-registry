//! Bounded maintenance of the completed-generation projections
//! (`projection`): folding completed versions, removing what abandoned
//! attempts staged, and releasing the bookkeeping that only distinguished
//! them, without changing what any reader selects.
//!
//! One step examines at most `limit` entries of `PROJECTION_LOG` from a
//! rotating cursor, in one registry write transaction:
//!
//! - an entry of the attempt in progress of its instance is left;
//! - an entry of an attempt that will never complete (a restarted or
//!   abandoned attempt) is removed with its version;
//! - an entry of a completed attempt is folded: every version of the same
//!   logical key and instance it supersedes (older completed versions, and
//!   abandoned ones) is removed, the version itself is removed when it is a
//!   tombstone (nothing older remains for it to hide), and its log entry is
//!   removed, which ends its charge on the staging capacity;
//! - an epoch with no log entry left loses its `PROJECTION_COMPLETED` row:
//!   every version that remains of it is of its completed attempt, which
//!   the instance's checkpoint then makes visible (`projection::visibility`).
//!
//! A folded tombstone of an allocation owner releases the instance's
//! ownership of the allocation; once the step commits, the allocation is
//! reclaimed if no other owner, pin or claim holds it, and by the inventory
//! sweep otherwise.

use std::sync::PoisonError;

use redb::{ReadableTable, Table, WriteTransaction};

use kappa_store::StoreError;

use crate::PersistentStore;
use crate::projection::{
    Family, Version, VersionKey, epoch_key, prefixed, split_logical, visibility,
};
use crate::projection_stage::{
    STAGED_BYTES, STAGED_ENTRIES, active_attempt, counter, set_counter, staged_size,
};
use crate::representation::AllocationId;
use crate::tables::{
    PROJECTION_ATTEMPTS, PROJECTION_COMPLETED, PROJECTION_COUNTERS, PROJECTION_INSTANCES,
    PROJECTION_LOG, PROJECTION_VERSIONS, SETTLED,
};

/// What one compaction step did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Compacted {
    /// Log entries examined.
    pub examined: u64,
    /// Versions of completed attempts folded.
    pub folded: u64,
    /// Versions removed: superseded, abandoned, or folded tombstones.
    pub removed: u64,
    /// Allocations reclaimed after the step committed.
    pub reclaimed: u64,
    /// The step reached the end of the log.
    pub complete: bool,
}

/// The tables one step works in.
struct Tables<'t> {
    versions: Table<'t, &'static [u8], &'static [u8]>,
    log: Table<'t, &'static [u8], &'static [u8]>,
    completed: Table<'t, &'static [u8], &'static [u8]>,
    settled: Table<'t, &'static [u8], &'static [u8]>,
    instances: Table<'t, &'static [u8], &'static [u8]>,
    attempts: Table<'t, &'static [u8], &'static [u8]>,
}

impl<'t> Tables<'t> {
    fn open(txn: &'t WriteTransaction) -> Result<Self, StoreError> {
        Ok(Self {
            versions: txn
                .open_table(PROJECTION_VERSIONS)
                .map_err(crate::error::redb)?,
            log: txn.open_table(PROJECTION_LOG).map_err(crate::error::redb)?,
            completed: txn
                .open_table(PROJECTION_COMPLETED)
                .map_err(crate::error::redb)?,
            settled: txn.open_table(SETTLED).map_err(crate::error::redb)?,
            instances: txn
                .open_table(PROJECTION_INSTANCES)
                .map_err(crate::error::redb)?,
            attempts: txn
                .open_table(PROJECTION_ATTEMPTS)
                .map_err(crate::error::redb)?,
        })
    }

    fn visible(&self, version: &VersionKey) -> Result<bool, StoreError> {
        Ok(visibility(&self.completed, &self.settled, &self.instances, version)?.is_some())
    }

    fn in_progress(&self, version: &VersionKey) -> Result<bool, StoreError> {
        Ok(active_attempt(&self.attempts, &version.instance)?
            == Some((version.attempt, version.epoch)))
    }

    /// Remove the version at `physical` and its log entry, if still logged.
    /// The staging charge of a version ends with its log entry.
    fn remove(&mut self, physical: &[u8], version: &VersionKey) -> Result<Removal, StoreError> {
        let removed = self
            .versions
            .remove(physical)
            .map_err(crate::error::redb)?
            .map(|value| value.value().len());
        let log_key = log_key(version);
        let logged = self
            .log
            .remove(log_key.as_slice())
            .map_err(crate::error::redb)?
            .is_some();
        Ok(Removal {
            released: match (logged, removed) {
                (true, Some(value)) => staged_size(physical.len(), value, log_key.len())?,
                _ => 0,
            },
            removed: u64::from(removed.is_some()),
            unlogged: u64::from(logged),
        })
    }

    /// Remove every version of `version`'s logical key and instance that
    /// `version` supersedes: completed versions older than it, and versions
    /// of attempts that will never complete. The attempt in progress and
    /// newer completed versions stay.
    fn supersede(&mut self, version: &VersionKey) -> Result<Removal, StoreError> {
        let mut prefix = version.logical.clone();
        prefix.extend_from_slice(&[0x00, 0x00]);
        prefix.push(version.instance.key_len());
        prefix.extend_from_slice(&version.instance.key());
        let mut stale: Vec<(Vec<u8>, VersionKey)> = Vec::new();
        for entry in prefixed(&self.versions, &prefix)? {
            let (physical, _) = entry.map_err(crate::error::redb)?;
            let other = VersionKey::decode(physical.value())?;
            if other == *version || self.in_progress(&other)? {
                continue;
            }
            let older = (other.epoch, other.sequence) < (version.epoch, version.sequence);
            if !self.visible(&other)? || older {
                stale.push((physical.value().to_vec(), other));
            }
        }
        let mut total = Removal::default();
        for (physical, other) in stale {
            total.add(self.remove(&physical, &other)?);
        }
        Ok(total)
    }

    /// Remove the completed row of `version`'s epoch once no log entry of
    /// the epoch remains.
    fn retire_completed(&mut self, version: &VersionKey) -> Result<(), StoreError> {
        let prefix = epoch_key(&version.instance, version.epoch);
        let remaining = prefixed(&self.log, &prefix)?
            .next()
            .transpose()
            .map_err(crate::error::redb)?
            .is_some();
        if !remaining {
            self.completed
                .remove(prefix.as_slice())
                .map_err(crate::error::redb)?;
        }
        Ok(())
    }
}

/// What removals released: staging bytes, versions removed, and log
/// entries removed (each ending one staged entry's charge).
#[derive(Clone, Copy, Debug, Default)]
struct Removal {
    released: u64,
    removed: u64,
    unlogged: u64,
}

impl Removal {
    const fn add(&mut self, other: Self) {
        self.released = self.released.saturating_add(other.released);
        self.removed = self.removed.saturating_add(other.removed);
        self.unlogged = self.unlogged.saturating_add(other.unlogged);
    }
}

/// What one log entry's step did.
enum Fold {
    /// Of the attempt in progress, not yet visible: left.
    Left,
    /// Never to complete, or already removed as superseded: removed.
    Removed,
    /// A completed version folded; a folded allocation owner tombstone
    /// releases the allocation it names.
    Folded(Option<AllocationId>),
}

impl Tables<'_> {
    /// Step over the log entry `key` naming the version at `physical`,
    /// accumulating what it released into `total`.
    fn fold(
        &mut self,
        key: &[u8],
        physical: &[u8],
        total: &mut Removal,
    ) -> Result<Fold, StoreError> {
        let version = VersionKey::decode(physical)?;
        if self.in_progress(&version)? && !self.visible(&version)? {
            return Ok(Fold::Left);
        }
        let value = self
            .versions
            .get(physical)
            .map_err(crate::error::redb)?
            .map(|value| Version::decode(value.value()))
            .transpose()?;
        if !self.visible(&version)? || value.is_none() {
            // Never to complete, or already removed as superseded (its log
            // entry with it): only what remains goes.
            total.add(self.remove(physical, &version)?);
            self.retire_completed(&version)?;
            return Ok(Fold::Removed);
        }
        total.add(self.supersede(&version)?);
        let mut released = None;
        if matches!(value, Some(Version::Tombstone)) {
            total.add(self.remove(physical, &version)?);
            let (family, key, member) = split_logical(&version.logical)?;
            if family == Family::AllocationOwner as u8 && member.is_some() {
                let id: [u8; 16] = key.as_slice().try_into().map_err(|_| {
                    StoreError::Internal("allocation owner key is not an allocation".into())
                })?;
                released = Some(AllocationId(id));
            }
        } else {
            // The put stays as settled state; its log entry, and with it its
            // staging charge, goes.
            let value_len = self
                .versions
                .get(physical)
                .map_err(crate::error::redb)?
                .map_or(0, |value| value.value().len());
            let logged = self.log.remove(key).map_err(crate::error::redb)?.is_some();
            if logged {
                total.add(Removal {
                    released: staged_size(physical.len(), value_len, key.len())?,
                    removed: 0,
                    unlogged: 1,
                });
            }
        }
        self.retire_completed(&version)?;
        Ok(Fold::Folded(released))
    }
}

/// Release what a step's removals ended from the staging counters, in the
/// step's transaction.
fn release_staging(txn: &WriteTransaction, total: Removal) -> Result<(), StoreError> {
    let mut counters = txn
        .open_table(PROJECTION_COUNTERS)
        .map_err(crate::error::redb)?;
    let bytes = counter(&counters, STAGED_BYTES)?
        .checked_sub(total.released)
        .ok_or_else(|| StoreError::Internal("staging bytes released below zero".into()))?;
    let entries = counter(&counters, STAGED_ENTRIES)?
        .checked_sub(total.unlogged)
        .ok_or_else(|| StoreError::Internal("staging entries released below zero".into()))?;
    set_counter(&mut counters, STAGED_BYTES, bytes)?;
    set_counter(&mut counters, STAGED_ENTRIES, entries)
}

/// The `PROJECTION_LOG` key of `version`.
fn log_key(version: &VersionKey) -> Vec<u8> {
    let mut key = epoch_key(&version.instance, version.epoch);
    key.extend_from_slice(&version.attempt.to_be_bytes());
    key.extend_from_slice(&version.sequence.to_be_bytes());
    key
}

impl PersistentStore {
    /// One bounded compaction step over at most `limit` log entries; see the
    /// module documentation.
    pub(crate) fn compact_projection(&self, limit: usize) -> Result<Compacted, StoreError> {
        let mut cursor = self
            .compaction_cursor
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut outcome = Compacted::default();
        let mut released_allocations = Vec::new();
        let txn = self.registry.begin_write().map_err(crate::error::redb)?;
        {
            let mut tables = Tables::open(&txn)?;
            let batch: Vec<(Vec<u8>, Vec<u8>)> = {
                let lower = cursor
                    .as_deref()
                    .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
                let mut batch = Vec::new();
                for entry in tables
                    .log
                    .range::<&[u8]>((lower, std::ops::Bound::Unbounded))
                    .map_err(crate::error::redb)?
                {
                    let (key, physical) = entry.map_err(crate::error::redb)?;
                    batch.push((key.value().to_vec(), physical.value().to_vec()));
                    if batch.len() >= limit {
                        break;
                    }
                }
                batch
            };
            outcome.complete = batch.len() < limit;
            let mut total = Removal::default();
            for (key, physical) in &batch {
                outcome.examined += 1;
                *cursor = Some(key.clone());
                match tables.fold(key, physical, &mut total)? {
                    Fold::Left | Fold::Removed => {}
                    Fold::Folded(released) => {
                        outcome.folded += 1;
                        released_allocations.extend(released);
                    }
                }
            }
            outcome.removed = total.removed;
            drop(tables);
            release_staging(&txn, total)?;
        }
        txn.commit().map_err(crate::error::redb)?;
        if outcome.complete {
            *cursor = None;
        }
        drop(cursor);
        for allocation in released_allocations {
            match self.reclaim_allocation(allocation) {
                Ok(crate::content_reclaim::Reclaimed::Deleted(_)) => outcome.reclaimed += 1,
                Ok(_) => {}
                Err(error) => tracing::warn!(
                    allocation = %allocation.hex(),
                    %error,
                    "released allocation left for the inventory sweep"
                ),
            }
        }
        Ok(outcome)
    }
}
