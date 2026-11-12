//! Bounded maintenance of the completed-generation projections
//! (`projection`): folding completed versions, removing what abandoned
//! attempts staged, and releasing the bookkeeping that only distinguished
//! them, without changing what any reader selects.
//!
//! One step folds the entries of `PROJECTION_LOG` its work meter admits
//! (at most `COMPACTION_BATCH`), from a cursor, in one registry write
//! transaction. Each entry is admitted with room to scan the first version
//! its fold reads (`COMPACTION_UNIT`) and folded before the next is read,
//! so reading the log never takes the allowance its folds need:
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
//! A fold the meter refuses partway through its scan keeps what it removed
//! of the versions it scanned (each removal is one the whole fold would
//! make) and leaves the entry, its tombstone and its log entry in place; the
//! next step resumes the scan after the last version scanned. Versions are
//! keyed in (epoch, attempt, sequence) order, so the scan meets the older
//! versions it supersedes first. The cursor and its within-key position are
//! installed only after the step commits.
//!
//! A folded tombstone of an allocation owner releases the instance's
//! ownership of the allocation; once the step commits, the allocation is
//! reclaimed if no other owner, pin or claim holds it and the meter admits
//! the reclamation, and by the inventory sweep otherwise.

use std::ops::Bound;
use std::sync::PoisonError;

use redb::{ReadableTable, Table, WriteTransaction};

use kappa_store::work::{Dimension, Meter};
use kappa_store::StoreError;

use crate::error::CommitFailure;
use crate::projection::visibility::visibility;
use crate::projection::{epoch_key, prefixed, split_logical, Family, Version, VersionKey};
use crate::projection_stage::{
    active_attempt, counter, set_counter, staged_size, STAGED_BYTES, STAGED_ENTRIES,
};
use crate::registry::{Attempt, RegistryWrite, Standing};
use crate::representation::AllocationId;
use crate::settlement::SettlementStop;
use crate::tables::{
    PROJECTION_ATTEMPTS, PROJECTION_COMPLETED, PROJECTION_COUNTERS, PROJECTION_INSTANCES,
    PROJECTION_LOG, PROJECTION_VERSIONS, SETTLED,
};
use crate::PersistentStore;

/// Log entries one step examines at most.
const COMPACTION_BATCH: u64 = 256;

/// The indivisible unit of compaction: one log entry and the first version
/// its fold scans; the floor a step's compaction part is given
/// (`settlement_work::part_cap`).
pub(crate) fn compaction_unit() -> kappa_store::work::Work {
    kappa_store::work::Work::default().with(Dimension::Entries, 2)
}

/// Where the next compaction step starts: after the last log entry a
/// committed step finished, and, when a committed step folded the next
/// entry partway, after the last version of its key that step scanned.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CompactionCursor {
    after: Option<Vec<u8>>,
    // A partial fold may have verified its target without scanning a row.
    // Keep that progress too, so a small step does not repeat visibility.
    within: Option<(Vec<u8>, Option<Vec<u8>>)>,
}

impl CompactionCursor {
    /// The next step starts at the start of the log.
    pub(crate) const fn at_start(&self) -> bool {
        self.after.is_none() && self.within.is_none()
    }

    /// A committed step left an entry folded partway.
    #[cfg(test)]
    pub(crate) const fn within_key(&self) -> bool {
        self.within.is_some()
    }
}

/// Why one compaction step stopped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FoldStop {
    /// The traversal reached the end of the log.
    #[default]
    End,
    /// The step examined `COMPACTION_BATCH` entries; the traversal continues
    /// from where it stopped and the meter may admit more.
    BatchLimit,
    /// The meter refused the next entry, or the rest of a fold's scan.
    Budget,
}

/// What one compaction step did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Compacted {
    /// Log entries examined to the end of their fold.
    pub examined: u64,
    /// Versions of completed attempts folded.
    pub folded: u64,
    /// Versions removed: superseded, abandoned, or folded tombstones.
    pub removed: u64,
    /// Staging bytes the step's committed removals released.
    pub released_bytes: u64,
    /// Allocations reclaimed after the step committed.
    pub reclaimed: u64,
    /// Why the step stopped.
    pub stopped: FoldStop,
    /// The step began at the start of the log: with `stopped == End`, it
    /// examined every entry the log held.
    pub from_start: bool,
    /// The step reached the end of the log.
    pub complete: bool,
}

/// What one folding step for a publication's epoch pressure found.
pub(crate) enum PressureFold {
    /// The step committed (see [`Compacted`]); its continuation is
    /// installed.
    Committed(Compacted),
    /// Nothing is known folded: the compaction cursor (`CompactionBusy`) or
    /// the registry writer (`RegistryBusy`) is held elsewhere, or a registry
    /// commit's outcome is unknown, before or by this step
    /// (`RegistryRecoveryRequired`).
    Deferred(SettlementStop),
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

/// A fold's scan of the versions it supersedes: the removals it made, and
/// whether it reached the end of the key, or else the last version it
/// scanned (`None` when the meter refused the first).
struct Superseded {
    removal: Removal,
    stopped_after: Option<Option<Vec<u8>>>,
}

impl<'t> Tables<'t> {
    fn open(txn: &'t WriteTransaction) -> Result<Self, StoreError> {
        let open = |table| txn.open_table(table).map_err(crate::error::redb);
        Ok(Self {
            versions: open(PROJECTION_VERSIONS)?,
            log: open(PROJECTION_LOG)?,
            completed: open(PROJECTION_COMPLETED)?,
            settled: open(SETTLED)?,
            instances: open(PROJECTION_INSTANCES)?,
            attempts: open(PROJECTION_ATTEMPTS)?,
        })
    }

    fn visible(&self, version: &VersionKey, work: &mut dyn Meter) -> Result<bool, StoreError> {
        Ok(visibility(
            &self.completed,
            &self.settled,
            &self.instances,
            version,
            work,
        )?
        .is_some())
    }

    fn in_progress(&self, version: &VersionKey) -> Result<bool, StoreError> {
        Ok(active_attempt(&self.attempts, &version.instance)?
            == Some((version.attempt, version.epoch)))
    }

    /// The first log entry after `after`, read into memory so the fold that
    /// follows may change the log.
    fn next_entry(&self, after: Option<&[u8]>) -> Result<Option<(Vec<u8>, Vec<u8>)>, StoreError> {
        let lower = after.map_or(Bound::Unbounded, Bound::Excluded);
        let mut range = self
            .log
            .range::<&[u8]>((lower, Bound::Unbounded))
            .map_err(crate::error::redb)?;
        let entry = range.next().transpose().map_err(crate::error::redb)?;
        Ok(entry.map(|(key, physical)| (key.value().to_vec(), physical.value().to_vec())))
    }

    /// Remove the version at `physical` and its log entry, if still logged.
    /// The staging charge of a version ends with its log entry.
    fn remove(&mut self, physical: &[u8], version: &VersionKey) -> Result<Removal, StoreError> {
        let removed = self
            .versions
            .remove(physical)
            .map_err(crate::error::redb)?
            .map(|value| value.value().len());
        let log_key = compact_log_key(version);
        let logged = self
            .log
            .remove(log_key.as_slice())
            .map_err(crate::error::redb)?
            .is_some();
        Ok(Removal {
            released: match (logged, removed) {
                (true, Some(value)) => {
                    staged_size(physical.len() as u64, value as u64, log_key.len() as u64)?
                }
                _ => 0,
            },
            removed: u64::from(removed.is_some()),
            unlogged: u64::from(logged),
        })
    }

    /// Remove every version of `version`'s logical key and instance that
    /// `version` supersedes, scanning after `resume` when a committed step
    /// scanned up to it: completed versions older than it, and versions of
    /// attempts that will never complete. The attempt in progress and newer
    /// completed versions stay. Every version scanned is charged to `work`
    /// before it is read; what the scan found stale before a refusal is
    /// removed.
    fn supersede(
        &mut self,
        version: &VersionKey,
        resume: Option<&[u8]>,
        work: &mut dyn Meter,
    ) -> Result<Superseded, StoreError> {
        let mut prefix = version.logical.clone();
        prefix.extend_from_slice(&[0x00, 0x00]);
        prefix.push(version.instance.key_len());
        prefix.extend_from_slice(&version.instance.key());
        let mut stale: Vec<(Vec<u8>, VersionKey)> = Vec::new();
        let mut scanned = None;
        let mut stopped_after = None;
        for entry in prefixed(&self.versions, &prefix, resume, work)? {
            if work.charge(Dimension::Entries, 1).is_err() {
                stopped_after = Some(scanned.take());
                break;
            }
            let (physical, _) = entry?;
            scanned = Some(physical.value().to_vec());
            let other = VersionKey::decode(physical.value())?;
            if other == *version || self.in_progress(&other)? {
                continue;
            }
            let older = (other.epoch, other.sequence) < (version.epoch, version.sequence);
            if !self.visible(&other, work)? || older {
                stale.push((physical.value().to_vec(), other));
            }
        }
        let mut removal = Removal::default();
        for (physical, other) in stale {
            removal.add(self.remove(&physical, &other)?);
        }
        Ok(Superseded {
            removal,
            stopped_after,
        })
    }

    /// Remove the completed row of `version`'s epoch once no log entry of
    /// the epoch remains.
    fn retire_completed(
        &mut self,
        version: &VersionKey,
        work: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let prefix = epoch_key(&version.instance, version.epoch)?;
        let remaining = prefixed(&self.log, &prefix, None, work)?
            .next()
            .transpose()?
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
    /// The meter refused the rest of the scan of what it supersedes: what
    /// the scan found stale is removed, the entry stays, and a later step
    /// resumes after the last version scanned (`None`: none was).
    Partial(Option<Vec<u8>>),
}

impl Tables<'_> {
    /// Step over the log entry `key` naming the version at `physical`,
    /// accumulating what it released into `total`, scanning what it
    /// supersedes on `work` after `resume`.
    fn fold(
        &mut self,
        key: &[u8],
        physical: &[u8],
        resume: Option<&[u8]>,
        target_verified: bool,
        total: &mut Removal,
        work: &mut dyn Meter,
    ) -> Result<Fold, StoreError> {
        let version = VersionKey::decode(physical)?;
        let visible = target_verified || self.visible(&version, work)?;
        if self.in_progress(&version)? && !visible {
            return Ok(Fold::Left);
        }
        let value = self
            .versions
            .get(physical)
            .map_err(crate::error::redb)?
            .map(|value| Version::decode(value.value()))
            .transpose()?;
        if !visible || value.is_none() {
            // Never to complete, or already removed as superseded (its log
            // entry with it): only what remains goes.
            total.add(self.remove(physical, &version)?);
            self.retire_completed(&version, work)?;
            return Ok(Fold::Removed);
        }
        let superseded = self.supersede(&version, resume, work)?;
        total.add(superseded.removal);
        if let Some(scanned) = superseded.stopped_after {
            return Ok(Fold::Partial(scanned));
        }
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
            if self.log.remove(key).map_err(crate::error::redb)?.is_some() {
                total.add(Removal {
                    released: staged_size(
                        physical.len() as u64,
                        value_len as u64,
                        key.len() as u64,
                    )?,
                    removed: 0,
                    unlogged: 1,
                });
            }
        }
        self.retire_completed(&version, work)?;
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

/// The `PROJECTION_LOG` key of `version`, built without going through
/// the fallible `log_key` that allocates at a checked length: compaction
/// knows the key exists and builds it inline.
fn compact_log_key(version: &VersionKey) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + usize::from(version.instance.key_len()) + 8 + 4 + 8);
    key.push(version.instance.key_len());
    version.instance.append_key(&mut key);
    key.extend_from_slice(&version.epoch.to_be_bytes());
    key.extend_from_slice(&version.attempt.to_be_bytes());
    key.extend_from_slice(&version.sequence.to_be_bytes());
    key
}

/// What one folding step committed, with the allocations its folded owner
/// tombstones released for reclamation.
struct CompactedBatch {
    outcome: Compacted,
    released: Vec<AllocationId>,
}

impl PersistentStore {
    /// One bounded compaction step on `work`; see the module documentation.
    /// The compaction cursor is taken before the registry writer, each
    /// waited for. Each released allocation is reclaimed only when `work`
    /// admits the reclamation; an allocation not reclaimed is left to the
    /// inventory, which decides it the same way. `RecoveryRequired` when a
    /// registry commit's outcome is unknown, before or by this step:
    /// nothing is known folded, and only a reopen decides what persisted.
    pub(crate) fn compact_projection(
        &self,
        work: &mut dyn Meter,
    ) -> Result<Standing<Compacted>, StoreError> {
        let mut cursor = self
            .compaction_cursor
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Standing::Ready(txn) = self.registry.write_standing()? else {
            return Ok(Standing::RecoveryRequired);
        };
        let Standing::Ready(CompactedBatch {
            mut outcome,
            released,
        }) = self.compact_projection_in(txn, &mut cursor, work)?
        else {
            return Ok(Standing::RecoveryRequired);
        };
        drop(cursor);
        let reclamation = self.inventory_entry_charge();
        for allocation in released {
            if work.charge_all(&reclamation).is_err() {
                break;
            }
            match self.reclaim_allocation(allocation, work) {
                Ok(crate::content_reclaim::Reclaimed::Deleted(_)) => outcome.reclaimed += 1,
                Ok(_) => {}
                Err(error) => tracing::warn!(
                    allocation = %allocation.hex(),
                    %error,
                    "released allocation left for the inventory sweep"
                ),
            }
        }
        Ok(Standing::Ready(outcome))
    }

    /// One bounded folding step for a publication's epoch pressure: the
    /// compaction cursor and the registry writer are each taken without
    /// waiting, and nothing is folded while either is held elsewhere.
    /// Allocations it releases are left to the inventory, which decides
    /// them as it decides every allocation.
    pub(crate) fn compact_for_pressure(
        &self,
        work: &mut dyn Meter,
    ) -> Result<PressureFold, StoreError> {
        let mut cursor = match self.compaction_cursor.try_lock() {
            Ok(cursor) => cursor,
            Err(std::sync::TryLockError::WouldBlock) => {
                return Ok(PressureFold::Deferred(SettlementStop::CompactionBusy));
            }
            // The cursor is written whole under the lock; a panic elsewhere
            // cannot leave it half-written.
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        };
        let txn = match self.registry.try_begin_write()? {
            Attempt::Ready(txn) => txn,
            Attempt::Busy => return Ok(PressureFold::Deferred(SettlementStop::RegistryBusy)),
            Attempt::RecoveryRequired => {
                return Ok(PressureFold::Deferred(
                    SettlementStop::RegistryRecoveryRequired,
                ));
            }
        };
        Ok(match self.compact_projection_in(txn, &mut cursor, work)? {
            Standing::Ready(batch) => PressureFold::Committed(batch.outcome),
            Standing::RecoveryRequired => {
                PressureFold::Deferred(SettlementStop::RegistryRecoveryRequired)
            }
        })
    }

    /// The one folding step, in `txn` from `cursor`: the next position is
    /// computed while folding and installed in `cursor` only after `txn`
    /// committed. A commit known not to have happened leaves `cursor` as it
    /// was and returns its error; after a commit of unknown outcome the
    /// registry is recovery-required, `cursor` is left as it was, and only
    /// a reopen decides what persisted. Neither offers an allocation for
    /// reclamation.
    fn compact_projection_in(
        &self,
        txn: RegistryWrite,
        cursor: &mut CompactionCursor,
        work: &mut dyn Meter,
    ) -> Result<Standing<CompactedBatch>, StoreError> {
        let mut outcome = Compacted {
            from_start: cursor.at_start(),
            ..Compacted::default()
        };
        let mut released_allocations = Vec::new();
        let mut proposed = cursor.clone();
        {
            let mut tables = Tables::open(&txn)?;
            let mut total = Removal::default();
            let stopped = loop {
                if outcome.examined >= COMPACTION_BATCH {
                    break FoldStop::BatchLimit;
                }
                if work.admits(&compaction_unit().as_bound()).is_err()
                    || work.charge(Dimension::Entries, 1).is_err()
                {
                    break FoldStop::Budget;
                }
                let Some((key, physical)) = tables.next_entry(proposed.after.as_deref())? else {
                    break FoldStop::End;
                };
                let retained = proposed.within.take().filter(|(entry, _)| *entry == key);
                let target_verified = retained.is_some();
                let resume = retained.and_then(|(_, scanned)| scanned);
                match tables.fold(
                    &key,
                    &physical,
                    resume.as_deref(),
                    target_verified,
                    &mut total,
                    work,
                )? {
                    Fold::Partial(scanned) => {
                        // Progress within the key is what the scan reached;
                        // a scan refused at its first version keeps the
                        // position it resumed from.
                        proposed.within = Some((key, scanned.or(resume)));
                        break FoldStop::Budget;
                    }
                    Fold::Left | Fold::Removed => {}
                    Fold::Folded(released) => {
                        outcome.folded += 1;
                        released_allocations.extend(released);
                    }
                }
                outcome.examined += 1;
                proposed.after = Some(key);
            };
            outcome.stopped = stopped;
            outcome.complete = stopped == FoldStop::End;
            outcome.removed = total.removed;
            outcome.released_bytes = total.released;
            drop(tables);
            release_staging(&txn, total)?;
        }
        match txn.commit() {
            Ok(()) => {
                *cursor = if outcome.complete {
                    CompactionCursor::default()
                } else {
                    proposed
                };
                Ok(Standing::Ready(CompactedBatch {
                    outcome,
                    released: released_allocations,
                }))
            }
            Err(CommitFailure::Known(error)) => Err(error),
            Err(CommitFailure::Unknown(error)) => {
                tracing::error!(%error, "compaction commit outcome unknown; the registry requires recovery");
                Ok(Standing::RecoveryRequired)
            }
        }
    }
}
