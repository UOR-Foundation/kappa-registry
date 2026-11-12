//! Staging one settlement attempt's projection rows and completing it
//! (`projection`).
//!
//! An attempt is begun for an (instance, epoch) each time the epoch is read
//! from its start (`begin_attempt`), in its own registry transaction: the
//! attempt number is never reused, so whatever an earlier attempt of the
//! epoch staged stays invisible for good. A [`ProjectionStage`] writes the
//! attempt's versions inside the registry write transaction of one
//! settlement step, each with its log entry and counted against the staging
//! capacity; the step's transaction commits what it staged whether or not
//! the epoch finished. When the epoch is verified, [`ProjectionStage::complete`]
//! records the attempt as the epoch's completed attempt in the transaction
//! that also advances `SETTLED`, so a reader sees all of the epoch's rows
//! or none of them.

use std::ops::ControlFlow;

use redb::{ReadableTable, Table, WriteTransaction};

use kappa_store::StoreError;
use kappa_store::work::{Dimension, Meter, Work, reserve_charged};

use crate::PersistentStore;
use crate::projection::reduce::{Emit, Reduced, Reduction, reduce_groups, undelivered};
use crate::projection::visibility::visibility;
use crate::projection::{
    END, Family, MAX_LOG_KEY_BYTES, Version, VersionKey, VersionRef, attempt_prefix,
    attempt_prefix_len, epoch_key, key_prefix, key_prefix_len, log_key, log_key_len, logical,
    logical_len, prefixed, prefixed_cost, version_key, version_key_len, zeroed,
};
use crate::settlement::SettlementLimits;
use crate::storage_instance::StorageInstance;
use crate::tables::{
    PROJECTION_ATTEMPTS, PROJECTION_COMPLETED, PROJECTION_COUNTERS, PROJECTION_INSTANCES,
    PROJECTION_LOG, PROJECTION_VERSIONS, SETTLED,
};

const COMPLETION: &[u8] = b"completion";
pub const STAGED_BYTES: &[u8] = b"staged-bytes";
pub const STAGED_ENTRIES: &[u8] = b"staged-entries";
/// The largest settlement record limit successfully established for this
/// registry (`PersistentStore::establish_version_bounds`, `store_open`).
pub(crate) const VERSION_RECORD_BYTES: &[u8] = b"version-record-bytes";

/// Bytes of a counter row's value: one big-endian `u64`.
const COUNTER_BYTES: u64 = 8;

/// Bytes one staged version holds until compaction folds or removes it,
/// from the lengths of its physical key, value and log key: its key in the
/// version table and its log value, its value, and its log key. Charged
/// when the version is staged and released when its log entry is removed,
/// so the counters hold exactly the versions still logged.
pub fn staged_size(physical: u64, value: u64, log_key: u64) -> Result<u64, StoreError> {
    physical
        .checked_mul(2)
        .and_then(|keys| keys.checked_add(value))
        .and_then(|size| size.checked_add(log_key))
        .ok_or_else(|| StoreError::Internal("projection version size exceeds u64".into()))
}

/// The projection counter at `key`, `None` when it was never written: the
/// one decoding of a counter row.
pub(crate) fn stored(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    key: &[u8],
) -> Result<Option<u64>, StoreError> {
    table
        .get(key)
        .map_err(crate::error::redb)?
        .map(|value| {
            value
                .value()
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| StoreError::Internal("malformed projection counter".into()))
        })
        .transpose()
}

/// The projection counter at `key`, zero when it was never written: for
/// counters whose absence means nothing counted yet (staged bytes and
/// entries, completions), never for one whose absence is itself a fact.
pub fn counter(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    key: &[u8],
) -> Result<u64, StoreError> {
    stored(table, key).map(Option::unwrap_or_default)
}

pub fn set_counter(
    table: &mut Table<'_, &'static [u8], &'static [u8]>,
    key: &[u8],
    value: u64,
) -> Result<(), StoreError> {
    table
        .insert(key, value.to_be_bytes().as_slice())
        .map_err(crate::error::redb)?;
    Ok(())
}

/// What staging one version costs ([`ProjectionStage::write_cost`]): the
/// work its write accounts, and the bytes it holds staged until compaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WriteCost {
    pub(crate) work: Work,
    pub(crate) staged: u64,
}

/// What every cross-instance observation of the projection depends on: the
/// registry's completion sequence. The producers of what a reader selects,
/// from the writers of the tables `projection::visibility` reads:
///
/// - another instance's staged versions are ineligible until its attempt
///   completes ([`ProjectionStage::complete`]), which raises `COMPLETION`,
///   records the completed attempt and the instance's completion order, and
///   advances its checkpoint in one transaction;
/// - compaction changes no group's selection (`projection_compact`): its
///   removal of completed-attempt rows switches readers to the checkpoint
///   fallback that selects the same versions, and its folds remove only
///   versions no reader selects or tombstones of nothing; a traversal
///   resumed across it retreats to a group boundary
///   (`Reduction::resume_in_new_transaction`);
/// - retirement writes none of these tables, and discards the cursors of
///   the retiring instance (`forget_cursors`) with every observation they
///   retained; recovery begins a new process, which retains none.
///
/// So an observation made with protection `p` still holds in a transaction
/// whose protection equals `p`, and one taken when the observation began
/// and compared under the registry writer before its answer is used, in
/// the transaction that applies it, leaves no change between the check and
/// the use. An instance's own versions change only by its own settlement,
/// which applies one element at a time: its observations need no protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Protection {
    completion: u64,
}

/// A resumable traversal of every holder of one logical key across
/// instances: the key's group prefix, the reduction state, and the holders
/// found so far. Owned by its caller across transactions; resumed in another
/// one only after [`Self::resume_in_new_transaction`] and a check of the
/// [`Protection`] it was begun under.
pub(crate) struct HolderScan {
    prefix: Vec<u8>,
    reduction: Reduction,
    found: Vec<(StorageInstance, Version)>,
}

impl HolderScan {
    /// A traversal of the holders of `key` (and `member`) in `family`, its
    /// prefix charged on `work` before it is built.
    pub(crate) fn new(
        family: Family,
        key: &[u8],
        member: Option<&[u8]>,
        work: &mut dyn Meter,
    ) -> Result<Self, StoreError> {
        work.charge(
            Dimension::BytesAllocated,
            logical_len(key, member, END.len())?,
        )?;
        Ok(Self {
            prefix: logical(family, key, member, &END)?,
            reduction: Reduction::default(),
            found: Vec::new(),
        })
    }

    /// The holders found so far: all of them once the scan is exhausted.
    pub(crate) fn found(&self) -> &[(StorageInstance, Version)] {
        &self.found
    }

    /// Prepare to resume in another transaction (see
    /// `Reduction::resume_in_new_transaction`).
    pub(crate) fn resume_in_new_transaction(
        &mut self,
        work: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        self.reduction.resume_in_new_transaction(work)
    }
}

/// The checked layout of one version's write: the lengths of what it
/// builds, and its cost. The one computation both costing and writing use.
struct WriteLayout {
    value: u64,
    built: u64,
    cost: WriteCost,
}

/// The staging projection maintenance holds: versions not yet compacted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StagingUse {
    pub bytes: u64,
    pub entries: u64,
}

/// Bytes of a `PROJECTION_ATTEMPTS` value: the attempt and its epoch.
pub(crate) const ATTEMPT_VALUE_BYTES: u64 = 4 + 8;

/// The bound of restarting an epoch's settlement: beginning its attempt
/// ([`begin_attempt`]: the instance key built, the attempt row examined and
/// read; the new value is inline) and opening the new attempt's stage
/// ([`ProjectionStage::open`]: the key built again, the row examined and
/// read again, the attempt's log prefix built, its log range built and
/// copied, at most twice the prefix and its upper bound, no longer than the
/// prefix, and the attempt's last log entry examined and its key read).
/// Decided from the instance alone before anything is written, so a
/// restart is admitted whole or not begun.
pub(crate) fn restart_cost(instance: &StorageInstance) -> Result<Work, StoreError> {
    let overflow = || StoreError::Internal("settlement restart bound exceeds u64".into());
    let key = u64::from(instance.key_len());
    let prefix = attempt_prefix_len(instance);
    let range = prefix.checked_mul(4).ok_or_else(overflow)?;
    Work::total(&[
        (Dimension::BytesAllocated, key),
        (Dimension::Entries, 1),
        (Dimension::BytesRead, ATTEMPT_VALUE_BYTES),
        (Dimension::BytesAllocated, key),
        (Dimension::Entries, 1),
        (Dimension::BytesRead, ATTEMPT_VALUE_BYTES),
        (Dimension::BytesAllocated, prefix),
        (Dimension::BytesAllocated, range),
        (Dimension::Entries, 1),
        (Dimension::BytesRead, MAX_LOG_KEY_BYTES),
    ])
    .map_err(|_| overflow())
}

/// Begin a new settlement attempt of `epoch` of `instance` in `txn`, on
/// `work`: returns its number, greater than every earlier attempt of the
/// instance, and makes it the attempt in progress. Versions of earlier
/// attempts of the epoch can then never complete. The instance key is the
/// one application-owned allocation here: charged, reserved exactly and
/// fallibly, then encoded once by its format owner, for both the lookup and
/// the write. The row's examination and read are charged before the lookup;
/// the new value is an inline array and allocates nothing.
pub fn begin_attempt(
    txn: &WriteTransaction,
    instance: &StorageInstance,
    epoch: u64,
    work: &mut dyn Meter,
) -> Result<u32, StoreError> {
    let key_len = usize::from(instance.key_len());
    work.charge(Dimension::BytesAllocated, key_len as u64)?;
    let mut key = Vec::new();
    key.try_reserve_exact(key_len).map_err(|_| {
        StoreError::CapacityExceeded("settlement attempt key could not be allocated".into())
    })?;
    instance.append_key(&mut key);
    let mut attempts = txn
        .open_table(PROJECTION_ATTEMPTS)
        .map_err(crate::error::redb)?;
    work.charge_all(&[
        (Dimension::Entries, 1),
        (Dimension::BytesRead, ATTEMPT_VALUE_BYTES),
    ])?;
    let next = match attempt_at(&attempts, &key)? {
        Some((last, _)) => last.checked_add(1).ok_or_else(|| {
            StoreError::CapacityExceeded(format!("settlement attempts of {instance} exhausted"))
        })?,
        None => 0,
    };
    let mut value = [0u8; ATTEMPT_VALUE_BYTES as usize];
    value[..4].copy_from_slice(&next.to_be_bytes());
    value[4..].copy_from_slice(&epoch.to_be_bytes());
    attempts
        .insert(key.as_slice(), value.as_slice())
        .map_err(crate::error::redb)?;
    Ok(next)
}

impl PersistentStore {
    /// The staging the projection holds now.
    pub(crate) fn projection_staged(&self) -> Result<StagingUse, StoreError> {
        let txn = self.registry.begin_read()?;
        let counters = txn
            .open_table(PROJECTION_COUNTERS)
            .map_err(crate::error::redb)?;
        Ok(StagingUse {
            bytes: counter(&counters, STAGED_BYTES)?,
            entries: counter(&counters, STAGED_ENTRIES)?,
        })
    }
}

/// The attempt in progress for `instance`: `(attempt, epoch)` ([`attempt_at`]
/// under the instance's key).
pub fn active_attempt(
    attempts: &impl ReadableTable<&'static [u8], &'static [u8]>,
    instance: &StorageInstance,
) -> Result<Option<(u32, u64)>, StoreError> {
    attempt_at(attempts, &instance.key())
}

/// The attempt in progress recorded under the instance key `key`: the one
/// decoding of an attempt row.
fn attempt_at(
    attempts: &impl ReadableTable<&'static [u8], &'static [u8]>,
    key: &[u8],
) -> Result<Option<(u32, u64)>, StoreError> {
    attempts
        .get(key)
        .map_err(crate::error::redb)?
        .map(|value| {
            let malformed = || StoreError::Internal("malformed settlement attempt".into());
            let bytes: &[u8; 12] = value.value().try_into().map_err(|_| malformed())?;
            let (attempt, epoch) = bytes.split_at(4);
            Ok((
                u32::from_be_bytes(attempt.try_into().map_err(|_| malformed())?),
                u64::from_be_bytes(epoch.try_into().map_err(|_| malformed())?),
            ))
        })
        .transpose()
}

/// The rows one settlement attempt stages inside one registry write
/// transaction.
pub struct ProjectionStage<'t> {
    versions: Table<'t, &'static [u8], &'static [u8]>,
    log: Table<'t, &'static [u8], &'static [u8]>,
    completed: Table<'t, &'static [u8], &'static [u8]>,
    counters: Table<'t, &'static [u8], &'static [u8]>,
    instances: Table<'t, &'static [u8], &'static [u8]>,
    settled: Table<'t, &'static [u8], &'static [u8]>,
    instance: StorageInstance,
    epoch: u64,
    attempt: u32,
    sequence: u64,
    capacity: u64,
    limits: SettlementLimits,
}

impl<'t> ProjectionStage<'t> {
    /// Stage for `attempt` of `epoch` of `instance` in `txn`, refusing
    /// staging beyond `capacity` bytes in all and any version beyond the
    /// projection's bounds under `limits`. The attempt must be the
    /// instance's attempt in progress for that epoch. The attempt's log
    /// prefix is charged to `work` before it is built; finding where the
    /// log resumes is then one unit: the range built and copied, and the
    /// attempt's last entry examined and its key read.
    pub(crate) fn open(
        txn: &'t WriteTransaction,
        instance: StorageInstance,
        epoch: u64,
        attempt: u32,
        capacity: u64,
        limits: SettlementLimits,
        work: &mut dyn Meter,
    ) -> Result<Self, StoreError> {
        let attempts = txn
            .open_table(PROJECTION_ATTEMPTS)
            .map_err(crate::error::redb)?;
        work.charge_all(&[
            (Dimension::BytesAllocated, u64::from(instance.key_len())),
            (Dimension::Entries, 1),
            (Dimension::BytesRead, ATTEMPT_VALUE_BYTES),
        ])?;
        if active_attempt(&attempts, &instance)? != Some((attempt, epoch)) {
            return Err(StoreError::Conflict(format!(
                "settlement attempt {attempt} of epoch {epoch} of {instance} is not in progress"
            )));
        }
        drop(attempts);
        let log = txn.open_table(PROJECTION_LOG).map_err(crate::error::redb)?;
        work.charge(Dimension::BytesAllocated, attempt_prefix_len(&instance))?;
        let prefix = attempt_prefix(&instance, epoch, attempt)?;
        let last = {
            let mut unit = work.admit(&[
                (Dimension::BytesAllocated, prefixed_cost(&prefix, None)?),
                (Dimension::Entries, 1),
                (Dimension::BytesRead, MAX_LOG_KEY_BYTES),
            ])?;
            let mut entries = prefixed(&log, &prefix, None, &mut unit)?;
            unit.account(Dimension::Entries, 1)?;
            match entries.next_back().transpose()? {
                Some((key, _)) => {
                    let key = key.value();
                    unit.account(Dimension::BytesRead, key.len() as u64)?;
                    let sequence = key
                        .get(prefix.len()..)
                        .and_then(|tail| <[u8; 8]>::try_from(tail).ok())
                        .map(u64::from_be_bytes)
                        .ok_or_else(|| {
                            StoreError::Internal("malformed projection log key".into())
                        })?;
                    Some(sequence)
                }
                None => None,
            }
        };
        let sequence = match last {
            Some(last) => last
                .checked_add(1)
                .ok_or_else(|| StoreError::Internal("projection sequence exhausted".into()))?,
            None => 0,
        };
        Ok(Self {
            versions: txn
                .open_table(PROJECTION_VERSIONS)
                .map_err(crate::error::redb)?,
            log,
            completed: txn
                .open_table(PROJECTION_COMPLETED)
                .map_err(crate::error::redb)?,
            counters: txn
                .open_table(PROJECTION_COUNTERS)
                .map_err(crate::error::redb)?,
            instances: txn
                .open_table(PROJECTION_INSTANCES)
                .map_err(crate::error::redb)?,
            settled: txn.open_table(SETTLED).map_err(crate::error::redb)?,
            instance,
            epoch,
            attempt,
            sequence,
            capacity,
            limits,
        })
    }

    /// What [`Self::write`] of `version` of `key` (and `member`) costs,
    /// decided from lengths alone with checked arithmetic: the unit it
    /// admits, and the bytes it stages. A version beyond the projection's
    /// bounds is refused here. The one computation of both, so a caller that
    /// admits several writes as one unit admits exactly what they will admit
    /// and stage.
    pub(crate) fn write_cost(
        &self,
        key: &[u8],
        member: Option<&[u8]>,
        version: VersionRef<'_>,
    ) -> Result<WriteCost, StoreError> {
        self.layout(key, member, version).map(|layout| layout.cost)
    }

    /// The checked layout of writing `version` of `key` (and `member`); a
    /// version beyond the projection's bounds is refused here, before
    /// anything is built.
    fn layout(
        &self,
        key: &[u8],
        member: Option<&[u8]>,
        version: VersionRef<'_>,
    ) -> Result<WriteLayout, StoreError> {
        let overflow = || StoreError::Internal("projection version size exceeds u64".into());
        let logical_bytes = logical_len(key, member, 0)?;
        let physical_bytes = version_key_len(logical_bytes, &self.instance)?;
        let value = version.encoded_len()?;
        self.limits
            .versions()
            .check_lengths(physical_bytes, value)?;
        let log_bytes = log_key_len(&self.instance);
        let staged = staged_size(physical_bytes, value, log_bytes)?;
        let built = [logical_bytes, physical_bytes, value, log_bytes]
            .into_iter()
            .try_fold(0u64, u64::checked_add)
            .ok_or_else(overflow)?;
        // The framed value is written once (bytes read: the payload copied).
        let work = Work::total(&[
            (Dimension::Entries, 2),
            (Dimension::BytesRead, 2 * COUNTER_BYTES),
            (Dimension::BytesRead, value),
            (Dimension::BytesAllocated, built),
        ])
        .map_err(|_| overflow())?;
        Ok(WriteLayout {
            value,
            built,
            cost: WriteCost { work, staged },
        })
    }

    /// Bytes of staging capacity not yet held, read in this transaction.
    pub(crate) fn headroom(&self) -> Result<u64, StoreError> {
        Ok(self
            .capacity
            .saturating_sub(counter(&self.counters, STAGED_BYTES)?))
    }

    /// Write `version` of `key` (and `member`) in `family` as one unit
    /// admitted on `work` at exactly its cost ([`Self::write_admitted`]).
    pub(crate) fn write(
        &mut self,
        family: Family,
        key: &[u8],
        member: Option<&[u8]>,
        version: VersionRef<'_>,
        work: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let cost = self.write_cost(key, member, version)?;
        let mut unit = work.admit(&cost.work.as_bound())?;
        self.write_admitted(family, key, member, version, &mut unit)
    }

    /// Write `version` of `key` (and `member`) in `family` inside `unit`, a
    /// unit already admitted for at least its cost ([`Self::write_cost`]),
    /// its work accounted without another admission or deadline check, its
    /// payload framed straight from its owner: the one write body. Every
    /// length, the version's bounds, the staging charge, both counters and
    /// the next sequence are decided with checked arithmetic before anything
    /// is built; then the keys and value are built in storage allocated
    /// fallibly, and the rows and counters written. A version beyond the
    /// projection's bounds is refused before anything is built or written:
    /// no stored version is one a reader cannot admit. A failed insertion
    /// propagates and abandons the transaction.
    pub(crate) fn write_admitted(
        &mut self,
        family: Family,
        key: &[u8],
        member: Option<&[u8]>,
        version: VersionRef<'_>,
        unit: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let WriteLayout {
            value: value_bytes,
            built,
            cost: WriteCost { staged: size, .. },
        } = self.layout(key, member, version)?;
        let next_sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| StoreError::Internal("projection sequence exhausted".into()))?;
        unit.account(Dimension::Entries, 2)?;
        unit.account(Dimension::BytesRead, 2 * COUNTER_BYTES)?;
        let staged = counter(&self.counters, STAGED_BYTES)?
            .checked_add(size)
            .filter(|staged| *staged <= self.capacity)
            .ok_or_else(|| {
                StoreError::CapacityExceeded(format!(
                    "projection staging would exceed its capacity of {} bytes",
                    self.capacity
                ))
            })?;
        let entries = counter(&self.counters, STAGED_ENTRIES)?
            .checked_add(1)
            .ok_or_else(|| StoreError::Internal("projection entries exceed u64".into()))?;
        unit.account(Dimension::BytesAllocated, built)?;
        let logical = logical(family, key, member, &[])?;
        let physical = version_key(
            &logical,
            &self.instance,
            self.epoch,
            self.attempt,
            self.sequence,
        )?;
        let mut value = zeroed(value_bytes)?;
        unit.account(Dimension::BytesRead, value_bytes)?;
        version.encode_into(&mut value)?;
        let log_key = log_key(&self.instance, self.epoch, self.attempt, self.sequence)?;
        self.versions
            .insert(physical.as_slice(), value.as_slice())
            .map_err(crate::error::redb)?;
        self.log
            .insert(log_key.as_slice(), physical.as_slice())
            .map_err(crate::error::redb)?;
        set_counter(&mut self.counters, STAGED_BYTES, staged)?;
        set_counter(&mut self.counters, STAGED_ENTRIES, entries)?;
        self.sequence = next_sequence;
        Ok(())
    }

    /// One step of this stage's reduction of every (logical key, instance)
    /// group under `prefix`, resumed from `state`, each group's selection
    /// offered to `emit`. A version is eligible when this attempt staged it
    /// (its order among this instance's versions is its own; it has no
    /// completion yet) and otherwise by committed `visibility`. The range
    /// is rebuilt after the state's position, in this transaction: a state
    /// carried into another transaction is only as valid as the protection
    /// its caller holds over what it observed.
    pub(crate) fn reduce(
        &self,
        prefix: &[u8],
        state: &mut Reduction,
        work: &mut dyn Meter,
        emit: &mut Emit<'_>,
    ) -> Result<Reduced, StoreError> {
        let mut versions = {
            let after = state.position();
            let mut unit =
                work.admit(&[(Dimension::BytesAllocated, prefixed_cost(prefix, after)?)])?;
            prefixed(&self.versions, prefix, after, &mut unit)?
        };
        let mut eligible = |version: &VersionKey, unit: &mut dyn Meter| {
            let own = version.instance == self.instance
                && version.epoch == self.epoch
                && version.attempt == self.attempt;
            if own {
                return Ok(Some(0));
            }
            visibility(
                &self.completed,
                &self.settled,
                &self.instances,
                version,
                unit,
            )
        };
        reduce_groups(
            state,
            &mut versions,
            &self.limits.versions(),
            &self.limits.selection_unit(),
            work,
            &mut eligible,
            emit,
        )
    }

    /// The newest version of `key` (and `member`) in `family` each instance
    /// holds as of this attempt: for this instance its own staged versions
    /// and its completed epochs' versions, for every other instance its
    /// completed epochs' versions. Tombstones included. Every holder or a
    /// refusal, never a partial list.
    pub(crate) fn holders(
        &self,
        family: Family,
        key: &[u8],
        member: Option<&[u8]>,
        work: &mut dyn Meter,
    ) -> Result<Vec<(StorageInstance, Version)>, StoreError> {
        let mut scan = HolderScan::new(family, key, member, work)?;
        self.scan_holders(&mut scan, work)?.complete()?;
        Ok(scan.found)
    }

    /// Advance `scan` within `work` (see [`HolderScan`]): `Exhausted` once
    /// every holder is found, `Refused` with everything processed kept in
    /// the scan. The one traversal of a key's holders.
    pub(crate) fn scan_holders(
        &self,
        scan: &mut HolderScan,
        work: &mut dyn Meter,
    ) -> Result<Reduced, StoreError> {
        let HolderScan {
            prefix,
            reduction,
            found,
        } = scan;
        self.reduce(prefix, reduction, work, &mut |offered, work| {
            reserve_charged(work, found)?;
            let delivery = offered.take().ok_or_else(undelivered)?;
            found.push((delivery.instance, delivery.version));
            Ok(ControlFlow::Continue(()))
        })
    }

    /// What a cross-instance observation made in this transaction depends
    /// on, read in it ([`Protection`]).
    pub(crate) fn protection(&self, work: &mut dyn Meter) -> Result<Protection, StoreError> {
        work.charge_all(&[
            (Dimension::Entries, 1),
            (Dimension::BytesRead, COUNTER_BYTES),
        ])?;
        Ok(Protection {
            completion: counter(&self.counters, COMPLETION)?,
        })
    }

    /// The newest version of `key` (and `member`) in `family` this instance
    /// holds as of this attempt, reduced over this instance's versions of
    /// the key alone (its exact group prefix), on `work`. `None` when it
    /// holds none.
    pub(crate) fn latest(
        &self,
        family: Family,
        key: &[u8],
        member: Option<&[u8]>,
        work: &mut dyn Meter,
    ) -> Result<Option<Version>, StoreError> {
        work.charge(Dimension::BytesAllocated, logical_len(key, member, 0)?)?;
        let logical = logical(family, key, member, &[])?;
        work.charge(
            Dimension::BytesAllocated,
            key_prefix_len(&logical, &self.instance)?,
        )?;
        let prefix = key_prefix(&logical, &self.instance)?;
        let mut latest = None;
        // The prefix holds one group; its delivery is the answer.
        self.reduce(
            &prefix,
            &mut Reduction::default(),
            work,
            &mut |offered, _| {
                latest = Some(offered.take().ok_or_else(undelivered)?.version);
                Ok(ControlFlow::Break(()))
            },
        )?
        .complete()?;
        Ok(latest)
    }

    /// The instance whose rows this stage writes.
    pub(crate) const fn instance(&self) -> &StorageInstance {
        &self.instance
    }

    /// Record this attempt as its epoch's completed attempt, with the next
    /// completion sequence. The caller advances `SETTLED` in the same
    /// transaction. Returns the completion sequence.
    pub(crate) fn complete(mut self) -> Result<u64, StoreError> {
        let key = epoch_key(&self.instance, self.epoch)?;
        if self
            .completed
            .get(key.as_slice())
            .map_err(crate::error::redb)?
            .is_some()
        {
            return Err(StoreError::Conflict(format!(
                "epoch {} of {} already completed",
                self.epoch, self.instance
            )));
        }
        let sequence = counter(&self.counters, COMPLETION)?
            .checked_add(1)
            .ok_or_else(|| StoreError::Internal("completion sequence exhausted".into()))?;
        let mut value = self.attempt.to_be_bytes().to_vec();
        value.extend_from_slice(&sequence.to_be_bytes());
        self.completed
            .insert(key.as_slice(), value.as_slice())
            .map_err(crate::error::redb)?;
        set_counter(&mut self.counters, COMPLETION, sequence)?;
        self.instances
            .insert(
                self.instance.key().as_slice(),
                sequence.to_be_bytes().as_slice(),
            )
            .map_err(crate::error::redb)?;
        Ok(sequence)
    }
}
