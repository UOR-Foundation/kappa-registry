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

use redb::{ReadableTable, Table, WriteTransaction};

use kappa_store::StoreError;

use crate::PersistentStore;
use crate::projection::{
    Family, Version, VersionKey, epoch_key, logical, prefixed, version_key, visibility,
};
use crate::storage_instance::StorageInstance;
use crate::tables::{
    PROJECTION_ATTEMPTS, PROJECTION_COMPLETED, PROJECTION_COUNTERS, PROJECTION_INSTANCES,
    PROJECTION_LOG, PROJECTION_VERSIONS, SETTLED,
};

const COMPLETION: &[u8] = b"completion";
pub const STAGED_BYTES: &[u8] = b"staged-bytes";
pub const STAGED_ENTRIES: &[u8] = b"staged-entries";

/// Bytes one staged version holds until compaction folds or removes it:
/// its key in the version table and its log value, its value, and its log
/// key. Charged when the version is staged and released when its log entry
/// is removed, so the counters hold exactly the versions still logged.
pub fn staged_size(physical: usize, value: usize, log_key: usize) -> Result<u64, StoreError> {
    (physical as u64)
        .checked_mul(2)
        .and_then(|keys| keys.checked_add(value as u64))
        .and_then(|size| size.checked_add(log_key as u64))
        .ok_or_else(|| StoreError::Internal("projection version size exceeds u64".into()))
}

pub fn counter(
    table: &Table<'_, &'static [u8], &'static [u8]>,
    key: &[u8],
) -> Result<u64, StoreError> {
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
        .map(Option::unwrap_or_default)
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

/// The staging projection maintenance holds: versions not yet compacted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StagingUse {
    pub bytes: u64,
    pub entries: u64,
}

/// Begin a new settlement attempt of `epoch` of `instance` in `txn`:
/// returns its number, greater than every earlier attempt of the instance,
/// and makes it the attempt in progress. Versions of earlier attempts of
/// the epoch can then never complete.
pub fn begin_attempt(
    txn: &WriteTransaction,
    instance: &StorageInstance,
    epoch: u64,
) -> Result<u32, StoreError> {
    let mut attempts = txn
        .open_table(PROJECTION_ATTEMPTS)
        .map_err(crate::error::redb)?;
    let next = match active_attempt(&attempts, instance)? {
        Some((last, _)) => last.checked_add(1).ok_or_else(|| {
            StoreError::CapacityExceeded(format!("settlement attempts of {instance} exhausted"))
        })?,
        None => 0,
    };
    let mut value = next.to_be_bytes().to_vec();
    value.extend_from_slice(&epoch.to_be_bytes());
    attempts
        .insert(instance.key().as_slice(), value.as_slice())
        .map_err(crate::error::redb)?;
    Ok(next)
}

impl PersistentStore {
    /// The staging the projection holds now.
    pub(crate) fn projection_staged(&self) -> Result<StagingUse, StoreError> {
        use redb::ReadableDatabase;
        let txn = self.registry.begin_read().map_err(crate::error::redb)?;
        let counters = txn
            .open_table(PROJECTION_COUNTERS)
            .map_err(crate::error::redb)?;
        let read = |key: &[u8]| -> Result<u64, StoreError> {
            counters
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
                .map(Option::unwrap_or_default)
        };
        Ok(StagingUse {
            bytes: read(STAGED_BYTES)?,
            entries: read(STAGED_ENTRIES)?,
        })
    }
}

/// The attempt in progress for `instance`: `(attempt, epoch)`.
pub fn active_attempt(
    attempts: &impl ReadableTable<&'static [u8], &'static [u8]>,
    instance: &StorageInstance,
) -> Result<Option<(u32, u64)>, StoreError> {
    attempts
        .get(instance.key().as_slice())
        .map_err(crate::error::redb)?
        .map(|value| {
            let bytes: &[u8; 12] = value
                .value()
                .try_into()
                .map_err(|_| StoreError::Internal("malformed settlement attempt".into()))?;
            let (attempt, epoch) = bytes.split_at(4);
            Ok((
                u32::from_be_bytes(
                    attempt
                        .try_into()
                        .map_err(|_| StoreError::Internal("malformed settlement attempt".into()))?,
                ),
                u64::from_be_bytes(
                    epoch
                        .try_into()
                        .map_err(|_| StoreError::Internal("malformed settlement attempt".into()))?,
                ),
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
}

impl<'t> ProjectionStage<'t> {
    /// Stage for `attempt` of `epoch` of `instance` in `txn`, refusing
    /// staging beyond `capacity` bytes in all. The attempt must be the
    /// instance's attempt in progress for that epoch.
    pub(crate) fn open(
        txn: &'t WriteTransaction,
        instance: StorageInstance,
        epoch: u64,
        attempt: u32,
        capacity: u64,
    ) -> Result<Self, StoreError> {
        let attempts = txn
            .open_table(PROJECTION_ATTEMPTS)
            .map_err(crate::error::redb)?;
        if active_attempt(&attempts, &instance)? != Some((attempt, epoch)) {
            return Err(StoreError::Conflict(format!(
                "settlement attempt {attempt} of epoch {epoch} of {instance} is not in progress"
            )));
        }
        drop(attempts);
        let log = txn.open_table(PROJECTION_LOG).map_err(crate::error::redb)?;
        let mut prefix = epoch_key(&instance, epoch);
        prefix.extend_from_slice(&attempt.to_be_bytes());
        let last = prefixed(&log, &prefix)?
            .next_back()
            .transpose()
            .map_err(crate::error::redb)?
            .map(|(key, _)| {
                key.value()
                    .get(prefix.len()..)
                    .and_then(|tail| <[u8; 8]>::try_from(tail).ok())
                    .map(u64::from_be_bytes)
                    .ok_or_else(|| StoreError::Internal("malformed projection log key".into()))
            })
            .transpose()?;
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
        })
    }

    /// Write `version` of `key` (and `member`) in `family`.
    pub(crate) fn write(
        &mut self,
        family: Family,
        key: &[u8],
        member: Option<&[u8]>,
        version: &Version,
    ) -> Result<(), StoreError> {
        let logical = logical(family, key, member);
        let physical = version_key(
            &logical,
            &self.instance,
            self.epoch,
            self.attempt,
            self.sequence,
        );
        let value = version.encode();
        let mut log_key = epoch_key(&self.instance, self.epoch);
        log_key.extend_from_slice(&self.attempt.to_be_bytes());
        log_key.extend_from_slice(&self.sequence.to_be_bytes());
        let size = staged_size(physical.len(), value.len(), log_key.len())?;
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
        self.versions
            .insert(physical.as_slice(), value.as_slice())
            .map_err(crate::error::redb)?;
        self.log
            .insert(log_key.as_slice(), physical.as_slice())
            .map_err(crate::error::redb)?;
        set_counter(&mut self.counters, STAGED_BYTES, staged)?;
        set_counter(&mut self.counters, STAGED_ENTRIES, entries)?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| StoreError::Internal("projection sequence exhausted".into()))?;
        Ok(())
    }

    /// The newest version of `key` (and `member`) in `family` each instance
    /// holds as of this attempt: for this instance its own staged versions
    /// and its completed epochs' versions, for every other instance its
    /// completed epochs' versions. Tombstones included.
    pub(crate) fn holders(
        &self,
        family: Family,
        key: &[u8],
        member: Option<&[u8]>,
    ) -> Result<Vec<(StorageInstance, Version)>, StoreError> {
        let mut prefix = logical(family, key, member);
        prefix.extend_from_slice(&[0x00, 0x00]);
        let mut newest: std::collections::BTreeMap<StorageInstance, ((u64, u64), Version)> =
            std::collections::BTreeMap::new();
        for entry in prefixed(&self.versions, &prefix)? {
            let (physical, value) = entry.map_err(crate::error::redb)?;
            let version = VersionKey::decode(physical.value())?;
            let own = version.instance == self.instance
                && version.epoch == self.epoch
                && version.attempt == self.attempt;
            if !own && !self.completed_attempt(&version)? {
                continue;
            }
            let order = (version.epoch, version.sequence);
            if newest
                .get(&version.instance)
                .is_some_and(|(held, _)| *held >= order)
            {
                continue;
            }
            newest.insert(version.instance, (order, Version::decode(value.value())?));
        }
        Ok(newest
            .into_iter()
            .map(|(instance, (_, version))| (instance, version))
            .collect())
    }

    /// The newest version of `key` (and `member`) in `family` this instance
    /// holds as of this attempt (`holders`). `None` when it holds none.
    pub(crate) fn latest(
        &self,
        family: Family,
        key: &[u8],
        member: Option<&[u8]>,
    ) -> Result<Option<Version>, StoreError> {
        Ok(self
            .holders(family, key, member)?
            .into_iter()
            .find(|(instance, _)| *instance == self.instance)
            .map(|(_, version)| version))
    }

    /// The instance whose rows this stage writes.
    pub(crate) const fn instance(&self) -> &StorageInstance {
        &self.instance
    }

    fn completed_attempt(&self, version: &VersionKey) -> Result<bool, StoreError> {
        Ok(visibility(&self.completed, &self.settled, &self.instances, version)?.is_some())
    }

    /// Record this attempt as its epoch's completed attempt, with the next
    /// completion sequence. The caller advances `SETTLED` in the same
    /// transaction. Returns the completion sequence.
    pub(crate) fn complete(mut self) -> Result<u64, StoreError> {
        let key = epoch_key(&self.instance, self.epoch);
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
