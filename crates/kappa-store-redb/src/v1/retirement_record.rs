//! The registry's retirement record of one storage instance (`RETIRED`).
//!
//! A record states what happened to an instance's storage and locates the
//! evidence for it; it never authorizes a removal on its own. Every reader
//! asks the record what it means instead of interpreting the row:
//!
//! - [`RetirementRecord::fence`]: the lifecycle state storage of the
//!   instance enters when it is opened (`storage_lifecycle`), so a recorded
//!   intent or release is enforced before any activity after a restart;
//! - [`RetirementRecord::explains_absence`]: whether the instance's missing
//!   or replaced storage released what it held, for reads and discovery.
//!
//! Whether a record authorizes destroying storage is decided where the
//! evidence it locates is verified (`storage_retirement`).
//!
//! Value encodings: empty for a record written before governed retirement
//! (an operator's decision, [`RetirementRecord::Legacy`]); `[1]` for a
//! creation proven never to have committed; `[2][governing:16][request key
//! bytes]` for a governed intent; `[3][governing:16][decision record key
//! bytes]` for a governed release. Any other value is refused.

use std::sync::Arc;

use redb::{Database, ReadableDatabase};

use kappa_store::{Kappa, StoreError};

use crate::PersistentStore;
use crate::storage::{Fence, Recording, RetirementSource};
use crate::storage_instance::StorageInstance;
use crate::tables::RETIRED;

const NEVER_COMMITTED: u8 = 1;
const INTENT: u8 = 2;
const RELEASED: u8 = 3;

/// What the registry records about one storage instance's retirement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetirementRecord {
    /// Written before governed retirement, by an operator's call: the
    /// instance's storage is released.
    Legacy,
    /// A creation of the instance was proven never to have committed.
    NeverCommitted,
    /// A governed retirement of the instance began: `request` names the
    /// principal's signed request, whose decision `governing` publishes.
    Intent { governing: [u8; 16], request: Kappa },
    /// A governed retirement released the instance: `decision` is the
    /// decision record `governing` published.
    Released {
        governing: [u8; 16],
        decision: Kappa,
    },
}

impl RetirementRecord {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let governed = |tag: u8, governing: &[u8; 16], record: &Kappa| {
            let key = record.key_bytes();
            let mut value = Vec::with_capacity(17 + key.len());
            value.push(tag);
            value.extend_from_slice(governing);
            value.extend_from_slice(&key);
            value
        };
        match self {
            Self::Legacy => Vec::new(),
            Self::NeverCommitted => vec![NEVER_COMMITTED],
            Self::Intent { governing, request } => governed(INTENT, governing, request),
            Self::Released {
                governing,
                decision,
            } => governed(RELEASED, governing, decision),
        }
    }

    pub(crate) fn decode(value: &[u8]) -> Result<Self, StoreError> {
        let governed = |rest: &[u8]| -> Result<([u8; 16], Kappa), StoreError> {
            let (governing, record) = rest.split_first_chunk::<16>().ok_or_else(|| {
                StoreError::Internal("governed retirement record shorter than its namespace".into())
            })?;
            Ok((*governing, Kappa::from_key_bytes(record)?))
        };
        match value.split_first() {
            None => Ok(Self::Legacy),
            Some((&NEVER_COMMITTED, [])) => Ok(Self::NeverCommitted),
            Some((&INTENT, rest)) => {
                let (governing, request) = governed(rest)?;
                Ok(Self::Intent { governing, request })
            }
            Some((&RELEASED, rest)) => {
                let (governing, decision) = governed(rest)?;
                Ok(Self::Released {
                    governing,
                    decision,
                })
            }
            Some((tag, _)) => Err(StoreError::Internal(format!(
                "retirement record of unknown kind {tag} or malformed length"
            ))),
        }
    }

    /// The state storage of the instance enters when it is opened.
    pub(crate) const fn fence(&self) -> Fence {
        match self {
            Self::Intent { .. } => Fence::Retiring,
            Self::Legacy | Self::NeverCommitted | Self::Released { .. } => Fence::Released,
        }
    }

    /// Whether the instance's storage, missing or replaced, released what
    /// it held: a read may treat the instance as gone. An intent releases
    /// nothing until it is released.
    pub(crate) const fn explains_absence(&self) -> bool {
        match self {
            Self::Legacy | Self::NeverCommitted | Self::Released { .. } => true,
            Self::Intent { .. } => false,
        }
    }
}

/// The record of `instance` in `txn`'s `RETIRED`, if any.
pub fn read_record(
    txn: &redb::ReadTransaction,
    instance: &StorageInstance,
) -> Result<Option<RetirementRecord>, StoreError> {
    let table = txn.open_table(RETIRED).map_err(crate::error::redb)?;
    table
        .get(instance.key().as_slice())
        .map_err(crate::error::redb)?
        .map(|value| RetirementRecord::decode(value.value()))
        .transpose()
}

/// Write `record` for `instance` into `txn`.
pub fn write_record(
    txn: &redb::WriteTransaction,
    instance: &StorageInstance,
    record: &RetirementRecord,
) -> Result<(), StoreError> {
    txn.open_table(RETIRED)
        .map_err(crate::error::redb)?
        .insert(instance.key().as_slice(), record.encode().as_slice())
        .map_err(crate::error::redb)?;
    Ok(())
}

/// Classify a retirement record's commit: a poisoned transaction was rolled
/// back and committed nothing; any other failure may have persisted it
/// (`redb::WriteTransaction::commit`).
pub fn commit_outcome(result: Result<(), redb::CommitError>) -> Result<(), Recording> {
    match result {
        Ok(()) => Ok(()),
        Err(error @ redb::CommitError::TransactionPoisoned) => {
            Err(Recording::Refused(crate::error::redb(error)))
        }
        Err(error) => Err(Recording::Unknown(crate::error::redb(error))),
    }
}

/// The registry's records as the storage layer consults them when it opens
/// storage.
pub struct RetirementRecords {
    pub(crate) registry: Arc<Database>,
}

impl RetirementSource for RetirementRecords {
    fn fence(&self, instance: &StorageInstance) -> Result<Option<Fence>, StoreError> {
        let txn = self.registry.begin_read().map_err(crate::error::redb)?;
        Ok(read_record(&txn, instance)?.map(|record| record.fence()))
    }
}

impl PersistentStore {
    /// The retirement record of `instance`, if any.
    pub(crate) fn retirement_record(
        &self,
        instance: &StorageInstance,
    ) -> Result<Option<RetirementRecord>, StoreError> {
        let txn = self.registry.begin_read().map_err(crate::error::redb)?;
        read_record(&txn, instance)
    }

    /// Commit `record` for `instance` in its own registry transaction.
    pub(crate) fn commit_retirement_record(
        &self,
        instance: &StorageInstance,
        record: &RetirementRecord,
    ) -> Result<(), Recording> {
        let txn = self.registry.begin_write().map_err(crate::error::redb)?;
        write_record(&txn, instance, record)?;
        commit_outcome(txn.commit())
    }

    /// Remove the record of `instance`: an intent given up before any
    /// decision was published.
    pub(crate) fn remove_retirement_record(
        &self,
        instance: &StorageInstance,
    ) -> Result<(), StoreError> {
        let txn = self.registry.begin_write().map_err(crate::error::redb)?;
        txn.open_table(RETIRED)
            .map_err(crate::error::redb)?
            .remove(instance.key().as_slice())
            .map_err(crate::error::redb)?;
        txn.commit().map_err(crate::error::redb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records() -> Vec<RetirementRecord> {
        vec![
            RetirementRecord::Legacy,
            RetirementRecord::NeverCommitted,
            RetirementRecord::Intent {
                governing: [3; 16],
                request: Kappa::sha256(b"request"),
            },
            RetirementRecord::Released {
                governing: [3; 16],
                decision: Kappa::sha256(b"decision"),
            },
        ]
    }

    #[test]
    fn records_round_trip_and_malformed_values_are_refused() -> Result<(), StoreError> {
        for record in records() {
            assert_eq!(RetirementRecord::decode(&record.encode())?, record);
        }
        assert_eq!(RetirementRecord::decode(&[])?, RetirementRecord::Legacy);
        for malformed in [
            &[9u8][..],
            &[NEVER_COMMITTED, 0],
            &[INTENT, 1, 2],
            &[RELEASED],
        ] {
            assert!(
                RetirementRecord::decode(malformed).is_err(),
                "{malformed:?}"
            );
        }
        Ok(())
    }

    /// One table of what each record means: an intent fences the storage
    /// as retiring and explains no absence; every release fences it as
    /// released and explains absence.
    #[test]
    fn what_each_record_means() {
        for record in records() {
            let intent = matches!(record, RetirementRecord::Intent { .. });
            assert_eq!(
                record.fence(),
                if intent {
                    Fence::Retiring
                } else {
                    Fence::Released
                },
                "{record:?}"
            );
            assert_eq!(record.explains_absence(), !intent, "{record:?}");
        }
    }
}
