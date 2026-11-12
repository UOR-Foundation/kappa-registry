//! The durable pending set and checkpoint reads of settlement.
//!
//! Pending markers (`instance_record::Kind::Pending`) name the storage
//! instances whose head may be past the registry's checkpoint; `SETTLED`
//! holds each instance's checkpoint; `SETTLEMENT_PASS` records that the
//! recovery enumeration since open finished. Every marker and checkpoint
//! names the storage instance (`storage_instance`), so an obligation of one
//! instance is never discharged by, or applied to, another instance of the
//! same namespace. See `settlement.rs` and `settlement_recovery.rs` for how
//! they are used.

use redb::ReadableTable;

use kappa_store::{Kappa, StoreError};

use crate::PersistentStore;
use crate::instance_record::Kind;
use crate::registry::{Attempt, RegistryWrite, Standing};
use crate::storage::NamespaceController;
use crate::storage_instance::StorageInstance;
use crate::tables::{SETTLED, SETTLEMENT_PASS};

const PASS_KEY: &[u8] = b"pass";

/// Longest checkpoint value: the epoch number and the longest root key.
pub(crate) const MAX_CHECKPOINT_BYTES: usize = 8 + kappa_types::kappa::MAX_KEY_BYTES;

/// The checkpoint value: `[epoch_number:8 BE][root key_bytes]`.
pub(super) fn checkpoint(epoch_number: u64, root: &Kappa) -> Vec<u8> {
    let key = root.key_bytes();
    let mut value = Vec::with_capacity(8 + key.len());
    value.extend_from_slice(&epoch_number.to_be_bytes());
    value.extend_from_slice(&key);
    value
}

/// The checkpoint of `instance` in the registry snapshot `txn`.
fn checkpoint_in(
    txn: &redb::ReadTransaction,
    instance: &StorageInstance,
) -> Result<Option<(u64, Kappa)>, StoreError> {
    checkpoint_of(
        &txn.open_table(SETTLED).map_err(crate::error::redb)?,
        instance,
    )
}

/// Read the predecessor checkpoint of `instance` before `txn` changes
/// `SETTLED`. The caller acquired this registry transaction with recovery
/// standing established (`Registry::try_begin_write`). This function must
/// not certify a checkpoint written by the same uncommitted transaction.
pub(super) fn checkpoint_in_write(
    txn: &RegistryWrite,
    instance: &StorageInstance,
) -> Result<Option<(u64, Kappa)>, StoreError> {
    checkpoint_of(
        &txn.open_table(SETTLED).map_err(crate::error::redb)?,
        instance,
    )
}

/// The checkpoint of `instance` in a `SETTLED` table, decoded by the one
/// checkpoint codec. Decoding authorizes nothing: what a checkpoint
/// establishes depends on how the caller acquired the table
/// (`Registry::established_read_standing`, `Registry::try_begin_write`).
pub(crate) fn checkpoint_of(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    instance: &StorageInstance,
) -> Result<Option<(u64, Kappa)>, StoreError> {
    table
        .get(instance.key().as_slice())
        .map_err(crate::error::redb)?
        .map(|value| decode_checkpoint(value.value()))
        .transpose()
}

/// The one checkpoint decoder: `[epoch_number:8 BE][root key_bytes]`.
pub(crate) fn decode_checkpoint(value: &[u8]) -> Result<(u64, Kappa), StoreError> {
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

impl PersistentStore {
    /// Record durably that `instance` has, or is about to have, epochs past
    /// its checkpoint. Called by the namespace's controller under its
    /// writer gate before the commit, and by a creation before it claims
    /// its alias. Idempotent.
    ///
    /// The pending marker takes over recovery ownership of the instance
    /// from its creation intent: the intent is completed only once the
    /// marker is durable, on every call, so a retried creation hands over
    /// the intent its earlier attempt left and no storage is ever owned by
    /// neither.
    pub(crate) fn mark_unsettled(&self, instance: &StorageInstance) -> Result<(), StoreError> {
        let root = self.namespaces.root();
        Kind::Pending.record(root, instance)?;
        Kind::Creating.complete(root, instance)
    }

    /// The namespaces with a pending marker, in identity order, each once.
    #[cfg(test)]
    pub(crate) fn pending_settlements(&self) -> Result<Vec<[u8; 16]>, StoreError> {
        let mut ids = Vec::new();
        if let Some(entries) = Kind::Pending.traversal(self.namespaces.root())? {
            for entry in entries {
                ids.push(*crate::instance_record::instance(&entry?)?.namespace());
            }
        }
        ids.sort_unstable();
        ids.dedup();
        Ok(ids)
    }

    /// The settlement checkpoint of `instance` as this handle reads it,
    /// established or not: test inspection only. Every decision a
    /// checkpoint authorizes (releasing ownership, discharging a record,
    /// reducing admitted backlog, publishing an observed head) reads an
    /// established one ([`Self::established_checkpoint`]).
    #[cfg(test)]
    pub(crate) fn settled_epoch(
        &self,
        instance: &StorageInstance,
    ) -> Result<Option<(u64, Kappa)>, StoreError> {
        checkpoint_in(&self.registry.begin_read()?, instance)
    }

    /// The established settlement checkpoint of `instance`: the last epoch
    /// whose effects the registry is known to hold committed, or `None`
    /// when none is (`Registry::established_read_standing`). Waits for the
    /// registry writer slot; refused (`Unavailable`) while a registry
    /// commit's outcome is unknown.
    pub(crate) fn established_checkpoint(
        &self,
        instance: &StorageInstance,
    ) -> Result<Option<(u64, Kappa)>, StoreError> {
        self.established_checkpoint_standing(instance)?
            .or_unavailable()
    }

    /// [`Self::established_checkpoint`] for settlement and recovery, which
    /// keep a registry commit of unknown outcome as `RecoveryRequired`
    /// rather than as an error of the instance they were visiting.
    pub(crate) fn established_checkpoint_standing(
        &self,
        instance: &StorageInstance,
    ) -> Result<Standing<Option<(u64, Kappa)>>, StoreError> {
        Ok(match self.registry.established_read_standing()? {
            Standing::Ready(txn) => Standing::Ready(checkpoint_in(&txn, instance)?),
            Standing::RecoveryRequired => Standing::RecoveryRequired,
        })
    }

    /// The checkpoint admission may subtract from `controller`'s head: the
    /// established checkpoint when it can be read now without waiting, and
    /// otherwise (the registry writer held, or a registry commit of unknown
    /// outcome) the instance's known-settled bound, which never exceeds
    /// the established checkpoint. Any other failure is the read's error.
    pub(crate) fn admissible_checkpoint(
        &self,
        controller: &NamespaceController,
    ) -> Result<u64, StoreError> {
        match self.try_established_checkpoint(&controller.instance)? {
            Attempt::Ready(checkpoint) => {
                let checkpoint = checkpoint.map_or(0, |(number, _)| number);
                controller.raise_known_settled(checkpoint);
                Ok(checkpoint)
            }
            Attempt::Busy | Attempt::RecoveryRequired => Ok(controller.known_settled()),
        }
    }

    /// [`Self::established_checkpoint`] without waiting: `Busy` while the
    /// registry writer slot is held, `RecoveryRequired` while a registry
    /// commit's outcome is unknown.
    pub(crate) fn try_established_checkpoint(
        &self,
        instance: &StorageInstance,
    ) -> Result<Attempt<Option<(u64, Kappa)>>, StoreError> {
        Ok(match self.registry.try_begin_established_read()? {
            Attempt::Ready(txn) => Attempt::Ready(checkpoint_in(&txn, instance)?),
            Attempt::Busy => Attempt::Busy,
            Attempt::RecoveryRequired => Attempt::RecoveryRequired,
        })
    }

    /// Whether the recovery enumeration since open finished: every pending
    /// entry present at open was visited and settled, classified, or handed
    /// to an owned obligation. Not a statement that discovery is complete
    /// (`discovery_coverage`); an operator signal.
    pub fn settlement_pass_complete(&self) -> Result<bool, StoreError> {
        let txn = self.registry.begin_read()?;
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
        let txn = self.registry.begin_write()?;
        txn.open_table(SETTLEMENT_PASS)
            .map_err(crate::error::redb)?
            .insert(PASS_KEY, &[u8::from(complete)][..])
            .map_err(crate::error::redb)?;
        match txn.commit() {
            Ok(()) => Ok(()),
            // An operator signal, cleared at every open and set again when
            // the enumeration finishes: a flag of unknown durability is
            // decided again by the next open.
            Err(
                crate::error::CommitFailure::Known(error)
                | crate::error::CommitFailure::Unknown(error),
            ) => Err(error),
        }
    }
}
