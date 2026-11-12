//! Anchor-keyed identity records written inside a caller-owned writer:
//! handles, device and prekey bindings, locators and revocation
//! commitments. Each write applies its member transition
//! (`MemberTransition`) through the boundary (`transition_apply`), which
//! dispatches the row effect here ([`TxnWriter::apply_member`]); the
//! evidence names the exact member, never the anchor alone.

use kappa_store::canonical::{canonical_bytes, from_canonical};
use kappa_store::clock::ClockMs;
use kappa_store::error::StoreError;
use kappa_store::identity::{
    DeviceBinding, HandleRecord, LocatorRecord, PrekeyBinding, RevocationCommitment,
};
use kappa_store::kappa::Kappa;
use kappa_store::namespace::{NamespaceRef, ProtocolId};
use kappa_store::transition::{MemberTransition, RecordTransition};
use kappa_store::work::Meter;
use redb::ReadableTable;

use crate::PersistentStore;
use crate::identity_write::handle_key;
use crate::tables;
use crate::transition_apply::{RedbPayload, TxnWriter};

/// The handle record under `key` in `txn`.
fn handle_in(txn: &redb::WriteTransaction, key: &str) -> Result<Option<HandleRecord>, StoreError> {
    txn.open_table(tables::ID_HANDLES)
        .map_err(crate::error::redb)?
        .get(key)
        .map_err(crate::error::redb)?
        .map(|value| from_canonical(value.value()))
        .transpose()
        .map_err(|e| StoreError::Internal(format!("handle decode: {e}")))
}

/// The list of records of `anchor` in an anchor-keyed `table` of `txn`.
fn anchor_list<T>(
    txn: &redb::WriteTransaction,
    table: redb::TableDefinition<'static, &'static [u8], &'static [u8]>,
    anchor: &Kappa,
) -> Result<Vec<T>, StoreError>
where
    Vec<T>: TryFrom<dcbor::prelude::CBOR, Error = dcbor::Error>,
{
    txn.open_table(table)
        .map_err(crate::error::redb)?
        .get(anchor.key_bytes().as_slice())
        .map_err(crate::error::redb)?
        .map_or(Ok(Vec::new()), |value| {
            from_canonical(value.value())
                .map_err(|e| StoreError::Internal(format!("anchor record decode: {e}")))
        })
}

impl PersistentStore {
    /// Apply one member transition whose evidence supplies every value, on
    /// `meter`, the allowance of the operation writing it.
    fn apply_member_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        member: MemberTransition,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        TxnWriter::new(self, txn, ns, now, meter)?
            .apply(RecordTransition::Member(member), RedbPayload::NoResources)
            .map(drop)
    }

    pub(crate) fn handle_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        record: &HandleRecord,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        self.apply_member_in_txn(
            txn,
            ns,
            MemberTransition::HandlePut(record.clone()),
            now,
            meter,
        )
    }

    /// Attests only when the stored record still equals `expected`; a stale
    /// or absent record returns false and records no mutation.
    pub(crate) fn handle_attest_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        expected: &HandleRecord,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<bool, StoreError> {
        let stored = handle_in(txn, &handle_key(&expected.protocol, &expected.handle))?;
        let Some(attested) =
            kappa_store::identity_ops::prepare_handle_attestation(stored.as_ref(), expected, now)
        else {
            return Ok(false);
        };
        self.apply_member_in_txn(txn, ns, MemberTransition::HandlePut(attested), now, meter)?;
        Ok(true)
    }

    /// Absent handles are a no-op and record no mutation.
    pub(crate) fn handle_delete_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        protocol: &ProtocolId,
        handle: &str,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let Some(record) = handle_in(txn, &handle_key(protocol, handle))? else {
            return Ok(());
        };
        self.apply_member_in_txn(txn, ns, MemberTransition::HandleDelete(record), now, meter)
    }

    pub(crate) fn device_binding_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        binding: &DeviceBinding,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        self.apply_member_in_txn(
            txn,
            ns,
            MemberTransition::DevicePut(binding.clone()),
            now,
            meter,
        )
    }

    /// Revoke the binding of `device_key`; an anchor or device this
    /// namespace does not hold is a no-op and records no mutation.
    pub(crate) fn device_binding_revoke_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        anchor: &Kappa,
        device_key: &[u8],
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let Some(binding) = anchor_list::<DeviceBinding>(txn, tables::ID_DEVICE_BINDINGS, anchor)?
            .into_iter()
            .find(|binding| binding.device_key == device_key)
        else {
            return Ok(());
        };
        self.apply_member_in_txn(txn, ns, MemberTransition::DeviceRevoke(binding), now, meter)
    }

    pub(crate) fn prekey_binding_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        binding: &PrekeyBinding,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        self.apply_member_in_txn(
            txn,
            ns,
            MemberTransition::PrekeyPut(binding.clone()),
            now,
            meter,
        )
    }

    /// Rejects a locator whose epoch precedes the stored record.
    pub(crate) fn locator_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        record: &LocatorRecord,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let stored: Option<LocatorRecord> = txn
            .open_table(tables::ID_LOCATOR_RECORDS)
            .map_err(crate::error::redb)?
            .get(record.anchor.key_bytes().as_slice())
            .map_err(crate::error::redb)?
            .map(|value| from_canonical(value.value()))
            .transpose()
            .map_err(|e| StoreError::Internal(format!("locator decode: {e}")))?;
        kappa_store::identity_ops::verify_locator_freshness(stored.as_ref(), record)?;
        self.apply_member_in_txn(
            txn,
            ns,
            MemberTransition::LocatorPut(record.clone()),
            now,
            meter,
        )
    }

    pub(crate) fn revocation_commitment_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        commitment: &RevocationCommitment,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        self.apply_member_in_txn(
            txn,
            ns,
            MemberTransition::CommitmentPut(commitment.clone()),
            now,
            meter,
        )
    }
}

impl TxnWriter<'_> {
    /// Write `bytes` as the row of `anchor` in an anchor-keyed `table`.
    fn put_anchor_row(
        &self,
        table: redb::TableDefinition<'static, &'static [u8], &'static [u8]>,
        anchor: &Kappa,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        self.txn
            .open_table(table)
            .map_err(crate::error::redb)?
            .insert(anchor.key_bytes().as_slice(), bytes)
            .map_err(crate::error::redb)?;
        Ok(())
    }

    /// The row effect of one identity member transition, with the indexes
    /// its reads use.
    pub(crate) fn apply_member(&self, member: &MemberTransition) -> Result<(), StoreError> {
        match member {
            MemberTransition::BindingPut(binding) => self.apply_binding_put(binding),
            MemberTransition::BindingDelete(binding) => self.apply_binding_delete(binding),
            MemberTransition::HandlePut(record) => self.apply_handle_put(record),
            MemberTransition::HandleDelete(record) => self.apply_handle_delete(record),
            MemberTransition::DevicePut(binding) => {
                let mut bindings: Vec<DeviceBinding> =
                    anchor_list(self.txn, tables::ID_DEVICE_BINDINGS, &binding.anchor)?;
                bindings.push(binding.clone());
                self.put_anchor_row(
                    tables::ID_DEVICE_BINDINGS,
                    &binding.anchor,
                    &canonical_bytes(&bindings),
                )
            }
            MemberTransition::DeviceRevoke(binding) => self.apply_device_revoke(binding),
            MemberTransition::PrekeyPut(binding) => {
                let mut bindings: Vec<PrekeyBinding> =
                    anchor_list(self.txn, tables::ID_PREKEY_BINDINGS, &binding.anchor)?;
                bindings.push(binding.clone());
                self.put_anchor_row(
                    tables::ID_PREKEY_BINDINGS,
                    &binding.anchor,
                    &canonical_bytes(&bindings),
                )
            }
            MemberTransition::LocatorPut(record) => self.put_anchor_row(
                tables::ID_LOCATOR_RECORDS,
                &record.anchor,
                &canonical_bytes(record),
            ),
            MemberTransition::CommitmentPut(commitment) => self.put_anchor_row(
                tables::ID_REVOCATION_COMMITMENTS,
                &commitment.anchor,
                &canonical_bytes(commitment),
            ),
        }
    }

    /// Hold `record` under its handle, moving the anchor index entry from a
    /// previous holder's anchor.
    fn apply_handle_put(&self, record: &HandleRecord) -> Result<(), StoreError> {
        let key = handle_key(&record.protocol, &record.handle);
        let previous = handle_in(self.txn, &key)?;
        self.txn
            .open_table(tables::ID_HANDLES)
            .map_err(crate::error::redb)?
            .insert(key.as_str(), canonical_bytes(record).as_slice())
            .map_err(crate::error::redb)?;
        let mut index = self
            .txn
            .open_multimap_table(tables::ID_HANDLE_ANCHOR_IDX)
            .map_err(crate::error::redb)?;
        if let Some(previous) = previous
            && previous.anchor != record.anchor
        {
            index
                .remove(previous.anchor.key_bytes().as_slice(), key.as_str())
                .map_err(crate::error::redb)?;
        }
        index
            .insert(record.anchor.key_bytes().as_slice(), key.as_str())
            .map_err(crate::error::redb)?;
        self.store
            .discoverable(self.ns, crate::unsettled_index::DiscoveryKey::Handle(key))?;
        self.store.discoverable(
            self.ns,
            crate::unsettled_index::DiscoveryKey::HandlesBy(record.anchor.clone()),
        )?;
        Ok(())
    }

    /// Remove exactly the handle `record`, with its anchor index entry.
    fn apply_handle_delete(&self, record: &HandleRecord) -> Result<(), StoreError> {
        let key = handle_key(&record.protocol, &record.handle);
        if handle_in(self.txn, &key)?.as_ref() != Some(record) {
            return Err(StoreError::Internal(format!(
                "handle {key} removal names a record the namespace does not hold"
            )));
        }
        self.txn
            .open_table(tables::ID_HANDLES)
            .map_err(crate::error::redb)?
            .remove(key.as_str())
            .map_err(crate::error::redb)?;
        self.txn
            .open_multimap_table(tables::ID_HANDLE_ANCHOR_IDX)
            .map_err(crate::error::redb)?
            .remove(record.anchor.key_bytes().as_slice(), key.as_str())
            .map_err(crate::error::redb)?;
        self.store
            .discoverable(self.ns, crate::unsettled_index::DiscoveryKey::Handle(key))?;
        Ok(())
    }

    /// Remove exactly the device `binding`, dropping the anchor's row with
    /// its last binding.
    fn apply_device_revoke(&self, binding: &DeviceBinding) -> Result<(), StoreError> {
        let bindings: Vec<DeviceBinding> =
            anchor_list(self.txn, tables::ID_DEVICE_BINDINGS, &binding.anchor)?;
        if !bindings.contains(binding) {
            return Err(StoreError::Internal(
                "device revocation names a binding the namespace does not hold".into(),
            ));
        }
        let remaining: Vec<DeviceBinding> = bindings
            .into_iter()
            .filter(|b| b.device_key != binding.device_key)
            .collect();
        if remaining.is_empty() {
            self.txn
                .open_table(tables::ID_DEVICE_BINDINGS)
                .map_err(crate::error::redb)?
                .remove(binding.anchor.key_bytes().as_slice())
                .map_err(crate::error::redb)?;
            return Ok(());
        }
        self.put_anchor_row(
            tables::ID_DEVICE_BINDINGS,
            &binding.anchor,
            &canonical_bytes(&remaining),
        )
    }
}
