//! Anchor-keyed identity records written inside a caller-owned writer:
//! handles, device and prekey bindings, locators and revocation
//! commitments. Each write records `AnchorOrigin` evidence with the scope
//! naming the row it changed (`identity_write::record_anchor_in_txn`).

use kappa_store::canonical::{canonical_bytes, from_canonical};
use kappa_store::clock::ClockMs;
use kappa_store::error::StoreError;
use kappa_store::identity::{
    DeviceBinding, HandleRecord, LocatorRecord, PrekeyBinding, RevocationCommitment,
};
use kappa_store::identity_scope::AnchorScope;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::{NamespaceRef, ProtocolId};
use redb::ReadableTable;

use crate::PersistentStore;
use crate::identity_write::handle_key;
use crate::tables;

impl PersistentStore {
    pub(crate) fn handle_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        record: &HandleRecord,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        let bytes = canonical_bytes(record);
        let key = handle_key(&record.protocol, &record.handle);
        let anchor_key = record.anchor.key_bytes();
        {
            let mut t = txn
                .open_table(tables::ID_HANDLES)
                .map_err(crate::error::redb)?;
            let previous: Option<HandleRecord> = t
                .get(key.as_str())
                .map_err(crate::error::redb)?
                .map(|value| from_canonical(value.value()))
                .transpose()?;
            t.insert(key.as_str(), bytes.as_slice())
                .map_err(crate::error::redb)?;
            let mut idx = txn
                .open_multimap_table(tables::ID_HANDLE_ANCHOR_IDX)
                .map_err(crate::error::redb)?;
            if let Some(previous) = previous
                && previous.anchor != record.anchor
            {
                idx.remove(previous.anchor.key_bytes().as_slice(), key.as_str())
                    .map_err(crate::error::redb)?;
            }
            idx.insert(anchor_key.as_slice(), key.as_str())
                .map_err(crate::error::redb)?;
        }
        self.record_anchor_in_txn(txn, ns, &record.anchor, &AnchorScope::Handle { key }, now)
    }

    /// Attests only when the stored record still equals `expected`; a stale
    /// or absent record returns false and records no mutation.
    pub(crate) fn handle_attest_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        expected: &HandleRecord,
        now: ClockMs,
    ) -> Result<bool, StoreError> {
        let key = handle_key(&expected.protocol, &expected.handle);
        {
            let mut table = txn
                .open_table(tables::ID_HANDLES)
                .map_err(crate::error::redb)?;
            let Some(value) = table.get(key.as_str()).map_err(crate::error::redb)? else {
                return Ok(false);
            };
            if value.value() != canonical_bytes(expected) {
                return Ok(false);
            }
            drop(value);
            let mut record = expected.clone();
            record.attested_at_ms = Some(now.as_i64());
            let bytes = canonical_bytes(&record);
            table
                .insert(key.as_str(), bytes.as_slice())
                .map_err(crate::error::redb)?;
        }
        self.record_anchor_in_txn(txn, ns, &expected.anchor, &AnchorScope::Handle { key }, now)?;
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
    ) -> Result<(), StoreError> {
        let key = handle_key(protocol, handle);
        let old_anchor = {
            let mut table = txn
                .open_table(tables::ID_HANDLES)
                .map_err(crate::error::redb)?;
            let removed = table
                .remove(key.as_str())
                .map_err(crate::error::redb)?
                .map(|value| from_canonical::<HandleRecord>(value.value()))
                .transpose()
                .map_err(|e| StoreError::Internal(format!("handle decode: {e}")))?;
            if let Some(record) = &removed {
                txn.open_multimap_table(tables::ID_HANDLE_ANCHOR_IDX)
                    .map_err(crate::error::redb)?
                    .remove(record.anchor.key_bytes().as_slice(), key.as_str())
                    .map_err(crate::error::redb)?;
            }
            removed.map(|record| record.anchor)
        };
        old_anchor.map_or(Ok(()), |anchor| {
            self.record_anchor_in_txn(txn, ns, &anchor, &AnchorScope::Handle { key }, now)
        })
    }

    pub(crate) fn device_binding_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        binding: &DeviceBinding,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        let anchor_key = binding.anchor.key_bytes();
        {
            let mut table = txn
                .open_table(tables::ID_DEVICE_BINDINGS)
                .map_err(crate::error::redb)?;
            let mut bindings: Vec<DeviceBinding> = match table
                .get(anchor_key.as_slice())
                .map_err(crate::error::redb)?
            {
                Some(val) => from_canonical(val.value())
                    .map_err(|e| StoreError::Internal(format!("device binding decode: {e}")))?,
                None => Vec::new(),
            };
            bindings.push(binding.clone());
            let encoded = canonical_bytes(&bindings);
            table
                .insert(anchor_key.as_slice(), encoded.as_slice())
                .map_err(crate::error::redb)?;
        }
        self.record_anchor_in_txn(txn, ns, &binding.anchor, &AnchorScope::Device, now)
    }

    /// Records the anchor mutation even when no binding matched; absent
    /// anchors are a no-op.
    pub(crate) fn device_binding_revoke_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        anchor: &Kappa,
        device_key: &[u8],
        now: ClockMs,
    ) -> Result<(), StoreError> {
        let anchor_key = anchor.key_bytes();
        {
            let mut table = txn
                .open_table(tables::ID_DEVICE_BINDINGS)
                .map_err(crate::error::redb)?;
            let bindings: Vec<DeviceBinding> = match table
                .get(anchor_key.as_slice())
                .map_err(crate::error::redb)?
            {
                Some(val) => from_canonical(val.value())
                    .map_err(|e| StoreError::Internal(format!("device binding decode: {e}")))?,
                None => return Ok(()),
            };
            let filtered: Vec<_> = bindings
                .into_iter()
                .filter(|b| b.device_key != device_key)
                .collect();
            if filtered.is_empty() {
                table
                    .remove(anchor_key.as_slice())
                    .map_err(crate::error::redb)?;
            } else {
                let encoded = canonical_bytes(&filtered);
                table
                    .insert(anchor_key.as_slice(), encoded.as_slice())
                    .map_err(crate::error::redb)?;
            }
        }
        self.record_anchor_in_txn(txn, ns, anchor, &AnchorScope::Device, now)
    }

    pub(crate) fn prekey_binding_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        binding: &PrekeyBinding,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        let anchor_key = binding.anchor.key_bytes();
        {
            let mut table = txn
                .open_table(tables::ID_PREKEY_BINDINGS)
                .map_err(crate::error::redb)?;
            let mut bindings: Vec<PrekeyBinding> = match table
                .get(anchor_key.as_slice())
                .map_err(crate::error::redb)?
            {
                Some(val) => from_canonical(val.value())
                    .map_err(|e| StoreError::Internal(format!("prekey binding decode: {e}")))?,
                None => Vec::new(),
            };
            bindings.push(binding.clone());
            let encoded = canonical_bytes(&bindings);
            table
                .insert(anchor_key.as_slice(), encoded.as_slice())
                .map_err(crate::error::redb)?;
        }
        self.record_anchor_in_txn(txn, ns, &binding.anchor, &AnchorScope::Prekey, now)
    }

    /// Rejects a locator whose epoch precedes the stored record.
    pub(crate) fn locator_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        record: &LocatorRecord,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        let anchor_key = record.anchor.key_bytes();
        {
            let mut table = txn
                .open_table(tables::ID_LOCATOR_RECORDS)
                .map_err(crate::error::redb)?;
            if let Some(existing_val) = table
                .get(anchor_key.as_slice())
                .map_err(crate::error::redb)?
            {
                let existing: LocatorRecord = from_canonical(existing_val.value())
                    .map_err(|e| StoreError::Internal(format!("locator decode: {e}")))?;
                if record.locator_epoch < existing.locator_epoch {
                    return Err(StoreError::Rejected(format!(
                        "stale locator: presented epoch {} < stored epoch {}",
                        record.locator_epoch, existing.locator_epoch,
                    )));
                }
            }
            let encoded = canonical_bytes(record);
            table
                .insert(anchor_key.as_slice(), encoded.as_slice())
                .map_err(crate::error::redb)?;
        }
        self.record_anchor_in_txn(txn, ns, &record.anchor, &AnchorScope::Locator, now)
    }

    pub(crate) fn revocation_commitment_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        commitment: &RevocationCommitment,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        let anchor_key = commitment.anchor.key_bytes();
        let encoded = canonical_bytes(commitment);
        txn.open_table(tables::ID_REVOCATION_COMMITMENTS)
            .map_err(crate::error::redb)?
            .insert(anchor_key.as_slice(), encoded.as_slice())
            .map_err(crate::error::redb)?;
        self.record_anchor_in_txn(txn, ns, &commitment.anchor, &AnchorScope::Commitment, now)
    }
}
