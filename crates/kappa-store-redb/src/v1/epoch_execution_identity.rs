//! Identity records written by an execution. Each record and its ledger
//! mutation stay private until the execution publishes.

use kappa_store::identity::{
    DeviceBinding, HandleRecord, IdentityAssertion, IdentityBinding, LocatorRecord, PrekeyBinding,
    Revocation, RevocationCommitment, Succession, TrustPosition, Watermark,
};
use kappa_store::{
    ClockMs, Kappa, NamespaceRef, Page, PageRequest, StoreError, namespace::ProtocolId,
};

use super::EpochExecution;
use crate::identity_local::{CredentialRotation, SessionGrant};
use crate::{PersistentStore, identity_records, tables};

impl EpochExecution<'_> {
    /// Runs one write against this execution's writer and latches failure.
    fn write<T>(
        &self,
        operation: impl FnOnce(
            &PersistentStore,
            &redb::WriteTransaction,
            &NamespaceRef,
            ClockMs,
        ) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.ensure_active()?;
        self.admit_result(operation(
            self.store,
            &self.transaction,
            &self.namespace,
            self.now,
        ))
    }

    pub fn binding_put(&mut self, binding: &IdentityBinding) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now| store.binding_put_in_txn(txn, ns, binding, now))
    }

    pub fn binding_delete(&mut self, source: &str, target: &Kappa) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now| store.binding_delete_in_txn(txn, ns, source, target, now))
    }

    pub fn assertion_put(&mut self, assertion: &IdentityAssertion) -> Result<Kappa, StoreError> {
        self.write(|store, txn, ns, now| store.assertion_put_in_txn(txn, ns, assertion, now))
    }

    pub fn revocation_put(&mut self, revocation: &Revocation) -> Result<Kappa, StoreError> {
        self.write(|store, txn, ns, now| store.revocation_put_in_txn(txn, ns, revocation, now))
    }

    pub fn watermark_put(&mut self, watermark: &Watermark) -> Result<Kappa, StoreError> {
        self.write(|store, txn, ns, now| store.watermark_put_in_txn(txn, ns, watermark, now))
    }

    pub fn handle_put(&mut self, record: &HandleRecord) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now| store.handle_put_in_txn(txn, ns, record, now))
    }

    pub fn handle_attest(&mut self, expected: &HandleRecord) -> Result<bool, StoreError> {
        self.write(|store, txn, ns, now| store.handle_attest_in_txn(txn, ns, expected, now))
    }

    pub fn handle_delete(&mut self, protocol: &ProtocolId, handle: &str) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now| store.handle_delete_in_txn(txn, ns, protocol, handle, now))
    }

    pub fn device_binding_put(&mut self, binding: &DeviceBinding) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now| store.device_binding_put_in_txn(txn, ns, binding, now))
    }

    pub fn device_binding_revoke(
        &mut self,
        anchor: &Kappa,
        device_key: &[u8],
    ) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now| {
            store.device_binding_revoke_in_txn(txn, ns, anchor, device_key, now)
        })
    }

    pub fn prekey_binding_put(&mut self, binding: &PrekeyBinding) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now| store.prekey_binding_put_in_txn(txn, ns, binding, now))
    }

    pub fn locator_put(&mut self, record: &LocatorRecord) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now| store.locator_put_in_txn(txn, ns, record, now))
    }

    pub fn revocation_commitment_put(
        &mut self,
        commitment: &RevocationCommitment,
    ) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now| {
            store.revocation_commitment_put_in_txn(txn, ns, commitment, now)
        })
    }

    pub fn succession_put(&mut self, succession: &Succession) -> Result<Kappa, StoreError> {
        self.write(|store, txn, ns, now| store.succession_put_in_txn(txn, ns, succession, now))
    }

    pub fn session_put(
        &mut self,
        token: &str,
        anchor: &Kappa,
        expires_at_ms: i64,
        metadata: &[u8],
    ) -> Result<(), StoreError> {
        let grant = SessionGrant {
            token,
            anchor,
            expires_at_ms,
            metadata,
        };
        self.write(|store, txn, ns, now| store.session_put_in_txn(txn, ns, grant, now))
    }

    pub fn session_delete(&mut self, token: &str) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now| store.session_delete_in_txn(txn, ns, token, now))
    }

    pub fn credential_put(
        &mut self,
        credential_id: &str,
        anchor: &Kappa,
        secret_hash: &[u8],
    ) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now| {
            store.credential_put_in_txn(txn, ns, credential_id, anchor, secret_hash, now)
        })
    }

    pub fn credential_rotate(
        &mut self,
        credential_id: &str,
        expected_owner: &Kappa,
        new_secret_hash: &[u8],
        grace_period_ms: u64,
    ) -> Result<(), StoreError> {
        let rotation = CredentialRotation {
            credential_id,
            expected_owner,
            new_secret_hash,
            grace_period_ms,
        };
        self.write(|store, txn, ns, now| store.credential_rotate_in_txn(txn, ns, rotation, now))
    }

    pub fn credential_delete(&mut self, credential_id: &str) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now| {
            store.credential_delete_in_txn(txn, ns, credential_id, now)
        })
    }

    pub fn trust_position_put(&mut self, position: &TrustPosition) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now| store.trust_position_put_in_txn(txn, ns, position, now))
    }

    /// Absence is a value and does not latch the execution.
    pub fn handle_get(
        &self,
        protocol: &ProtocolId,
        handle: &str,
    ) -> Result<Option<HandleRecord>, StoreError> {
        self.ensure_active()?;
        let result = self
            .transaction
            .open_table(tables::ID_HANDLES)
            .map_err(crate::error::redb)
            .and_then(|table| identity_records::handle_from_table(&table, protocol, handle));
        self.admit_result(kappa_store::absent(result))
    }

    pub fn handle_list_by_anchor(
        &self,
        anchor: &Kappa,
        page: &PageRequest,
    ) -> Result<Page<HandleRecord>, StoreError> {
        self.ensure_active()?;
        let result = (|| {
            let index = self
                .transaction
                .open_multimap_table(tables::ID_HANDLE_ANCHOR_IDX)
                .map_err(crate::error::redb)?;
            let table = self
                .transaction
                .open_table(tables::ID_HANDLES)
                .map_err(crate::error::redb)?;
            identity_records::handles_by_anchor_from(&index, &table, anchor, page)
        })();
        self.admit_result(result)
    }
}
