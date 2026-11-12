//! Identity records written by an execution. Each record and its ledger
//! mutation stay private until the execution publishes; each write runs on
//! the execution's allowance (`EpochExecution::write`).

use kappa_store::identity::{
    DeviceBinding, HandleRecord, IdentityAssertion, IdentityBinding, LocatorRecord, PrekeyBinding,
    Revocation, RevocationCommitment, Succession, TrustPosition, Watermark,
};
use kappa_store::{Kappa, Page, PageRequest, StoreError, namespace::ProtocolId};

use super::EpochExecution;
use crate::identity_local::{CredentialRotation, SessionGrant};
use crate::{identity_records, tables};

impl EpochExecution<'_> {
    pub fn binding_put(&mut self, binding: &IdentityBinding) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.binding_put_in_txn(txn, ns, binding, now, meter)
        })
    }

    pub fn binding_delete(&mut self, source: &str, target: &Kappa) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.binding_delete_in_txn(txn, ns, source, target, now, meter)
        })
    }

    pub fn assertion_put(&mut self, assertion: &IdentityAssertion) -> Result<Kappa, StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.assertion_put_in_txn(txn, ns, assertion, now, meter)
        })
    }

    pub fn revocation_put(&mut self, revocation: &Revocation) -> Result<Kappa, StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.revocation_put_in_txn(txn, ns, revocation, now, meter)
        })
    }

    pub fn watermark_put(&mut self, watermark: &Watermark) -> Result<Kappa, StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.watermark_put_in_txn(txn, ns, watermark, now, meter)
        })
    }

    pub fn handle_put(&mut self, record: &HandleRecord) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.handle_put_in_txn(txn, ns, record, now, meter)
        })
    }

    pub fn handle_attest(&mut self, expected: &HandleRecord) -> Result<bool, StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.handle_attest_in_txn(txn, ns, expected, now, meter)
        })
    }

    pub fn handle_delete(&mut self, protocol: &ProtocolId, handle: &str) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.handle_delete_in_txn(txn, ns, protocol, handle, now, meter)
        })
    }

    pub fn device_binding_put(&mut self, binding: &DeviceBinding) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.device_binding_put_in_txn(txn, ns, binding, now, meter)
        })
    }

    pub fn device_binding_revoke(
        &mut self,
        anchor: &Kappa,
        device_key: &[u8],
    ) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.device_binding_revoke_in_txn(txn, ns, anchor, device_key, now, meter)
        })
    }

    pub fn prekey_binding_put(&mut self, binding: &PrekeyBinding) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.prekey_binding_put_in_txn(txn, ns, binding, now, meter)
        })
    }

    pub fn locator_put(&mut self, record: &LocatorRecord) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.locator_put_in_txn(txn, ns, record, now, meter)
        })
    }

    pub fn revocation_commitment_put(
        &mut self,
        commitment: &RevocationCommitment,
    ) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.revocation_commitment_put_in_txn(txn, ns, commitment, now, meter)
        })
    }

    pub fn succession_put(&mut self, succession: &Succession) -> Result<Kappa, StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.succession_put_in_txn(txn, ns, succession, now, meter)
        })
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
        self.write(|store, txn, ns, now, meter| {
            store.session_put_in_txn(txn, ns, grant, now, meter)
        })
    }

    pub fn session_delete(&mut self, token: &str) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.session_delete_in_txn(txn, ns, token, now, meter)
        })
    }

    pub fn credential_put(
        &mut self,
        credential_id: &str,
        anchor: &Kappa,
        secret_hash: &[u8],
    ) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.credential_put_in_txn(txn, ns, credential_id, anchor, secret_hash, now, meter)
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
        self.write(|store, txn, ns, now, meter| {
            store.credential_rotate_in_txn(txn, ns, rotation, now, meter)
        })
    }

    pub fn credential_delete(&mut self, credential_id: &str) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.credential_delete_in_txn(txn, ns, credential_id, now, meter)
        })
    }

    pub fn trust_position_put(&mut self, position: &TrustPosition) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.trust_position_put_in_txn(txn, ns, position, now, meter)
        })
    }

    /// Absence is a value and does not latch the execution. Read on the
    /// execution's allowance.
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
            .and_then(|table| {
                self.lend(|meter| {
                    identity_records::handle_from_table(&table, protocol, handle, meter)
                })
            });
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
            self.lend(|meter| {
                identity_records::handles_by_anchor_from(&index, &table, anchor, page, meter)
            })
        })();
        self.admit_result(result)
    }
}
