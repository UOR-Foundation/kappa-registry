//! The shared execution contract over the redb writer-owned execution.

use std::time::Instant;

use kappa_store::{
    ClockMs, EdgeInput, Execution, ExecutionReads, ExecutionWrites, IngestResult, Kappa,
    NamespaceInfo, NamespaceRef, Page, PageRequest, Published, StoreError, TagEntry, TagUpdate,
    VerifiedContent,
    identity::{
        DeviceBinding, HandleRecord, IdentityAssertion, IdentityBinding, LocatorRecord,
        PrekeyBinding, Revocation, RevocationCommitment, Succession, TrustPosition, Watermark,
    },
    namespace::ProtocolId,
};

use super::EpochExecution;

impl ExecutionReads for EpochExecution<'_> {
    fn namespace(&self) -> &NamespaceRef {
        &self.namespace
    }
    fn now(&self) -> ClockMs {
        self.now
    }
    fn tag_get(&self, name: &str) -> Result<Option<TagEntry>, StoreError> {
        Self::tag_get(self, name)
    }
    fn tag_get_raw(&self, name: &str) -> Result<Option<TagEntry>, StoreError> {
        Self::tag_get_raw(self, name)
    }
    fn namespace_info(&self) -> Result<Option<NamespaceInfo>, StoreError> {
        Self::namespace_info(self)
    }
    fn sequence_current(&self, name: &str) -> Result<u64, StoreError> {
        Self::sequence_current(self, name)
    }
    fn namespace_get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Self::namespace_get_meta(self, key)
    }
    fn blob_meta_get(&self, identity: &Kappa, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.ensure_active()?;
        let result = self
            .transaction
            .open_table(crate::tables::BLOB_META)
            .map_err(crate::error::redb)
            .and_then(|table| {
                self.lend(|meter| {
                    crate::epoch_blob::blob_meta_from_table(
                        self.store, &table, identity, key, meter,
                    )
                })
            });
        self.admit_result(kappa_store::absent(result))
    }
    fn blob_get_verified(
        &self,
        identity: &Kappa,
        maximum: u64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        Self::blob_get_verified(self, identity, maximum)
    }
    fn handle_get(
        &self,
        protocol: &ProtocolId,
        handle: &str,
    ) -> Result<Option<HandleRecord>, StoreError> {
        Self::handle_get(self, protocol, handle)
    }
    fn handle_list_by_anchor(
        &self,
        anchor: &Kappa,
        page: &PageRequest,
    ) -> Result<Page<HandleRecord>, StoreError> {
        Self::handle_list_by_anchor(self, anchor, page)
    }
    fn edge_query(
        &self,
        query: &kappa_store::EdgeQuery,
        page: &PageRequest,
    ) -> Result<Page<kappa_store::Edge>, StoreError> {
        self.ensure_active()?;
        let result = self
            .store
            .edge_query_in_txn(&self.transaction, &self.namespace, query, page);
        self.admit_result(result)
    }
    fn session_get(&self, token: &str) -> Result<Option<(Kappa, Vec<u8>)>, StoreError> {
        Self::session_get(self, token)
    }
    fn credential_get(
        &self,
        credential_id: &str,
    ) -> Result<Option<kappa_store::traits::identity::CredentialLookup>, StoreError> {
        Self::credential_get(self, credential_id)
    }
}

impl ExecutionWrites for EpochExecution<'_> {
    fn tag_put(&mut self, name: &str, update: &TagUpdate) -> Result<(), StoreError> {
        Self::tag_put(self, name, update)
    }
    fn tag_delete(&mut self, name: &str) -> Result<(), StoreError> {
        Self::tag_delete(self, name)
    }
    fn tag_batch_update(&mut self, updates: &[(String, TagUpdate)]) -> Result<(), StoreError> {
        Self::tag_batch_update(self, updates)
    }
    fn edge_put(&mut self, input: &EdgeInput) -> Result<Kappa, StoreError> {
        Self::edge_put(self, input)
    }
    fn edge_put_batch(&mut self, inputs: &[EdgeInput]) -> Result<Vec<Kappa>, StoreError> {
        Self::edge_put_batch(self, inputs)
    }
    fn edge_delete(&mut self, identity: &Kappa) -> Result<(), StoreError> {
        Self::edge_delete(self, identity)
    }
    fn sequence_next(&mut self, name: &str) -> Result<u64, StoreError> {
        Self::sequence_next(self, name)
    }
    fn namespace_create(
        &mut self,
        owner: Option<&Kappa>,
        protocol: Option<&ProtocolId>,
    ) -> Result<(), StoreError> {
        Self::namespace_create(self, owner, protocol)
    }
    fn namespace_transfer(&mut self, new_owner: &Kappa) -> Result<(), StoreError> {
        Self::namespace_transfer(self, new_owner)
    }
    fn namespace_delete(&mut self) -> Result<(), StoreError> {
        Self::namespace_delete(self)
    }
    fn namespace_rename(&mut self, new_name: &str) -> Result<(), StoreError> {
        Self::namespace_rename(self, new_name)
    }
    fn namespace_add_alias(
        &mut self,
        alias: &str,
        protocol: Option<&ProtocolId>,
    ) -> Result<(), StoreError> {
        Self::namespace_add_alias(self, alias, protocol)
    }
    fn namespace_put_meta(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        Self::namespace_put_meta(self, key, value)
    }
    fn namespace_delete_meta(&mut self, key: &str) -> Result<(), StoreError> {
        Self::namespace_delete_meta(self, key)
    }
    fn binding_put(&mut self, binding: &IdentityBinding) -> Result<(), StoreError> {
        Self::binding_put(self, binding)
    }
    fn binding_delete(&mut self, source: &str, target: &Kappa) -> Result<(), StoreError> {
        Self::binding_delete(self, source, target)
    }
    fn assertion_put(&mut self, assertion: &IdentityAssertion) -> Result<Kappa, StoreError> {
        Self::assertion_put(self, assertion)
    }
    fn revocation_put(&mut self, revocation: &Revocation) -> Result<Kappa, StoreError> {
        Self::revocation_put(self, revocation)
    }
    fn watermark_put(&mut self, watermark: &Watermark) -> Result<Kappa, StoreError> {
        Self::watermark_put(self, watermark)
    }
    fn handle_put(&mut self, record: &HandleRecord) -> Result<(), StoreError> {
        Self::handle_put(self, record)
    }
    fn handle_attest(&mut self, expected: &HandleRecord) -> Result<bool, StoreError> {
        Self::handle_attest(self, expected)
    }
    fn handle_delete(&mut self, protocol: &ProtocolId, handle: &str) -> Result<(), StoreError> {
        Self::handle_delete(self, protocol, handle)
    }
    fn device_binding_put(&mut self, binding: &DeviceBinding) -> Result<(), StoreError> {
        Self::device_binding_put(self, binding)
    }
    fn device_binding_revoke(
        &mut self,
        anchor: &Kappa,
        device_key: &[u8],
    ) -> Result<(), StoreError> {
        Self::device_binding_revoke(self, anchor, device_key)
    }
    fn prekey_binding_put(&mut self, binding: &PrekeyBinding) -> Result<(), StoreError> {
        Self::prekey_binding_put(self, binding)
    }
    fn locator_put(&mut self, record: &LocatorRecord) -> Result<(), StoreError> {
        Self::locator_put(self, record)
    }
    fn revocation_commitment_put(
        &mut self,
        commitment: &RevocationCommitment,
    ) -> Result<(), StoreError> {
        Self::revocation_commitment_put(self, commitment)
    }
    fn succession_put(
        &mut self,
        succession: &kappa_crypto::Verified<Succession>,
    ) -> Result<Kappa, StoreError> {
        Self::succession_put(self, succession.get())
    }
    fn session_put(
        &mut self,
        token: &str,
        anchor: &Kappa,
        expires_at_ms: i64,
        metadata: &[u8],
    ) -> Result<(), StoreError> {
        Self::session_put(self, token, anchor, expires_at_ms, metadata)
    }
    fn session_delete(&mut self, token: &str) -> Result<(), StoreError> {
        Self::session_delete(self, token)
    }
    fn credential_put(
        &mut self,
        credential_id: &str,
        anchor: &Kappa,
        secret_hash: &[u8],
    ) -> Result<(), StoreError> {
        Self::credential_put(self, credential_id, anchor, secret_hash)
    }
    fn credential_rotate(
        &mut self,
        credential_id: &str,
        expected_owner: &Kappa,
        new_secret_hash: &[u8],
        grace_period_ms: u64,
    ) -> Result<(), StoreError> {
        Self::credential_rotate(
            self,
            credential_id,
            expected_owner,
            new_secret_hash,
            grace_period_ms,
        )
    }
    fn credential_delete(&mut self, credential_id: &str) -> Result<(), StoreError> {
        Self::credential_delete(self, credential_id)
    }
    fn trust_position_put(&mut self, position: &TrustPosition) -> Result<(), StoreError> {
        Self::trust_position_put(self, position)
    }
    fn blob_put(&mut self, content: &VerifiedContent) -> Result<bool, StoreError> {
        Self::blob_put(self, content)
    }
    fn blob_meta_put(
        &mut self,
        identity: &Kappa,
        key: &str,
        value: &[u8],
    ) -> Result<(), StoreError> {
        self.with_writer(|writer| writer.admit_blob_meta(identity, key, Some(value)))
    }
    /// Deleting metadata this namespace does not hold is a no-op and
    /// records no mutation.
    fn blob_meta_delete(&mut self, identity: &Kappa, key: &str) -> Result<(), StoreError> {
        self.with_writer(|writer| writer.admit_blob_meta(identity, key, None))
    }
    fn content_install(
        &mut self,
        prepared: Box<dyn kappa_store::PreparedContent>,
    ) -> Result<IngestResult, StoreError> {
        self.ensure_active()?;
        let etag = prepared.etag().map(str::to_owned);
        let prepared = prepared
            .as_any()
            .downcast::<crate::PreparedContent>()
            .map_err(|_| StoreError::Rejected("content was prepared by another store".into()))?;
        let mut result = Self::install_content(self, *prepared)?;
        result.etag = etag;
        Ok(result)
    }
    fn content_retire(
        &mut self,
        identity: &Kappa,
    ) -> Result<kappa_store::execution::Retirement, StoreError> {
        Self::retire_content(self, identity)
    }
    fn content_compose(
        &mut self,
        evidence: &kappa_store::CompositionEvidence,
    ) -> Result<IngestResult, StoreError> {
        Self::compose_content(self, evidence)
    }
}

impl Execution for EpochExecution<'_> {
    fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = Some(deadline);
        self.meter.get_mut().tighten_deadline(deadline);
    }
    fn publish(self: Box<Self>) -> Result<Published, StoreError> {
        let (epoch_number, root) = Self::publish(*self)?;
        Ok(Published { epoch_number, root })
    }
    fn publish_result(self: Box<Self>, result: Vec<u8>) -> Result<Published, StoreError> {
        let (epoch_number, root) = Self::publish_result(*self, result)?;
        Ok(Published { epoch_number, root })
    }
    fn abort(self: Box<Self>) -> Result<(), StoreError> {
        Self::abort(*self)
    }
}
