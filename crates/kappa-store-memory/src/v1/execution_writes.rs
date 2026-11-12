//! The `ExecutionWrites` contract over the memory execution: every write
//! applies to the private candidate through the writer of its module
//! (`WriteCx`), which records its ledger mutation there.

use kappa_crypto::Verified;
use kappa_store::execution::Retirement;
use kappa_store::{
    CompositionEvidence, EdgeInput, ExecutionWrites, IngestResult, Kappa, PreparedContent,
    StoreError, TagUpdate, VerifiedContent,
    identity::{
        DeviceBinding, HandleRecord, IdentityAssertion, IdentityBinding, LocatorRecord,
        PrekeyBinding, Revocation, RevocationCommitment, Succession, TrustPosition, Watermark,
    },
    namespace::ProtocolId,
};

use super::execution::MemoryExecution;

impl ExecutionWrites for MemoryExecution<'_> {
    fn tag_put(&mut self, name: &str, update: &TagUpdate) -> Result<(), StoreError> {
        self.write(|cx| cx.tag_put(name, update).map(drop))
    }

    fn tag_delete(&mut self, name: &str) -> Result<(), StoreError> {
        self.write(|cx| cx.tag_delete(name).map(drop))
    }

    fn tag_batch_update(&mut self, updates: &[(String, TagUpdate)]) -> Result<(), StoreError> {
        self.write(|cx| cx.tag_batch(updates).map(drop))
    }

    fn edge_put(&mut self, input: &EdgeInput) -> Result<Kappa, StoreError> {
        self.write(|cx| cx.edge_put(input))
    }

    fn edge_put_batch(&mut self, inputs: &[EdgeInput]) -> Result<Vec<Kappa>, StoreError> {
        self.write(|cx| inputs.iter().map(|input| cx.edge_put(input)).collect())
    }

    fn edge_delete(&mut self, identity: &Kappa) -> Result<(), StoreError> {
        self.write(|cx| cx.edge_delete(identity))
    }

    fn sequence_next(&mut self, name: &str) -> Result<u64, StoreError> {
        self.write(|cx| cx.sequence_next(name))
    }

    fn namespace_create(
        &mut self,
        owner: Option<&Kappa>,
        protocol: Option<&ProtocolId>,
    ) -> Result<(), StoreError> {
        self.write(|cx| cx.namespace_create(owner, protocol))
    }

    fn namespace_transfer(&mut self, new_owner: &Kappa) -> Result<(), StoreError> {
        self.write(|cx| cx.namespace_transfer(new_owner))
    }

    #[expect(
        clippy::redundant_closure_for_method_calls,
        reason = "`WriteCx`'s lifetime is an impl parameter, fixed per path; `write` needs a closure general over it"
    )]
    fn namespace_delete(&mut self) -> Result<(), StoreError> {
        self.write(|cx| cx.namespace_delete())
    }

    fn namespace_rename(&mut self, new_name: &str) -> Result<(), StoreError> {
        let renamed = self.write(|cx| {
            let ns = cx.ns;
            cx.namespace_rename(ns.display_name(), new_name, ns.protocol())
        })?;
        self.set_namespace(renamed);
        Ok(())
    }

    fn namespace_add_alias(
        &mut self,
        alias: &str,
        protocol: Option<&ProtocolId>,
    ) -> Result<(), StoreError> {
        self.write(|cx| cx.namespace_add_alias(alias, protocol))
    }

    fn namespace_put_meta(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.write(|cx| cx.namespace_put_meta(key, value))
    }

    fn namespace_delete_meta(&mut self, key: &str) -> Result<(), StoreError> {
        self.write(|cx| cx.namespace_delete_meta(key))
    }

    fn binding_put(&mut self, binding: &IdentityBinding) -> Result<(), StoreError> {
        self.write(|cx| cx.binding_put(binding))
    }

    fn binding_delete(&mut self, source: &str, target: &Kappa) -> Result<(), StoreError> {
        self.write(|cx| cx.binding_delete(source, target))
    }

    fn assertion_put(&mut self, assertion: &IdentityAssertion) -> Result<Kappa, StoreError> {
        self.write(|cx| cx.assertion_put(assertion))
    }

    fn revocation_put(&mut self, revocation: &Revocation) -> Result<Kappa, StoreError> {
        self.write(|cx| cx.revocation_put(revocation))
    }

    fn watermark_put(&mut self, watermark: &Watermark) -> Result<Kappa, StoreError> {
        self.write(|cx| cx.watermark_put(watermark))
    }

    fn handle_put(&mut self, record: &HandleRecord) -> Result<(), StoreError> {
        self.write(|cx| cx.handle_put(record))
    }

    fn handle_attest(&mut self, expected: &HandleRecord) -> Result<bool, StoreError> {
        self.write(|cx| cx.handle_attest(expected))
    }

    fn handle_delete(&mut self, protocol: &ProtocolId, handle: &str) -> Result<(), StoreError> {
        self.write(|cx| cx.handle_delete(protocol, handle))
    }

    fn device_binding_put(&mut self, binding: &DeviceBinding) -> Result<(), StoreError> {
        self.write(|cx| cx.device_binding_put(binding))
    }

    fn device_binding_revoke(
        &mut self,
        anchor: &Kappa,
        device_key: &[u8],
    ) -> Result<(), StoreError> {
        self.write(|cx| cx.device_binding_revoke(anchor, device_key))
    }

    fn prekey_binding_put(&mut self, binding: &PrekeyBinding) -> Result<(), StoreError> {
        self.write(|cx| cx.prekey_binding_put(binding))
    }

    fn locator_put(&mut self, record: &LocatorRecord) -> Result<(), StoreError> {
        self.write(|cx| cx.locator_put(record))
    }

    fn revocation_commitment_put(
        &mut self,
        commitment: &RevocationCommitment,
    ) -> Result<(), StoreError> {
        self.write(|cx| cx.revocation_commitment_put(commitment))
    }

    fn succession_put(&mut self, succession: &Verified<Succession>) -> Result<Kappa, StoreError> {
        self.write(|cx| cx.succession_put(succession.get()))
    }

    fn session_put(
        &mut self,
        token: &str,
        anchor: &Kappa,
        expires_at_ms: i64,
        metadata: &[u8],
    ) -> Result<(), StoreError> {
        self.write(|cx| cx.session_put(token, anchor, expires_at_ms, metadata))
    }

    fn session_delete(&mut self, token: &str) -> Result<(), StoreError> {
        self.write(|cx| cx.session_delete(token))
    }

    fn credential_put(
        &mut self,
        credential_id: &str,
        anchor: &Kappa,
        secret_hash: &[u8],
    ) -> Result<(), StoreError> {
        self.write(|cx| cx.credential_put(credential_id, anchor, secret_hash))
    }

    fn credential_rotate(
        &mut self,
        credential_id: &str,
        expected_owner: &Kappa,
        new_secret_hash: &[u8],
        grace_period_ms: u64,
    ) -> Result<(), StoreError> {
        self.write(|cx| {
            cx.credential_rotate(
                credential_id,
                expected_owner,
                new_secret_hash,
                grace_period_ms,
            )
        })
    }

    fn credential_delete(&mut self, credential_id: &str) -> Result<(), StoreError> {
        self.write(|cx| cx.credential_delete(credential_id))
    }

    fn trust_position_put(&mut self, position: &TrustPosition) -> Result<(), StoreError> {
        self.write(|cx| cx.trust_position_put(position))
    }

    fn blob_put(&mut self, content: &VerifiedContent) -> Result<bool, StoreError> {
        self.write(|cx| cx.publish_record(content))
    }

    fn blob_meta_put(
        &mut self,
        identity: &Kappa,
        key: &str,
        value: &[u8],
    ) -> Result<(), StoreError> {
        self.write(|cx| cx.blob_meta_put(identity, key, value))
    }

    fn blob_meta_delete(&mut self, identity: &Kappa, key: &str) -> Result<(), StoreError> {
        self.write(|cx| cx.blob_meta_delete(identity, key))
    }

    fn content_install(
        &mut self,
        prepared: Box<dyn PreparedContent>,
    ) -> Result<IngestResult, StoreError> {
        self.write(|cx| cx.install_prepared(prepared))
    }

    /// The bytes of a retired identity are released with the last view or
    /// reader holding its allocation (`allocation`).
    fn content_retire(&mut self, identity: &Kappa) -> Result<Retirement, StoreError> {
        self.write(|cx| cx.retire(identity))
    }

    fn content_compose(
        &mut self,
        evidence: &CompositionEvidence,
    ) -> Result<IngestResult, StoreError> {
        self.write(|cx| cx.compose(evidence))
    }
}
