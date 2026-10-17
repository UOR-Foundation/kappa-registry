//! `IdentityStore` over redb.
//!
//! Published identity records are written only by `EpochExecution`
//! (`epoch_execution_identity.rs` over the `*_in_txn` transitions in
//! `identity_write.rs` and `identity_records.rs`) into the publishing
//! namespace's database, so every record publishes with the epoch that
//! commits it; settlement projects them into the registry's completed
//! cross-namespace projection (`projection`), which these reads serve.
//! Sessions, credentials, and the trust position are written the same way
//! and read from their admitting namespace at its head
//! (`identity_local.rs`).

use kappa_store::clock::ClockMs;
use kappa_store::error::StoreError;
use kappa_store::identity::{
    DeviceBinding, HandleRecord, IdentityAssertion, IdentityBinding, LocatorRecord, PrekeyBinding,
    Revocation, RevocationCommitment, Succession, TrustPosition, Watermark,
};
use kappa_store::kappa::Kappa;
use kappa_store::namespace::ProtocolId;
use kappa_store::page::{Page, PageRequest};
use kappa_store::traits::identity::{CredentialLookup, IdentityStore};

use crate::PersistentStore;

impl IdentityStore for PersistentStore {
    fn binding_get(&self, source: &str) -> Result<Vec<IdentityBinding>, StoreError> {
        self.read_bindings(source)
    }

    fn binding_list_by_target(
        &self,
        target: &Kappa,
        page: &PageRequest,
    ) -> Result<Page<IdentityBinding>, StoreError> {
        self.read_bindings_by_target(target, page)
    }

    fn assertion_get(&self, kappa: &Kappa) -> Result<IdentityAssertion, StoreError> {
        self.read_assertion(kappa)
    }

    fn assertion_list_by_asserter(
        &self,
        asserter: &Kappa,
    ) -> Result<Vec<(Kappa, IdentityAssertion)>, StoreError> {
        self.read_assertions_by_asserter(asserter)
    }

    fn assertion_list_by_subject(
        &self,
        subject: &str,
        page: &PageRequest,
    ) -> Result<Page<(Kappa, IdentityAssertion)>, StoreError> {
        self.read_assertions_by_subject(subject, &|_| true, page)
    }

    fn assertion_list_by_subject_filtered(
        &self,
        subject: &str,
        trust_filter: &dyn Fn(&[u8; 16]) -> bool,
        page: &PageRequest,
    ) -> Result<Page<(Kappa, IdentityAssertion)>, StoreError> {
        self.read_assertions_by_subject(subject, trust_filter, page)
    }

    fn revocation_get(&self, kappa: &Kappa) -> Result<Revocation, StoreError> {
        self.read_revocation(kappa)
    }

    fn revocation_list_by_asserter(&self, asserter: &Kappa) -> Result<Vec<Revocation>, StoreError> {
        self.read_revocations_by_asserter(asserter)
    }

    fn succession_get(&self, old_anchor: &Kappa) -> Result<Kappa, StoreError> {
        self.read_successor(old_anchor)
    }

    fn watermark_get(&self, kappa: &Kappa) -> Result<Watermark, StoreError> {
        self.read_watermark(kappa)
    }

    fn watermark_list_by_asserter(&self, asserter: &Kappa) -> Result<Vec<Watermark>, StoreError> {
        self.read_watermarks_by_asserter(asserter)
    }

    fn handle_get(&self, protocol: ProtocolId, handle: &str) -> Result<HandleRecord, StoreError> {
        self.read_handle(&protocol, handle)
    }

    fn handle_list(&self, page: &PageRequest) -> Result<Page<HandleRecord>, StoreError> {
        self.read_handles(page)
    }

    fn handle_list_by_anchor(
        &self,
        anchor: &Kappa,
        page: &PageRequest,
    ) -> Result<Page<HandleRecord>, StoreError> {
        self.read_handles_by_anchor(anchor, page)
    }

    fn session_get(&self, token: &str, now: ClockMs) -> Result<(Kappa, Vec<u8>), StoreError> {
        self.read_session(token, now)
    }

    fn session_evict(&self, now: ClockMs) -> Result<u64, StoreError> {
        self.evict_sessions(now)
    }

    fn credential_get(
        &self,
        credential_id: &str,
        now: ClockMs,
    ) -> Result<CredentialLookup, StoreError> {
        self.read_credential(credential_id, now)
    }

    fn trust_position_get(&self) -> Result<TrustPosition, StoreError> {
        self.read_trust_position()
    }

    fn device_binding_list(&self, anchor: &Kappa) -> Result<Vec<DeviceBinding>, StoreError> {
        self.read_device_bindings(anchor)
    }

    fn prekey_binding_list(&self, anchor: &Kappa) -> Result<Vec<PrekeyBinding>, StoreError> {
        self.read_prekey_bindings(anchor)
    }

    fn locator_get(&self, anchor: &Kappa) -> Result<Option<LocatorRecord>, StoreError> {
        self.read_locator(anchor)
    }

    fn succession_chain_get(&self, anchor: &Kappa) -> Result<Vec<Succession>, StoreError> {
        self.read_succession_chain(anchor)
    }

    fn revocation_commitment_get(
        &self,
        anchor: &Kappa,
    ) -> Result<Option<RevocationCommitment>, StoreError> {
        self.read_revocation_commitment(anchor)
    }

    fn assertion_index_query(&self, subject: &str) -> Result<Vec<Kappa>, StoreError> {
        self.read_assertion_index(subject)
    }
}
