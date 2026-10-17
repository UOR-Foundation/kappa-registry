use kappa_cursor::KappaCursor;

use kappa_types::clock::ClockMs;
use kappa_types::error::StoreError;
use kappa_types::identity::{
    HandleRecord, IdentityAssertion, IdentityBinding, Revocation, Succession, TrustPosition,
    Watermark,
};
use kappa_types::kappa::Kappa;
use kappa_types::namespace::ProtocolId;
use kappa_types::page::{Page, PageRequest};

pub type CredentialLookup = (Kappa, Vec<u8>, Option<(Vec<u8>, i64)>);

/// The key an `assertion_list_by_subject_filtered` trust filter receives.
///
/// For an asserter: the first 16 bytes of BLAKE3 over the asserter's
/// `key_bytes`. Every backend and every filter builder computes it here.
#[must_use]
pub fn asserter_filter_key(asserter: &Kappa) -> [u8; 16] {
    let hash = blake3::hash(&asserter.key_bytes());
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash.as_bytes()[..16]);
    key
}

/// Identity storage primitives.
///
/// Native record types read as typed Rust values. Every identity record
/// (bindings, assertions, revocations, successions, watermarks, handles,
/// device and prekey bindings, locators, revocation commitments) and
/// every authorization row (sessions, credentials, the trust position) is
/// written through `ExecutionWrites` and publishes with the namespace
/// epoch that commits it; the epoch's ledger carries the transition record
/// that governs the row. This trait only reads, except `session_evict`,
/// which removes rows whose recorded deadline has already passed and
/// therefore changes no authorization outcome.
///
/// Business logic (succession creates watermark, binding upsert,
/// chain walk with cycle detection, delegation depth enforcement,
/// resolution filtering by revocation+watermark) lives in free
/// functions in `identity_ops`.
pub trait IdentityStore: Send + Sync {
    // =====================================================================
    // 1. BINDINGS — external identifier -> anchor
    // =====================================================================

    /// Get all bindings for a source identifier. Cross-namespace.
    fn binding_get(&self, source: &str) -> Result<Vec<IdentityBinding>, StoreError>;

    /// List all bindings targeting a given anchor. Cross-namespace.
    /// Paginated for consistency with the rest of the trait surface.
    fn binding_list_by_target(
        &self,
        target: &Kappa,
        page: &PageRequest,
    ) -> Result<Page<IdentityBinding>, StoreError>;

    // =====================================================================
    // 2. ASSERTIONS — signed claims about subjects
    // =====================================================================

    /// Get an assertion by its kappa.
    fn assertion_get(&self, kappa: &Kappa) -> Result<IdentityAssertion, StoreError>;

    /// List all assertions by a given asserter.
    /// Per-anchor, bounded by assertion count per anchor (~hundreds).
    fn assertion_list_by_asserter(
        &self,
        asserter: &Kappa,
    ) -> Result<Vec<(Kappa, IdentityAssertion)>, StoreError>;

    /// List all assertions about a given subject. Cross-namespace.
    /// Paginated — at scale, one subject may have thousands of
    /// assertions from hundreds of asserters.
    fn assertion_list_by_subject(
        &self,
        subject: &str,
        page: &PageRequest,
    ) -> Result<Page<(Kappa, IdentityAssertion)>, StoreError>;

    /// List assertions about a subject, filtering by asserter hash
    /// BEFORE loading assertion blobs.
    ///
    /// The `trust_filter` receives `asserter_filter_key` of each
    /// asserter. It returns true for trusted asserters.
    /// Assertions from untrusted asserters are never loaded from
    /// storage. This is filter-before-dereference.
    ///
    /// At 10,000 assertions from 100 asserters where 1 is trusted,
    /// the unfiltered method loads 10,000 blobs. This method loads
    /// ~100 blobs (only those from the trusted asserter).
    fn assertion_list_by_subject_filtered(
        &self,
        subject: &str,
        trust_filter: &dyn Fn(&[u8; 16]) -> bool,
        page: &PageRequest,
    ) -> Result<Page<(Kappa, IdentityAssertion)>, StoreError>;

    // =====================================================================
    // 3. DELEGATION
    //
    // Delegations are edges with SemanticRelation(semantic::DELEGATION)
    // and DelegationScope metadata. They use EdgeStore. No separate
    // IdentityStore methods. Business logic (depth enforcement, scope
    // narrowing, chain walk) is in free functions that query EdgeStore.
    // =====================================================================

    // =====================================================================
    // 4. REVOCATION — voiding previous claims
    // =====================================================================

    /// Get a revocation by its kappa.
    fn revocation_get(&self, kappa: &Kappa) -> Result<Revocation, StoreError>;

    /// List all revocations by a given asserter.
    /// Per-anchor, bounded (~tens of revocations per asserter).
    fn revocation_list_by_asserter(&self, asserter: &Kappa) -> Result<Vec<Revocation>, StoreError>;

    // =====================================================================
    // 5. SUCCESSION — key rotation without losing identity
    // =====================================================================

    /// Get the immediate successor of an anchor. Returns `NotFound`
    /// if no successor exists.
    fn succession_get(&self, old_anchor: &Kappa) -> Result<Kappa, StoreError>;

    // =====================================================================
    // 6. WATERMARK — O(1) bulk invalidation
    // =====================================================================

    /// Get a watermark by its kappa.
    fn watermark_get(&self, kappa: &Kappa) -> Result<Watermark, StoreError>;

    /// List all watermarks for a given asserter.
    /// Per-anchor, bounded (~few per anchor lifetime).
    fn watermark_list_by_asserter(&self, asserter: &Kappa) -> Result<Vec<Watermark>, StoreError>;

    // =====================================================================
    // 7. HANDLES — human-readable names -> anchors
    // =====================================================================

    /// Get a handle by (protocol, `handle_string`).
    fn handle_get(&self, protocol: ProtocolId, handle: &str) -> Result<HandleRecord, StoreError>;

    /// Traverse current handle records across protocols, ordered by protocol and handle.
    fn handle_list(&self, page: &PageRequest) -> Result<Page<HandleRecord>, StoreError>;

    /// Get all handles for a given anchor. Cross-protocol, paginated.
    fn handle_list_by_anchor(
        &self,
        anchor: &Kappa,
        page: &PageRequest,
    ) -> Result<Page<HandleRecord>, StoreError>;

    // =====================================================================
    // 8. SESSIONS — ephemeral authenticated state
    // =====================================================================

    /// Get a session by access token. Returns `NotFound` if expired
    /// or nonexistent. `expires_at_ms` was recorded as an encoded
    /// `ClockMs` (`now.add_physical_ms(ttl).as_i64()`) and is compared
    /// with the encoded current time.
    fn session_get(&self, token: &str, now: ClockMs) -> Result<(Kappa, Vec<u8>), StoreError>;

    /// Remove the rows of sessions already expired before `now` from the
    /// published view. Expiry is decided by the record, so this changes no
    /// authorization outcome; it reclaims the rows. Writes are
    /// `ExecutionWrites::session_put` and `session_delete`.
    fn session_evict(&self, now: ClockMs) -> Result<u64, StoreError>;

    // =====================================================================
    // 9. CREDENTIALS — proof material for authentication
    // =====================================================================

    /// Get a credential by its identifier. Writes are
    /// `ExecutionWrites::credential_put`, `credential_rotate` and
    /// `credential_delete`.
    ///
    /// Returns (anchor, `current_secret_hash`, grace).
    /// grace is `Some((old_secret_hash, grace_expires_ms))` when the
    /// credential was recently rotated and `now < grace_expires_ms`.
    /// The store filters expired grace internally. The caller never
    /// sees grace data past its expiration.
    ///
    /// The `grace_expires_ms` is returned for audit logging. The auth
    /// layer uses it to log "accepted via grace period expiring at T."
    /// It is an encoded `ClockMs`: rotation time plus the grace period in
    /// physical milliseconds.
    ///
    /// The auth layer checks: if the provided secret matches
    /// `current_secret_hash`, accept. If not and grace is Some and
    /// the provided secret matches `old_secret_hash`, accept.
    /// Otherwise reject. The caller does not check expiration —
    /// the store already filtered it.
    fn credential_get(
        &self,
        credential_id: &str,
        now: ClockMs,
    ) -> Result<CredentialLookup, StoreError>;

    // =====================================================================
    // 10. TRUST POSITION — runtime federation state
    // =====================================================================

    /// Get the node's current trust position. The write is
    /// `ExecutionWrites::trust_position_put`.
    fn trust_position_get(&self) -> Result<TrustPosition, StoreError>;

    // =====================================================================
    // 11. DEVICE BINDINGS — per-device keys under one anchor
    // =====================================================================

    /// List all device bindings for an anchor.
    fn device_binding_list(
        &self,
        anchor: &Kappa,
    ) -> Result<Vec<kappa_types::identity::DeviceBinding>, StoreError>;

    // =====================================================================
    // 12. PREKEY BINDINGS — forward-secret key agreement material
    // =====================================================================

    /// List all prekey bindings for an anchor.
    fn prekey_binding_list(
        &self,
        anchor: &Kappa,
    ) -> Result<Vec<kappa_types::identity::PrekeyBinding>, StoreError>;

    /// Get the current prekey binding for an anchor.
    /// Returns the binding with the highest epoch.
    fn prekey_binding_current(
        &self,
        anchor: &Kappa,
    ) -> Result<Option<kappa_types::identity::PrekeyBinding>, StoreError> {
        let bindings = self.prekey_binding_list(anchor)?;
        Ok(bindings.into_iter().max_by_key(|b| b.epoch))
    }

    // =====================================================================
    // 13. LOCATOR RECORDS — network addressing with epoch protection
    // =====================================================================

    /// Get the current locator record for an anchor.
    fn locator_get(
        &self,
        anchor: &Kappa,
    ) -> Result<Option<kappa_types::identity::LocatorRecord>, StoreError>;

    // =====================================================================
    // 14. SUCCESSION CHAIN QUERY
    // =====================================================================

    /// Get all succession records starting from an anchor.
    /// Returns the chain in epoch order. Used by `verify_succession_chain`
    /// in `identity_ops` to construct a `SuccessionChain`.
    fn succession_chain_get(&self, anchor: &Kappa) -> Result<Vec<Succession>, StoreError>;

    // =====================================================================
    // 15. REVOCATION COMMITMENT — pre-committed revocation
    // =====================================================================

    /// Get the revocation commitment for an anchor.
    fn revocation_commitment_get(
        &self,
        anchor: &Kappa,
    ) -> Result<Option<kappa_types::identity::RevocationCommitment>, StoreError>;

    // =====================================================================
    // CROSS-NAMESPACE INDEX — query accelerator
    // =====================================================================

    /// Query the assertion index by subject. Returns all assertion
    /// kappas across all namespaces. `ExecutionWrites::assertion_put`
    /// maintains the index.
    fn assertion_index_query(&self, subject: &str) -> Result<Vec<Kappa>, StoreError>;

    /// Cursor over assertion kappas for a subject, sorted by `key_bytes()`.
    /// Composable with trust filter cursors via Intersection.
    ///
    /// Default: materializes `assertion_index_query` into a `SliceCursor`.
    fn assertion_cursor(&self, subject: &str) -> Result<Box<dyn KappaCursor + '_>, StoreError> {
        let kappas = self.assertion_index_query(subject)?;
        let key_bytes: Vec<Vec<u8>> = kappas.iter().map(Kappa::key_bytes).collect();
        Ok(Box::new(kappa_cursor::SliceCursor::from_owned(key_bytes)))
    }
}
