//! Authorization rows written by an execution: sessions, credentials and
//! the trust position. Each goes through the shared transition boundary
//! (`apply_record_transition`) with its checked private payload; the
//! boundary dispatches the row effect to the `apply_*` helpers here, which
//! change the candidate's rows and emit nothing themselves.
//!
//! Shared identity policy decides rotation against the candidate row.
//! Native claims protect admission. Every authorization key an execution writes is
//! held under its stripe across the publication's store (`dependency`).

use kappa_store::transition::RecordTransition;

use kappa_types::authorization::{CredentialTransition, SessionTransition};
use kappa_types::error::StoreError;
use kappa_types::identity::TrustPosition;
use kappa_types::kappa::Kappa;

use kappa_store::identity_scope::session_id;

use super::claims::ClaimKey;
use super::execution::{MemoryPayload, WriteCx};
use super::view::Row;

impl WriteCx<'_> {
    /// Record the session under `token`'s derived identifier. A session
    /// already held under that identifier is replaced; either way the
    /// ledger carries the transition under the identifier, never the token.
    pub fn session_put(
        &mut self,
        token: &str,
        anchor: &Kappa,
        expires_at_ms: i64,
        metadata: &[u8],
    ) -> Result<(), StoreError> {
        let id = session_id(token);
        self.reserve(ClaimKey::Session(id.clone()))?;
        self.apply_record_transition(
            RecordTransition::Session(SessionTransition::set(
                id,
                anchor.clone(),
                expires_at_ms,
                metadata,
            )),
            MemoryPayload::SessionMetadata(metadata.to_vec()),
        )
        .map(drop)
    }

    /// A session this namespace does not hold is a no-op and records no
    /// mutation.
    pub fn session_delete(&mut self, token: &str) -> Result<(), StoreError> {
        let id = session_id(token);
        let Some(row) = self.view.authorization.sessions.get(&id) else {
            return Ok(());
        };
        let anchor = row.value.0.clone();
        self.release(ClaimKey::Session(id.clone()));
        self.apply_record_transition(
            RecordTransition::Session(SessionTransition::deleted(id, anchor)),
            MemoryPayload::NoResources,
        )
        .map(drop)
    }

    pub fn credential_put(
        &mut self,
        credential_id: &str,
        anchor: &Kappa,
        secret_hash: &[u8],
    ) -> Result<(), StoreError> {
        self.reserve(ClaimKey::Credential(credential_id.to_owned()))?;
        self.apply_record_transition(
            RecordTransition::Credential(CredentialTransition::set(
                credential_id.to_owned(),
                anchor.clone(),
                secret_hash,
                None,
            )),
            MemoryPayload::CredentialSecrets {
                secret_hash: secret_hash.to_vec(),
                grace_secret_hash: None,
            },
        )
        .map(drop)
    }

    /// Rotate the secret; the previous one stays valid for
    /// `grace_period_ms` of physical time after now. The credential must be
    /// held by this namespace and owned by `expected_owner`; a deadline
    /// that overflows is refused.
    pub fn credential_rotate(
        &mut self,
        credential_id: &str,
        expected_owner: &Kappa,
        new_secret_hash: &[u8],
        grace_period_ms: u64,
    ) -> Result<(), StoreError> {
        let row = self.view.authorization.credentials.get(credential_id);
        let record = kappa_store::identity_ops::prepare_credential_rotation(
            credential_id,
            row.map(|row| (&row.value.0, row.value.1.as_slice())),
            expected_owner,
            new_secret_hash,
            grace_period_ms,
            self.now,
        )?;
        let previous_hash = row.map(|row| row.value.1.clone());
        self.attempt_guard(ClaimKey::Credential(credential_id.to_owned()));
        self.apply_record_transition(
            RecordTransition::Credential(record),
            MemoryPayload::CredentialSecrets {
                secret_hash: new_secret_hash.to_vec(),
                grace_secret_hash: previous_hash,
            },
        )
        .map(drop)
    }

    /// A credential this namespace does not hold is a no-op and records no
    /// mutation.
    pub fn credential_delete(&mut self, credential_id: &str) -> Result<(), StoreError> {
        let Some(row) = self.view.authorization.credentials.get(credential_id) else {
            return Ok(());
        };
        let anchor = row.value.0.clone();
        self.release(ClaimKey::Credential(credential_id.to_owned()));
        self.apply_record_transition(
            RecordTransition::Credential(CredentialTransition::deleted(
                credential_id.to_owned(),
                anchor,
            )),
            MemoryPayload::NoResources,
        )
        .map(drop)
    }

    /// Set the trust position; the ledger names the identity of the
    /// position record, which is published as evidence.
    pub fn trust_position_put(&mut self, position: &TrustPosition) -> Result<(), StoreError> {
        self.reserve(ClaimKey::Trust)?;
        self.apply_record_transition(
            RecordTransition::Trust(position.clone()),
            MemoryPayload::NoResources,
        )
        .map(drop)
    }

    // -- Application helpers (called only by `apply_write`) ------------------

    /// Hold the session `session` sets, with the metadata its transition's
    /// digest was checked against, at the candidate's revision.
    pub(super) fn apply_session_set(&mut self, session: SessionTransition, metadata: Vec<u8>) {
        let revision = self.view.revision;
        self.view.authorization.sessions.insert(
            session.id,
            Row {
                value: (session.anchor, session.expires_at_ms, metadata),
                revision,
            },
        );
    }

    /// Remove the session `session` deletes.
    pub(super) fn apply_session_delete(&mut self, session: &SessionTransition) {
        self.view.authorization.sessions.remove(&session.id);
    }

    /// Hold the credential `credential` sets, with the secret hashes its
    /// commitments were checked against, at the candidate's revision. The
    /// grace secret is held with the grace deadline the transition carries.
    pub(super) fn apply_credential_set(
        &mut self,
        credential: CredentialTransition,
        secret_hash: Vec<u8>,
        grace_secret_hash: Option<Vec<u8>>,
    ) {
        let revision = self.view.revision;
        self.view.authorization.credentials.insert(
            credential.id,
            Row {
                value: (
                    credential.anchor,
                    secret_hash,
                    grace_secret_hash.zip(credential.grace_expires_ms),
                ),
                revision,
            },
        );
    }

    /// Remove the credential `credential` deletes.
    pub(super) fn apply_credential_delete(&mut self, credential: &CredentialTransition) {
        self.view.authorization.credentials.remove(&credential.id);
    }

    /// Hold `position` as the trust position at the candidate's revision.
    pub(super) const fn apply_trust(&mut self, position: TrustPosition) {
        let revision = self.view.revision;
        self.view.authorization.trust = Some(Row {
            value: position,
            revision,
        });
    }
}
