//! Authorization rows written by an execution: sessions, credentials and
//! the trust position. Each is an exclusive claim of the namespace that
//! writes it (`claims`), held in that namespace's view with the revision
//! that wrote it. Each write changes the row in the candidate, publishes
//! the transition record (`kappa_types::authorization`) as content, and
//! records the `AnchorOrigin` naming that record's identity under the row's
//! scope, so the epoch is bound to exactly this transition. Sessions are
//! keyed by `session_id(token)`, never by the token.
//!
//! Every authorization key an execution writes is held under its stripe
//! across the publication's store (`dependency`), so an execution of
//! another namespace that decided under the row is ordered against it.

use kappa_store::identity_scope::{AnchorScope, session_id};
use kappa_types::VerifiedContent;
use kappa_types::authorization::{CredentialTransition, SessionTransition};
use kappa_types::axis::Axis;
use kappa_types::canonical::canonical_bytes;
use kappa_types::error::StoreError;
use kappa_types::identity::TrustPosition;
use kappa_types::kappa::Kappa;

use super::claims::ClaimKey;
use super::execution::WriteCx;
use super::view::Row;

impl WriteCx<'_> {
    /// Publish a transition record and record the `AnchorOrigin` naming
    /// its identity under `scope`.
    fn record_transition(
        &mut self,
        scope: &AnchorScope,
        transition: &[u8],
    ) -> Result<(), StoreError> {
        let content = VerifiedContent::compute(Axis::Sha256, transition)?;
        self.publish_content(&content)?;
        self.anchor_origin(content.kappa(), scope);
        Ok(())
    }

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
        let revision = self.view.revision;
        self.view.authorization.sessions.insert(
            id.clone(),
            Row {
                value: (anchor.clone(), expires_at_ms, metadata.to_vec()),
                revision,
            },
        );
        let transition =
            SessionTransition::set(id.clone(), anchor.clone(), expires_at_ms, metadata);
        self.record_transition(&AnchorScope::Session { id }, &canonical_bytes(&transition))
    }

    /// A session this namespace does not hold is a no-op and records no
    /// mutation.
    pub fn session_delete(&mut self, token: &str) -> Result<(), StoreError> {
        let id = session_id(token);
        let Some(row) = self.view.authorization.sessions.remove(&id) else {
            return Ok(());
        };
        self.release(ClaimKey::Session(id.clone()));
        let transition = SessionTransition::deleted(id.clone(), row.value.0);
        self.record_transition(&AnchorScope::Session { id }, &canonical_bytes(&transition))
    }

    pub fn credential_put(
        &mut self,
        credential_id: &str,
        anchor: &Kappa,
        secret_hash: &[u8],
    ) -> Result<(), StoreError> {
        self.reserve(ClaimKey::Credential(credential_id.to_owned()))?;
        let revision = self.view.revision;
        self.view.authorization.credentials.insert(
            credential_id.to_owned(),
            Row {
                value: (anchor.clone(), secret_hash.to_vec(), None),
                revision,
            },
        );
        let transition =
            CredentialTransition::set(credential_id.to_owned(), anchor.clone(), secret_hash, None);
        self.record_transition(
            &AnchorScope::Credential {
                id: credential_id.to_owned(),
            },
            &canonical_bytes(&transition),
        )
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
        let grace_expires = self
            .now
            .checked_add_physical_ms(grace_period_ms)
            .ok_or_else(|| StoreError::Rejected("credential grace deadline overflow".into()))?
            .as_i64();
        let revision = self.view.revision;
        let row = self
            .view
            .authorization
            .credentials
            .get_mut(credential_id)
            .ok_or_else(|| StoreError::NotFound(format!("credential {credential_id}")))?;
        if row.value.0 != *expected_owner {
            return Err(StoreError::Rejected(format!(
                "credential {credential_id} is owned by {}, not {expected_owner}",
                row.value.0
            )));
        }
        let previous = std::mem::replace(&mut row.value.1, new_secret_hash.to_vec());
        row.value.2 = Some((previous.clone(), grace_expires));
        row.revision = revision;
        let anchor = row.value.0.clone();
        self.attempt_guard(ClaimKey::Credential(credential_id.to_owned()));
        let transition = CredentialTransition::set(
            credential_id.to_owned(),
            anchor,
            new_secret_hash,
            Some((previous.as_slice(), grace_expires)),
        );
        self.record_transition(
            &AnchorScope::Credential {
                id: credential_id.to_owned(),
            },
            &canonical_bytes(&transition),
        )
    }

    /// A credential this namespace does not hold is a no-op and records no
    /// mutation.
    pub fn credential_delete(&mut self, credential_id: &str) -> Result<(), StoreError> {
        let Some(row) = self.view.authorization.credentials.remove(credential_id) else {
            return Ok(());
        };
        self.release(ClaimKey::Credential(credential_id.to_owned()));
        let transition = CredentialTransition::deleted(credential_id.to_owned(), row.value.0);
        self.record_transition(
            &AnchorScope::Credential {
                id: credential_id.to_owned(),
            },
            &canonical_bytes(&transition),
        )
    }

    /// Set the trust position; the ledger names the identity of the
    /// position record, which is published as evidence.
    pub fn trust_position_put(&mut self, position: &TrustPosition) -> Result<(), StoreError> {
        self.reserve(ClaimKey::Trust)?;
        let content = VerifiedContent::compute(Axis::Sha256, &canonical_bytes(position))?;
        self.publish_content(&content)?;
        let revision = self.view.revision;
        self.view.authorization.trust = Some(Row {
            value: position.clone(),
            revision,
        });
        self.anchor_origin(content.kappa(), &AnchorScope::Trust);
        Ok(())
    }
}
