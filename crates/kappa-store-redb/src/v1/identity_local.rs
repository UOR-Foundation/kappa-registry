//! Sessions, credentials and the trust position: authorization-bearing
//! identity records.
//!
//! Their transitions (a session granted or revoked, a credential issued,
//! rotated or deleted, the trust position moved) are epoch-governed like
//! every other identity record: an execution writes the row into its
//! namespace database, publishes the transition record
//! (`kappa_types::authorization`) as content, and records `AnchorOrigin`
//! evidence naming that record's content identity under the scope of the
//! row (`AnchorScope::Session`, `Credential`, `Trust`).
//!
//! Ownership is a claim, never projection content. Before the namespace
//! transaction commits, the writer records the admitting namespace in the
//! registry under the row's key (`claim_locator`, a separate committed
//! registry write, the only registry write a publication makes), so a read
//! that follows the publication finds the namespace whether or not
//! settlement has run. The claim holds the namespace and nothing else; it
//! survives an unknown commit outcome and is released only by maintenance
//! that confirms, under the namespace's writer gate, that the namespace's
//! row is gone or expired (`evict_sessions`). Settlement projects the
//! row's admitted ciphertext as a cache (`projection::Family::Session`,
//! `Credential`, `CredentialGrace`, `Trust`), which decides nothing. A read
//! resolves the claim and decides from the admitting namespace's database
//! at its head: a deleted session is absent from the epoch that deleted
//! it, a created one is found from the epoch that created it, and a
//! credential and its grace are read in one transaction of that database,
//! so no read observes a pair no epoch admitted. A claim whose
//! namespace's storage is missing makes the read unavailable, never
//! absent.
//!
//! A key is owned by the first namespace that claims it: a claim naming
//! another namespace is refused at write, and settlement refuses to
//! project a row another namespace's completed projection holds. Every
//! value is encrypted under the table key with its row key bound; the
//! context is the same in both databases, so the cache holds the
//! namespace's ciphertext.
//!
//! Sessions are keyed by `session_id(token)`, never by the token. Expiry
//! is decided by the record at read time. Reads are in
//! `identity_local_read.rs`.

use redb::{ReadableDatabase, ReadableTable};

use kappa_store::VerifiedContent;
use kappa_store::authorization::{CredentialTransition, SessionTransition};
use kappa_store::axis::Axis;
use kappa_store::canonical::canonical_bytes;
use kappa_store::clock::ClockMs;
use kappa_store::epoch::MutationOp;
use kappa_store::error::StoreError;
use kappa_store::identity::TrustPosition;
use kappa_store::identity_scope::{AnchorScope, session_id};
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;

use crate::PersistentStore;
use crate::encrypted::bound;
use crate::epoch_blob::blob_put_in_txn;
use crate::tables;

#[path = "identity_local_read.rs"]
mod read;
pub use read::AuthorizationRead;

/// The string-keyed authorization tables, in the namespace and registry
/// databases alike.
pub type AuthorizationTable = redb::TableDefinition<'static, &'static str, &'static [u8]>;

/// A session to grant: the token it is keyed by (through `session_id`,
/// never stored), the anchor it authenticates, its deadline and its
/// metadata.
#[derive(Clone, Copy, Debug)]
pub struct SessionGrant<'a> {
    pub token: &'a str,
    pub anchor: &'a Kappa,
    pub expires_at_ms: i64,
    pub metadata: &'a [u8],
}

/// A credential rotation: the credential, the owner the caller expects it
/// to have, the new secret hash, and how long the previous hash stays
/// valid.
#[derive(Clone, Copy, Debug)]
pub struct CredentialRotation<'a> {
    pub credential_id: &'a str,
    pub expected_owner: &'a Kappa,
    pub new_secret_hash: &'a [u8],
    pub grace_period_ms: u64,
}

/// Packed values begin with the owning anchor's key bytes.
pub fn decode_anchor_from_packed(bytes: &[u8]) -> Result<(Kappa, usize), StoreError> {
    if bytes.is_empty() {
        return Err(StoreError::Internal("empty packed value".into()));
    }
    let axis = Axis::from_discriminant(bytes[0])
        .ok_or_else(|| StoreError::Internal("invalid anchor axis".into()))?;
    let anchor_len = 1 + axis.digest_len();
    if bytes.len() < anchor_len {
        return Err(StoreError::Internal("truncated packed value".into()));
    }
    let anchor = Kappa::from_key_bytes(&bytes[..anchor_len])
        .map_err(|e| StoreError::Internal(format!("anchor decode: {e}")))?;
    Ok((anchor, anchor_len))
}

/// AEAD contexts of the session, credential and trust rows, bound to the
/// row key. Identical in the namespace and registry databases.
pub fn session_context(id: &str) -> String {
    bound("id_session", id.as_bytes())
}

pub fn credential_context(id: &str) -> String {
    bound("id_credential", id.as_bytes())
}

pub fn grace_context(id: &str) -> String {
    bound("id_credential_grace", id.as_bytes())
}

pub fn trust_context() -> String {
    bound("id_trust", TRUST_KEY.as_bytes())
}

/// The one row of `ID_TRUST`.
pub const TRUST_KEY: &str = "current";

/// Session expiry stored after the anchor.
pub fn session_expiry(bytes: &[u8], anchor_len: usize) -> Result<i64, StoreError> {
    let expires: [u8; 8] = bytes
        .get(anchor_len..anchor_len + 8)
        .ok_or_else(|| StoreError::Internal("truncated session value".into()))?
        .try_into()
        .map_err(|_| StoreError::Internal("session expires decode".into()))?;
    Ok(i64::from_be_bytes(expires))
}

/// `[anchor key][expires i64 BE][metadata]`.
fn pack_session(anchor: &Kappa, expires_at_ms: i64, metadata: &[u8]) -> Vec<u8> {
    let anchor_kb = anchor.key_bytes();
    let mut value = Vec::with_capacity(anchor_kb.len() + 8 + metadata.len());
    value.extend_from_slice(&anchor_kb);
    value.extend_from_slice(&expires_at_ms.to_be_bytes());
    value.extend_from_slice(metadata);
    value
}

/// `[anchor key][secret hash]`.
fn pack_credential(anchor: &Kappa, secret_hash: &[u8]) -> Vec<u8> {
    let anchor_kb = anchor.key_bytes();
    let mut value = Vec::with_capacity(anchor_kb.len() + secret_hash.len());
    value.extend_from_slice(&anchor_kb);
    value.extend_from_slice(secret_hash);
    value
}

/// `[old hash][expires i64 BE]`.
fn pack_grace(old_hash: &[u8], expires: i64) -> Vec<u8> {
    let mut value = Vec::with_capacity(old_hash.len() + 8);
    value.extend_from_slice(old_hash);
    value.extend_from_slice(&expires.to_be_bytes());
    value
}

/// A registry claim row: `[ns_uuid:16]`, the namespace owning the key.
/// Rows written before claims and caches were separated carry the settled
/// ciphertext after it; only the namespace is ever read.
pub fn claim_value(ns: &[u8; 16]) -> Vec<u8> {
    ns.to_vec()
}

pub fn locator_namespace(value: &[u8]) -> Result<[u8; 16], StoreError> {
    value
        .get(..16)
        .and_then(|ns| <[u8; 16]>::try_from(ns).ok())
        .ok_or_else(|| StoreError::Internal("authorization locator names no namespace".into()))
}

impl PersistentStore {
    /// The namespace the registry locates `key` of `table` in, if any.
    pub(crate) fn locate_authorization(
        &self,
        table: AuthorizationTable,
        key: &str,
    ) -> Result<Option<[u8; 16]>, StoreError> {
        let rtxn = self.registry.begin_read().map_err(crate::error::redb)?;
        rtxn.open_table(table)
            .map_err(crate::error::redb)?
            .get(key)
            .map_err(crate::error::redb)?
            .map(|value| locator_namespace(value.value()))
            .transpose()
    }

    /// Claim `key` of `table` for `ns` in the registry before the
    /// namespace transaction that writes the row commits. A key another
    /// namespace owns is refused: ownership of an authorization key is
    /// exclusive and decided here, never by settlement order. An existing
    /// claim by `ns` is kept as it is.
    fn claim_locator(
        &self,
        table: AuthorizationTable,
        key: &str,
        ns: &NamespaceRef,
    ) -> Result<(), StoreError> {
        let wtxn = self.registry.begin_write().map_err(crate::error::redb)?;
        {
            let mut rows = wtxn.open_table(table).map_err(crate::error::redb)?;
            let owner = rows
                .get(key)
                .map_err(crate::error::redb)?
                .map(|value| locator_namespace(value.value()))
                .transpose()?;
            match owner {
                Some(owner) if owner == *ns.id() => {
                    drop(rows);
                    wtxn.abort().map_err(crate::error::redb)?;
                    return Ok(());
                }
                Some(owner) => {
                    return Err(StoreError::Conflict(format!(
                        "authorization key is owned by namespace {}",
                        hex::encode(owner)
                    )));
                }
                None => {
                    rows.insert(key, claim_value(ns.id()).as_slice())
                        .map_err(crate::error::redb)?;
                }
            }
        }
        Self::commit_write(wtxn)
    }

    /// Publish the transition record and record the `AnchorOrigin` naming
    /// its content identity under `scope`.
    fn record_transition(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        scope: &AnchorScope,
        transition: &[u8],
        now: ClockMs,
    ) -> Result<(), StoreError> {
        let content = VerifiedContent::compute(Axis::Sha256, transition)?;
        blob_put_in_txn(self, txn, ns, &content)?;
        self.record_mutation_in_txn(
            txn,
            ns,
            MutationOp::AnchorOrigin,
            content.kappa().clone(),
            now,
            Some(scope.to_context()),
        )
    }

    pub(crate) fn session_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        grant: SessionGrant<'_>,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        let SessionGrant {
            token,
            anchor,
            expires_at_ms,
            metadata,
        } = grant;
        let id = session_id(token);
        self.claim_locator(tables::ID_SESSIONS, &id, ns)?;
        let stored = self.encrypt_bytes(
            &session_context(&id),
            &pack_session(anchor, expires_at_ms, metadata),
        )?;
        txn.open_table(tables::ID_SESSIONS)
            .map_err(crate::error::redb)?
            .insert(id.as_str(), stored.as_slice())
            .map_err(crate::error::redb)?;
        let transition =
            SessionTransition::set(id.clone(), anchor.clone(), expires_at_ms, metadata);
        self.record_transition(
            txn,
            ns,
            &AnchorScope::Session { id },
            &canonical_bytes(&transition),
            now,
        )
    }

    /// An absent session is a no-op and records no mutation.
    pub(crate) fn session_delete_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        token: &str,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        let id = session_id(token);
        let removed = txn
            .open_table(tables::ID_SESSIONS)
            .map_err(crate::error::redb)?
            .remove(id.as_str())
            .map_err(crate::error::redb)?
            .map(|value| self.decrypt_bytes(&session_context(&id), value.value()))
            .transpose()?;
        let Some(bytes) = removed else {
            return Ok(());
        };
        let (anchor, _) = decode_anchor_from_packed(&bytes)?;
        let transition = SessionTransition::deleted(id.clone(), anchor);
        self.record_transition(
            txn,
            ns,
            &AnchorScope::Session { id },
            &canonical_bytes(&transition),
            now,
        )
    }

    pub(crate) fn credential_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        credential_id: &str,
        anchor: &Kappa,
        secret_hash: &[u8],
        now: ClockMs,
    ) -> Result<(), StoreError> {
        self.claim_locator(tables::ID_CREDENTIALS, credential_id, ns)?;
        self.claim_locator(tables::ID_CREDENTIAL_GRACE, credential_id, ns)?;
        let stored = self.encrypt_bytes(
            &credential_context(credential_id),
            &pack_credential(anchor, secret_hash),
        )?;
        txn.open_table(tables::ID_CREDENTIALS)
            .map_err(crate::error::redb)?
            .insert(credential_id, stored.as_slice())
            .map_err(crate::error::redb)?;
        txn.open_table(tables::ID_CREDENTIAL_GRACE)
            .map_err(crate::error::redb)?
            .remove(credential_id)
            .map_err(crate::error::redb)?;
        let transition =
            CredentialTransition::set(credential_id.to_owned(), anchor.clone(), secret_hash, None);
        self.record_transition(
            txn,
            ns,
            &AnchorScope::Credential {
                id: credential_id.to_string(),
            },
            &canonical_bytes(&transition),
            now,
        )
    }

    pub(crate) fn credential_rotate_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        rotation: CredentialRotation<'_>,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        let CredentialRotation {
            credential_id,
            expected_owner,
            new_secret_hash,
            grace_period_ms,
        } = rotation;
        let grace_expires = now
            .checked_add_physical_ms(grace_period_ms)
            .ok_or_else(|| StoreError::Rejected("credential grace deadline overflow".into()))?
            .as_i64();
        let mut table = txn
            .open_table(tables::ID_CREDENTIALS)
            .map_err(crate::error::redb)?;
        let bytes = {
            let value = table
                .get(credential_id)
                .map_err(crate::error::redb)?
                .ok_or_else(|| StoreError::NotFound(format!("credential {credential_id}")))?;
            self.decrypt_bytes(&credential_context(credential_id), value.value())?
        };
        let (current_anchor, anchor_len) = decode_anchor_from_packed(&bytes)?;
        if current_anchor != *expected_owner {
            return Err(StoreError::Rejected(format!(
                "credential {credential_id} is owned by {current_anchor}, not {expected_owner}"
            )));
        }
        let old_hash = &bytes[anchor_len..];
        let stored = self.encrypt_bytes(
            &credential_context(credential_id),
            &pack_credential(&current_anchor, new_secret_hash),
        )?;
        table
            .insert(credential_id, stored.as_slice())
            .map_err(crate::error::redb)?;
        drop(table);
        let stored_grace = self.encrypt_bytes(
            &grace_context(credential_id),
            &pack_grace(old_hash, grace_expires),
        )?;
        txn.open_table(tables::ID_CREDENTIAL_GRACE)
            .map_err(crate::error::redb)?
            .insert(credential_id, stored_grace.as_slice())
            .map_err(crate::error::redb)?;
        let transition = CredentialTransition::set(
            credential_id.to_owned(),
            current_anchor,
            new_secret_hash,
            Some((old_hash, grace_expires)),
        );
        self.record_transition(
            txn,
            ns,
            &AnchorScope::Credential {
                id: credential_id.to_string(),
            },
            &canonical_bytes(&transition),
            now,
        )
    }

    /// An absent credential is a no-op and records no mutation.
    pub(crate) fn credential_delete_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        credential_id: &str,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        let removed = txn
            .open_table(tables::ID_CREDENTIALS)
            .map_err(crate::error::redb)?
            .remove(credential_id)
            .map_err(crate::error::redb)?
            .map(|value| self.decrypt_bytes(&credential_context(credential_id), value.value()))
            .transpose()?;
        txn.open_table(tables::ID_CREDENTIAL_GRACE)
            .map_err(crate::error::redb)?
            .remove(credential_id)
            .map_err(crate::error::redb)?;
        let Some(bytes) = removed else {
            return Ok(());
        };
        let (anchor, _) = decode_anchor_from_packed(&bytes)?;
        let transition = CredentialTransition::deleted(credential_id.to_owned(), anchor);
        self.record_transition(
            txn,
            ns,
            &AnchorScope::Credential {
                id: credential_id.to_string(),
            },
            &canonical_bytes(&transition),
            now,
        )
    }

    pub(crate) fn trust_position_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        position: &TrustPosition,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        self.claim_locator(tables::ID_TRUST, TRUST_KEY, ns)?;
        let bytes = canonical_bytes(position);
        let stored = self.encrypt_bytes(&trust_context(), &bytes)?;
        txn.open_table(tables::ID_TRUST)
            .map_err(crate::error::redb)?
            .insert(TRUST_KEY, stored.as_slice())
            .map_err(crate::error::redb)?;
        self.record_transition(txn, ns, &AnchorScope::Trust, &bytes, now)
    }
}
