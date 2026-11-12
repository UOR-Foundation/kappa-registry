//! Sessions, credentials and the trust position: authorization-bearing
//! identity records.
//!
//! Their transitions (a session granted or revoked, a credential issued,
//! rotated or deleted, the trust position moved) are epoch-governed like
//! every other identity record: an execution applies the transition record
//! (`kappa_types::authorization`) through the transition boundary
//! (`transition_apply`), which installs it as evidence, writes the row
//! through the helpers here with the private values its digests commit,
//! and records its `AnchorOrigin` mutation under the row's scope.
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

use redb::ReadableTable;

use kappa_store::authorization::{CredentialTransition, SessionTransition};
use kappa_store::axis::Axis;
use kappa_store::canonical::canonical_bytes;
use kappa_store::clock::ClockMs;
use kappa_store::error::StoreError;
use kappa_store::identity::TrustPosition;
use kappa_store::identity_scope::session_id;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::transition::RecordTransition;
use kappa_store::work::Meter;

use crate::PersistentStore;
use crate::encrypted::bound;
use crate::tables;
use crate::transition_apply::{RedbPayload, TxnWriter};

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
        let rtxn = self.registry.begin_read()?;
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
        let wtxn = self.registry.begin_write()?;
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
                    wtxn.abort()?;
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
        match wtxn.commit() {
            Ok(()) => Ok(()),
            // The namespace transaction that writes the row is refused
            // either way. A claim that persisted names this namespace only:
            // it authorizes nothing without the row, and this namespace's
            // retry finds its own claim and keeps it.
            Err(
                crate::error::CommitFailure::Known(error)
                | crate::error::CommitFailure::Unknown(error),
            ) => Err(error),
        }
    }

    /// The plaintext of row `key` of the authorization `table` this
    /// namespace's private writer holds (`private_row`), under `context`.
    fn private_plain(
        &self,
        txn: &redb::WriteTransaction,
        table: AuthorizationTable,
        key: &str,
        context: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        Self::private_row(txn, table, key)?
            .map(|stored| self.decrypt_bytes(context, &stored))
            .transpose()
    }

    pub(crate) fn session_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        grant: SessionGrant<'_>,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let SessionGrant {
            token,
            anchor,
            expires_at_ms,
            metadata,
        } = grant;
        let id = session_id(token);
        self.claim_locator(tables::ID_SESSIONS, &id, ns)?;
        TxnWriter::new(self, txn, ns, now, meter)?
            .apply(
                RecordTransition::Session(SessionTransition::set(
                    id,
                    anchor.clone(),
                    expires_at_ms,
                    metadata,
                )),
                RedbPayload::SessionMetadata(metadata.to_vec()),
            )
            .map(drop)
    }

    /// An absent session is a no-op and records no mutation.
    pub(crate) fn session_delete_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        token: &str,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let id = session_id(token);
        let Some(bytes) =
            self.private_plain(txn, tables::ID_SESSIONS, &id, &session_context(&id))?
        else {
            return Ok(());
        };
        let (anchor, _) = decode_anchor_from_packed(&bytes)?;
        TxnWriter::new(self, txn, ns, now, meter)?
            .apply(
                RecordTransition::Session(SessionTransition::deleted(id, anchor)),
                RedbPayload::NoResources,
            )
            .map(drop)
    }

    pub(crate) fn credential_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        credential_id: &str,
        anchor: &Kappa,
        secret_hash: &[u8],
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        self.claim_locator(tables::ID_CREDENTIALS, credential_id, ns)?;
        self.claim_locator(tables::ID_CREDENTIAL_GRACE, credential_id, ns)?;
        TxnWriter::new(self, txn, ns, now, meter)?
            .apply(
                RecordTransition::Credential(CredentialTransition::set(
                    credential_id.to_owned(),
                    anchor.clone(),
                    secret_hash,
                    None,
                )),
                RedbPayload::CredentialSecrets {
                    secret_hash: secret_hash.to_vec(),
                    grace_secret_hash: None,
                },
            )
            .map(drop)
    }

    /// Rotate the secret under shared policy against the protected row; the
    /// previous secret stays valid for the grace the transition carries.
    pub(crate) fn credential_rotate_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        rotation: CredentialRotation<'_>,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let CredentialRotation {
            credential_id,
            expected_owner,
            new_secret_hash,
            grace_period_ms,
        } = rotation;
        let bytes = self.private_plain(
            txn,
            tables::ID_CREDENTIALS,
            credential_id,
            &credential_context(credential_id),
        )?;
        let current = bytes
            .as_deref()
            .map(decode_anchor_from_packed)
            .transpose()?;
        let observed = current
            .as_ref()
            .zip(bytes.as_deref())
            .map(|((anchor, length), bytes)| (anchor, &bytes[*length..]));
        let transition = kappa_store::identity_ops::prepare_credential_rotation(
            credential_id,
            observed,
            expected_owner,
            new_secret_hash,
            grace_period_ms,
            now,
        )?;
        let (_, old_hash) = observed.ok_or_else(|| {
            StoreError::Internal("accepted credential rotation has no protected row".into())
        })?;
        TxnWriter::new(self, txn, ns, now, meter)?
            .apply(
                RecordTransition::Credential(transition),
                RedbPayload::CredentialSecrets {
                    secret_hash: new_secret_hash.to_vec(),
                    grace_secret_hash: Some(old_hash.to_vec()),
                },
            )
            .map(drop)
    }

    /// An absent credential is a no-op and records no mutation.
    pub(crate) fn credential_delete_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        credential_id: &str,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let Some(bytes) = self.private_plain(
            txn,
            tables::ID_CREDENTIALS,
            credential_id,
            &credential_context(credential_id),
        )?
        else {
            return Ok(());
        };
        let (anchor, _) = decode_anchor_from_packed(&bytes)?;
        TxnWriter::new(self, txn, ns, now, meter)?
            .apply(
                RecordTransition::Credential(CredentialTransition::deleted(
                    credential_id.to_owned(),
                    anchor,
                )),
                RedbPayload::NoResources,
            )
            .map(drop)
    }

    pub(crate) fn trust_position_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        position: &TrustPosition,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        self.claim_locator(tables::ID_TRUST, TRUST_KEY, ns)?;
        TxnWriter::new(self, txn, ns, now, meter)?
            .apply(
                RecordTransition::Trust(position.clone()),
                RedbPayload::NoResources,
            )
            .map(drop)
    }
}

impl TxnWriter<'_> {
    /// Encrypt `value` under `context` and hold it as row `key` of `table`.
    fn put_authorization(
        &self,
        table: AuthorizationTable,
        key: &str,
        context: &str,
        value: &[u8],
    ) -> Result<(), StoreError> {
        let stored = self.store.encrypt_bytes(context, value)?;
        self.txn
            .open_table(table)
            .map_err(crate::error::redb)?
            .insert(key, stored.as_slice())
            .map_err(crate::error::redb)?;
        Ok(())
    }

    fn remove_authorization(&self, table: AuthorizationTable, key: &str) -> Result<(), StoreError> {
        self.txn
            .open_table(table)
            .map_err(crate::error::redb)?
            .remove(key)
            .map_err(crate::error::redb)?;
        Ok(())
    }

    /// Hold the session `session` sets, with the metadata its digest was
    /// checked against.
    pub(crate) fn apply_session_set(
        &self,
        session: &SessionTransition,
        metadata: &[u8],
    ) -> Result<(), StoreError> {
        self.put_authorization(
            tables::ID_SESSIONS,
            &session.id,
            &session_context(&session.id),
            &pack_session(&session.anchor, session.expires_at_ms, metadata),
        )
    }

    /// Remove the session `session` deletes.
    pub(crate) fn apply_session_delete(
        &self,
        session: &SessionTransition,
    ) -> Result<(), StoreError> {
        self.remove_authorization(tables::ID_SESSIONS, &session.id)
    }

    /// Hold the credential `credential` sets with the secret hashes its
    /// commitments were checked against: the grace secret with the grace
    /// deadline the transition carries, or no grace row.
    pub(crate) fn apply_credential_set(
        &self,
        credential: &CredentialTransition,
        secret_hash: &[u8],
        grace_secret_hash: Option<&[u8]>,
    ) -> Result<(), StoreError> {
        let id = credential.id.as_str();
        self.put_authorization(
            tables::ID_CREDENTIALS,
            id,
            &credential_context(id),
            &pack_credential(&credential.anchor, secret_hash),
        )?;
        match grace_secret_hash.zip(credential.grace_expires_ms) {
            Some((old_hash, expires)) => self.put_authorization(
                tables::ID_CREDENTIAL_GRACE,
                id,
                &grace_context(id),
                &pack_grace(old_hash, expires),
            ),
            None => self.remove_authorization(tables::ID_CREDENTIAL_GRACE, id),
        }
    }

    /// Remove the credential `credential` deletes and its grace.
    pub(crate) fn apply_credential_delete(
        &self,
        credential: &CredentialTransition,
    ) -> Result<(), StoreError> {
        self.remove_authorization(tables::ID_CREDENTIALS, &credential.id)?;
        self.remove_authorization(tables::ID_CREDENTIAL_GRACE, &credential.id)
    }

    /// Hold `position` as the trust position.
    pub(crate) fn apply_trust(&self, position: &TrustPosition) -> Result<(), StoreError> {
        self.put_authorization(
            tables::ID_TRUST,
            TRUST_KEY,
            &trust_context(),
            &canonical_bytes(position),
        )
    }
}
