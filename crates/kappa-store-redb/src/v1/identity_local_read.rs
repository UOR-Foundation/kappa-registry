//! Reads of authorization rows: locate through the registry, decide from
//! the admitting namespace at its head (see `identity_local`).

use std::ops::Bound::{Excluded, Unbounded};
use std::sync::PoisonError;

use redb::{ReadableDatabase, ReadableTable};

use kappa_store::canonical::from_canonical;
use kappa_store::clock::ClockMs;
use kappa_store::error::StoreError;
use kappa_store::identity::TrustPosition;
use kappa_store::identity_scope::session_id;
use kappa_store::kappa::Kappa;
use kappa_store::traits::identity::CredentialLookup;

use super::{
    AuthorizationTable, TRUST_KEY, credential_context, decode_anchor_from_packed, grace_context,
    locator_namespace, session_context, session_expiry, trust_context,
};
use crate::PersistentStore;
use crate::namespace_snapshot::NamespaceSnapshot;
use crate::projection::Family;
use crate::tables;

/// An authorization row an execution read: its table, key, and the
/// ciphertext observed in the admitting namespace (`None` for absent).
/// `authorization_reads_hold` re-reads it before the execution publishes.
#[derive(Clone)]
pub struct AuthorizationRead {
    pub(crate) table: AuthorizationTable,
    pub(crate) key: String,
    pub(crate) observed: Option<Vec<u8>>,
}

/// A credential's row and its grace row, each as stored or absent.
type CredentialRows = (Option<Vec<u8>>, Option<Vec<u8>>);

/// A session as an execution reads it: the row as observed, to record,
/// and the live session it yields.
type SessionRead = (AuthorizationRead, Option<(Kappa, Vec<u8>)>);

/// The grace a stored row grants at `now`, or `None` once its deadline has
/// passed.
fn unpack_grace(bytes: &[u8], now: ClockMs) -> Result<Option<(Vec<u8>, i64)>, StoreError> {
    if bytes.len() < 8 {
        return Err(StoreError::Internal(
            "truncated credential grace row".into(),
        ));
    }
    let expires_bytes: [u8; 8] = bytes[bytes.len() - 8..]
        .try_into()
        .map_err(|_| StoreError::Internal("grace expires decode".into()))?;
    let grace_expires = i64::from_be_bytes(expires_bytes);
    Ok((now.as_i64() < grace_expires).then(|| (bytes[..bytes.len() - 8].to_vec(), grace_expires)))
}

impl PersistentStore {
    /// Run `read` over one read transaction of the namespace the registry's
    /// claim locates `key` of `table` in; `None` when no claim names one.
    /// The rows read inside are one coherent snapshot. A claim whose
    /// namespace's storage is missing is `Unavailable`: the claim says a
    /// namespace owns the key, and its missing storage cannot say the row
    /// is absent.
    fn with_admitting_namespace<T>(
        &self,
        table: AuthorizationTable,
        key: &str,
        read: impl FnOnce(&redb::ReadTransaction) -> Result<T, StoreError>,
    ) -> Result<Option<T>, StoreError> {
        let Some(ns) = self.locate_authorization(table, key)? else {
            return Ok(None);
        };
        let grant = match self.namespaces.admit_read(&ns) {
            Ok(grant) => grant,
            Err(StoreError::NotFound(_)) => {
                return Err(StoreError::Unavailable(format!(
                    "authorization key {key} is claimed by namespace {} whose storage is missing",
                    hex::encode(ns)
                )));
            }
            Err(error) => return Err(error),
        };
        let snapshot = NamespaceSnapshot::of(self, grant)?;
        Ok(Some(read(snapshot.transaction())?))
    }

    fn row_in(
        txn: &redb::ReadTransaction,
        table: AuthorizationTable,
        key: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(txn
            .open_table(table)
            .map_err(crate::error::redb)?
            .get(key)
            .map_err(crate::error::redb)?
            .map(|value| value.value().to_vec()))
    }

    /// The ciphertext of `key` in `table` as its admitting namespace holds
    /// it now; `None` when absent everywhere.
    pub(crate) fn authorization_row(
        &self,
        table: AuthorizationTable,
        key: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .with_admitting_namespace(table, key, |txn| Self::row_in(txn, table, key))?
            .flatten())
    }

    /// Whether every row in `reads` is still what the execution observed.
    pub(crate) fn authorization_reads_hold(
        &self,
        reads: &[AuthorizationRead],
    ) -> Result<(), StoreError> {
        for read in reads {
            if self.authorization_row(read.table, &read.key)? != read.observed {
                return Err(StoreError::Conflict(
                    "an authorization row this execution read changed before it published".into(),
                ));
            }
        }
        Ok(())
    }

    fn decode_session(
        &self,
        id: &str,
        stored: &[u8],
        now: ClockMs,
    ) -> Result<Option<(Kappa, Vec<u8>)>, StoreError> {
        let bytes = self.decrypt_bytes(&session_context(id), stored)?;
        let (anchor, anchor_len) = decode_anchor_from_packed(&bytes)?;
        if now.as_i64() > session_expiry(&bytes, anchor_len)? {
            return Ok(None);
        }
        Ok(Some((anchor, bytes[anchor_len + 8..].to_vec())))
    }

    pub(crate) fn read_session(
        &self,
        token: &str,
        now: ClockMs,
    ) -> Result<(Kappa, Vec<u8>), StoreError> {
        let id = session_id(token);
        let stored = self
            .authorization_row(tables::ID_SESSIONS, &id)?
            .ok_or_else(|| StoreError::NotFound("session".into()))?;
        self.decode_session(&id, &stored, now)?
            .ok_or_else(|| StoreError::NotFound("session expired".into()))
    }

    /// The session read for an execution: the row as observed, to record,
    /// and the live session it yields.
    pub(crate) fn session_read_for_execution(
        &self,
        token: &str,
        now: ClockMs,
    ) -> Result<SessionRead, StoreError> {
        let id = session_id(token);
        let observed = self.authorization_row(tables::ID_SESSIONS, &id)?;
        let session = match &observed {
            Some(stored) => self.decode_session(&id, stored, now)?,
            None => None,
        };
        Ok((
            AuthorizationRead {
                table: tables::ID_SESSIONS,
                key: id,
                observed,
            },
            session,
        ))
    }

    /// The credential row and its grace row from one transaction of the
    /// admitting namespace.
    fn credential_rows(&self, credential_id: &str) -> Result<Option<CredentialRows>, StoreError> {
        self.with_admitting_namespace(tables::ID_CREDENTIALS, credential_id, |txn| {
            Ok((
                Self::row_in(txn, tables::ID_CREDENTIALS, credential_id)?,
                Self::row_in(txn, tables::ID_CREDENTIAL_GRACE, credential_id)?,
            ))
        })
    }

    fn decode_credential(
        &self,
        credential_id: &str,
        stored: &[u8],
        grace: Option<&[u8]>,
        now: ClockMs,
    ) -> Result<CredentialLookup, StoreError> {
        let bytes = self.decrypt_bytes(&credential_context(credential_id), stored)?;
        let (anchor, anchor_len) = decode_anchor_from_packed(&bytes)?;
        let secret_hash = bytes[anchor_len..].to_vec();
        let grace = match grace {
            Some(stored) => unpack_grace(
                &self.decrypt_bytes(&grace_context(credential_id), stored)?,
                now,
            )?,
            None => None,
        };
        Ok((anchor, secret_hash, grace))
    }

    pub(crate) fn read_credential(
        &self,
        credential_id: &str,
        now: ClockMs,
    ) -> Result<CredentialLookup, StoreError> {
        let absent = || StoreError::NotFound(format!("credential {credential_id}"));
        let (stored, grace) = self.credential_rows(credential_id)?.ok_or_else(absent)?;
        let stored = stored.ok_or_else(absent)?;
        self.decode_credential(credential_id, &stored, grace.as_deref(), now)
    }

    /// The credential read for an execution: both rows as observed, to
    /// record, and the credential they yield.
    pub(crate) fn credential_read_for_execution(
        &self,
        credential_id: &str,
        now: ClockMs,
    ) -> Result<(Vec<AuthorizationRead>, Option<CredentialLookup>), StoreError> {
        let (stored, grace) = self.credential_rows(credential_id)?.unwrap_or((None, None));
        let credential = match &stored {
            Some(stored) => {
                Some(self.decode_credential(credential_id, stored, grace.as_deref(), now)?)
            }
            None => None,
        };
        let reads = vec![
            AuthorizationRead {
                table: tables::ID_CREDENTIALS,
                key: credential_id.to_owned(),
                observed: stored,
            },
            AuthorizationRead {
                table: tables::ID_CREDENTIAL_GRACE,
                key: credential_id.to_owned(),
                observed: grace,
            },
        ];
        Ok((reads, credential))
    }

    pub(crate) fn read_trust_position(&self) -> Result<TrustPosition, StoreError> {
        self.authorization_row(tables::ID_TRUST, TRUST_KEY)?.map_or(
            Ok(TrustPosition::Unprobed),
            |stored| {
                let bytes = self.decrypt_bytes(&trust_context(), &stored)?;
                from_canonical(&bytes)
                    .map_err(|e| StoreError::Internal(format!("trust position decode: {e}")))
            },
        )
    }

    /// Release the claims of sessions whose rows are gone or expired at
    /// `now`, at most `EVICTION_BATCH` claims examined per call from a
    /// rotating cursor. The completed projection's cached ciphertext is only
    /// a candidate filter: a claim whose cache shows the session expired is
    /// confirmed, under its namespace's writer gate, against the row the
    /// namespace holds at its head, and released only when that row is
    /// absent or expired. A claim without a cache, one whose namespace's
    /// gate is held or whose storage is missing, is kept for a later pass;
    /// a renewal admitted after the cache was settled therefore never loses
    /// its claim. The authorization outcome of each released claim was
    /// already decided by the row's expiry; this records nothing.
    pub(crate) fn evict_sessions(&self, now: ClockMs) -> Result<u64, StoreError> {
        const EVICTION_BATCH: usize = 1024;
        let mut cursor = self
            .session_eviction_cursor
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut examined = 0usize;
        let mut last = None;
        let mut candidates = Vec::new();
        {
            let read = self.projection()?;
            let claims = read
                .transaction()
                .open_table(tables::ID_SESSIONS)
                .map_err(crate::error::redb)?;
            let lower = cursor.as_deref().map_or(Unbounded, Excluded);
            for entry in claims
                .range::<&str>((lower, Unbounded))
                .map_err(crate::error::redb)?
            {
                let (key, value) = entry.map_err(crate::error::redb)?;
                examined += 1;
                let id = key.value().to_string();
                last = Some(id.clone());
                let owner = locator_namespace(value.value())?;
                let cached = read
                    .get(Family::Session, id.as_bytes())?
                    .into_iter()
                    .filter(|visible| *visible.instance.namespace() == owner)
                    .max_by_key(|visible| visible.completion);
                if let Some(cached) = cached
                    && self.decode_session(&id, &cached.value, now)?.is_none()
                {
                    candidates.push((id, owner));
                }
                if examined >= EVICTION_BATCH {
                    break;
                }
            }
        }
        let mut released = 0u64;
        for (id, owner) in &candidates {
            if self.release_expired_claim(id, owner, now)? {
                released += 1;
            }
        }
        *cursor = if examined < EVICTION_BATCH {
            None
        } else {
            last
        };
        drop(cursor);
        Ok(released)
    }

    /// Release the claim of session `id` held by namespace `owner` when the
    /// namespace's head row of the session is absent or expired at `now`,
    /// read under maintenance of the namespace, which holds its writer gate
    /// so no execution can renew the session between the read and the
    /// release (an execution claims under that gate, and the gate is taken
    /// before the registry writer, in the order executions take them). A
    /// namespace whose gate is held, or that is being retired, keeps its
    /// claim for a later pass. Returns whether the claim was released.
    fn release_expired_claim(
        &self,
        id: &str,
        owner: &[u8; 16],
        now: ClockMs,
    ) -> Result<bool, StoreError> {
        let maintenance = match self.namespaces.try_maintain(owner) {
            Ok(Some(maintenance)) => maintenance,
            // A held gate keeps the claim for a later pass; a claim of
            // missing or retired storage is resolved by the namespace's
            // retirement, never by eviction.
            Ok(None) | Err(StoreError::NotFound(_)) => return Ok(false),
            Err(error) => return Err(error),
        };
        let row = {
            let txn = maintenance
                .controller()
                .db
                .begin_read()
                .map_err(crate::error::redb)?;
            Self::row_in(&txn, tables::ID_SESSIONS, id)?
        };
        let live = match &row {
            Some(stored) => self.decode_session(id, stored, now)?.is_some(),
            None => false,
        };
        if live {
            maintenance.finish();
            return Ok(false);
        }
        let wtxn = self.registry.begin_write().map_err(crate::error::redb)?;
        let released = {
            let mut claims = wtxn
                .open_table(tables::ID_SESSIONS)
                .map_err(crate::error::redb)?;
            let held = claims
                .get(id)
                .map_err(crate::error::redb)?
                .map(|value| locator_namespace(value.value()))
                .transpose()?;
            if held == Some(*owner) {
                claims.remove(id).map_err(crate::error::redb)?;
                true
            } else {
                false
            }
        };
        Self::commit_write(wtxn)?;
        maintenance.finish();
        Ok(released)
    }
}
