//! Authorization reads and the one maintenance operation on them.
//!
//! A session, a credential or the trust position is a row of the view of
//! the namespace holding its claim. A read finds the holder through the
//! claim and decides from the holder's published view; an execution's read
//! also records what it observed (`dependency`), which its publication
//! validates under the key's stripe.
//!
//! Expiry cleanup removes rows whose recorded deadline has passed at the
//! time it is given, from one namespace at a time, under that namespace's
//! writer gate, and releases their claims. It changes no authorization
//! outcome: an expired row already reads as absent. It records no
//! mutation; the revision of every remaining row is unchanged, and the
//! claim release invalidates any absence observation of the removed keys.
//! Each call examines at most `EVICTION_BATCH` rows from a cursor it keeps
//! between calls, and skips a namespace whose writer is busy.

use std::ops::Bound::{Excluded, Unbounded};
use std::sync::Arc;

use kappa_store::identity_scope::session_id;
use kappa_store::traits::identity::CredentialLookup;
use kappa_types::clock::ClockMs;
use kappa_types::error::StoreError;
use kappa_types::identity::TrustPosition;
use kappa_types::kappa::Kappa;

use super::InMemoryStore;
use super::claims::{ClaimKey, Holder};
use super::dependency::Dependency;
use super::execution::ReadCx;
use super::view::{CredentialRecord, NamespaceView, SessionRecord};

/// Session rows one eviction call examines.
pub const EVICTION_BATCH: usize = 1024;

/// Whether a session whose deadline is `expires_at_ms` is expired at `now`.
pub const fn session_expired(expires_at_ms: i64, now: ClockMs) -> bool {
    now.as_i64() > expires_at_ms
}

/// The revision of `key`'s row in `view`, if the view holds it.
pub fn row_revision(view: &NamespaceView, key: &ClaimKey) -> Option<u64> {
    let rows = &view.authorization;
    match key {
        ClaimKey::Session(id) => rows.sessions.get(id).map(|row| row.revision),
        ClaimKey::Credential(id) => rows.credentials.get(id).map(|row| row.revision),
        ClaimKey::Trust => rows.trust.as_ref().map(|row| row.revision),
        _ => None,
    }
}

fn filter_grace(row: CredentialRecord, now: ClockMs) -> CredentialLookup {
    let (anchor, secret, grace) = row;
    (
        anchor,
        secret,
        grace.filter(|(_, expires)| now.as_i64() < *expires),
    )
}

impl InMemoryStore {
    pub(crate) fn read_session(
        &self,
        token: &str,
        now: ClockMs,
    ) -> Result<(Kappa, Vec<u8>), StoreError> {
        let id = session_id(token);
        let view = self
            .claimed(&ClaimKey::Session(id.clone()))
            .ok_or_else(|| StoreError::NotFound("session".into()))?;
        let row = view
            .authorization
            .sessions
            .get(&id)
            .ok_or_else(|| StoreError::NotFound("session".into()))?;
        let (anchor, expires_at_ms, metadata) = &row.value;
        if session_expired(*expires_at_ms, now) {
            return Err(StoreError::NotFound("session expired".into()));
        }
        Ok((anchor.clone(), metadata.clone()))
    }

    /// The grace secret is returned only while its deadline has not passed.
    pub(crate) fn read_credential(
        &self,
        credential_id: &str,
        now: ClockMs,
    ) -> Result<CredentialLookup, StoreError> {
        let view = self
            .claimed(&ClaimKey::Credential(credential_id.to_owned()))
            .ok_or_else(|| StoreError::NotFound(format!("credential {credential_id}")))?;
        let row = view
            .authorization
            .credentials
            .get(credential_id)
            .ok_or_else(|| StoreError::NotFound(format!("credential {credential_id}")))?;
        Ok(filter_grace(row.value.clone(), now))
    }

    pub(crate) fn read_trust_position(&self) -> TrustPosition {
        self.claimed(&ClaimKey::Trust)
            .and_then(|view| {
                view.authorization
                    .trust
                    .as_ref()
                    .map(|row| row.value.clone())
            })
            .unwrap_or(TrustPosition::Unprobed)
    }

    /// Remove expired session rows: at most `EVICTION_BATCH` examined from
    /// the cursor, one namespace at a time under its writer gate.
    pub(crate) fn evict_sessions(&self, now: ClockMs) -> Result<u64, StoreError> {
        let mut cursor = self
            .session_eviction_cursor
            .lock()
            .map_err(|_| StoreError::Internal("session eviction cursor poisoned".into()))?;
        let mut namespaces: Vec<_> = self.slots.iter().map(|entry| *entry.key()).collect();
        namespaces.sort_unstable();
        let (start, mut after) = cursor
            .clone()
            .map_or((None, None), |(ns, id)| (Some(ns), Some(id)));
        let mut examined = 0usize;
        let mut evicted = 0u64;
        let lower = start.map_or(0, |start| namespaces.partition_point(|ns| *ns < start));
        for namespace in &namespaces[lower..] {
            if start.is_some_and(|start| *namespace != start) {
                after = None;
            }
            let slot = self.slot(namespace)?;
            let Some(writer) = slot.gate.try_acquire() else {
                after = None;
                continue;
            };
            let view = slot.view.load_full();
            let bound = after.as_deref().map_or(Unbounded, Excluded);
            let mut expired = Vec::new();
            let mut last = None;
            for (id, row) in view
                .authorization
                .sessions
                .range::<_, str>((bound, Unbounded))
            {
                examined += 1;
                last = Some(id.clone());
                if session_expired(row.value.1, now) {
                    expired.push(id.clone());
                }
                if examined >= EVICTION_BATCH {
                    break;
                }
            }
            if !expired.is_empty() {
                let holder = Holder {
                    namespace: *namespace,
                    incarnation: view.incarnation,
                };
                let attempt = self.attempt()?;
                let mut next = NamespaceView::clone(&view);
                let mut keys = Vec::with_capacity(expired.len());
                for id in &expired {
                    next.authorization.sessions.remove(id);
                    let key = ClaimKey::Session(id.clone());
                    if self.claims.release(&key, holder, attempt) {
                        keys.push(key);
                    }
                }
                // Ordered against every execution depending on these rows.
                let stripes = self.stripes.hold(&keys);
                slot.view.store(Arc::new(next));
                self.claims.settle(&keys, holder, attempt, true);
                drop(stripes);
                evicted += expired.len() as u64;
            }
            drop(writer);
            if examined >= EVICTION_BATCH {
                *cursor = last.map(|id| (*namespace, id));
                drop(cursor);
                return Ok(evicted);
            }
            after = None;
        }
        *cursor = None;
        drop(cursor);
        Ok(evicted)
    }
}

impl ReadCx<'_> {
    /// The row of authorization `key`: this execution's own candidate when
    /// its namespace holds the key, otherwise the holder's published view,
    /// recording the observation for validation at publication.
    fn authorization<T>(
        &self,
        key: ClaimKey,
        row: impl Fn(&NamespaceView) -> Option<(T, u64)>,
    ) -> Option<T> {
        let observation = self.store.claims.observe(&key);
        if let Some(holder) = observation.holder
            && holder == self.holder
        {
            return row(self.view).map(|(value, _)| value);
        }
        let found = observation
            .holder
            .and_then(|holder| self.store.holder_view(holder).map(|view| (holder, view)))
            .and_then(|(holder, view)| {
                row(view.as_ref()).map(|(value, revision)| (holder, value, revision))
            });
        if let Some((holder, value, revision)) = found {
            self.depend(Dependency::Owned {
                key,
                holder,
                revision,
            });
            Some(value)
        } else {
            self.depend(Dependency::Unowned {
                key,
                at: observation.at,
            });
            None
        }
    }

    /// The session under `token`, expired or not: the dependency is the row
    /// as observed, so a concurrent change conflicts either way.
    pub fn session_row(&self, token: &str) -> Option<SessionRecord> {
        let id = session_id(token);
        self.authorization(ClaimKey::Session(id.clone()), |view| {
            view.authorization
                .sessions
                .get(&id)
                .map(|row| (row.value.clone(), row.revision))
        })
    }

    pub fn credential_row(&self, credential_id: &str) -> Option<CredentialLookup> {
        let now = self.now;
        self.authorization(ClaimKey::Credential(credential_id.to_owned()), |view| {
            view.authorization
                .credentials
                .get(credential_id)
                .map(|row| (filter_grace(row.value.clone(), now), row.revision))
        })
    }
}
