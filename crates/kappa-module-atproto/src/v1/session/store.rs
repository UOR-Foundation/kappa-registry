//! AT Protocol sessions and account credentials over the substrate.
//!
//! Every session transition (creation, refresh, deletion) and every
//! credential registration is a published execution of the `_sessions`
//! namespace: the access token and the refresh token are two session rows
//! (`ExecutionWrites::session_put`) that name each other, so a refresh
//! replaces both and a deletion removes both in one epoch, and the account
//! credential is a credential row (`credential_put`) holding the salted
//! argon2id hash and the account's signing secret.
//!
//! Every decision is made inside the execution that acts on it, through
//! the execution's own authorization reads (`ExecutionReads::session_get`,
//! `credential_get`), which the store records as dependencies: a refresh
//! consumes exactly the refresh row it read, a registration creates only
//! a credential it observed absent, and a concurrent transition of the
//! same row refuses the execution (`Conflict`) rather than letting two
//! refreshes of one token both succeed. Reads outside executions decide
//! from the published state (`IdentityStore::session_get`,
//! `credential_get`), so a revoked session is refused from the epoch that
//! revoked it. Executions issue their time from the store's clock
//! authority; the caller's `now` decides expiry of what it reads.

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use dcbor::prelude::*;
use kappa_store::clock::ClockMs;
use kappa_store::kappa::Kappa;
use kappa_store::time::Clock;
use kappa_store::traits::KappaStore;
use kappa_store::{Execution, NamespaceRef, StoreError};

use super::account::AccountSecret;
use super::dpop::DpopClaims;
use super::policy::{ProofRefusal, ProofWindow, SessionConfig, verify_binding};
use kappa_handler::generate_session_token;

/// Name of the namespace whose epochs govern sessions and credentials.
pub const SESSIONS_NAMESPACE: &str = "_sessions";

/// Authenticated session. The DID is the external AT Protocol identifier.
/// The anchor is the substrate's internal cryptographic root derived from
/// the signing key at account creation time. Both are needed: DID for
/// external API responses, anchor for internal store operations.
///
/// After key rotation (succession), the session's anchor is the OLD
/// anchor. The handler resolves through the succession chain to get
/// the current anchor. If the old anchor is watermarked with
/// KeyCompromise, the session is rejected.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub did: String,
    pub anchor: Kappa,
    pub access_token: String,
    pub refresh_token: String,
    pub dpop_jkt: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub handle: String,
}

pub use super::error::SessionError;

/// Metadata of a session row.
/// CBOR key assignments (PERMANENT): 0-6
#[derive(Clone, CBORCodable)]
struct SessionMeta {
    /// `ACCESS` or `REFRESH`.
    #[cbor(n = 0)]
    kind: u64,
    #[cbor(n = 1)]
    did: String,
    #[cbor(n = 2)]
    handle: String,
    #[cbor(n = 3)]
    dpop_jkt: String,
    #[cbor(n = 4)]
    created_at_ms: i64,
    /// The access row's refresh token; the refresh row's access token.
    #[cbor(n = 5)]
    counterpart: String,
    /// The pair's deadline, as the row's `expires_at_ms`.
    #[cbor(n = 6)]
    expires_at_ms: i64,
}

const ACCESS: u64 = 0;
const REFRESH: u64 = 1;

fn lock<T>(m: &Mutex<T>) -> Result<MutexGuard<'_, T>, SessionError> {
    m.lock().map_err(|_| SessionError::LockPoisoned)
}

fn decode_meta(bytes: &[u8]) -> Result<SessionMeta, SessionError> {
    kappa_store::canonical::from_canonical(bytes)
        .map_err(|e| SessionError::Internal(format!("session row decode: {e}")))
}

pub struct SessionStore {
    store: Arc<dyn KappaStore>,
    clock: Arc<dyn Clock>,
    namespace: OnceLock<NamespaceRef>,
    proofs: Mutex<ProofWindow>,
    /// Unix seconds this process started serving: proofs issued before it
    /// are refused, because an earlier process may have accepted them.
    started_at_secs: u64,
    config: SessionConfig,
}

impl SessionStore {
    /// # Errors
    ///
    /// The clock cannot read its physical time.
    pub fn new(
        store: Arc<dyn KappaStore>,
        clock: Arc<dyn Clock>,
        config: SessionConfig,
    ) -> Result<Self, SessionError> {
        let started = clock
            .physical_now()
            .map_err(|e| SessionError::Internal(e.to_string()))?;
        let started_at_secs = u64::try_from(started.unix_seconds())
            .map_err(|_| SessionError::Internal("physical time before the Unix epoch".into()))?;
        let max_jtis = config.max_jtis;
        Ok(Self {
            store,
            clock,
            namespace: OnceLock::new(),
            proofs: Mutex::new(ProofWindow::new(max_jtis)),
            started_at_secs,
            config,
        })
    }

    /// The `_sessions` namespace, created on first use.
    fn namespace(&self) -> Result<NamespaceRef, SessionError> {
        if let Some(ns) = self.namespace.get() {
            return Ok(ns.clone());
        }
        let ns = kappa_store::namespace_ensure(
            &*self.store,
            SESSIONS_NAMESPACE,
            None,
            None,
            &*self.clock,
        )?;
        Ok(self.namespace.get_or_init(|| ns).clone())
    }

    /// Run `write` in one execution of the sessions namespace and publish
    /// it; a failing write aborts the execution.
    fn publish<T>(
        &self,
        write: impl FnOnce(&mut dyn Execution) -> Result<T, SessionError>,
    ) -> Result<T, SessionError> {
        let ns = self.namespace()?;
        let mut execution = self.store.begin_execution(&ns, &*self.clock)?;
        match write(&mut *execution) {
            Ok(value) => {
                execution.publish()?;
                Ok(value)
            }
            Err(error) => {
                execution.abort()?;
                Err(error)
            }
        }
    }

    fn credential(&self, did: &str, now: ClockMs) -> Result<(Kappa, AccountSecret), SessionError> {
        let (anchor, secret, _) = match self.store.credential_get(did, now) {
            Ok(found) => found,
            Err(StoreError::NotFound(_)) => return Err(SessionError::AuthenticationRequired),
            Err(error) => return Err(error.into()),
        };
        Ok((anchor, AccountSecret::decode(&secret)?))
    }

    /// Register `did` with `password`. The credential is created only if
    /// the execution observes it absent; a concurrent registration of the
    /// same account conflicts and is reported as `AccountExists`.
    pub fn register_credentials(&self, did: &str, password: &str) -> Result<(), SessionError> {
        let secret = AccountSecret::new(password)?;
        let anchor = secret.anchor()?;
        let bytes = secret.encode();
        self.publish(|execution| {
            if execution.credential_get(did)?.is_some() {
                return Err(SessionError::AccountExists);
            }
            execution.credential_put(did, &anchor, &bytes)?;
            Ok(())
        })
        .map_err(|error| match error {
            SessionError::Contended => SessionError::AccountExists,
            other => other,
        })
    }

    /// Resolve the account's key-derived anchor after password verification.
    pub fn account_anchor(
        &self,
        did: &str,
        password: &str,
        now: ClockMs,
    ) -> Result<Kappa, SessionError> {
        let (anchor, secret) = self.credential(did, now)?;
        if !secret.verify(password) {
            return Err(SessionError::AuthenticationRequired);
        }
        if secret.anchor()? != anchor {
            return Err(SessionError::Internal(
                "credential anchor disagrees with its signing secret".into(),
            ));
        }
        Ok(anchor)
    }

    fn deadline(&self, now: ClockMs) -> Result<i64, SessionError> {
        let ttl = u64::try_from(self.config.session_ttl_ms)
            .map_err(|_| SessionError::Internal("session ttl is negative".into()))?;
        now.checked_add_physical_ms(ttl)
            .map(ClockMs::as_i64)
            .ok_or_else(|| SessionError::Internal("session deadline overflow".into()))
    }

    fn physical_ms(now: ClockMs) -> Result<i64, SessionError> {
        i64::try_from(now.physical_ms())
            .map_err(|_| SessionError::Internal("physical time out of range".into()))
    }

    fn fresh_pair(&self, now: ClockMs) -> Result<(String, String, i64), SessionError> {
        let access = generate_session_token().map_err(|e| SessionError::Internal(e.to_string()))?;
        let refresh =
            generate_session_token().map_err(|e| SessionError::Internal(e.to_string()))?;
        Ok((access, refresh, self.deadline(now)?))
    }

    /// Write the access and refresh rows of `session` into `execution`,
    /// after observing both tokens unused in it.
    fn put_pair(execution: &mut dyn Execution, session: &Session) -> Result<(), SessionError> {
        for token in [&session.access_token, &session.refresh_token] {
            if execution.session_get(token)?.is_some() {
                return Err(SessionError::Internal("generated token collision".into()));
            }
        }
        let access = SessionMeta {
            kind: ACCESS,
            did: session.did.clone(),
            handle: session.handle.clone(),
            dpop_jkt: session.dpop_jkt.clone(),
            created_at_ms: session.created_at_ms,
            counterpart: session.refresh_token.clone(),
            expires_at_ms: session.expires_at_ms,
        };
        let refresh = SessionMeta {
            kind: REFRESH,
            counterpart: session.access_token.clone(),
            ..access.clone()
        };
        execution.session_put(
            &session.access_token,
            &session.anchor,
            session.expires_at_ms,
            &kappa_store::canonical::canonical_bytes(&access),
        )?;
        execution.session_put(
            &session.refresh_token,
            &session.anchor,
            session.expires_at_ms,
            &kappa_store::canonical::canonical_bytes(&refresh),
        )?;
        Ok(())
    }

    pub fn create_session(
        &self,
        identifier: &str,
        password: &str,
        handle: &str,
        anchor: &Kappa,
        dpop_jkt: &str,
        now: ClockMs,
    ) -> Result<Session, SessionError> {
        let expected = self.account_anchor(identifier, password, now)?;
        if *anchor != expected {
            return Err(SessionError::KeyMismatch);
        }
        let (access_token, refresh_token, expires_at_ms) = self.fresh_pair(now)?;
        let session = Session {
            did: identifier.to_string(),
            anchor: anchor.clone(),
            access_token,
            refresh_token,
            dpop_jkt: dpop_jkt.to_string(),
            created_at_ms: Self::physical_ms(now)?,
            expires_at_ms,
            handle: handle.to_string(),
        };
        self.publish(|execution| Self::put_pair(execution, &session))?;
        Ok(session)
    }

    /// The row `token` names in the published state, with its kind.
    fn row(&self, token: &str, now: ClockMs) -> Result<(Kappa, SessionMeta), SessionError> {
        let (anchor, metadata) = match self.store.session_get(token, now) {
            Ok(found) => found,
            Err(StoreError::NotFound(reason)) if reason.contains("expired") => {
                return Err(SessionError::ExpiredToken);
            }
            Err(StoreError::NotFound(_)) => return Err(SessionError::InvalidToken),
            Err(error) => return Err(error.into()),
        };
        Ok((anchor, decode_meta(&metadata)?))
    }

    /// Refresh the pair `refresh_token` belongs to. The refresh row is
    /// read and consumed inside the publishing execution: a second refresh
    /// of the same token, concurrent or later, finds no row or conflicts.
    pub fn refresh_session(
        &self,
        refresh_token: &str,
        now: ClockMs,
    ) -> Result<Session, SessionError> {
        let (new_access, new_refresh, expires_at_ms) = self.fresh_pair(now)?;
        let created_at_ms = Self::physical_ms(now)?;
        self.publish(|execution| {
            let (anchor, metadata) = execution
                .session_get(refresh_token)?
                .ok_or(SessionError::InvalidToken)?;
            let meta = decode_meta(&metadata)?;
            if meta.kind != REFRESH {
                return Err(SessionError::InvalidToken);
            }
            let session = Session {
                did: meta.did,
                anchor,
                access_token: new_access.clone(),
                refresh_token: new_refresh.clone(),
                dpop_jkt: meta.dpop_jkt,
                created_at_ms,
                expires_at_ms,
                handle: meta.handle,
            };
            // The old pair goes and the new pair comes in one epoch: no
            // interval exists in which both or neither is valid.
            execution.session_delete(&meta.counterpart)?;
            execution.session_delete(refresh_token)?;
            Self::put_pair(execution, &session)?;
            Ok(session)
        })
        .map_err(|error| match error {
            SessionError::Contended => SessionError::InvalidToken,
            other => other,
        })
    }

    pub fn delete_session(&self, access_token: &str) -> Result<(), SessionError> {
        self.publish(|execution| {
            let (_, metadata) = execution
                .session_get(access_token)?
                .ok_or(SessionError::InvalidToken)?;
            let meta = decode_meta(&metadata)?;
            if meta.kind != ACCESS {
                return Err(SessionError::InvalidToken);
            }
            execution.session_delete(access_token)?;
            execution.session_delete(&meta.counterpart)?;
            Ok(())
        })
        .map_err(|error| match error {
            SessionError::Contended => SessionError::InvalidToken,
            other => other,
        })
    }

    pub fn get_session(&self, access_token: &str, now: ClockMs) -> Result<Session, SessionError> {
        let (anchor, meta) = self.row(access_token, now)?;
        if meta.kind != ACCESS {
            return Err(SessionError::InvalidToken);
        }
        Ok(Session {
            did: meta.did,
            anchor,
            access_token: access_token.to_string(),
            refresh_token: meta.counterpart,
            dpop_jkt: meta.dpop_jkt,
            created_at_ms: meta.created_at_ms,
            expires_at_ms: meta.expires_at_ms,
            handle: meta.handle,
        })
    }

    /// Validate a token and return the session's DID and anchor. An
    /// invalid or expired token is `Ok(None)`; a storage or decode
    /// failure is an error, never a silent refusal.
    pub fn validate_token(
        &self,
        access_token: &str,
        now: ClockMs,
    ) -> Result<Option<(String, Kappa)>, SessionError> {
        match self.row(access_token, now) {
            Ok((anchor, meta)) => Ok((meta.kind == ACCESS).then_some((meta.did, anchor))),
            Err(SessionError::InvalidToken | SessionError::ExpiredToken) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn verify_dpop_request(
        &self,
        access_token: &str,
        claims: &DpopClaims,
        method: &str,
        uri: &str,
        now: ClockMs,
    ) -> Result<String, SessionError> {
        let session = self.get_session(access_token, now)?;
        verify_binding(&session, access_token, claims, method, uri)?;
        let now_secs = now.physical_ms() / 1000;
        if now_secs.abs_diff(claims.iat) > self.config.dpop_clock_skew_secs
            || claims.iat < self.started_at_secs
        {
            return Err(SessionError::ProofExpired);
        }
        match lock(&self.proofs)?.admit(
            claims.jti.clone(),
            claims.iat,
            now_secs,
            self.config.dpop_clock_skew_secs,
        ) {
            Ok(()) => Ok(session.did),
            Err(ProofRefusal::Replay) => Err(SessionError::ReplayDetected),
            Err(ProofRefusal::Capacity) => Err(SessionError::ProofCapacity),
        }
    }
}
