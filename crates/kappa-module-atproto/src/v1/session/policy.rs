//! Session policy: lifetimes, DPoP proof verification and its replay
//! window.
//!
//! A DPoP proof is accepted while its `iat` is within the configured
//! skew of the server's time; a replay within that window must be
//! refused. The window is process-local state over proof identifiers,
//! bounded by time, not by count: identifiers are kept until their proof
//! can no longer be accepted (`iat + skew < now`), and when the configured
//! capacity is reached new proofs are refused (`ProofCapacity`) rather
//! than older identifiers forgotten while their proofs remain acceptable.
//! A restart empties the window; proofs issued before the process started
//! are refused for that reason, so no proof accepted by a previous process
//! can be replayed against this one.

use std::collections::{BTreeMap, BTreeSet};

use kappa_handler::base64url_sha256;

use super::dpop::DpopClaims;
use super::store::{Session, SessionError};

/// Configuration for session management policy.
pub struct SessionConfig {
    /// Session lifetime in milliseconds.
    pub session_ttl_ms: i64,
    /// Maximum DPoP clock skew tolerance in seconds.
    pub dpop_clock_skew_secs: u64,
    /// Maximum number of DPoP proof identifiers held in the replay window.
    /// New proofs are refused while the window is full.
    pub max_jtis: usize,
}

impl Default for SessionConfig {
    /// One day of session lifetime, one minute of DPoP skew, 65536 proof
    /// identifiers in the replay window.
    fn default() -> Self {
        Self {
            session_ttl_ms: 24 * 60 * 60 * 1000,
            dpop_clock_skew_secs: 60,
            max_jtis: 65_536,
        }
    }
}

/// The replay window: every proof identifier accepted whose proof could
/// still be accepted again.
pub(super) struct ProofWindow {
    by_identifier: BTreeMap<String, u64>,
    by_expiry: BTreeSet<(u64, String)>,
    max: usize,
}

/// Why a proof was not admitted into the window.
pub(super) enum ProofRefusal {
    Replay,
    Capacity,
}

impl ProofWindow {
    pub(super) fn new(max: usize) -> Self {
        Self {
            by_identifier: BTreeMap::new(),
            by_expiry: BTreeSet::new(),
            max,
        }
    }

    /// Forget identifiers whose proofs expired before `now_secs`.
    fn expire(&mut self, now_secs: u64, skew_secs: u64) {
        while let Some((expires, jti)) = self.by_expiry.first().cloned() {
            if expires.saturating_add(skew_secs) >= now_secs {
                break;
            }
            self.by_expiry.remove(&(expires, jti.clone()));
            self.by_identifier.remove(&jti);
        }
    }

    /// Admit `jti` issued at `iat_secs`: refused as a replay when present,
    /// as capacity when the window is full of live identifiers.
    pub(super) fn admit(
        &mut self,
        jti: String,
        iat_secs: u64,
        now_secs: u64,
        skew_secs: u64,
    ) -> Result<(), ProofRefusal> {
        self.expire(now_secs, skew_secs);
        if self.by_identifier.contains_key(&jti) {
            return Err(ProofRefusal::Replay);
        }
        if self.by_identifier.len() >= self.max {
            return Err(ProofRefusal::Capacity);
        }
        self.by_expiry.insert((iat_secs, jti.clone()));
        self.by_identifier.insert(jti, iat_secs);
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.by_identifier.len()
    }
}

/// Check the DPoP binding of `claims` to `session`, `method` and `uri`:
/// method, URI (without query), token hash, key thumbprint. Time and
/// replay are decided by the caller against its window.
pub(super) fn verify_binding(
    session: &Session,
    access_token: &str,
    claims: &DpopClaims,
    method: &str,
    uri: &str,
) -> Result<(), SessionError> {
    if !claims.htm.eq_ignore_ascii_case(method) {
        return Err(SessionError::MethodMismatch {
            expected: method.to_string(),
            got: claims.htm.clone(),
        });
    }
    let htu_base = claims
        .htu
        .split_once('?')
        .map_or(claims.htu.as_str(), |(base, _)| base);
    let uri_base = uri.split_once('?').map_or(uri, |(base, _)| base);
    if htu_base != uri_base {
        return Err(SessionError::UriMismatch {
            expected: uri_base.to_string(),
            got: htu_base.to_string(),
        });
    }
    if let Some(ath) = claims.ath.as_deref().filter(|ath| !ath.is_empty())
        && ath != base64url_sha256(access_token.as_bytes())
    {
        return Err(SessionError::TokenHashMismatch);
    }
    if !session.dpop_jkt.is_empty() && claims.jkt != session.dpop_jkt {
        return Err(SessionError::KeyMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_is_bounded_by_time_and_fails_closed_at_capacity() {
        let mut window = ProofWindow::new(2);
        assert!(window.admit("a".into(), 100, 100, 30).is_ok());
        assert!(matches!(
            window.admit("a".into(), 100, 110, 30),
            Err(ProofRefusal::Replay)
        ));
        assert!(window.admit("b".into(), 105, 110, 30).is_ok());
        // Full of live identifiers: a third proof is refused, not admitted
        // by forgetting an identifier whose proof is still acceptable.
        assert!(matches!(
            window.admit("c".into(), 110, 110, 30),
            Err(ProofRefusal::Capacity)
        ));
        assert_eq!(window.len(), 2);
        // Once "a" can no longer be accepted (100 + 30 < 131) it is
        // forgotten and the capacity is free again.
        assert!(window.admit("c".into(), 131, 131, 30).is_ok());
        assert_eq!(window.len(), 2);
        assert!(matches!(
            window.admit("b".into(), 105, 131, 30),
            Err(ProofRefusal::Replay)
        ));
    }
}
