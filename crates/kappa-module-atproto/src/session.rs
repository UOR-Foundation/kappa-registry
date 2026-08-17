//! OAuth 2.0 + DPoP (RFC 9449) session management for AT Protocol.
//!
//! Access tokens are DPoP-bound: the client generates a key pair,
//! proves possession on every request via a DPoP proof JWT, and the
//! server verifies the proof before accepting the request.
//!
//! DPoP proof structure (ES256-signed JWT):
//!   Header: { typ: "dpop+jwt", alg: "ES256", jwk: { ... } }
//!   Payload: {
//!     jti: unique identifier (replay prevention),
//!     htm: HTTP method (GET, POST, etc.),
//!     htu: HTTP URI (scheme + host + path, no query),
//!     iat: issued-at timestamp (seconds),
//!     ath: SHA-256 hash of the access token (base64url)
//!   }
//!
//! Access token: opaque string containing session state.
//! The `cnf.jkt` field in the access token binds it to the DPoP key.
//! JKT = JWK Thumbprint (RFC 7638) = base64url(SHA-256(canonical JWK)).

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use sha2::{Digest, Sha256};

/// A session record stored server-side.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub did: String,
    pub access_token: String,
    pub refresh_token: String,
    pub dpop_jkt: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub handle: String,
}

/// DPoP proof claims extracted from the proof JWT.
#[derive(Debug, Clone)]
pub struct DpopClaims {
    /// Unique identifier for replay prevention.
    pub jti: String,
    /// HTTP method the proof is bound to.
    pub htm: String,
    /// HTTP URI the proof is bound to (no query string).
    pub htu: String,
    /// Issued-at timestamp in seconds.
    pub iat: u64,
    /// SHA-256 hash of the access token, base64url-encoded.
    pub ath: String,
    /// JWK thumbprint of the DPoP key.
    pub jkt: String,
}

/// Session store with DPoP binding.
pub struct SessionStore {
    sessions: Mutex<HashMap<String, Session>>,
    refresh_index: Mutex<HashMap<String, String>>,
    credentials: Mutex<HashMap<String, String>>,
    /// JTI replay prevention set. In production this would be a
    /// time-bounded bloom filter or Redis set. For MVP, in-memory HashSet.
    seen_jtis: Mutex<HashSet<String>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            refresh_index: Mutex::new(HashMap::new()),
            credentials: Mutex::new(HashMap::new()),
            seen_jtis: Mutex::new(HashSet::new()),
        }
    }

    /// Register credentials for a DID.
    /// Password is stored as SHA-256 hash. In production use argon2.
    pub fn register_credentials(&self, did: &str, password: &str) {
        let hash = hash_password(password);
        self.credentials.lock().unwrap()
            .insert(did.to_string(), hash);
    }

    /// Authenticate with identifier + password, create a DPoP-bound session.
    ///
    /// `dpop_jkt` is the JWK thumbprint of the client's DPoP key,
    /// extracted from the DPoP proof header's JWK field.
    pub fn create_session(
        &self,
        identifier: &str,
        password: &str,
        handle: &str,
        dpop_jkt: &str,
    ) -> Result<Session, SessionError> {
        let password_hash = hash_password(password);
        let creds = self.credentials.lock().unwrap();
        match creds.get(identifier) {
            Some(stored) if *stored == password_hash => {}
            _ => return Err(SessionError::AuthenticationRequired),
        }
        drop(creds);

        let now_ms = now_millis();
        let expires_ms = now_ms + 3600 * 1000; // 1 hour

        let access_token = generate_token(identifier, now_ms, "access");
        let refresh_token = generate_token(identifier, now_ms, "refresh");

        let session = Session {
            did: identifier.to_string(),
            access_token: access_token.clone(),
            refresh_token: refresh_token.clone(),
            dpop_jkt: dpop_jkt.to_string(),
            created_at_ms: now_ms,
            expires_at_ms: expires_ms,
            handle: handle.to_string(),
        };

        self.sessions.lock().unwrap()
            .insert(access_token.clone(), session.clone());
        self.refresh_index.lock().unwrap()
            .insert(refresh_token, access_token);

        Ok(session)
    }

    /// Refresh a session. Consumes the refresh token, issues new pair.
    /// The DPoP key binding carries over from the original session.
    pub fn refresh_session(&self, refresh_token: &str) -> Result<Session, SessionError> {
        let access_token = {
            let mut idx = self.refresh_index.lock().unwrap();
            idx.remove(refresh_token).ok_or(SessionError::InvalidToken)?
        };

        let old = {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.remove(&access_token).ok_or(SessionError::InvalidToken)?
        };

        let now_ms = now_millis();
        let expires_ms = now_ms + 3600 * 1000;
        let new_access = generate_token(&old.did, now_ms, "access");
        let new_refresh = generate_token(&old.did, now_ms, "refresh");

        let session = Session {
            did: old.did,
            access_token: new_access.clone(),
            refresh_token: new_refresh.clone(),
            dpop_jkt: old.dpop_jkt, // DPoP key binding carries over
            created_at_ms: now_ms,
            expires_at_ms: expires_ms,
            handle: old.handle,
        };

        self.sessions.lock().unwrap()
            .insert(new_access.clone(), session.clone());
        self.refresh_index.lock().unwrap()
            .insert(new_refresh, new_access);

        Ok(session)
    }

    /// Delete (revoke) a session.
    pub fn delete_session(&self, access_token: &str) -> Result<(), SessionError> {
        let session = {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.remove(access_token).ok_or(SessionError::InvalidToken)?
        };
        self.refresh_index.lock().unwrap().remove(&session.refresh_token);
        Ok(())
    }

    /// Get session info by access token.
    pub fn get_session(&self, access_token: &str) -> Result<Session, SessionError> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions.get(access_token).ok_or(SessionError::InvalidToken)?;
        if session.expires_at_ms < now_millis() {
            return Err(SessionError::ExpiredToken);
        }
        Ok(session.clone())
    }

    /// Verify a DPoP-bound request.
    ///
    /// Validates:
    /// 1. Access token exists and is not expired
    /// 2. DPoP proof JTI is unique (replay prevention)
    /// 3. DPoP proof HTM matches the request method
    /// 4. DPoP proof HTU matches the request URI
    /// 5. DPoP proof ATH matches SHA-256(access_token)
    /// 6. DPoP proof JKT matches the session's bound key
    /// 7. DPoP proof IAT is recent (within 5 minutes)
    ///
    /// Returns the session DID on success.
    pub fn verify_dpop_request(
        &self,
        access_token: &str,
        dpop_claims: &DpopClaims,
        request_method: &str,
        request_uri: &str,
    ) -> Result<String, SessionError> {
        // 1. Token validity
        let session = self.get_session(access_token)?;

        // 2. JTI replay prevention
        {
            let mut jtis = self.seen_jtis.lock().unwrap();
            if !jtis.insert(dpop_claims.jti.clone()) {
                return Err(SessionError::ReplayDetected);
            }
        }

        // 3. Method binding
        if dpop_claims.htm.to_uppercase() != request_method.to_uppercase() {
            return Err(SessionError::MethodMismatch);
        }

        // 4. URI binding (scheme + host + path, no query)
        let clean_uri = request_uri.split('?').next().unwrap_or(request_uri);
        if dpop_claims.htu != clean_uri {
            return Err(SessionError::UriMismatch);
        }

        // 5. Access token hash binding
        let expected_ath = base64url_sha256(access_token.as_bytes());
        if dpop_claims.ath != expected_ath {
            return Err(SessionError::TokenHashMismatch);
        }

        // 6. Key binding
        if dpop_claims.jkt != session.dpop_jkt {
            return Err(SessionError::KeyMismatch);
        }

        // 7. Freshness (IAT within 5 minutes)
        let now_secs = now_millis() / 1000;
        let clock_skew = 300; // 5 minutes
        if dpop_claims.iat + clock_skew < now_secs || dpop_claims.iat > now_secs + clock_skew {
            return Err(SessionError::ProofExpired);
        }

        Ok(session.did)
    }

    /// Simple token validation without DPoP (for backward compatibility
    /// during migration to full DPoP). Returns the DID if the token is
    /// valid. Handlers that require DPoP should use verify_dpop_request.
    pub fn validate_token(&self, access_token: &str) -> Option<String> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(access_token)
            .filter(|s| s.expires_at_ms >= now_millis())
            .map(|s| s.did.clone())
    }
}

impl Default for SessionStore {
    fn default() -> Self { Self::new() }
}

fn hash_password(password: &str) -> String {
    hex::encode(Sha256::digest(password.as_bytes()))
}

/// Monotonic counter for token uniqueness within the same millisecond.
static TOKEN_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn generate_token(did: &str, timestamp: u64, kind: &str) -> String {
    let seq = TOKEN_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let input = format!("{}:{}:{}:{}", did, timestamp, kind, seq);
    hex::encode(Sha256::digest(input.as_bytes()))
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Base64url-encode the SHA-256 hash of data (no padding).
fn base64url_sha256(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    base64url_encode(&hash)
}

/// Base64url encoding (RFC 4648 section 5, no padding).
fn base64url_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    for &byte in data {
        bits = (bits << 8) | byte as u32;
        nbits += 8;
        while nbits >= 6 {
            nbits -= 6;
            out.push(TABLE[((bits >> nbits) & 0x3F) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(TABLE[((bits << (6 - nbits)) & 0x3F) as usize] as char);
    }
    out
}

/// Base64url decoding (RFC 4648 section 5, no padding).
pub fn base64url_decode(input: &str) -> Result<Vec<u8>, SessionError> {
    let mut out = Vec::new();
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    for b in input.bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => continue, // skip padding
            _ => return Err(SessionError::InvalidToken),
        };
        bits = (bits << 6) | val as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Ok(out)
}

/// Parse and verify a DPoP proof JWT.
///
/// JWT format: {base64url_header}.{base64url_payload}.{base64url_signature}
/// Header must contain: typ="dpop+jwt", alg="ES256", jwk={EC P-256 key}
/// Payload contains: jti, htm, htu, iat, ath
///
/// Verifies ES256 (P-256 ECDSA) signature over "{header}.{payload}" bytes
/// using the public key from the header's JWK field.
///
/// Returns DpopClaims with the computed JKT (JWK Thumbprint).
/// Generic over algorithm: supports ES256 (P-256) now, extensible to
/// ES384 (P-384), ES512 (P-521), EdDSA via the algorithm dispatch.
pub fn parse_and_verify_dpop_proof(
    proof_jwt: &str,
) -> Result<DpopClaims, SessionError> {
    let parts: Vec<&str> = proof_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(SessionError::InvalidToken);
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    // Decode header
    let header_bytes = base64url_decode(header_b64)?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| SessionError::InvalidToken)?;

    // Verify header fields
    let typ = header.get("typ").and_then(|v| v.as_str()).unwrap_or("");
    if typ != "dpop+jwt" {
        return Err(SessionError::InvalidToken);
    }

    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");

    // Extract JWK public key
    let jwk = header.get("jwk").ok_or(SessionError::InvalidToken)?;
    let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
    let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");

    let (public_key_bytes, verify_algorithm) = match (alg, kty, crv) {
        ("ES256", "EC", "P-256") => {
            let x_b64 = jwk.get("x").and_then(|v| v.as_str())
                .ok_or(SessionError::InvalidToken)?;
            let y_b64 = jwk.get("y").and_then(|v| v.as_str())
                .ok_or(SessionError::InvalidToken)?;
            let x = base64url_decode(x_b64)?;
            let y = base64url_decode(y_b64)?;
            if x.len() != 32 || y.len() != 32 {
                return Err(SessionError::InvalidToken);
            }
            // Uncompressed SEC1: 04 || x || y
            let mut pk = vec![0x04];
            pk.extend_from_slice(&x);
            pk.extend_from_slice(&y);
            (pk, "p256")
        }
        _ => return Err(SessionError::InvalidToken),
    };

    // Verify signature over "{header_b64}.{payload_b64}"
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature_bytes = base64url_decode(signature_b64)?;

    let verifier = kappa_core::crypto::verifier_for(verify_algorithm)
        .map_err(|_| SessionError::InvalidToken)?;

    match verifier.verify(&public_key_bytes, signing_input.as_bytes(), &signature_bytes) {
        Ok(true) => {}
        _ => return Err(SessionError::InvalidToken),
    }

    // Decode payload
    let payload_bytes = base64url_decode(payload_b64)?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| SessionError::InvalidToken)?;

    let jti = payload.get("jti").and_then(|v| v.as_str())
        .ok_or(SessionError::InvalidToken)?.to_string();
    let htm = payload.get("htm").and_then(|v| v.as_str())
        .ok_or(SessionError::InvalidToken)?.to_string();
    let htu = payload.get("htu").and_then(|v| v.as_str())
        .ok_or(SessionError::InvalidToken)?.to_string();
    let iat = payload.get("iat").and_then(|v| v.as_u64())
        .ok_or(SessionError::InvalidToken)?;
    let ath = payload.get("ath").and_then(|v| v.as_str())
        .unwrap_or("").to_string();

    // Compute JWK Thumbprint from the key in the header
    let jkt = match (alg, kty, crv) {
        ("ES256", "EC", "P-256") => {
            let x_b64 = jwk.get("x").and_then(|v| v.as_str()).unwrap_or("");
            let y_b64 = jwk.get("y").and_then(|v| v.as_str()).unwrap_or("");
            jwk_thumbprint_p256(x_b64, y_b64)
        }
        _ => return Err(SessionError::InvalidToken),
    };

    Ok(DpopClaims { jti, htm, htu, iat, ath, jkt })
}

/// Compute the JWK Thumbprint (RFC 7638) for a P-256 public key.
///
/// The thumbprint is base64url(SHA-256(canonical_jwk)) where the
/// canonical JWK contains only the required members in lexicographic
/// order: {"crv":"P-256","kty":"EC","x":"...","y":"..."}
pub fn jwk_thumbprint_p256(x_b64url: &str, y_b64url: &str) -> String {
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        x_b64url, y_b64url
    );
    base64url_sha256(canonical.as_bytes())
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("authentication required")]
    AuthenticationRequired,
    #[error("invalid or expired token")]
    InvalidToken,
    #[error("token expired")]
    ExpiredToken,
    #[error("DPoP proof replay detected")]
    ReplayDetected,
    #[error("DPoP proof method mismatch")]
    MethodMismatch,
    #[error("DPoP proof URI mismatch")]
    UriMismatch,
    #[error("DPoP proof token hash mismatch")]
    TokenHashMismatch,
    #[error("DPoP proof key mismatch")]
    KeyMismatch,
    #[error("DPoP proof expired or too far in the future")]
    ProofExpired,
}

impl SessionError {
    /// XRPC error name for this error type.
    pub fn xrpc_error(&self) -> &'static str {
        match self {
            Self::AuthenticationRequired => "AuthenticationRequired",
            Self::InvalidToken | Self::ExpiredToken => "ExpiredToken",
            Self::ReplayDetected => "InvalidToken",
            Self::MethodMismatch | Self::UriMismatch => "InvalidToken",
            Self::TokenHashMismatch | Self::KeyMismatch => "InvalidToken",
            Self::ProofExpired => "ExpiredToken",
        }
    }

    /// HTTP status code for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::AuthenticationRequired => 401,
            _ => 401,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_create_and_get() {
        let store = SessionStore::new();
        store.register_credentials("did:plc:test", "secret");
        let session = store.create_session("did:plc:test", "secret", "test.handle", "jkt123").unwrap();
        assert!(!session.access_token.is_empty());
        assert!(!session.refresh_token.is_empty());
        assert_eq!(session.dpop_jkt, "jkt123");

        let got = store.get_session(&session.access_token).unwrap();
        assert_eq!(got.did, "did:plc:test");
        assert_eq!(got.dpop_jkt, "jkt123");
    }

    #[test]
    fn session_refresh_rotates_tokens() {
        let store = SessionStore::new();
        store.register_credentials("did:plc:test", "pass");
        let session = store.create_session("did:plc:test", "pass", "h", "jkt").unwrap();

        let refreshed = store.refresh_session(&session.refresh_token).unwrap();
        assert_ne!(refreshed.access_token, session.access_token);
        assert_ne!(refreshed.refresh_token, session.refresh_token);
        assert_eq!(refreshed.dpop_jkt, "jkt"); // key binding preserved

        // Old tokens invalid
        assert!(store.get_session(&session.access_token).is_err());
        // New token works
        assert!(store.get_session(&refreshed.access_token).is_ok());
    }

    #[test]
    fn session_delete_revokes() {
        let store = SessionStore::new();
        store.register_credentials("did:plc:test", "pass");
        let session = store.create_session("did:plc:test", "pass", "h", "jkt").unwrap();
        store.delete_session(&session.access_token).unwrap();
        assert!(store.get_session(&session.access_token).is_err());
    }

    #[test]
    fn wrong_password_rejected() {
        let store = SessionStore::new();
        store.register_credentials("did:plc:test", "correct");
        assert!(store.create_session("did:plc:test", "wrong", "h", "jkt").is_err());
    }

    #[test]
    fn dpop_verification_full_flow() {
        let store = SessionStore::new();
        store.register_credentials("did:plc:test", "pass");
        let session = store.create_session("did:plc:test", "pass", "h", "my-jkt").unwrap();

        let ath = base64url_sha256(session.access_token.as_bytes());
        let now_secs = now_millis() / 1000;

        let claims = DpopClaims {
            jti: "unique-1".to_string(),
            htm: "POST".to_string(),
            htu: "https://pds.example.com/xrpc/com.atproto.repo.createRecord".to_string(),
            iat: now_secs,
            ath,
            jkt: "my-jkt".to_string(),
        };

        let did = store.verify_dpop_request(
            &session.access_token, &claims,
            "POST", "https://pds.example.com/xrpc/com.atproto.repo.createRecord"
        ).unwrap();
        assert_eq!(did, "did:plc:test");
    }

    #[test]
    fn dpop_replay_rejected() {
        let store = SessionStore::new();
        store.register_credentials("did:plc:test", "pass");
        let session = store.create_session("did:plc:test", "pass", "h", "jkt").unwrap();

        let ath = base64url_sha256(session.access_token.as_bytes());
        let claims = DpopClaims {
            jti: "replay-me".to_string(),
            htm: "GET".to_string(),
            htu: "https://pds.example.com/xrpc/test".to_string(),
            iat: now_millis() / 1000,
            ath,
            jkt: "jkt".to_string(),
        };

        // First request succeeds
        store.verify_dpop_request(&session.access_token, &claims, "GET",
            "https://pds.example.com/xrpc/test").unwrap();

        // Replay with same JTI fails
        let result = store.verify_dpop_request(&session.access_token, &claims, "GET",
            "https://pds.example.com/xrpc/test");
        assert!(matches!(result, Err(SessionError::ReplayDetected)));
    }

    #[test]
    fn dpop_method_mismatch_rejected() {
        let store = SessionStore::new();
        store.register_credentials("did:plc:test", "pass");
        let session = store.create_session("did:plc:test", "pass", "h", "jkt").unwrap();

        let claims = DpopClaims {
            jti: "j1".to_string(),
            htm: "GET".to_string(), // proof says GET
            htu: "https://pds.example.com/xrpc/test".to_string(),
            iat: now_millis() / 1000,
            ath: base64url_sha256(session.access_token.as_bytes()),
            jkt: "jkt".to_string(),
        };

        // Request is POST but proof says GET
        let result = store.verify_dpop_request(&session.access_token, &claims,
            "POST", "https://pds.example.com/xrpc/test");
        assert!(matches!(result, Err(SessionError::MethodMismatch)));
    }

    #[test]
    fn dpop_key_mismatch_rejected() {
        let store = SessionStore::new();
        store.register_credentials("did:plc:test", "pass");
        let session = store.create_session("did:plc:test", "pass", "h", "correct-jkt").unwrap();

        let claims = DpopClaims {
            jti: "j2".to_string(),
            htm: "GET".to_string(),
            htu: "https://pds.example.com/xrpc/test".to_string(),
            iat: now_millis() / 1000,
            ath: base64url_sha256(session.access_token.as_bytes()),
            jkt: "wrong-jkt".to_string(), // wrong key
        };

        let result = store.verify_dpop_request(&session.access_token, &claims,
            "GET", "https://pds.example.com/xrpc/test");
        assert!(matches!(result, Err(SessionError::KeyMismatch)));
    }

    #[test]
    fn jwk_thumbprint_deterministic() {
        let t1 = jwk_thumbprint_p256("x-value", "y-value");
        let t2 = jwk_thumbprint_p256("x-value", "y-value");
        assert_eq!(t1, t2);
        assert!(!t1.is_empty());
    }

    #[test]
    fn base64url_no_padding() {
        let encoded = base64url_encode(b"test");
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn validate_token_simple() {
        let store = SessionStore::new();
        store.register_credentials("did:plc:test", "pass");
        let session = store.create_session("did:plc:test", "pass", "h", "jkt").unwrap();
        assert_eq!(store.validate_token(&session.access_token), Some("did:plc:test".to_string()));
        assert_eq!(store.validate_token("bogus"), None);
    }
}
