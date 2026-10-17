use topcoat::context::Cx;

use kappa_store::kappa::Kappa;

use crate::error::HandlerError;

/// The authenticated caller identity.
#[derive(Debug, Clone)]
pub struct CallerIdentity {
    pub anchor: Option<Kappa>,
    pub method: AuthMethod,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AuthMethod {
    Bearer,
    SigV4,
    DPoP,
    MutualTls,
    Anonymous,
}

#[derive(Debug, Clone)]
pub struct AuthScope {
    pub namespace: Option<String>,
    pub operation: Operation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Operation {
    Read,
    Write,
    Admin,
    Delete,
}

impl Operation {
    pub const fn is_write(&self) -> bool {
        matches!(self, Self::Write | Self::Admin | Self::Delete)
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    #[error("invalid token: {reason}")]
    InvalidToken { reason: String },

    #[error("expired token: {reason}")]
    ExpiredToken { reason: String },

    #[error("invalid signature: {reason}")]
    InvalidSignature { reason: String },

    #[error("insufficient scope: {reason}")]
    InsufficientScope { reason: String },

    #[error("replay detected: {jti}")]
    ReplayDetected { jti: String },

    #[error("method mismatch: expected {expected}, got {got}")]
    MethodMismatch { expected: String, got: String },

    #[error("uri mismatch: expected {expected}, got {got}")]
    UriMismatch { expected: String, got: String },

    #[error("token hash mismatch: {reason}")]
    TokenHashMismatch { reason: String },

    #[error("key binding mismatch: {reason}")]
    KeyMismatch { reason: String },

    #[error("proof expired: {reason}")]
    ProofExpired { reason: String },

    #[error("internal: {reason}")]
    Internal { reason: String },
}

impl From<AuthError> for HandlerError {
    fn from(e: AuthError) -> Self {
        Self::Unauthorized {
            reason: e.to_string(),
        }
    }
}

/// Trait for auth validation backends.
///
/// Defined in kappa-handler, implemented in kappa-server.
/// Each backend (bearer, sigv4, dpop) has its own internal error
/// type that converts to `AuthError` via `From`. Implementations
/// write ? and the conversion happens in one place.
pub trait AuthValidator: Send + Sync {
    fn validate_bearer(&self, token: &str, scope: &AuthScope) -> Result<CallerIdentity, AuthError>;

    fn validate_sigv4(&self, cx: &Cx, scope: &AuthScope) -> Result<CallerIdentity, AuthError>;

    fn validate_dpop(
        &self,
        access_token: &str,
        proof_jwt: &str,
        method: &str,
        uri: &str,
        scope: &AuthScope,
    ) -> Result<CallerIdentity, AuthError>;

    fn is_auth_required(&self, scope: &AuthScope) -> bool;
}

/// Require authentication. Dispatches by Authorization header prefix.
///
/// Returns `CallerIdentity` on success. The anchor is None for
/// anonymous requests when auth is not required.
///
/// # Errors
///
/// Returns `HandlerError::Unauthorized` if authentication fails
/// or is required but not provided.
pub fn require_auth(
    cx: &Cx,
    validator: &dyn AuthValidator,
    scope: &AuthScope,
) -> Result<CallerIdentity, HandlerError> {
    let parts: &http::request::Parts = topcoat::context::request_context(cx);

    let auth_header = if let Some(v) = parts.headers.get("authorization") {
        v.to_str().map_err(|_| HandlerError::Unauthorized {
            reason: "malformed authorization header: non-ASCII".into(),
        })?
    } else {
        if validator.is_auth_required(scope) {
            return Err(HandlerError::Unauthorized {
                reason: "authentication required".into(),
            });
        }
        return Ok(CallerIdentity {
            anchor: None,
            method: AuthMethod::Anonymous,
        });
    };

    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        return Ok(validator.validate_bearer(token, scope)?);
    }

    if auth_header.starts_with("AWS4-HMAC-SHA256") {
        return Ok(validator.validate_sigv4(cx, scope)?);
    }

    if let Some(access_token) = auth_header.strip_prefix("DPoP ") {
        let dpop_proof = parts
            .headers
            .get("dpop")
            .ok_or_else(|| HandlerError::Unauthorized {
                reason: "DPoP proof header missing".into(),
            })?
            .to_str()
            .map_err(|_| HandlerError::Unauthorized {
                reason: "malformed DPoP header: non-ASCII".into(),
            })?;
        let method = parts.method.as_str();
        let uri = parts.uri.to_string();
        return Ok(validator.validate_dpop(access_token, dpop_proof, method, &uri, scope)?);
    }

    Err(HandlerError::Unauthorized {
        reason: "unsupported authorization scheme".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_is_write() {
        assert!(!Operation::Read.is_write());
        assert!(Operation::Write.is_write());
        assert!(Operation::Admin.is_write());
        assert!(Operation::Delete.is_write());
    }

    #[test]
    fn auth_error_converts_to_handler_error() {
        let auth_err = AuthError::InvalidToken {
            reason: "expired".into(),
        };
        let handler_err: HandlerError = auth_err.into();
        match handler_err {
            HandlerError::Unauthorized { reason } => {
                assert!(reason.contains("expired"), "reason: {reason}");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn anonymous_identity_has_no_anchor() {
        let identity = CallerIdentity {
            anchor: None,
            method: AuthMethod::Anonymous,
        };
        assert!(identity.anchor.is_none());
    }

    #[test]
    fn caller_identity_with_anchor() {
        let anchor = Kappa::sha256(b"test key material");
        let identity = CallerIdentity {
            anchor: Some(anchor.clone()),
            method: AuthMethod::Bearer,
        };
        assert_eq!(identity.anchor.as_ref(), Some(&anchor));
    }
}
