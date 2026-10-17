//! Session outcomes and their XRPC presentation.

use kappa_store::StoreError;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SessionError {
    #[error("authentication required")]
    AuthenticationRequired,
    #[error("invalid token")]
    InvalidToken,
    #[error("expired token")]
    ExpiredToken,
    #[error("replay detected")]
    ReplayDetected,
    #[error("proof replay window is full")]
    ProofCapacity,
    #[error("method mismatch: expected {expected}, got {got}")]
    MethodMismatch { expected: String, got: String },
    #[error("URI mismatch: expected {expected}, got {got}")]
    UriMismatch { expected: String, got: String },
    #[error("token hash mismatch")]
    TokenHashMismatch,
    #[error("key mismatch")]
    KeyMismatch,
    #[error("proof expired")]
    ProofExpired,
    /// The row this transition decided on changed under a concurrent
    /// transition; the request did nothing and may be retried.
    #[error("session state changed concurrently")]
    Contended,
    #[error("account already exists")]
    AccountExists,
    #[error("lock poisoned")]
    LockPoisoned,
    #[error("store: {0}")]
    Store(StoreError),
    #[error("internal: {0}")]
    Internal(String),
}

impl From<StoreError> for SessionError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Conflict(_) => Self::Contended,
            other => Self::Store(other),
        }
    }
}

impl From<SessionError> for kappa_handler::HandlerError {
    /// Authentication outcomes carry their XRPC error name at their
    /// status; store and internal failures are internal errors.
    fn from(error: SessionError) -> Self {
        match error.status_code() {
            500 => Self::internal(error.to_string()),
            status => Self::protocol(
                topcoat::router::StatusCode::from_u16(status)
                    .unwrap_or(topcoat::router::StatusCode::INTERNAL_SERVER_ERROR),
                error.xrpc_error(),
                error.to_string(),
            ),
        }
    }
}

impl SessionError {
    pub fn xrpc_error(&self) -> &'static str {
        match self {
            Self::AuthenticationRequired => "AuthenticationRequired",
            Self::InvalidToken => "InvalidToken",
            Self::ExpiredToken => "ExpiredToken",
            Self::ReplayDetected => "ReplayDetected",
            Self::ProofCapacity => "RateLimitExceeded",
            Self::MethodMismatch { .. } => "MethodMismatch",
            Self::UriMismatch { .. } => "UriMismatch",
            Self::TokenHashMismatch => "TokenHashMismatch",
            Self::KeyMismatch => "KeyMismatch",
            Self::ProofExpired => "ProofExpired",
            Self::Contended => "Conflict",
            Self::AccountExists => "HandleNotAvailable",
            Self::LockPoisoned | Self::Store(_) | Self::Internal(_) => "InternalServerError",
        }
    }

    pub fn status_code(&self) -> u16 {
        match self {
            Self::AuthenticationRequired
            | Self::InvalidToken
            | Self::ExpiredToken
            | Self::ReplayDetected
            | Self::MethodMismatch { .. }
            | Self::UriMismatch { .. }
            | Self::TokenHashMismatch
            | Self::KeyMismatch
            | Self::ProofExpired => 401,
            Self::AccountExists | Self::Contended => 409,
            Self::ProofCapacity => 429,
            Self::LockPoisoned | Self::Store(_) | Self::Internal(_) => 500,
        }
    }
}
