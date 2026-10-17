use http::StatusCode;
use kappa_store::StoreError;
use kappa_store::kappa::KappaParseError;

/// Map a `StoreError` to an HTTP status code.
///
/// This is the ONE place this mapping lives.
pub const fn status_for_store_error(err: &StoreError) -> StatusCode {
    match err {
        StoreError::NotFound(_) => StatusCode::NOT_FOUND,
        StoreError::AlreadyExists(_) | StoreError::Conflict(_) => StatusCode::CONFLICT,
        StoreError::Rejected(_) => StatusCode::BAD_REQUEST,
        StoreError::CapacityExceeded(_) => StatusCode::INSUFFICIENT_STORAGE,
        StoreError::VersionMismatch { .. } | StoreError::PreconditionFailed(_) => {
            StatusCode::PRECONDITION_FAILED
        }
        StoreError::NotSupported(_) => StatusCode::NOT_IMPLEMENTED,
        // Nothing was published; the operation may be retried.
        StoreError::DeadlineExceeded { .. } => StatusCode::GATEWAY_TIMEOUT,
        // The outcome is unknown until the service recovers its storage;
        // an unavailable subject is undecided, never absent.
        StoreError::Unavailable(_)
        | StoreError::PublicationIndeterminate { .. }
        | StoreError::PublicationRecoveryRequired { .. }
        // Nothing seals until a restart restores the committed authority.
        | StoreError::AuthorityUnresolved { .. }
        | StoreError::AuthorityInterrupted
        | StoreError::AuthorityDiverged { .. } => StatusCode::SERVICE_UNAVAILABLE,
        // The node's keys do not include the store's committed authority: a
        // server misconfiguration, not a client error.
        StoreError::AuthorityMismatch { .. } | StoreError::AuthorityHistoryAbsent { .. } => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        // `Io` and `Internal` are server failures. `StoreError` is
        // non-exhaustive across crates, so variants added later also remain
        // failures at the HTTP boundary until they are mapped here.
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Errors that any handler can produce.
///
/// Protocol modules convert these to protocol-specific wire format responses.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HandlerError {
    #[error("body exceeds {limit} byte limit")]
    BodyTooLarge { limit: usize },

    #[error("bad request: {reason}")]
    BadRequest { reason: String },

    #[error("unauthorized: {reason}")]
    Unauthorized { reason: String },

    #[error("forbidden: {reason}")]
    Forbidden { reason: String },

    #[error("not found: {reason}")]
    NotFound { reason: String },

    #[error("conflict: {reason}")]
    Conflict { reason: String },

    #[error("store: {0}")]
    Store(#[from] StoreError),

    #[error("time authority: {0}")]
    Clock(#[from] crate::clock::ClockError),

    #[error("timeout: operation exceeded {deadline_ms}ms")]
    Timeout { deadline_ms: u64 },

    #[error("internal: {reason}")]
    Internal { reason: String },

    /// Protocol-specific error with a wire-format error code.
    ///
    /// The handler constructs this with the protocol's error vocabulary
    /// (e.g., AT Protocol `HandleNotFound`, OCI `BLOB_UNKNOWN`,
    /// S3 `NoSuchKey`). The protocol's error formatter reads the code
    /// field and produces the protocol-specific error envelope.
    /// The status field overrides the default status mapping.
    #[error("{code}: {message}")]
    Protocol {
        status: StatusCode,
        code: String,
        message: String,
    },
}

impl HandlerError {
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::BodyTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
            Self::Forbidden { .. } => StatusCode::FORBIDDEN,
            Self::NotFound { .. } => StatusCode::NOT_FOUND,
            Self::Conflict { .. } => StatusCode::CONFLICT,
            Self::Store(e) => status_for_store_error(e),
            Self::Clock(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Timeout { .. } => StatusCode::GATEWAY_TIMEOUT,
            Self::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Protocol { status, .. } => *status,
        }
    }

    pub fn protocol(
        status: StatusCode,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::Protocol {
            status,
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn bad_request(reason: impl Into<String>) -> Self {
        Self::BadRequest {
            reason: reason.into(),
        }
    }

    pub fn not_found(reason: impl Into<String>) -> Self {
        Self::NotFound {
            reason: reason.into(),
        }
    }

    pub fn unauthorized(reason: impl Into<String>) -> Self {
        Self::Unauthorized {
            reason: reason.into(),
        }
    }

    pub fn forbidden(reason: impl Into<String>) -> Self {
        Self::Forbidden {
            reason: reason.into(),
        }
    }

    pub fn internal(reason: impl Into<String>) -> Self {
        Self::Internal {
            reason: reason.into(),
        }
    }
}

impl From<KappaParseError> for HandlerError {
    fn from(e: KappaParseError) -> Self {
        Self::BadRequest {
            reason: e.to_string(),
        }
    }
}

impl From<crate::body::BodyError> for HandlerError {
    fn from(e: crate::body::BodyError) -> Self {
        match e {
            crate::body::BodyError::TooLarge { limit } => Self::BodyTooLarge { limit },
            crate::body::BodyError::ReadFailed(reason) => Self::BadRequest { reason },
        }
    }
}
