//! Typed failures of the passkey routes.
//!
//! Every failure has a stable code from prism/identity/2, an HTTP status and
//! one sentence for the reader. The body is `{"error": code, "message": ...}`.

use kappa_core::StoreError;
use topcoat::router::StatusCode;

#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    /// The request is not well formed: bad JSON, base64url or lengths.
    #[error("{0}")]
    Request(String),
    #[error("the challenge is unknown, expired or already used")]
    Challenge,
    #[error("the origin is not an identity origin this registry accepts")]
    Origin,
    #[error("the authenticator data was made for a different relying party")]
    Rp,
    #[error("the authenticator did not report user presence and user verification")]
    Flags,
    #[error("the attested credential is not the credential named")]
    Credential,
    #[error("{0}")]
    Key(String),
    #[error("this credential is already registered")]
    Exists,
    #[error("{0}")]
    Binding(String),
    #[error("the assertion does not sign this message with a key of this account")]
    Signature,
    #[error("this key has been revoked")]
    Revoked,
    #[error("too many sign-in attempts are in progress; try again shortly")]
    Rate,
    #[error("no key is registered for this credential")]
    UnknownCredential,
    #[error("no key is registered for this account")]
    UnknownAccount,
    #[error("the registry could not read or write its store")]
    Store(#[from] StoreError),
}

impl PasskeyError {
    /// The protocol's error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Request(_) => "request",
            Self::Challenge => "challenge",
            Self::Origin => "origin",
            Self::Rp => "rp",
            Self::Flags => "flags",
            Self::Credential | Self::UnknownCredential => "credential",
            Self::Key(_) => "key",
            Self::Exists => "exists",
            Self::Binding(_) => "binding",
            Self::Signature => "signature",
            Self::Revoked => "revoked",
            Self::Rate => "rate",
            Self::UnknownAccount => "account",
            Self::Store(_) => "store",
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::Request(_)
            | Self::Challenge
            | Self::Rp
            | Self::Flags
            | Self::Credential
            | Self::Key(_) => StatusCode::BAD_REQUEST,
            Self::Origin | Self::Binding(_) | Self::Signature => StatusCode::FORBIDDEN,
            Self::Exists => StatusCode::CONFLICT,
            Self::Revoked => StatusCode::GONE,
            Self::Rate => StatusCode::TOO_MANY_REQUESTS,
            Self::UnknownCredential | Self::UnknownAccount => StatusCode::NOT_FOUND,
            Self::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The JSON body. A store failure's detail is logged, never sent.
    pub fn body(&self) -> String {
        serde_json::json!({ "error": self.code(), "message": self.to_string() }).to_string()
    }
}
