use kappa_types::canonical::CanonicalError;
use kappa_types::error::StoreError;

/// Failures of the directory and of proof verification.
#[derive(Debug, thiserror::Error)]
pub enum DirectoryError {
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// A publication's outcome disagreed with the directory's expectation
    /// and the committed state must be recovered before proofs are
    /// served again.
    #[error(
        "directory publication failed; recover committed directory state before serving proofs"
    )]
    Unavailable,
    /// A proof, a record or a recovered state failed verification.
    #[error("verification: {0}")]
    Verification(String),
    /// A request the directory refuses: an epoch it does not hold, a
    /// retraction of a label never asserted, a malformed range.
    #[error("rejected: {0}")]
    Rejected(String),
    #[error("encoding: {0}")]
    Encoding(String),
}

impl From<CanonicalError> for DirectoryError {
    fn from(error: CanonicalError) -> Self {
        Self::Encoding(error.to_string())
    }
}

/// A record read from the store whose bytes do not hash to the identity
/// that named them is a verification failure, not a parse error.
impl From<kappa_types::kappa::KappaParseError> for DirectoryError {
    fn from(error: kappa_types::kappa::KappaParseError) -> Self {
        Self::Verification(error.to_string())
    }
}
