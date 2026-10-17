/// Errors returned by all `KappaStore` sub-trait methods.
///
/// Every variant carries context so log lines identify WHAT was not
/// found, WHAT conflicted, WHY the request was rejected.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    #[error("not found: {0}")]
    NotFound(String),

    /// Whether the subject exists cannot be decided now: evidence that
    /// could hold it is unavailable (storage missing without a recorded
    /// retirement, a namespace whose committed state cannot be read).
    /// Never a statement of absence; the request may be retried.
    #[error("unavailable: {0}")]
    Unavailable(String),

    #[error("already exists: {0}")]
    AlreadyExists(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("rejected: {0}")]
    Rejected(String),

    #[error("capacity exceeded: {0}")]
    CapacityExceeded(String),

    /// Retry the conditional mutation using the returned record's version.
    /// Captured at the failed comparison, not by a subsequent racing read.
    /// None denotes absence (version zero); another writer can still win
    /// before the caller retries.
    #[error("version mismatch: expected {expected}, found {found}; retry using the current record")]
    VersionMismatch {
        expected: u64,
        found: u64,
        current: Option<Box<crate::TagEntry>>,
    },

    #[error("precondition failed: {0}")]
    PreconditionFailed(String),

    #[error("not supported: {0}")]
    NotSupported(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("internal: {0}")]
    Internal(String),

    /// The caller's deadline passed before publication. Nothing was
    /// published; the operation may be retried under the same identity.
    #[error(
        "deadline exceeded by {overrun_ms}ms before publication in namespace {}",
        hex_namespace(namespace)
    )]
    DeadlineExceeded {
        namespace: [u8; 16],
        overrun_ms: u64,
    },

    #[error("epoch publication outcome indeterminate for {root} at epoch {epoch_number}: {detail}")]
    PublicationIndeterminate {
        namespace: [u8; 16],
        epoch_number: u64,
        root: Box<crate::kappa::Kappa>,
        detail: String,
    },

    #[error("epoch {epoch_number} publication {root} observed, storage reopen required: {detail}")]
    PublicationRecoveryRequired {
        namespace: [u8; 16],
        epoch_number: u64,
        root: Box<crate::kappa::Kappa>,
        detail: String,
    },

    /// A rotation of the signing authority has an unknown commit outcome on
    /// this handle. Nothing is sealed under either authority until the store
    /// is reopened and its persisted history selects one.
    #[error("signing authority unresolved since rotation from {outgoing}; reopen the store")]
    AuthorityUnresolved { outgoing: Box<crate::kappa::Kappa> },

    /// An authority transition panicked, so whether its backend change
    /// committed is unknown. Nothing is signed until a restart selects the
    /// committed authority.
    #[error("signing authority transition interrupted; restart to restore the committed authority")]
    AuthorityInterrupted,

    /// The node's live signing authority differs from the store's committed
    /// authority. Nothing is signed until a restart selects the committed
    /// authority.
    #[error(
        "live signing authority {live} differs from the committed authority {committed}; restart"
    )]
    AuthorityDiverged {
        live: Box<crate::kappa::Kappa>,
        committed: Box<crate::kappa::Kappa>,
    },

    /// The offered signing keys do not include the authority the store's
    /// persisted history ends at.
    #[error("offered authority {offered} is not this store's current authority {current}")]
    AuthorityMismatch {
        offered: Box<crate::kappa::Kappa>,
        current: Box<crate::kappa::Kappa>,
    },

    /// Several signing keys were offered to select from, but the store has
    /// no authority history to select with.
    #[error("store has no authority history to select among {offered} offered keys")]
    AuthorityHistoryAbsent { offered: usize },
}

fn hex_namespace(namespace: &[u8; 16]) -> String {
    use std::fmt::Write as _;
    namespace
        .iter()
        .fold(String::with_capacity(32), |mut out, byte| {
            // Formatting into a String cannot fail.
            let _ = write!(out, "{byte:02x}");
            out
        })
}

impl From<crate::kappa::KappaParseError> for StoreError {
    fn from(e: crate::kappa::KappaParseError) -> Self {
        Self::Rejected(e.to_string())
    }
}

impl From<crate::canonical::CanonicalError> for StoreError {
    fn from(e: crate::canonical::CanonicalError) -> Self {
        Self::Internal(e.to_string())
    }
}
