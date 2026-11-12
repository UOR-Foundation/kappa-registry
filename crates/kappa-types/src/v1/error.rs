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

    /// The operation's work allowance refused its next unit before the
    /// unit started: what it reports was done, nothing else, and nothing
    /// absent was concluded. A limit refusal may be retried with a larger
    /// allowance or later; a deadline refusal reports the deadline passed.
    #[error("work refused: {0}")]
    WorkRefused(crate::work::WorkExhausted),

    /// The store's durable state cannot be opened under this build or
    /// configuration without an upgrade or a compatible configuration; it
    /// was not modified.
    #[error("upgrade required: {0}")]
    UpgradeRequired(String),

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

    /// A publication known not to be published whose signing coordinate is
    /// consumed. The backend retains its candidate and resources, and its
    /// namespace refuses other publications until it is resolved.
    #[error("{0}")]
    PublicationRetained(Box<RetainedPublication>),

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

/// How far a retained publication progressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublicationPhase {
    /// Prepared and its coordinate consumed; the signer was not invoked.
    Prepared,
    /// The signer was invoked and returned nothing the store observed. A
    /// signature may exist, so the signer is never invoked again.
    SignerInvoked,
    /// The signer returned an error and no bytes.
    SignerRefused,
    /// The signer returned bytes; no signed root has been formed from them.
    SignatureReturned,
    /// The returned bytes are conclusively invalid for this candidate.
    SignatureInvalid,
    /// A signed root exists and the evidence it names is being completed.
    Completing,
    /// The signed publication is being installed into its candidate view.
    Installing,
    /// The candidate's discovery registrations are being made.
    Registering,
}

impl PublicationPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::SignerInvoked => "signer invoked",
            Self::SignerRefused => "signer refused",
            Self::SignatureReturned => "signature returned",
            Self::SignatureInvalid => "signature invalid",
            Self::Completing => "completing signed evidence",
            Self::Installing => "installing",
            Self::Registering => "registering",
        }
    }
}

/// What resolution of a retained publication can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryDisposition {
    /// Its retained progress supports another resolution attempt. Each
    /// attempt still checks current authority, authorization, predecessor
    /// and work admission before it continues.
    Resumable,
    /// No resolution can publish it: no valid signature exists for its
    /// coordinate, or the authority or authorization it depends on can no
    /// longer hold.
    Terminal,
}

impl RecoveryDisposition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resumable => "resumable",
            Self::Terminal => "terminal",
        }
    }
}

/// The outcome record of a publication known not to be published whose
/// coordinate is consumed, derived from the backend's retained state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedPublication {
    pub namespace: [u8; 16],
    pub incarnation: [u8; 16],
    /// The consumed coordinate.
    pub epoch_number: u64,
    /// The identity of the unsigned root, naming the candidate.
    pub candidate: crate::kappa::Kappa,
    /// The signed root, present only once one was formed from the bytes
    /// the signer returned.
    pub signed_root: Option<crate::kappa::Kappa>,
    pub phase: PublicationPhase,
    pub disposition: RecoveryDisposition,
    /// Why the publication stopped where it did.
    pub cause: String,
}

impl std::fmt::Display for RetainedPublication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "epoch {} of namespace {} retained unpublished ({}, {}), candidate {}",
            self.epoch_number,
            hex_namespace(&self.namespace),
            self.phase.as_str(),
            self.disposition.as_str(),
            self.candidate,
        )?;
        if let Some(root) = &self.signed_root {
            write!(f, ", signed root {root}")?;
        }
        write!(f, ": {}", self.cause)
    }
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
