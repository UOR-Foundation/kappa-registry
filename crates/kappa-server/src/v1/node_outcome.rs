//! Outcomes of the node authority lifecycle in
//! [`crate::node_authority`]: startup, rotation, reconciliation and status,
//! each typed by what it leaves in force.
//!
//! A rotation that did not commit can still have left key material behind:
//! a successor record published before a later step failed, or a staging
//! copy. Such outcomes carry a [`Residual`]: whether the key store still
//! durably selects the committed key, and whether every other node key has
//! been removed. The coordinator records it, so status and readiness report
//! the remaining obligation and reconciliation completes it.

use kappa_crypto::CryptoError;
use kappa_crypto::keystore::Settlement;
use kappa_crypto::node::Availability;
use kappa_store::StoreError;
use kappa_store::kappa::Kappa;

use crate::node_completion::{Completion, FollowUp};

/// Why establishing the node's authority at startup failed.
#[derive(Debug, thiserror::Error)]
pub enum EstablishError {
    #[error("key store: {0}")]
    KeyStore(#[source] CryptoError),
    #[error("persistent store: {0}")]
    Store(#[source] StoreError),
}

/// What a settlement to the committed authority left in the key store.
#[derive(Debug)]
pub struct Residual {
    /// The key store durably selects the committed key.
    pub custody: Result<(), CryptoError>,
    /// No other node key, staged or retired, remains.
    pub key_removal: Result<(), CryptoError>,
}

impl Residual {
    /// The residual of `settled`, a settlement to the committed authority.
    /// A failed selection removed nothing.
    pub fn of(settled: Result<Settlement, CryptoError>) -> Self {
        match settled {
            Ok(settled) => Self {
                custody: Ok(()),
                key_removal: settled.cleanup,
            },
            Err(error) => Self {
                custody: Err(error),
                key_removal: Err(not_attempted()),
            },
        }
    }

    pub const fn holds(&self) -> bool {
        self.custody.is_ok() && self.key_removal.is_ok()
    }
}

/// Removal that did not run because selection failed first.
pub fn not_attempted() -> CryptoError {
    CryptoError::IntegrityFailure {
        path: "node records".into(),
        reason: "not attempted: custody settlement failed".into(),
    }
}

/// What a rotation that committed nothing failed on.
#[derive(Debug, thiserror::Error)]
pub enum Precommit {
    #[error("succession signing: {0}")]
    Signing(#[source] CryptoError),
    #[error("succession record: {0}")]
    Succession(#[source] StoreError),
    /// No qualifying rotation witness could be obtained: the control
    /// namespace or its activation domain could not be read, or the witness
    /// source refused or is not configured.
    #[error("rotation witness: {0}")]
    Witness(#[source] StoreError),
    #[error("store refused the rotation: {0}")]
    Store(#[source] StoreError),
}

/// Why a rotation did not complete. Every variant but `Indeterminate`
/// leaves the outgoing authority live; see each for the key store.
#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    /// The key store's lifecycle could not be taken; nothing was attempted.
    #[error("key store lifecycle: {0}")]
    KeyStore(#[source] CryptoError),
    /// Settling the key store to the committed authority before staging
    /// failed; nothing was staged.
    #[error("key store settlement before staging: {}", residual_state(.0))]
    Custody(Box<Residual>),
    /// Staging the successor failed. A successor record it published is
    /// discarded by settling to the committed authority; `residual` says
    /// whether that succeeded.
    #[error("successor staging: {cause}; {}", residual_state(residual))]
    Staging {
        #[source]
        cause: CryptoError,
        residual: Box<Residual>,
    },
    /// The live authority is unresolved, diverged or was interrupted; only
    /// a restart restores signing. Nothing was attempted.
    #[error("node authority unavailable: {0}")]
    Unavailable(#[source] CryptoError),
    /// The live authority differs from the committed one; the identity now
    /// refuses all signing until a restart.
    #[error(
        "live authority {live} differs from the store's committed authority {committed}; restart to reconcile"
    )]
    Diverged {
        live: Box<Kappa>,
        committed: Box<Kappa>,
    },
    /// A successor was staged and nothing was committed. `residual` reports
    /// the discard of the staged key.
    #[error("rotation not committed: {cause}; {}", residual_state(residual))]
    NotCommitted {
        #[source]
        cause: Precommit,
        residual: Box<Residual>,
    },
    /// The store's commit outcome is unknown. The staged key is retained,
    /// and no authority signs until the next start settles to the committed
    /// one.
    #[error(
        "store rotation outcome unknown: {0}; the staged key is retained and the next start settles to the committed authority"
    )]
    Indeterminate(#[source] StoreError),
}

fn residual_state(residual: &Residual) -> String {
    match (&residual.custody, &residual.key_removal) {
        (Ok(()), Ok(())) => "key store settled to the committed authority".to_owned(),
        (Ok(()), Err(error)) => {
            format!("key store selects the committed authority; key removal incomplete ({error})")
        }
        (Err(error), _) => format!("key store settlement failed ({error})"),
    }
}

impl RotationError {
    /// What the outcome established for custody and key removal of the
    /// still-committed authority, when it touched the key store.
    pub const fn custody_state(&self) -> Option<(bool, bool)> {
        match self {
            Self::Custody(residual)
            | Self::Staging { residual, .. }
            | Self::NotCommitted { residual, .. } => {
                Some((residual.custody.is_ok(), residual.key_removal.is_ok()))
            }
            // Both keys are retained until a restart selects one.
            Self::Indeterminate(_) => Some((false, false)),
            Self::KeyStore(_) | Self::Unavailable(_) | Self::Diverged { .. } => None,
        }
    }
}

impl From<CryptoError> for RotationError {
    /// An error from the live identity itself, before any step ran.
    fn from(error: CryptoError) -> Self {
        match error {
            CryptoError::AuthorityUnresolved { .. }
            | CryptoError::AuthorityInterrupted
            | CryptoError::AuthorityDiverged { .. } => Self::Unavailable(error),
            other => Self::KeyStore(other),
        }
    }
}

/// A committed rotation and the outcome of each guarantee that completes
/// it. Every guarantee that failed is retried by the next reconciliation,
/// which readiness runs while any is incomplete.
#[derive(Debug)]
pub struct Rotation {
    pub retired: Kappa,
    pub current: Kappa,
    pub follow_up: FollowUp,
}

/// Why reconciliation could not run. Each guarantee it did run is reported
/// in its [`FollowUp`] instead.
#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("key store lifecycle: {0}")]
    KeyStore(#[source] CryptoError),
    #[error("node authority unavailable: {0}")]
    Unavailable(#[source] CryptoError),
    /// The live authority differs from the committed one; the identity now
    /// refuses all signing until a restart.
    #[error(
        "live authority {live} differs from the store's committed authority {committed}; restart to reconcile"
    )]
    Diverged {
        live: Box<Kappa>,
        committed: Box<Kappa>,
    },
}

impl From<CryptoError> for ReconcileError {
    fn from(error: CryptoError) -> Self {
        match error {
            CryptoError::AuthorityUnresolved { .. }
            | CryptoError::AuthorityInterrupted
            | CryptoError::AuthorityDiverged { .. } => Self::Unavailable(error),
            other => Self::KeyStore(other),
        }
    }
}

/// The node's authority as an operator verifies it, observed in one
/// instant of the lifecycle: no rotation or reconciliation runs between its
/// parts.
#[derive(Debug)]
pub struct AuthorityStatus {
    pub availability: Availability,
    /// The authority the store last established: its committed authority,
    /// unless `commit_known` is false.
    pub established: Kappa,
    /// False while a rotation from `established` has an unknown commit
    /// outcome on this store handle; a restart selects whichever the
    /// persisted history committed.
    pub commit_known: bool,
    /// Every authority the established history retired, oldest first.
    pub retired: Vec<Kappa>,
    /// Which guarantees hold for `established`. Outcomes recorded for any
    /// other authority do not count.
    pub completion: Completion,
}
