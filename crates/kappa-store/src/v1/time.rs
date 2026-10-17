//! Time contract: the one causal-time authority interface, its failure
//! modes, and the durable continuity it is built on. The only implementation
//! is `kappa_handler::clock::WallClock`.

use kappa_types::{
    StoreError,
    clock::{CausalTime, ClockMs, TimeError, UnixTimeMs},
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// The registry's causal-time authority.
///
/// Every timestamp the registry issues comes from one instance: request
/// handling, background tasks, reconciliation, and execution publication.
/// Stores call `now` after acquiring their writer, so issuance order is
/// publication order.
pub trait Clock: Send + Sync {
    /// Issue a strictly increasing causal timestamp.
    ///
    /// # Errors
    ///
    /// Reservation exhausted, physical source failure, or logical exhaustion;
    /// a failed issuance advances nothing.
    fn now(&self) -> Result<ClockMs, ClockError>;

    /// Physical acquisition from the same authority, separate from causal
    /// issuance and its recovered floor.
    ///
    /// # Errors
    ///
    /// Physical source failure.
    fn physical_now(&self) -> Result<UnixTimeMs, ClockError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ClockError {
    #[error("durable issuance reservation exhausted")]
    ReservationExhausted,
    #[error("diskless authority provides process-local continuity only")]
    DisklessAuthority,
    #[error("time reservation persistence: {0}")]
    Persistence(StoreError),
    #[error(transparent)]
    Time(#[from] TimeError),
    #[error("physical source precedes the Unix epoch")]
    BeforeUnixEpoch,
    #[error("admitted observation exceeds the configured future-skew bound")]
    FutureObservation,
    #[error("invalid datetime format: {0}")]
    InvalidFormat(String),
}

/// Store-facing form of a clock failure. A failed persistence keeps its
/// store error; exhausting the durable reservation is a capacity condition.
impl From<ClockError> for StoreError {
    fn from(error: ClockError) -> Self {
        match error {
            ClockError::Persistence(error) => error,
            ClockError::ReservationExhausted => Self::CapacityExceeded(error.to_string()),
            other => Self::Internal(format!("time authority: {other}")),
        }
    }
}

/// Non-cloneable ownership guard retained for the authority lifetime.
pub struct TimeAuthorityLease {
    occupied: Arc<AtomicBool>,
}

impl TimeAuthorityLease {
    pub fn acquire(occupied: Arc<AtomicBool>) -> Result<Self, StoreError> {
        occupied
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| StoreError::Conflict("time authority already owned".into()))?;
        Ok(Self { occupied })
    }
}

impl Drop for TimeAuthorityLease {
    fn drop(&mut self) {
        self.occupied.store(false, Ordering::Release);
    }
}

/// Durable authority storage, separate from namespace operations. One live
/// authority owns a backend instance. Recovery and reservation perform blocking
/// I/O and must run outside async executor threads.
pub trait TimeReservationStore: Send + Sync {
    /// Claim exclusive ownership before reading recovery state.
    fn acquire_time_authority(&self) -> Result<TimeAuthorityLease, StoreError>;
    /// Recover the maximum committed timestamp and durable reservation from
    /// one snapshot. Missing expected continuity state must be an error.
    fn recover_time(&self) -> Result<CausalTime, StoreError>;

    /// Durably persist a monotonically increasing ceiling before returning.
    /// Failure must not report successful reservation. Ordinary relaxed write
    /// durability must not weaken this obligation.
    fn reserve_time(&self, ceiling: CausalTime) -> Result<(), StoreError>;
}
