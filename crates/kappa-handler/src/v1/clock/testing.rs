//! Deterministic control of the one authority. Tests drive `WallClock`
//! through its physical source; they never substitute another clock.

use super::{ClockError, ClockMs, PhysicalSource, WallClock};
use kappa_store::clock::{CausalTime, DurationMs, TimeError, UnixTimeMs};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

/// Controlled physical acquisition consumed by the production authority.
/// A negative reading fails like a source before the Unix epoch.
pub struct ControlledSource {
    physical: AtomicI64,
}

impl ControlledSource {
    pub const fn new(physical: UnixTimeMs) -> Self {
        Self {
            physical: AtomicI64::new(physical.as_millis()),
        }
    }

    pub fn set(&self, physical: UnixTimeMs) {
        self.physical.store(physical.as_millis(), Ordering::Release);
    }

    pub fn advance(&self, duration: DurationMs) -> Result<UnixTimeMs, ClockError> {
        let mut previous = self.physical.load(Ordering::Acquire);
        loop {
            let next = UnixTimeMs::from_millis(previous).checked_add(duration)?;
            match self.physical.compare_exchange_weak(
                previous,
                next.as_millis(),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(next),
                Err(actual) => previous = actual,
            }
        }
    }
}

impl PhysicalSource for ControlledSource {
    fn read(&self) -> Result<UnixTimeMs, ClockError> {
        let value = self.physical.load(Ordering::Acquire);
        if value < 0 {
            return Err(ClockError::BeforeUnixEpoch);
        }
        Ok(UnixTimeMs::from_millis(value))
    }
}

/// The authority whose next issuance is exactly `at`: physical time held at
/// `at`'s millisecond, recovered from the encoding immediately before it.
///
/// # Errors
///
/// `at` is the first representable time, which has no predecessor.
pub fn clock_at(at: ClockMs) -> Result<WallClock, ClockError> {
    let previous = at.as_i64().checked_sub(1).ok_or(TimeError::OutOfRange)?;
    let physical = i64::try_from(CausalTime::from_encoded(at).physical_ms())
        .map_err(|_| TimeError::OutOfRange)?;
    let source = Arc::new(ControlledSource::new(UnixTimeMs::from_millis(physical)));
    Ok(WallClock::recovered(
        source,
        CausalTime::from_encoded(ClockMs::from_raw(previous)),
    ))
}
