use std::time::{SystemTime, UNIX_EPOCH};

use kappa_store::clock::{TimeError, UnixTimeMs};

use super::ClockError;

/// Physical acquisition only. A source reading is not causal ordering or
/// authenticated evidence of UTC accuracy.
pub trait PhysicalSource: Send + Sync {
    fn read(&self) -> Result<UnixTimeMs, ClockError>;
}

pub struct SystemSource;

impl PhysicalSource for SystemSource {
    fn read(&self) -> Result<UnixTimeMs, ClockError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClockError::BeforeUnixEpoch)?;
        let millis = i64::try_from(elapsed.as_millis()).map_err(|_| TimeError::OutOfRange)?;
        Ok(UnixTimeMs::from_millis(millis))
    }
}
