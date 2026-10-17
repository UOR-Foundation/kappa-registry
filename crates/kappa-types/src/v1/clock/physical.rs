use super::{DurationMs, TimeError};

/// Signed Unix milliseconds. This value does not assert clock accuracy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnixTimeMs(i64);

impl UnixTimeMs {
    pub const fn from_millis(millis: i64) -> Self {
        Self(millis)
    }

    pub const fn as_millis(self) -> i64 {
        self.0
    }

    pub const fn unix_seconds(self) -> i64 {
        self.0.div_euclid(1000)
    }

    pub fn checked_add(self, duration: DurationMs) -> Result<Self, TimeError> {
        let result = i128::from(self.0) + i128::from(duration.as_millis());
        i64::try_from(result)
            .map(Self)
            .map_err(|_| TimeError::OutOfRange)
    }

    /// Validity intervals are half-open: a deadline is expired at equality.
    pub const fn has_reached(self, deadline: Self) -> bool {
        self.0 >= deadline.0
    }
}
