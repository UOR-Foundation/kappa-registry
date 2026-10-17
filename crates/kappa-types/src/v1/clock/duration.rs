use super::TimeError;

/// Nonnegative physical milliseconds, never packed causal ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DurationMs(u64);

impl DurationMs {
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    pub fn try_from_signed(millis: i64) -> Result<Self, TimeError> {
        u64::try_from(millis)
            .map(Self)
            .map_err(|_| TimeError::NegativeDuration)
    }

    pub const fn as_millis(self) -> u64 {
        self.0
    }
}
