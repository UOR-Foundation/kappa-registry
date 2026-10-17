use super::{TimeError, UnixTimeMs};

/// Closed physical-time bounds. Construction does not establish trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeInterval {
    earliest: UnixTimeMs,
    latest: UnixTimeMs,
}

/// A half-open validity window evaluated against uncertain physical time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    Valid,
    NotYetValid,
    Expired,
    Indeterminate,
}

impl TimeInterval {
    pub fn new(earliest: UnixTimeMs, latest: UnixTimeMs) -> Result<Self, TimeError> {
        if earliest > latest {
            return Err(TimeError::InvalidInterval);
        }
        Ok(Self { earliest, latest })
    }

    pub fn around(center: UnixTimeMs, uncertainty_ms: u64) -> Result<Self, TimeError> {
        let center = i128::from(center.as_millis());
        let radius = i128::from(uncertainty_ms);
        let earliest = i64::try_from(center - radius).map_err(|_| TimeError::OutOfRange)?;
        let latest = i64::try_from(center + radius).map_err(|_| TimeError::OutOfRange)?;
        Self::new(
            UnixTimeMs::from_millis(earliest),
            UnixTimeMs::from_millis(latest),
        )
    }

    pub const fn earliest(self) -> UnixTimeMs {
        self.earliest
    }

    pub const fn latest(self) -> UnixTimeMs {
        self.latest
    }

    /// Callers must establish that both observations concern the same instant.
    pub fn intersection(self, other: Self) -> Result<Self, TimeError> {
        Self::new(
            self.earliest.max(other.earliest),
            self.latest.min(other.latest),
        )
    }

    /// Evaluates an explicitly half-open window; protocols select their window.
    pub fn evaluate_half_open(
        self,
        start: UnixTimeMs,
        end: UnixTimeMs,
    ) -> Result<Validity, TimeError> {
        if start >= end {
            return Err(TimeError::InvalidInterval);
        }
        Ok(if self.latest < start {
            Validity::NotYetValid
        } else if self.earliest >= end {
            Validity::Expired
        } else if self.earliest >= start && self.latest < end {
            Validity::Valid
        } else {
            Validity::Indeterminate
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn time(value: i64) -> UnixTimeMs {
        UnixTimeMs::from_millis(value)
    }

    #[test]
    fn uncertainty_cannot_silently_authorize_boundary_crossings() -> Result<(), TimeError> {
        for (center, radius, expected) in [
            (9, 0, Validity::NotYetValid),
            (10, 0, Validity::Valid),
            (19, 0, Validity::Valid),
            (20, 0, Validity::Expired),
            (10, 1, Validity::Indeterminate),
            (19, 1, Validity::Indeterminate),
            (15, 10, Validity::Indeterminate),
        ] {
            let interval = TimeInterval::around(time(center), radius)?;
            assert_eq!(interval.evaluate_half_open(time(10), time(20))?, expected);
        }
        Ok(())
    }

    #[test]
    fn invalid_or_unrepresentable_evidence_is_rejected() -> Result<(), TimeError> {
        assert_eq!(
            TimeInterval::around(time(i64::MAX), 1),
            Err(TimeError::OutOfRange)
        );
        assert_eq!(
            TimeInterval::around(time(i64::MIN), 1),
            Err(TimeError::OutOfRange)
        );
        assert_eq!(
            TimeInterval::around(time(0), u64::MAX),
            Err(TimeError::OutOfRange)
        );
        assert_eq!(
            TimeInterval::new(time(2), time(1)),
            Err(TimeError::InvalidInterval)
        );
        let a = TimeInterval::around(time(10), 2)?;
        let b = TimeInterval::around(time(15), 2)?;
        assert_eq!(a.intersection(b), Err(TimeError::InvalidInterval));
        let c = TimeInterval::around(time(12), 2)?;
        assert_eq!(a.intersection(c)?, TimeInterval::new(time(10), time(12))?);
        Ok(())
    }
}
