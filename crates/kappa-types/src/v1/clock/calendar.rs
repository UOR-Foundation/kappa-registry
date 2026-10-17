use super::{TimeError, UnixTimeMs};
use chrono::{DateTime, Datelike, NaiveDate, Timelike};

/// Gregorian UTC components, validated on conversion using `Chrono`.
///
/// Unix milliseconds are non-leap time. Textual representations belong to
/// adapters; the four-digit year constraint is explicit in this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcDateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub millisecond: u16,
}

impl UtcDateTime {
    pub fn to_unix(self) -> Result<UnixTimeMs, TimeError> {
        if self.year > 9999 || self.millisecond > 999 {
            return Err(TimeError::OutOfRange);
        }
        let date = NaiveDate::from_ymd_opt(
            i32::from(self.year),
            u32::from(self.month),
            u32::from(self.day),
        )
        .ok_or(TimeError::OutOfRange)?;
        let datetime = date
            .and_hms_milli_opt(
                u32::from(self.hour),
                u32::from(self.minute),
                u32::from(self.second),
                u32::from(self.millisecond),
            )
            .ok_or(TimeError::OutOfRange)?;
        Ok(UnixTimeMs::from_millis(
            datetime.and_utc().timestamp_millis(),
        ))
    }

    pub fn from_unix(time: UnixTimeMs) -> Result<Self, TimeError> {
        let datetime =
            DateTime::from_timestamp_millis(time.as_millis()).ok_or(TimeError::OutOfRange)?;
        if !(0..=9999).contains(&datetime.year()) {
            return Err(TimeError::OutOfRange);
        }
        Ok(Self {
            year: u16::try_from(datetime.year()).map_err(|_| TimeError::OutOfRange)?,
            month: u8::try_from(datetime.month()).map_err(|_| TimeError::OutOfRange)?,
            day: u8::try_from(datetime.day()).map_err(|_| TimeError::OutOfRange)?,
            hour: u8::try_from(datetime.hour()).map_err(|_| TimeError::OutOfRange)?,
            minute: u8::try_from(datetime.minute()).map_err(|_| TimeError::OutOfRange)?,
            second: u8::try_from(datetime.second()).map_err(|_| TimeError::OutOfRange)?,
            millisecond: u16::try_from(datetime.timestamp_subsec_millis())
                .map_err(|_| TimeError::OutOfRange)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_epoch_roundtrips_and_calendar_exhaustion_is_rejected() -> Result<(), TimeError> {
        for millis in [
            -62_167_219_200_000,
            -1001,
            -1,
            0,
            951_782_400_123,
            253_402_300_799_999,
        ] {
            let time = UnixTimeMs::from_millis(millis);
            assert_eq!(UtcDateTime::from_unix(time)?.to_unix()?, time);
        }
        assert!(UtcDateTime::from_unix(UnixTimeMs::from_millis(i64::MAX)).is_err());
        assert!(UtcDateTime::from_unix(UnixTimeMs::from_millis(i64::MIN)).is_err());
        Ok(())
    }

    #[test]
    fn century_rules_and_component_validation() {
        let mut date = UtcDateTime {
            year: 2000,
            month: 2,
            day: 29,
            hour: 0,
            minute: 0,
            second: 0,
            millisecond: 0,
        };
        assert!(date.to_unix().is_ok());
        date.year = 2100;
        assert!(date.to_unix().is_err());
        date.year = 2024;
        date.second = 60;
        assert!(date.to_unix().is_err());
        date.second = 59;
        date.millisecond = 1000;
        assert!(
            date.to_unix().is_err(),
            "non-leap Unix time rejects Chrono leap-second encoding"
        );
    }
}
