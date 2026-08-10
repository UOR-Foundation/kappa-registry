//! Clock trait (seam S1), datetime parsing, and implementations.
//!
//! Two concerns:
//! - `Clock::now_ms()` -- current time, monotonic, for the running process.
//! - `parse_datetime_to_epoch_secs()` -- incoming/stored datetime strings
//!   to Unix epoch. Single source of truth for all datetime parsing in
//!   the workspace. No module rolls its own calendar math.

pub mod ntp_lamport;

/// A clock provides monotonic timestamps for epoch roots.
///
/// Implementations must be Send + Sync. The returned timestamp
/// must never decrease across calls within the same process.
pub trait Clock: Send + Sync {
    /// Current timestamp in milliseconds since Unix epoch.
    /// Must be monotonically non-decreasing.
    fn now_ms(&self) -> u64;
}

/// Errors from datetime parsing.
#[derive(Debug, thiserror::Error)]
pub enum ClockError {
    #[error("invalid datetime format: {0}")]
    InvalidFormat(String),
}

/// Parse an AWS/ISO 8601 compact datetime "YYYYMMDDTHHMMSSZ" to Unix epoch seconds.
///
/// This is the SSOT for all datetime-to-epoch conversion in the workspace.
/// SigV4 presigned URL expiration, epoch root timestamps, event log
/// timestamps -- everything calls this one function.
///
/// Uses chrono for correctness. No hand-rolled leap year tables.
pub fn parse_datetime_to_epoch_secs(datetime: &str) -> Result<u64, ClockError> {
    let parsed = chrono::NaiveDateTime::parse_from_str(datetime, "%Y%m%dT%H%M%SZ")
        .map_err(|e| ClockError::InvalidFormat(format!("{}: {}", datetime, e)))?;
    let epoch = parsed
        .and_utc()
        .timestamp();
    if epoch < 0 {
        return Err(ClockError::InvalidFormat(format!(
            "{} is before Unix epoch", datetime
        )));
    }
    Ok(epoch as u64)
}

/// Parse raw epoch milliseconds to compact datetime string "YYYYMMDDTHHMMSSZ".
///
/// Accepts actual milliseconds since Unix epoch (not NtpLamport-encoded).
/// For NtpLamportClock values, extract physical ms first via
/// `NtpLamportClock::physical_ms()` before calling this.
pub fn epoch_ms_to_datetime(epoch_ms: u64) -> String {
    let secs = (epoch_ms / 1000) as i64;
    let dt = chrono::DateTime::from_timestamp(secs, 0)
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());
    dt.format("%Y%m%dT%H%M%SZ").to_string()
}

/// Parse raw epoch seconds to compact datetime string "YYYYMMDDTHHMMSSZ".
pub fn epoch_secs_to_datetime(epoch_secs: u64) -> String {
    let dt = chrono::DateTime::from_timestamp(epoch_secs as i64, 0)
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());
    dt.format("%Y%m%dT%H%M%SZ").to_string()
}

/// Convert epoch milliseconds to RFC 7231 HTTP date.
/// "Sat, 09 Aug 2026 12:34:56 GMT"
/// SSOT for Last-Modified and Date response headers.
pub fn epoch_ms_to_http_date(epoch_ms: u64) -> String {
    let secs = (epoch_ms / 1000) as i64;
    let dt = chrono::DateTime::from_timestamp(secs, 0)
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());
    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_aws_datetime() {
        let secs = parse_datetime_to_epoch_secs("20130524T000000Z").unwrap();
        assert_eq!(secs, 1369353600);
    }

    #[test]
    fn parse_datetime_roundtrip() {
        let original = "20260808T123456Z";
        let secs = parse_datetime_to_epoch_secs(original).unwrap();
        let back = epoch_secs_to_datetime(secs);
        assert_eq!(back, original);
    }

    #[test]
    fn parse_invalid_format() {
        assert!(parse_datetime_to_epoch_secs("not-a-date").is_err());
        assert!(parse_datetime_to_epoch_secs("2013-05-24T00:00:00Z").is_err());
        assert!(parse_datetime_to_epoch_secs("").is_err());
    }

    #[test]
    fn epoch_2000() {
        let secs = parse_datetime_to_epoch_secs("20000101T000000Z").unwrap();
        assert_eq!(secs, 946684800);
    }

    #[test]
    fn leap_year_feb_29() {
        // 2024 is a leap year
        let secs = parse_datetime_to_epoch_secs("20240229T120000Z").unwrap();
        assert!(secs > 0);
        let back = epoch_secs_to_datetime(secs);
        assert_eq!(back, "20240229T120000Z");
    }

    #[test]
    fn century_boundary() {
        // 1900 is not a leap year, 2000 is
        let secs_2000 = parse_datetime_to_epoch_secs("20000229T000000Z").unwrap();
        assert!(secs_2000 > 0);
    }
}
