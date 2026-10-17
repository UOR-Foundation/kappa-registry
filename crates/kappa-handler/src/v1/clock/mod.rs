use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

#[cfg(test)]
mod authority_tests;
mod source;
#[cfg(any(test, feature = "test-util"))]
mod testing;
use kappa_store::clock::{CausalTime, DurationMs, TimeError};
pub use source::{PhysicalSource, SystemSource};
#[cfg(any(test, feature = "test-util"))]
pub use testing::{ControlledSource, clock_at};

pub use kappa_store::clock::ClockMs;
pub use kappa_store::time::{Clock, ClockError};

/// Process-wide causal authority using shared, checked transition rules:
/// the only implementation of `Clock`.
///
/// CAS provides one issuance/observation linearization point. Persistence of
/// a recovery floor is a composition obligation, not supplied by this atomic.
pub struct WallClock {
    state: AtomicI64,
    source: Arc<dyn PhysicalSource>,
    continuity: Continuity,
}

enum Continuity {
    ProcessLocal,
    Durable {
        _lease: kappa_store::time::TimeAuthorityLease,
        persistence: Arc<dyn kappa_store::time::TimeReservationStore>,
        ceiling: AtomicI64,
    },
    #[cfg(test)]
    SimulatedReservation(AtomicI64),
}

impl WallClock {
    pub fn new() -> Self {
        Self {
            state: AtomicI64::new(0),
            source: Arc::new(SystemSource),
            continuity: Continuity::ProcessLocal,
        }
    }

    /// Initialize before publishing the authority to dependent services.
    /// The supplied floor must cover committed history and durable reservations.
    pub fn recovered(source: Arc<dyn PhysicalSource>, floor: CausalTime) -> Self {
        Self {
            state: AtomicI64::new(floor.encoded().as_i64()),
            source,
            continuity: Continuity::ProcessLocal,
        }
    }

    /// Construct only after `ceiling` has been durably reserved. Recovery starts
    /// at the previous reservation, so even issued-but-uncommitted timestamps
    /// cannot be reused. Physical acquisition remains independent.
    #[cfg(test)]
    fn reserved(
        source: Arc<dyn PhysicalSource>,
        recovered_floor: CausalTime,
        ceiling: CausalTime,
    ) -> Result<Self, ClockError> {
        if ceiling <= recovered_floor {
            return Err(ClockError::ReservationExhausted);
        }
        Ok(Self {
            state: AtomicI64::new(recovered_floor.encoded().as_i64()),
            source,
            continuity: Continuity::SimulatedReservation(AtomicI64::new(
                ceiling.encoded().as_i64(),
            )),
        })
    }

    /// Recover and reserve through the retained backend before exposing an
    /// authority. Run on a blocking worker. No supplied ceiling establishes
    /// durability independently of this backend.
    ///
    /// Issuance is available immediately: it resumes strictly above the
    /// recovered floor (which covers every reservation, so no issued but
    /// uncommitted timestamp is reused) and, while physical time still lags
    /// that floor, carries into following milliseconds under the new
    /// durable ceiling.
    pub fn durable(
        source: Arc<dyn PhysicalSource>,
        persistence: Arc<dyn kappa_store::time::TimeReservationStore>,
        headroom: DurationMs,
    ) -> Result<Self, ClockError> {
        let lease = persistence
            .acquire_time_authority()
            .map_err(ClockError::Persistence)?;
        let floor = persistence
            .recover_time()
            .map_err(ClockError::Persistence)?;
        let physical = source.read()?;
        let ceiling = floor.reservation_ceiling(physical, headroom)?;
        persistence
            .reserve_time(ceiling)
            .map_err(ClockError::Persistence)?;
        Ok(Self {
            state: AtomicI64::new(floor.encoded().as_i64()),
            source,
            continuity: Continuity::Durable {
                _lease: lease,
                ceiling: AtomicI64::new(ceiling.encoded().as_i64()),
                persistence,
            },
        })
    }

    pub fn renew_reservation(&self, headroom: DurationMs) -> Result<(), ClockError> {
        let Continuity::Durable { persistence, .. } = &self.continuity else {
            return Err(ClockError::DisklessAuthority);
        };
        // The continuity retains its authority lease throughout this borrow.
        let ceiling = CausalTime::renewal_ceiling(self.source.read()?, headroom)?;
        self.extend_reservation(ceiling, |ceiling| persistence.reserve_time(ceiling))
    }

    /// Persist before making an extension available to concurrent issuers.
    /// Invoke on a blocking worker when persistence performs blocking I/O.
    /// Failed persistence leaves the active ceiling unchanged.
    fn extend_reservation(
        &self,
        ceiling: CausalTime,
        persist: impl FnOnce(CausalTime) -> Result<(), kappa_store::StoreError>,
    ) -> Result<(), ClockError> {
        let reservation = self.reservation().ok_or(ClockError::DisklessAuthority)?;
        persist(ceiling).map_err(ClockError::Persistence)?;
        let mut previous = reservation.load(Ordering::Acquire);
        loop {
            if CausalTime::from_encoded(ClockMs::from_raw(previous)) >= ceiling {
                return Ok(());
            }
            match reservation.compare_exchange_weak(
                previous,
                ceiling.encoded().as_i64(),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => previous = actual,
            }
        }
    }

    pub fn physical_now(&self) -> Result<kappa_store::clock::UnixTimeMs, ClockError> {
        self.source.read()
    }

    pub fn issued_floor(&self) -> CausalTime {
        CausalTime::from_encoded(ClockMs::from_raw(self.state.load(Ordering::Acquire)))
    }

    const fn reservation(&self) -> Option<&AtomicI64> {
        match &self.continuity {
            Continuity::ProcessLocal => None,
            Continuity::Durable { ceiling, .. } => Some(ceiling),
            #[cfg(test)]
            Continuity::SimulatedReservation(ceiling) => Some(ceiling),
        }
    }

    /// Only admitted history can advance causal state. A verified epoch does
    /// not establish UTC accuracy; the local physical source remains separate.
    pub fn observe_epoch(
        &self,
        epoch: &kappa_crypto::epoch_verification::VerifiedEpoch,
        max_future_skew: DurationMs,
    ) -> Result<ClockMs, ClockError> {
        let remote = CausalTime::from_encoded(ClockMs::from_raw(epoch.root().timestamp_ms()));
        self.transition(Some((remote, max_future_skew)))
    }

    fn transition(
        &self,
        observation: Option<(CausalTime, DurationMs)>,
    ) -> Result<ClockMs, ClockError> {
        loop {
            let prev = self.state.load(Ordering::Acquire);
            let previous = CausalTime::from_encoded(ClockMs::from_raw(prev));
            let physical = u64::try_from(self.source.read()?.as_millis())
                .map_err(|_| ClockError::BeforeUnixEpoch)?;
            let next = match observation {
                Some((remote, tolerance)) => {
                    if remote.physical_ms().saturating_sub(physical) > tolerance.as_millis() {
                        return Err(ClockError::FutureObservation);
                    }
                    previous.observe(remote, physical)?
                }
                // A durable reservation bounds causal lead, so exhausting a
                // millisecond's logical range may carry into the next one;
                // the ceiling check below refuses any carry past it.
                // Process-local authorities have no such bound and fail.
                None => match previous.issue(physical) {
                    Err(TimeError::LogicalExhausted) if self.reservation().is_some() => {
                        previous.carry()?
                    }
                    issued => issued?,
                },
            }
            .encoded();
            if let Some(reservation) = self.reservation() {
                let ceiling = CausalTime::from_encoded(ClockMs::from_raw(
                    reservation.load(Ordering::Acquire),
                ));
                if CausalTime::from_encoded(next) > ceiling {
                    return Err(ClockError::ReservationExhausted);
                }
            }
            if self
                .state
                .compare_exchange_weak(prev, next.as_i64(), Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(next);
            }
        }
    }
}

impl Default for WallClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for WallClock {
    fn now(&self) -> Result<ClockMs, ClockError> {
        self.transition(None)
    }

    fn physical_now(&self) -> Result<kappa_store::clock::UnixTimeMs, ClockError> {
        self.source.read()
    }
}

/// Parses "YYYYMMDDTHHMMSSZ" to Unix epoch seconds.
pub fn parse_datetime_to_epoch_secs(datetime: &str) -> Result<u64, ClockError> {
    if datetime.len() != 16
        || !datetime.is_ascii()
        || !datetime.ends_with('Z')
        || datetime.as_bytes()[8] != b'T'
        || !datetime
            .as_bytes()
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 8 || index == 15 || byte.is_ascii_digit())
    {
        return Err(ClockError::InvalidFormat(format!(
            "{datetime} does not match YYYYMMDDTHHMMSSZ"
        )));
    }
    let year: u16 = datetime[0..4]
        .parse()
        .map_err(|_| ClockError::InvalidFormat(format!("bad year in {datetime}")))?;
    let month: u8 = datetime[4..6]
        .parse()
        .map_err(|_| ClockError::InvalidFormat(format!("bad month in {datetime}")))?;
    let day: u8 = datetime[6..8]
        .parse()
        .map_err(|_| ClockError::InvalidFormat(format!("bad day in {datetime}")))?;
    let hour: u8 = datetime[9..11]
        .parse()
        .map_err(|_| ClockError::InvalidFormat(format!("bad hour in {datetime}")))?;
    let min: u8 = datetime[11..13]
        .parse()
        .map_err(|_| ClockError::InvalidFormat(format!("bad minute in {datetime}")))?;
    let sec: u8 = datetime[13..15]
        .parse()
        .map_err(|_| ClockError::InvalidFormat(format!("bad second in {datetime}")))?;

    let components = kappa_store::clock::UtcDateTime {
        year,
        month,
        day,
        hour,
        minute: min,
        second: sec,
        millisecond: 0,
    };
    let total_secs = components
        .to_unix()
        .map_err(|error| ClockError::InvalidFormat(format!("{datetime}: {error}")))?
        .unix_seconds();
    u64::try_from(total_secs)
        .map_err(|_| ClockError::InvalidFormat(format!("{datetime} is before Unix epoch")))
}

/// Formats epoch milliseconds as "YYYYMMDDTHHMMSSZ".
pub fn epoch_ms_to_datetime(epoch_ms: u64) -> Result<String, ClockError> {
    format_epoch_secs(epoch_ms / 1000)
}

/// Formats epoch seconds as "YYYYMMDDTHHMMSSZ".
pub fn epoch_secs_to_datetime(epoch_secs: u64) -> Result<String, ClockError> {
    format_epoch_secs(epoch_secs)
}

fn civil_from_epoch(epoch_secs: u64) -> Result<kappa_store::clock::UtcDateTime, ClockError> {
    let millis = epoch_secs
        .checked_mul(1000)
        .and_then(|millis| i64::try_from(millis).ok())
        .ok_or(TimeError::OutOfRange)?;
    Ok(kappa_store::clock::UtcDateTime::from_unix(
        kappa_store::clock::UnixTimeMs::from_millis(millis),
    )?)
}

fn format_epoch_secs(epoch_secs: u64) -> Result<String, ClockError> {
    let date = civil_from_epoch(epoch_secs)?;
    Ok(format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        date.year, date.month, date.day, date.hour, date.minute, date.second
    ))
}

/// Formats epoch milliseconds as ISO 8601 "2026-01-01T00:00:00.000Z".
pub fn epoch_ms_to_iso8601(epoch_ms: u64) -> Result<String, ClockError> {
    let millis = epoch_ms % 1000;
    let date = civil_from_epoch(epoch_ms / 1000)?;
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        date.year, date.month, date.day, date.hour, date.minute, date.second, millis
    ))
}

/// Formats epoch milliseconds as RFC 7231 HTTP date.
pub fn epoch_ms_to_http_date(epoch_ms: u64) -> Result<String, ClockError> {
    static DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    static MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let secs = epoch_ms / 1000;
    let day_of_week = ((secs / 86400) % 7) as usize;
    let date = civil_from_epoch(secs)?;

    Ok(format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        DAYS[day_of_week],
        date.day,
        MONTHS[usize::from(date.month) - 1],
        date.year,
        date.hour,
        date.minute,
        date.second,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn wall_clock_monotonic() -> TestResult {
        let clock = WallClock::new();
        let a = clock.now()?;
        let b = clock.now()?;
        assert!(b.as_i64() >= a.as_i64());
        Ok(())
    }

    #[test]
    fn wall_clock_strictly_increases_within_ms() -> TestResult {
        let clock = WallClock::new();
        let mut prev = clock.now()?.as_i64();
        for _ in 0..100 {
            let next = clock.now()?.as_i64();
            assert!(
                next > prev,
                "must strictly increase: prev={prev}, next={next}"
            );
            prev = next;
        }
        Ok(())
    }

    #[test]
    fn controlled_source_drives_the_authority() -> TestResult {
        use kappa_store::clock::UnixTimeMs;
        let source = Arc::new(ControlledSource::new(UnixTimeMs::from_millis(1000)));
        let clock = WallClock::recovered(
            source.clone(),
            CausalTime::from_encoded(ClockMs::from_raw(0)),
        );
        let first = clock.now()?;
        assert_eq!(first.physical_ms(), 1000);
        source.advance(DurationMs::from_millis(500))?;
        assert_eq!(clock.now()?.physical_ms(), 1500);
        source.set(UnixTimeMs::from_millis(900));
        let after_rollback = clock.now()?;
        assert_eq!(after_rollback.physical_ms(), 1500);
        assert_eq!(clock.physical_now()?.as_millis(), 900);
        assert!(CausalTime::from_encoded(after_rollback) > CausalTime::from_encoded(first));
        Ok(())
    }

    #[test]
    fn parse_aws_datetime() -> TestResult {
        assert_eq!(
            parse_datetime_to_epoch_secs("20260101T000000Z")?,
            1_767_225_600
        );
        Ok(())
    }

    #[test]
    fn roundtrip_epoch_ms() -> TestResult {
        let ms = 1_767_225_600_000_u64;
        let dt = epoch_ms_to_datetime(ms)?;
        assert_eq!(dt, "20260101T000000Z");
        assert_eq!(parse_datetime_to_epoch_secs(&dt)?, ms / 1000);
        Ok(())
    }

    #[test]
    fn iso8601_format() -> TestResult {
        assert_eq!(
            epoch_ms_to_iso8601(1_767_225_600_123_u64)?,
            "2026-01-01T00:00:00.123Z"
        );
        Ok(())
    }

    #[test]
    fn http_date_format() -> TestResult {
        assert_eq!(
            epoch_ms_to_http_date(1_767_225_600_000_u64)?,
            "Thu, 01 Jan 2026 00:00:00 GMT"
        );
        Ok(())
    }

    #[test]
    fn unrepresentable_dates_fail_without_epoch_substitution() -> TestResult {
        assert!(epoch_ms_to_datetime(u64::MAX).is_err());
        assert!(epoch_secs_to_datetime(u64::MAX).is_err());
        assert!(epoch_ms_to_iso8601(u64::MAX).is_err());
        assert!(epoch_ms_to_http_date(u64::MAX).is_err());
        assert_eq!(
            epoch_ms_to_iso8601(253_402_300_799_999)?,
            "9999-12-31T23:59:59.999Z"
        );
        assert!(epoch_ms_to_iso8601(253_402_300_800_000).is_err());
        Ok(())
    }

    #[test]
    fn invalid_datetime_rejected() {
        assert!(parse_datetime_to_epoch_secs("not-a-date").is_err());
        assert!(parse_datetime_to_epoch_secs("20261301T000000Z").is_err());
        assert!(parse_datetime_to_epoch_secs("20260100T000000Z").is_err());
    }

    #[test]
    fn impossible_calendar_dates_are_rejected() {
        for input in ["20260229T000000Z", "21000229T000000Z", "20260431T000000Z"] {
            assert!(parse_datetime_to_epoch_secs(input).is_err(), "{input}");
        }
        assert!(parse_datetime_to_epoch_secs("20000229T000000Z").is_ok());
        assert!(parse_datetime_to_epoch_secs("20240229T000000Z").is_ok());
    }

    #[test]
    fn unicode_datetime_is_rejected_without_panicking() -> TestResult {
        let input = "202é101T000000Z";
        assert_eq!(input.len(), 16);
        let parsed = std::panic::catch_unwind(|| parse_datetime_to_epoch_secs(input))
            .map_err(|_| "untrusted datetime must not panic")?;
        assert!(parsed.is_err());
        Ok(())
    }
}
