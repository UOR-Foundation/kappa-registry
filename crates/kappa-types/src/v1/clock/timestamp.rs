/// Millisecond-precision timestamp with HLC encoding.
///
/// The type lives in kappa-types because store trait methods take it
/// as a parameter. The one `Clock` trait is defined in kappa-store's `time`
/// module; its one implementation, `WallClock`, lives in kappa-handler
/// because it reads `SystemTime`. This split avoids a circular dependency.
///
/// Construction is restricted. Production code obtains `ClockMs` from
/// `Clock::now()`; stores issue it under their writer.
/// Test code uses `ClockMs::test_value` (cfg-gated).
///
/// HLC encoding: upper 48 bits physical milliseconds, lower 16 bits
/// logical counter. Wall-time recoverable via right shift 16.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClockMs(i64);

impl ClockMs {
    /// Largest physical millisecond value whose encoding remains a
    /// non-negative `i64`. `ClockMs` orders by its signed encoding, so a
    /// larger physical value would order before every real timestamp.
    pub const MAX_PHYSICAL_MS: u64 = (i64::MAX as u64) >> 16;

    /// Construct from a raw HLC-encoded value.
    ///
    /// Public because `Clock` trait implementations in kappa-handler
    /// must construct `ClockMs`, and kappa-handler is a separate crate.
    ///
    /// Protocol modules and handlers MUST NOT call this directly.
    /// Use `clock_now(cx)` from kappa-handler instead. This function
    /// exists for `Clock` trait implementations and deserialization.
    pub const fn from_raw(ms: i64) -> Self {
        Self(ms)
    }

    /// Extract the raw i64 for persistence.
    pub const fn as_i64(self) -> i64 {
        self.0
    }

    /// Extract physical milliseconds (upper 48 bits).
    pub const fn physical_ms(self) -> u64 {
        u64::from_ne_bytes(self.0.to_ne_bytes()) >> 16
    }

    /// Extract logical counter (lower 16 bits).
    pub const fn logical(self) -> u16 {
        let bytes = self.0.to_le_bytes();
        u16::from_le_bytes([bytes[0], bytes[1]])
    }

    /// Add physical milliseconds to this timestamp.
    ///
    /// Operates on the physical component (upper 48 bits) only.
    /// The logical counter is reset to zero because the result
    /// represents a future physical time, not a causal successor
    /// of the current event.
    ///
    /// Used for computing expiration deadlines:
    /// `let expires_at = now.add_physical_ms(timeout_secs * 1000);`
    #[must_use]
    pub fn add_physical_ms(self, ms: u64) -> Self {
        let physical = self
            .physical_ms()
            .saturating_add(ms)
            .min(Self::MAX_PHYSICAL_MS);
        Self(i64::from_ne_bytes((physical << 16).to_ne_bytes()))
    }

    /// `add_physical_ms` without saturation: `None` when the deadline's
    /// physical component exceeds `MAX_PHYSICAL_MS`.
    ///
    /// Use where an unrepresentable deadline must be refused rather than
    /// treated as unbounded, such as a grace period a caller configures.
    /// Deadlines stored as `i64` keep this encoding and compare against
    /// `ClockMs::as_i64` of the current time; adding milliseconds to the
    /// encoded integer instead would scale every window by 2^-16.
    #[must_use]
    pub fn checked_add_physical_ms(self, ms: u64) -> Option<Self> {
        let physical = self.physical_ms().checked_add(ms)?;
        (physical <= Self::MAX_PHYSICAL_MS)
            .then(|| Self(i64::from_ne_bytes((physical << 16).to_ne_bytes())))
    }

    /// Test-only constructor for deterministic timestamps.
    #[cfg(any(test, feature = "test-util"))]
    pub const fn test_value(ms: i64) -> Self {
        Self(ms)
    }
}

impl std::fmt::Display for ClockMs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}ms", self.physical_ms())
    }
}

impl serde::Serialize for ClockMs {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(self.0)
    }
}

impl<'de> serde::Deserialize<'de> for ClockMs {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = i64::deserialize(deserializer)?;
        Ok(Self(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_roundtrip() {
        let ms = ClockMs::test_value(42);
        assert_eq!(ms.as_i64(), 42);
    }

    #[test]
    fn physical_and_logical_extraction() {
        let physical: u64 = 1_700_000_000_000;
        let logical: u16 = 7;
        let encoded = i64::from_ne_bytes(((physical << 16) | u64::from(logical)).to_ne_bytes());
        let ms = ClockMs::from_raw(encoded);
        assert_eq!(ms.physical_ms(), physical);
        assert_eq!(ms.logical(), logical);
    }

    #[test]
    fn display_shows_physical_ms() {
        let encoded = i64::from_ne_bytes((1000_u64 << 16).to_ne_bytes());
        let ms = ClockMs::from_raw(encoded);
        assert_eq!(format!("{ms}"), "1000ms");
    }

    #[test]
    fn ordering_is_total() {
        let a = ClockMs::from_raw(100);
        let b = ClockMs::from_raw(200);
        assert!(a < b);
        assert_eq!(a, a);
    }

    #[test]
    fn add_physical_ms_advances_physical_only() {
        let physical: u64 = 1_000;
        let logical: u16 = 42;
        let encoded = i64::from_ne_bytes(((physical << 16) | u64::from(logical)).to_ne_bytes());
        let ms = ClockMs::from_raw(encoded);

        let future = ms.add_physical_ms(5000);
        assert_eq!(future.physical_ms(), 6000);
        // Logical counter resets to zero — this is a future time, not
        // a causal successor.
        assert_eq!(future.logical(), 0);
    }

    #[test]
    fn saturated_deadline_orders_after_every_real_time() {
        let now = ClockMs::from_raw(i64::from_ne_bytes((1000_u64 << 16).to_ne_bytes()));
        let unbounded = now.add_physical_ms(u64::MAX / 2);
        assert_eq!(unbounded.physical_ms(), ClockMs::MAX_PHYSICAL_MS);
        assert!(unbounded.as_i64() > 0);
        assert!(unbounded > now);
        let at_max = ClockMs::from_raw(i64::from_ne_bytes(
            (ClockMs::MAX_PHYSICAL_MS << 16).to_ne_bytes(),
        ));
        assert_eq!(at_max.add_physical_ms(1), at_max);
        assert!(at_max > now);
    }

    #[test]
    fn checked_deadline_refuses_instead_of_saturating() {
        let encode =
            |physical: u64| ClockMs::from_raw(i64::from_ne_bytes((physical << 16).to_ne_bytes()));
        let now = ClockMs::from_raw(i64::from_ne_bytes(
            ((1_700_000_000_000_u64 << 16) | 9).to_ne_bytes(),
        ));
        assert_eq!(
            now.checked_add_physical_ms(60_000),
            Some(encode(1_700_000_060_000))
        );
        assert_eq!(
            now.checked_add_physical_ms(60_000),
            Some(now.add_physical_ms(60_000))
        );
        // One minute of grace moves the encoded value by 60_000 * 2^16.
        assert_eq!(
            now.checked_add_physical_ms(60_000)
                .map(|d| d.as_i64() - now.as_i64()),
            Some(60_000 * 65_536 - 9)
        );
        let max = encode(ClockMs::MAX_PHYSICAL_MS);
        assert_eq!(max.checked_add_physical_ms(0), Some(max));
        assert_eq!(max.checked_add_physical_ms(1), None);
        assert_eq!(now.checked_add_physical_ms(u64::MAX), None);
        // A negative encoding has no physical time to extend.
        assert_eq!(ClockMs::from_raw(-1).checked_add_physical_ms(0), None);
    }

    #[test]
    fn expires_at_comparison() {
        let now = ClockMs::from_raw(i64::from_ne_bytes((1000_u64 << 16).to_ne_bytes()));
        let expires = now.add_physical_ms(3_600_000);
        let later = ClockMs::from_raw(i64::from_ne_bytes((5_000_000_u64 << 16).to_ne_bytes()));
        // Before expiration
        assert!(now < expires);
        // After expiration
        assert!(later > expires);
    }

    #[test]
    fn serde_roundtrip() -> Result<(), serde_json::Error> {
        let ms = ClockMs::test_value(999);
        let json = serde_json::to_string(&ms)?;
        assert_eq!(json, "999");
        let parsed: ClockMs = serde_json::from_str(&json)?;
        assert_eq!(parsed, ms);
        Ok(())
    }
}
