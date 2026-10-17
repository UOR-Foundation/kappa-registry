use super::{ClockMs, DurationMs, TimeError, UnixTimeMs};

/// Decoded causal components. Component ordering is independent of wire integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CausalTime {
    physical_ms: u64,
    logical: u16,
}

impl CausalTime {
    pub const MAX_PHYSICAL_MS: u64 = u64::MAX >> 16;

    pub const fn new(physical_ms: u64, logical: u16) -> Result<Self, TimeError> {
        if physical_ms > Self::MAX_PHYSICAL_MS {
            return Err(TimeError::OutOfRange);
        }
        Ok(Self {
            physical_ms,
            logical,
        })
    }

    pub const fn physical_ms(self) -> u64 {
        self.physical_ms
    }

    pub const fn logical(self) -> u16 {
        self.logical
    }

    pub const fn from_encoded(value: ClockMs) -> Self {
        Self {
            physical_ms: value.physical_ms(),
            logical: value.logical(),
        }
    }

    /// Preserves existing packed bytes; does not select signed wire ordering.
    pub fn encoded(self) -> ClockMs {
        let packed = (self.physical_ms << 16) | u64::from(self.logical);
        ClockMs::from_raw(i64::from_ne_bytes(packed.to_ne_bytes()))
    }

    /// Establish the issuance floor from committed history and any durable
    /// reservation. Only authenticated history and locally durable bounds
    /// belong here; unadmitted peer timestamps must not become restart state.
    pub fn recovery_floor(committed: Self, reserved: Option<Self>) -> Self {
        reserved.map_or(committed, |bound| committed.max(bound))
    }

    /// Reserve physical headroom relative to acquisition, not relative to a
    /// recovered future bound. Repeated restart must not add an entire window
    /// to causal lead. A future recovered floor instead receives one physical
    /// millisecond of checked headroom, with the full logical range available.
    pub fn reservation_ceiling(
        self,
        physical: UnixTimeMs,
        headroom: DurationMs,
    ) -> Result<Self, TimeError> {
        let deadline = physical.checked_add(headroom)?;
        let physical_bound =
            u64::try_from(deadline.as_millis()).map_err(|_| TimeError::OutOfRange)?;
        let next_physical = self
            .physical_ms
            .checked_add(1)
            .ok_or(TimeError::OutOfRange)?;
        Self::new(physical_bound.max(next_physical), 0)
    }

    /// Renewal bound anchored to physical acquisition alone. It never
    /// extends past `physical + headroom`, so issuance that carried ahead of
    /// a frozen physical source fails closed at the ceiling instead of
    /// ratcheting causal lead forward on every renewal.
    pub fn renewal_ceiling(physical: UnixTimeMs, headroom: DurationMs) -> Result<Self, TimeError> {
        let deadline = physical.checked_add(headroom)?;
        let bound = u64::try_from(deadline.as_millis()).map_err(|_| TimeError::OutOfRange)?;
        Self::new(bound, 0)
    }

    /// Successor at the next physical millisecond. Issuance under a durable
    /// reservation takes it once the current millisecond's logical range is
    /// exhausted; the reservation ceiling bounds the resulting causal lead.
    pub fn carry(self) -> Result<Self, TimeError> {
        let next = self
            .physical_ms
            .checked_add(1)
            .ok_or(TimeError::OutOfRange)?;
        Self::new(next, 0)
    }

    /// Issue after the previous event, tolerating a physical-clock regression.
    /// Exhaustion requires the caller to carry within a durable reservation,
    /// await physical progress, or fail.
    pub fn issue(self, physical_ms: u64) -> Result<Self, TimeError> {
        if physical_ms > Self::MAX_PHYSICAL_MS {
            return Err(TimeError::OutOfRange);
        }
        if physical_ms > self.physical_ms {
            return Self::new(physical_ms, 0);
        }
        Self::new(
            self.physical_ms,
            self.logical
                .checked_add(1)
                .ok_or(TimeError::LogicalExhausted)?,
        )
    }

    /// Observe admitted causal evidence. Admission and future-skew policy must
    /// run before this transition; receipt alone confers no authority.
    pub fn observe(self, remote: Self, physical_ms: u64) -> Result<Self, TimeError> {
        if physical_ms > Self::MAX_PHYSICAL_MS {
            return Err(TimeError::OutOfRange);
        }
        let physical = physical_ms.max(self.physical_ms).max(remote.physical_ms);
        let logical = match (physical == self.physical_ms, physical == remote.physical_ms) {
            (true, true) => self.logical.max(remote.logical).checked_add(1),
            (true, false) => self.logical.checked_add(1),
            (false, true) => remote.logical.checked_add(1),
            (false, false) => Some(0),
        }
        .ok_or(TimeError::LogicalExhausted)?;
        Self::new(physical, logical)
    }
}
