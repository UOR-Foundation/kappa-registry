//! NTP-Lamport hybrid clock.
//!
//! Combines wall-clock time (milliseconds since epoch) with a Lamport
//! counter to ensure monotonicity even when the system clock steps
//! backward. The physical component comes from the system clock.
//! The logical component increments when the physical component has
//! not advanced since the last call.

use std::sync::Mutex;

use super::Clock;

pub struct NtpLamportClock {
    state: Mutex<ClockState>,
}

struct ClockState {
    last_physical_ms: u64,
    logical: u32,
}

impl NtpLamportClock {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(ClockState {
                last_physical_ms: 0,
                logical: 0,
            }),
        }
    }

    fn system_time_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_millis() as u64
    }
}

impl Default for NtpLamportClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for NtpLamportClock {
    fn now_ms(&self) -> u64 {
        let mut state = self.state.lock().expect("clock lock poisoned");
        let physical = Self::system_time_ms();

        if physical > state.last_physical_ms {
            state.last_physical_ms = physical;
            state.logical = 0;
        } else {
            state.logical += 1;
        }

        // Encode: upper 48 bits = physical ms, lower 16 bits = logical counter.
        // This gives ~8900 years of physical range and 65535 logical ticks
        // per millisecond before overflow.
        (state.last_physical_ms << 16) | (state.logical as u64 & 0xFFFF)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic() {
        let clock = NtpLamportClock::new();
        let t1 = clock.now_ms();
        let t2 = clock.now_ms();
        let t3 = clock.now_ms();
        assert!(t2 >= t1);
        assert!(t3 >= t2);
    }

    #[test]
    fn rapid_calls_still_monotonic() {
        let clock = NtpLamportClock::new();
        let mut prev = 0;
        for _ in 0..1000 {
            let t = clock.now_ms();
            assert!(t > prev, "clock went backward: {} <= {}", t, prev);
            prev = t;
        }
    }

    #[test]
    fn nonzero() {
        let clock = NtpLamportClock::new();
        assert!(clock.now_ms() > 0);
    }
}
