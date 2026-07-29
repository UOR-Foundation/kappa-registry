//! Clock trait (seam S1) and implementations.

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
