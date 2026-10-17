//! Monotonic counter with optional filesystem persistence.
//!
//! Used for hardware or software-backed monotonic counters that
//! survive process restarts. The counter value only increases.
//! Persistence uses atomic rename for crash safety.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// Errors from counter operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CounterError {
    #[error("counter io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("counter file corrupted: not a valid u64")]
    Corrupted,
}

/// A counter that only increments. Thread-safe. Optionally persisted.
pub trait MonotonicCounter: Send + Sync {
    /// Increment by 1 and return the new value.
    fn increment(&self) -> Result<u64, CounterError>;
    /// Read the current value without incrementing.
    fn current(&self) -> Result<u64, CounterError>;
}

/// Atomic software counter with optional file persistence.
///
/// On construction, loads the persisted value if the file exists.
/// On each increment, writes the new value atomically (tmp + rename).
/// Without a persist path, the counter is in-memory only and resets
/// to 0 on restart.
pub struct SoftwareCounter {
    value: AtomicU64,
    persist_path: Option<PathBuf>,
}

impl SoftwareCounter {
    /// Create a counter, optionally loading the initial value from disk.
    ///
    /// # Errors
    ///
    /// Returns `CounterError::Io` if the persist path exists but cannot be read.
    /// Returns `CounterError::Corrupted` if the file contents are not a valid u64.
    pub fn new(persist_path: Option<PathBuf>) -> Result<Self, CounterError> {
        let initial = match &persist_path {
            Some(path) if path.exists() => {
                let data = std::fs::read_to_string(path)?;
                data.trim()
                    .parse::<u64>()
                    .map_err(|_| CounterError::Corrupted)?
            }
            _ => 0,
        };
        Ok(Self {
            value: AtomicU64::new(initial),
            persist_path,
        })
    }
}

impl MonotonicCounter for SoftwareCounter {
    fn increment(&self) -> Result<u64, CounterError> {
        let new_val = self.value.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(path) = &self.persist_path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, format!("{new_val}\n"))?;
            std::fs::rename(&tmp, path)?;
        }
        Ok(new_val)
    }

    fn current(&self) -> Result<u64, CounterError> {
        Ok(self.value.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_counter_starts_at_zero() -> Result<(), CounterError> {
        let c = SoftwareCounter::new(None)?;
        assert_eq!(c.current()?, 0);
        Ok(())
    }

    #[test]
    fn in_memory_counter_increments() -> Result<(), CounterError> {
        let c = SoftwareCounter::new(None)?;
        assert_eq!(c.increment()?, 1);
        assert_eq!(c.increment()?, 2);
        assert_eq!(c.current()?, 2);
        Ok(())
    }

    #[test]
    fn persisted_counter_survives_reopen() -> Result<(), CounterError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("counter");

        let c1 = SoftwareCounter::new(Some(path.clone()))?;
        c1.increment()?;
        c1.increment()?;
        assert_eq!(c1.current()?, 2);

        let c2 = SoftwareCounter::new(Some(path))?;
        assert_eq!(c2.current()?, 2);
        assert_eq!(c2.increment()?, 3);
        Ok(())
    }

    #[test]
    fn corrupted_file_returns_error() -> Result<(), CounterError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("counter");
        std::fs::write(&path, "not_a_number\n")?;
        assert!(matches!(
            SoftwareCounter::new(Some(path)),
            Err(CounterError::Corrupted)
        ));
        Ok(())
    }

    #[test]
    fn nonexistent_path_starts_at_zero() -> Result<(), CounterError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("does_not_exist");
        let c = SoftwareCounter::new(Some(path))?;
        assert_eq!(c.current()?, 0);
        Ok(())
    }
}
