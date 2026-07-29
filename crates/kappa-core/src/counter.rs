//! MonotonicCounter trait (seam S7): hardware or software counter.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, thiserror::Error)]
pub enum CounterError {
    #[error("counter io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("counter corrupted")]
    Corrupted,
}

pub trait MonotonicCounter: Send + Sync {
    fn increment(&self) -> Result<u64, CounterError>;
    fn current(&self) -> Result<u64, CounterError>;
}

pub struct SoftwareCounter {
    value: AtomicU64,
    persist_path: Option<PathBuf>,
}

impl SoftwareCounter {
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
            std::fs::write(&tmp, format!("{}\n", new_val))?;
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
    fn in_memory_counter() {
        let c = SoftwareCounter::new(None).unwrap();
        assert_eq!(c.current().unwrap(), 0);
        assert_eq!(c.increment().unwrap(), 1);
        assert_eq!(c.increment().unwrap(), 2);
        assert_eq!(c.current().unwrap(), 2);
    }

    #[test]
    fn persisted_counter() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("counter");

        let c1 = SoftwareCounter::new(Some(path.clone())).unwrap();
        c1.increment().unwrap();
        c1.increment().unwrap();
        assert_eq!(c1.current().unwrap(), 2);

        let c2 = SoftwareCounter::new(Some(path)).unwrap();
        assert_eq!(c2.current().unwrap(), 2);
        assert_eq!(c2.increment().unwrap(), 3);
    }
}
