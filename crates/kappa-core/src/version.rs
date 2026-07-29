//! Store format version markers.
//!
//! The store refuses to open a version it does not understand.
//! Upgrading the format version requires a migration path.

use std::path::Path;

use crate::types::StoreError;

/// Current store format version.
///
/// v3: dCBOR canonical encoding, hashbrown store, Merkle epoch roots,
///     EdgeRelation enum, ThresholdSigner/ThresholdCoordinator split.
pub const STORE_FORMAT_VERSION: u32 = 3;

const VERSION_FILE: &str = "format_version";

/// Check or write the format version marker in the store root.
///
/// On first use: writes the current version.
/// On subsequent use: reads and validates the version matches.
/// Returns an error if the stored version is different from current.
pub fn check_or_write_version(store_root: &Path) -> Result<(), StoreError> {
    let path = store_root.join(VERSION_FILE);

    if path.exists() {
        let stored = std::fs::read_to_string(&path)?;
        let stored_version: u32 = stored.trim().parse().map_err(|_| {
            StoreError::Rejected(format!(
                "corrupt format version file: {:?}",
                stored.trim()
            ))
        })?;
        if stored_version != STORE_FORMAT_VERSION {
            return Err(StoreError::Rejected(format!(
                "store format version {} is not supported (current: {})",
                stored_version, STORE_FORMAT_VERSION
            )));
        }
        Ok(())
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, format!("{}\n", STORE_FORMAT_VERSION))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_version_on_first_use() {
        let dir = tempfile::tempdir().unwrap();
        check_or_write_version(dir.path()).unwrap();
        let content = std::fs::read_to_string(dir.path().join(VERSION_FILE)).unwrap();
        assert_eq!(content.trim(), STORE_FORMAT_VERSION.to_string());
    }

    #[test]
    fn accepts_matching_version() {
        let dir = tempfile::tempdir().unwrap();
        check_or_write_version(dir.path()).unwrap();
        check_or_write_version(dir.path()).unwrap();
    }

    #[test]
    fn rejects_mismatched_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VERSION_FILE);
        std::fs::write(&path, "999\n").unwrap();
        assert!(matches!(
            check_or_write_version(dir.path()),
            Err(StoreError::Rejected(_))
        ));
    }

    #[test]
    fn rejects_corrupt_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VERSION_FILE);
        std::fs::write(&path, "not-a-number\n").unwrap();
        assert!(matches!(
            check_or_write_version(dir.path()),
            Err(StoreError::Rejected(_))
        ));
    }
}
