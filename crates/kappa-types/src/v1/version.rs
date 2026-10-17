//! Store format version markers.
//!
//! The store refuses to open a version it does not understand.
//! Upgrading the format version requires a migration path.

use std::path::Path;

use crate::error::StoreError;

/// Current store format version.
///
/// Increment when any on-disk format changes in a way that prevents
/// older code from reading the store correctly.
///
/// v5: `VerifiedContent` newtype, `SigV4` verifier, compression-transparent
///     blob storage, identity binding/succession, framed AEAD encryption,
///     mandatory multi-axis hashing, streaming upload verification proofs.
/// v6: Sub-trait store architecture, UUID-based namespaces, protocol-scoped
///     aliases, `NAMESPACE_NAMES` secondary index, `NAMESPACE_CONFIG` table,
///     `ALIAS_HISTORY` audit trail, Argon2id password hashing, bounded JTI
///     replay set, CSPRNG session tokens, NTP-Lamport hybrid clock.
pub const STORE_FORMAT_VERSION: u32 = 6;

const VERSION_FILE: &str = "format_version";

/// Check or write the format version marker in the store root.
///
/// On first use: writes the current version.
/// On subsequent use: reads and validates the version matches.
///
/// # Errors
///
/// Returns `StoreError::Rejected` if the stored version differs from
/// `STORE_FORMAT_VERSION` or if the version file is corrupt.
pub fn check_or_write_version(store_root: &Path) -> Result<(), StoreError> {
    let path = store_root.join(VERSION_FILE);

    if path.exists() {
        let stored = std::fs::read_to_string(&path)?;
        let stored_version: u32 = stored.trim().parse().map_err(|_| {
            StoreError::Rejected(format!("corrupt format version file: {:?}", stored.trim()))
        })?;
        if stored_version != STORE_FORMAT_VERSION {
            return Err(StoreError::Rejected(format!(
                "store format version {stored_version} is not supported (current: {STORE_FORMAT_VERSION})"
            )));
        }
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, format!("{STORE_FORMAT_VERSION}\n"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_version_on_first_use() -> Result<(), StoreError> {
        let dir = tempfile::tempdir()?;
        check_or_write_version(dir.path())?;
        let content = std::fs::read_to_string(dir.path().join(VERSION_FILE))?;
        assert_eq!(content.trim(), STORE_FORMAT_VERSION.to_string());
        Ok(())
    }

    #[test]
    fn accepts_matching_version() -> Result<(), StoreError> {
        let dir = tempfile::tempdir()?;
        check_or_write_version(dir.path())?;
        check_or_write_version(dir.path())?;
        Ok(())
    }

    #[test]
    fn rejects_mismatched_version() -> Result<(), StoreError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(VERSION_FILE);
        std::fs::write(&path, "999\n")?;
        assert!(matches!(
            check_or_write_version(dir.path()),
            Err(StoreError::Rejected(_))
        ));
        Ok(())
    }

    #[test]
    fn rejects_corrupt_version() -> Result<(), StoreError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(VERSION_FILE);
        std::fs::write(&path, "not-a-number\n")?;
        assert!(matches!(
            check_or_write_version(dir.path()),
            Err(StoreError::Rejected(_))
        ));
        Ok(())
    }

    #[test]
    fn creates_parent_directories() -> Result<(), StoreError> {
        let dir = tempfile::tempdir()?;
        let nested = dir.path().join("deep").join("nested").join("store");
        check_or_write_version(&nested)?;
        assert!(nested.join(VERSION_FILE).exists());
        Ok(())
    }
}
