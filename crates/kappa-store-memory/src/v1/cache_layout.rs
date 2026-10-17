//! The layout of the content cache under the blob root, written by the
//! allocation table and read back by the inventory.
//!
//! - instance file: `{root}/{axis}/{aa}/{bb}/{hex}.{table}-{instance}`,
//!   where `{axis}:{hex}` is the storage identity, `aa` and `bb` its first
//!   two hex pairs, `table` the creating table's nonce as 16 hex digits and
//!   `instance` the instance number in decimal;
//! - preparation file: `{root}/.tmp{table}{random}`.

use std::path::{Path, PathBuf};

use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;

/// Prefix of every preparation file.
const TEMPORARY_PREFIX: &str = ".tmp";

/// What a path under the blob root is, decided from the path alone.
#[derive(Debug, PartialEq, Eq)]
pub enum CacheEntry {
    /// A preparation's private file, of the table with this nonce when the
    /// name carries one.
    Temporary { table: Option<u64> },
    /// The file of `instance` of `storage` created by table `table`.
    Instance {
        storage: Kappa,
        table: u64,
        instance: u64,
    },
    /// A path the layout does not explain.
    Stranger,
}

/// The file of `instance` of `storage` created by table `table`.
pub fn instance_path(
    root: &Path,
    storage: &Kappa,
    table: u64,
    instance: u64,
) -> Result<PathBuf, StoreError> {
    let base = kappa_types::path::blob_path_for(root, storage.format().as_str())?;
    let mut name = base.into_os_string();
    name.push(format!(".{table:016x}-{instance}"));
    Ok(PathBuf::from(name))
}

/// The name prefix of table `table`'s preparation files.
pub fn staging_prefix(table: u64) -> String {
    format!("{TEMPORARY_PREFIX}{table:016x}")
}

/// Classify `path` under `root`.
pub fn classify(root: &Path, path: &Path) -> CacheEntry {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return CacheEntry::Stranger;
    };
    if let Some(rest) = name.strip_prefix(TEMPORARY_PREFIX) {
        let table = rest
            .get(..16)
            .and_then(|nonce| u64::from_str_radix(nonce, 16).ok());
        return CacheEntry::Temporary { table };
    }
    let Ok(relative) = path.strip_prefix(root) else {
        return CacheEntry::Stranger;
    };
    let parts: Vec<&str> = relative.iter().filter_map(|part| part.to_str()).collect();
    let [axis, first, second, file] = parts.as_slice() else {
        return CacheEntry::Stranger;
    };
    let Some((hex, suffix)) = file.split_once('.') else {
        return CacheEntry::Stranger;
    };
    let Some((table, instance)) = suffix.split_once('-') else {
        return CacheEntry::Stranger;
    };
    if hex.get(..2) != Some(*first) || hex.get(2..4) != Some(*second) || table.len() != 16 {
        return CacheEntry::Stranger;
    }
    let (Ok(table), Ok(instance), Ok(storage)) = (
        u64::from_str_radix(table, 16),
        instance.parse::<u64>(),
        Kappa::parse(&format!("{axis}:{hex}")),
    ) else {
        return CacheEntry::Stranger;
    };
    // The parsed path must be exactly the path this layout writes.
    if instance_path(root, &storage, table, instance)
        .ok()
        .as_deref()
        != Some(path)
    {
        return CacheEntry::Stranger;
    }
    CacheEntry::Instance {
        storage,
        table,
        instance,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_types::Axis;

    #[test]
    fn instance_paths_classify_back_to_their_instance() -> Result<(), StoreError> {
        let root = Path::new("/cache");
        let storage = Kappa::compute(Axis::Sha256, b"bytes")?;
        let path = instance_path(root, &storage, 0xfeed, 7)?;
        assert_eq!(
            classify(root, &path),
            CacheEntry::Instance {
                storage,
                table: 0xfeed,
                instance: 7
            }
        );
        Ok(())
    }

    #[test]
    fn preparation_files_carry_their_table() {
        let root = Path::new("/cache");
        let name = format!("{}abc123", staging_prefix(0xbeef));
        assert_eq!(
            classify(root, &root.join(name)),
            CacheEntry::Temporary {
                table: Some(0xbeef)
            }
        );
        assert_eq!(
            classify(root, &root.join(".tmpXYZ")),
            CacheEntry::Temporary { table: None }
        );
    }

    #[test]
    fn unexplained_paths_are_strangers() -> Result<(), StoreError> {
        let root = Path::new("/cache");
        let storage = Kappa::compute(Axis::Sha256, b"bytes")?;
        let path = instance_path(root, &storage, 1, 1)?;
        let name = path
            .file_name()
            .ok_or_else(|| StoreError::Internal(format!("{} has no file name", path.display())))?;
        let moved = root.join("elsewhere").join(name);
        assert_eq!(classify(root, &moved), CacheEntry::Stranger);
        assert_eq!(
            classify(root, &root.join("sha256/zz/zz/zzzz")),
            CacheEntry::Stranger
        );
        Ok(())
    }
}
