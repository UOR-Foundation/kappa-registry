use std::path::{Path, PathBuf};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::store::fs::safe_name;
use crate::store::StoreError;

const SEQ_TABLE: TableDefinition<&str, u64> = TableDefinition::new("sequences");

fn db_path(root: &Path, ns: &str) -> PathBuf {
    root.join("sequences")
        .join(format!("{}.redb", safe_name(ns)))
}

fn open_db(root: &Path, ns: &str) -> Result<Database, StoreError> {
    let path = db_path(root, ns);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Database::create(&path).map_err(|e| StoreError::Io(std::io::Error::other(e)))
}

pub fn next(root: &Path, ns: &str, name: &str) -> Result<u64, StoreError> {
    let db = open_db(root, ns)?;
    let write_txn = db
        .begin_write()
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    let new_val;
    {
        let mut table = write_txn
            .open_table(SEQ_TABLE)
            .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
        let current = table
            .get(name)
            .map_err(|e| StoreError::Io(std::io::Error::other(e)))?
            .map(|v| v.value())
            .unwrap_or(0);
        new_val = current + 1;
        table
            .insert(name, new_val)
            .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    }
    write_txn
        .commit()
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    Ok(new_val)
}

pub fn current(root: &Path, ns: &str, name: &str) -> Result<u64, StoreError> {
    let db = open_db(root, ns)?;
    let read_txn = db
        .begin_read()
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    let table = match read_txn.open_table(SEQ_TABLE) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
        Err(e) => return Err(StoreError::Io(std::io::Error::other(e))),
    };
    let val = table
        .get(name)
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?
        .map(|v| v.value())
        .unwrap_or(0);
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn sequence_starts_at_zero() {
        let dir = TempDir::new().unwrap();
        assert_eq!(current(dir.path(), "test-ns", "counter").unwrap(), 0);
    }

    #[test]
    fn sequence_next_increments() {
        let dir = TempDir::new().unwrap();
        assert_eq!(next(dir.path(), "test-ns", "counter").unwrap(), 1);
        assert_eq!(next(dir.path(), "test-ns", "counter").unwrap(), 2);
        assert_eq!(next(dir.path(), "test-ns", "counter").unwrap(), 3);
        assert_eq!(current(dir.path(), "test-ns", "counter").unwrap(), 3);
    }

    #[test]
    fn sequence_namespace_isolation() {
        let dir = TempDir::new().unwrap();
        assert_eq!(next(dir.path(), "ns-a", "counter").unwrap(), 1);
        assert_eq!(next(dir.path(), "ns-a", "counter").unwrap(), 2);
        assert_eq!(current(dir.path(), "ns-b", "counter").unwrap(), 0);
        assert_eq!(next(dir.path(), "ns-b", "counter").unwrap(), 1);
    }

    #[test]
    fn sequence_multiple_names() {
        let dir = TempDir::new().unwrap();
        assert_eq!(next(dir.path(), "ns", "alpha").unwrap(), 1);
        assert_eq!(next(dir.path(), "ns", "beta").unwrap(), 1);
        assert_eq!(next(dir.path(), "ns", "alpha").unwrap(), 2);
        assert_eq!(current(dir.path(), "ns", "beta").unwrap(), 1);
    }
}
