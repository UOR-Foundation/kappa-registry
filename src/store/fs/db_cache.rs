//! Per-namespace redb Database handle cache.
//!
//! Solves the file-lock problem: `Database::create` acquires an exclusive
//! OS file lock. Only one Database instance may exist per file at a time.
//! Previously, `open_db` created a new Database on every call, causing
//! `DatabaseAlreadyOpen` errors under concurrent access and silent
//! fallback to empty results.
//!
//! This module caches Database handles for the process lifetime. Every
//! module that previously called `open_db` calls `get_or_open` instead.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use redb::Database;

use crate::store::StoreError;

/// Thread-safe cache of redb Database handles, keyed by file path.
pub struct DbCache {
    handles: Mutex<HashMap<PathBuf, Arc<Database>>>,
}

impl DbCache {
    pub fn new() -> Self {
        Self {
            handles: Mutex::new(HashMap::new()),
        }
    }

    /// Get or open a Database for the given file path.
    ///
    /// If the file does not exist, it is created (along with parent
    /// directories). The Database handle is cached and reused for
    /// subsequent calls with the same path.
    ///
    /// # Errors
    ///
    /// Returns `StoreError::Io` if the database cannot be opened.
    pub fn get_or_open(&self, path: &Path) -> Result<Arc<Database>, StoreError> {
        let mut handles = self.handles.lock().expect("db cache lock poisoned");
        if let Some(db) = handles.get(path) {
            return Ok(Arc::clone(db));
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let db = Database::create(path)
            .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
        let arc = Arc::new(db);
        handles.insert(path.to_path_buf(), Arc::clone(&arc));
        Ok(arc)
    }

    /// Build the standard path for a namespace-scoped redb file.
    ///
    /// Pattern: `{root}/{subdir}/{safe_name(ns)}.redb`
    pub fn ns_db_path(root: &Path, subdir: &str, ns: &str) -> PathBuf {
        root.join(subdir)
            .join(format!("{}.redb", super::safe_name(ns)))
    }
}

impl Default for DbCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn get_or_open_creates_and_caches() {
        let dir = TempDir::new().unwrap();
        let cache = DbCache::new();
        let path = dir.path().join("test.redb");

        let db1 = cache.get_or_open(&path).unwrap();
        let db2 = cache.get_or_open(&path).unwrap();

        // Same Arc (pointer equality)
        assert!(Arc::ptr_eq(&db1, &db2));
    }

    #[test]
    fn different_paths_different_handles() {
        let dir = TempDir::new().unwrap();
        let cache = DbCache::new();

        let db1 = cache.get_or_open(&dir.path().join("a.redb")).unwrap();
        let db2 = cache.get_or_open(&dir.path().join("b.redb")).unwrap();

        assert!(!Arc::ptr_eq(&db1, &db2));
    }

    #[test]
    fn creates_parent_directories() {
        let dir = TempDir::new().unwrap();
        let cache = DbCache::new();
        let path = dir.path().join("deep").join("nested").join("test.redb");

        cache.get_or_open(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn ns_db_path_format() {
        let root = Path::new("/data");
        let path = DbCache::ns_db_path(root, "edges", "my-namespace");
        assert!(path.to_str().unwrap().contains("edges"));
        assert!(path.to_str().unwrap().ends_with(".redb"));
    }
}
