use std::path::{Path, PathBuf};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::store::fs::safe_name;
use crate::store::StoreError;

const META_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("meta_index");

fn db_path(root: &Path, ns: &str) -> PathBuf {
    root.join("index")
        .join("meta")
        .join(format!("{}.redb", safe_name(ns)))
}

fn open_db(root: &Path, ns: &str) -> Result<Database, StoreError> {
    let path = db_path(root, ns);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Database::create(&path).map_err(|e| StoreError::Io(std::io::Error::other(e)))
}

/// Length-prefixed compound key: u16(key.len) + key + u16(value.len) + value + u16(kappa.len) + kappa.
fn compound_key(key: &str, value: &str, kappa: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + key.len() + value.len() + kappa.len());
    out.extend_from_slice(&(key.len() as u16).to_le_bytes());
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(&(kappa.len() as u16).to_le_bytes());
    out.extend_from_slice(kappa.as_bytes());
    out
}

/// Prefix for scanning all entries with a given key and value.
fn key_value_prefix(key: &str, value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + key.len() + value.len());
    out.extend_from_slice(&(key.len() as u16).to_le_bytes());
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
    out
}

/// Prefix for scanning all entries with a given key (any value).
fn key_prefix(key: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + key.len());
    out.extend_from_slice(&(key.len() as u16).to_le_bytes());
    out.extend_from_slice(key.as_bytes());
    out
}

/// Compute exclusive upper bound for prefix range scan.
fn prefix_upper_bound(prefix: &[u8]) -> Vec<u8> {
    let mut bound = prefix.to_vec();
    while let Some(last) = bound.last_mut() {
        if *last < 0xFF {
            *last += 1;
            return bound;
        }
        bound.pop();
    }
    vec![0xFF; prefix.len() + 1]
}

/// Extract kappa (third field) from a length-prefixed compound key.
fn extract_kappa(data: &[u8]) -> Option<&str> {
    let mut pos = 0;
    let len1 = u16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?) as usize;
    pos += 2 + len1;
    let len2 = u16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?) as usize;
    pos += 2 + len2;
    let len3 = u16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?) as usize;
    pos += 2;
    std::str::from_utf8(data.get(pos..pos + len3)?).ok()
}

/// Extract value (second field) from a length-prefixed compound key.
fn extract_value(data: &[u8]) -> Option<&str> {
    let mut pos = 0;
    let len1 = u16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?) as usize;
    pos += 2 + len1;
    let len2 = u16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?) as usize;
    pos += 2;
    std::str::from_utf8(data.get(pos..pos + len2)?).ok()
}

pub fn set(root: &Path, ns: &str, kappa: &str, entries: &[(&str, &str)]) -> Result<(), StoreError> {
    let db = open_db(root, ns)?;
    let write_txn = db
        .begin_write()
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    {
        let mut table = write_txn
            .open_table(META_TABLE)
            .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
        for (key, value) in entries {
            let ck = compound_key(key, value, kappa);
            table
                .insert(ck.as_slice(), &[] as &[u8])
                .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
        }
    }
    write_txn
        .commit()
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    Ok(())
}

pub fn get(root: &Path, ns: &str, kappa: &str, key: &str) -> Result<Option<String>, StoreError> {
    let db = open_db(root, ns)?;
    let read_txn = db
        .begin_read()
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    let table = match read_txn.open_table(META_TABLE) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(StoreError::Io(std::io::Error::other(e))),
    };
    // Scan all entries with this key, find one ending with this kappa
    let pfx = key_prefix(key);
    let upper = prefix_upper_bound(&pfx);
    let range = table
        .range(pfx.as_slice()..upper.as_slice())
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    for entry in range {
        let (k, _) = entry.map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
        let data = k.value();
        if let (Some(found_kappa), Some(found_value)) = (extract_kappa(data), extract_value(data)) {
            if found_kappa == kappa {
                return Ok(Some(found_value.to_string()));
            }
        }
    }
    Ok(None)
}

pub fn query(root: &Path, ns: &str, key: &str, value: &str) -> Result<Vec<String>, StoreError> {
    let db = open_db(root, ns)?;
    let read_txn = db
        .begin_read()
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    let table = match read_txn.open_table(META_TABLE) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(e) => return Err(StoreError::Io(std::io::Error::other(e))),
    };
    let pfx = key_value_prefix(key, value);
    let upper = prefix_upper_bound(&pfx);
    let range = table
        .range(pfx.as_slice()..upper.as_slice())
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    let mut results = Vec::new();
    for entry in range {
        let (k, _) = entry.map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
        if let Some(kappa) = extract_kappa(k.value()) {
            results.push(kappa.to_string());
        }
    }
    results.sort();
    Ok(results)
}

pub fn query_exists(root: &Path, ns: &str, key: &str) -> Result<Vec<String>, StoreError> {
    let db = open_db(root, ns)?;
    let read_txn = db
        .begin_read()
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    let table = match read_txn.open_table(META_TABLE) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(e) => return Err(StoreError::Io(std::io::Error::other(e))),
    };
    let pfx = key_prefix(key);
    let upper = prefix_upper_bound(&pfx);
    let range = table
        .range(pfx.as_slice()..upper.as_slice())
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    let mut results = std::collections::BTreeSet::new();
    for entry in range {
        let (k, _) = entry.map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
        if let Some(kappa) = extract_kappa(k.value()) {
            results.insert(kappa.to_string());
        }
    }
    Ok(results.into_iter().collect())
}

pub fn query_compound(
    root: &Path,
    ns: &str,
    filters: &[(&str, &str)],
) -> Result<Vec<String>, StoreError> {
    if filters.is_empty() {
        return Ok(Vec::new());
    }
    let mut sets: Vec<std::collections::BTreeSet<String>> = Vec::with_capacity(filters.len());
    for (key, value) in filters {
        let results = query(root, ns, key, value)?;
        sets.push(results.into_iter().collect());
    }
    let mut iter = sets.into_iter();
    let mut result = iter.next().unwrap_or_default();
    for set in iter {
        result = result.intersection(&set).cloned().collect();
    }
    Ok(result.into_iter().collect())
}

pub fn query_prefix(
    root: &Path,
    ns: &str,
    key: &str,
    value_prefix: &str,
) -> Result<Vec<String>, StoreError> {
    let db = open_db(root, ns)?;
    let read_txn = db
        .begin_read()
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    let table = match read_txn.open_table(META_TABLE) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(e) => return Err(StoreError::Io(std::io::Error::other(e))),
    };
    // Scan entries where key matches and value starts with value_prefix
    let pfx = key_value_prefix(key, value_prefix);
    let upper = prefix_upper_bound(&pfx);
    let range = table
        .range(pfx.as_slice()..upper.as_slice())
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    let mut results = std::collections::BTreeSet::new();
    for entry in range {
        let (k, _) = entry.map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
        if let Some(kappa) = extract_kappa(k.value()) {
            results.insert(kappa.to_string());
        }
    }
    Ok(results.into_iter().collect())
}

pub fn remove_by_value_prefix(
    root: &Path,
    ns: &str,
    key: &str,
    value_prefix: &str,
) -> Result<usize, StoreError> {
    let db = open_db(root, ns)?;
    let write_txn = db
        .begin_write()
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    let count;
    {
        let mut table = write_txn
            .open_table(META_TABLE)
            .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
        let pfx = key_value_prefix(key, value_prefix);
        let upper = prefix_upper_bound(&pfx);
        let to_remove: Vec<Vec<u8>> = {
            let range = table
                .range(pfx.as_slice()..upper.as_slice())
                .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
            range
                .filter_map(|entry| {
                    let (k, _) = entry.ok()?;
                    Some(k.value().to_vec())
                })
                .collect()
        };
        count = to_remove.len();
        for k in &to_remove {
            table
                .remove(k.as_slice())
                .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
        }
    }
    write_txn
        .commit()
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    Ok(count)
}

pub fn remove(root: &Path, ns: &str, kappa: &str) -> Result<(), StoreError> {
    let db = open_db(root, ns)?;
    let write_txn = db
        .begin_write()
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    {
        let mut table = write_txn
            .open_table(META_TABLE)
            .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
        let to_remove: Vec<Vec<u8>> = {
            let iter = table
                .iter()
                .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
            iter.filter_map(|entry| {
                let (k, _) = entry.ok()?;
                let data = k.value();
                if extract_kappa(data) == Some(kappa) {
                    Some(data.to_vec())
                } else {
                    None
                }
            })
            .collect()
        };
        for key in &to_remove {
            table
                .remove(key.as_slice())
                .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
        }
    }
    write_txn
        .commit()
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn set_and_query_equals() {
        let dir = TempDir::new().unwrap();
        set(
            dir.path(),
            "ns",
            "sha256:abc",
            &[("object-type", "manifest")],
        )
        .unwrap();
        set(dir.path(), "ns", "sha256:def", &[("object-type", "edge")]).unwrap();
        set(
            dir.path(),
            "ns",
            "sha256:ghi",
            &[("object-type", "manifest")],
        )
        .unwrap();
        let results = query(dir.path(), "ns", "object-type", "manifest").unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.contains(&"sha256:abc".to_string()));
        assert!(results.contains(&"sha256:ghi".to_string()));
    }

    #[test]
    fn query_empty_result() {
        let dir = TempDir::new().unwrap();
        let results = query(dir.path(), "ns", "object-type", "nonexistent").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn query_exists_filter() {
        let dir = TempDir::new().unwrap();
        set(
            dir.path(),
            "ns",
            "sha256:abc",
            &[("object-type", "manifest")],
        )
        .unwrap();
        set(
            dir.path(),
            "ns",
            "sha256:def",
            &[("object-type", "edge"), ("format", "parquet")],
        )
        .unwrap();
        let results = query_exists(dir.path(), "ns", "format").unwrap();
        assert_eq!(results.len(), 1);
        assert!(results.contains(&"sha256:def".to_string()));
    }

    #[test]
    fn get_returns_value() {
        let dir = TempDir::new().unwrap();
        set(
            dir.path(),
            "ns",
            "sha256:abc",
            &[("object-type", "manifest"), ("format", "vortex")],
        )
        .unwrap();
        assert_eq!(
            get(dir.path(), "ns", "sha256:abc", "format").unwrap(),
            Some("vortex".to_string())
        );
        assert_eq!(
            get(dir.path(), "ns", "sha256:abc", "missing").unwrap(),
            None
        );
    }

    #[test]
    fn remove_cleans_all_entries() {
        let dir = TempDir::new().unwrap();
        set(
            dir.path(),
            "ns",
            "sha256:abc",
            &[("object-type", "manifest"), ("format", "vortex")],
        )
        .unwrap();
        remove(dir.path(), "ns", "sha256:abc").unwrap();
        assert!(query(dir.path(), "ns", "object-type", "manifest")
            .unwrap()
            .is_empty());
        assert!(query(dir.path(), "ns", "format", "vortex")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn namespace_isolation() {
        let dir = TempDir::new().unwrap();
        set(
            dir.path(),
            "ns-a",
            "sha256:abc",
            &[("object-type", "manifest")],
        )
        .unwrap();
        let results = query(dir.path(), "ns-b", "object-type", "manifest").unwrap();
        assert!(results.is_empty());
    }
}
