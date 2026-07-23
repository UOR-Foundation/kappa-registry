use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::store::fs::{atomic_write, escape_namespace};
use crate::store::{StoreError, TagEntry, TagListOpts, TagPage};

fn index_path(root: &Path, ns: &str) -> PathBuf {
    root.join("tags")
        .join(escape_namespace(ns))
        .join("index.json")
}

fn read_index(path: &Path) -> Result<BTreeMap<String, String>, StoreError> {
    match std::fs::read(path) {
        Ok(data) => Ok(serde_json::from_slice(&data)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(e.into()),
    }
}

fn write_index(path: &Path, index: &BTreeMap<String, String>) -> Result<(), StoreError> {
    let data =
        serde_json::to_vec_pretty(index).map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    atomic_write(path, &data)
}

pub fn set(root: &Path, ns: &str, name: &str, kappa: &str) -> Result<(), StoreError> {
    let path = index_path(root, ns);
    let mut index = read_index(&path)?;
    index.insert(name.to_string(), kappa.to_string());
    write_index(&path, &index)
}

pub fn get(root: &Path, ns: &str, name: &str) -> Result<Option<String>, StoreError> {
    let path = index_path(root, ns);
    let index = read_index(&path)?;
    Ok(index.get(name).cloned())
}

pub fn list(root: &Path, ns: &str, opts: &TagListOpts) -> Result<TagPage, StoreError> {
    let path = index_path(root, ns);
    let index = read_index(&path)?;

    let mut entries: Vec<TagEntry> = index
        .iter()
        .map(|(name, kappa)| TagEntry {
            name: name.clone(),
            kappa: kappa.clone(),
        })
        .collect();

    if opts.order.as_deref() == Some("desc") {
        entries.reverse();
    }

    if let Some(ref after) = opts.after {
        entries.retain(|e| e.name.as_str() > after.as_str());
    }
    if let Some(ref before) = opts.before {
        entries.retain(|e| e.name.as_str() < before.as_str());
    }

    if let Some(ref last) = opts.last {
        if opts.order.as_deref() == Some("desc") {
            entries.retain(|e| e.name.as_str() < last.as_str());
        } else {
            entries.retain(|e| e.name.as_str() > last.as_str());
        }
    }

    let n = opts.n.unwrap_or(100);
    if n == 0 {
        return Ok(TagPage {
            tags: Vec::new(),
            has_more: false,
        });
    }

    let has_more = entries.len() > n;
    entries.truncate(n);

    Ok(TagPage {
        tags: entries,
        has_more,
    })
}

pub fn delete(root: &Path, ns: &str, name: &str) -> Result<bool, StoreError> {
    let path = index_path(root, ns);
    let mut index = read_index(&path)?;
    let removed = index.remove(name).is_some();
    if removed {
        write_index(&path, &index)?;
    }
    Ok(removed)
}

pub fn set_if(
    root: &Path,
    ns: &str,
    name: &str,
    kappa: &str,
    expected: Option<&str>,
) -> Result<bool, StoreError> {
    let path = index_path(root, ns);
    let mut index = read_index(&path)?;
    let current = index.get(name).cloned();

    match expected {
        Some(exp) => {
            if current.as_deref() != Some(exp) {
                return Ok(false);
            }
        }
        None => {
            if current.is_some() {
                return Ok(false);
            }
        }
    }

    index.insert(name.to_string(), kappa.to_string());
    write_index(&path, &index)?;
    Ok(true)
}

pub fn find_by_kappa(root: &Path, ns: &str, kappa: &str) -> Result<Vec<String>, StoreError> {
    let path = index_path(root, ns);
    let index = read_index(&path)?;
    let names: Vec<String> = index
        .iter()
        .filter(|(_, v)| v.as_str() == kappa)
        .map(|(k, _)| k.clone())
        .collect();
    Ok(names)
}

pub fn all_kappas_global(root: &Path) -> Result<Vec<String>, StoreError> {
    let tags_dir = root.join("tags");
    if !tags_dir.exists() {
        return Ok(Vec::new());
    }
    let mut all = Vec::new();
    for ns_entry in std::fs::read_dir(&tags_dir)? {
        let ns_entry = ns_entry?;
        if !ns_entry.file_type()?.is_dir() {
            continue;
        }
        let idx = ns_entry.path().join("index.json");
        if !idx.exists() {
            continue;
        }
        let index = read_index(&idx)?;
        all.extend(index.values().cloned());
    }
    all.sort();
    all.dedup();
    Ok(all)
}
