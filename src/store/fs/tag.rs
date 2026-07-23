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

/// Maximum depth for symbolic ref resolution (matches Git's SYMREF_MAXDEPTH).
const SYMREF_MAXDEPTH: usize = 10;

/// Symbolic ref prefix. Values starting with this are pointers to other
/// tag names within the same namespace, not kappa-labels.
const SYMREF_PREFIX: &str = "ref:";

/// Resolve a tag value, following symbolic ref chains up to SYMREF_MAXDEPTH.
/// Returns the terminal kappa-label, or None if the chain is broken
/// (target does not exist) or exceeds the depth limit.
pub fn get(root: &Path, ns: &str, name: &str) -> Result<Option<String>, StoreError> {
    let path = index_path(root, ns);
    let index = read_index(&path)?;

    let mut current_name = name.to_string();
    for _ in 0..SYMREF_MAXDEPTH {
        match index.get(&current_name) {
            None => return Ok(None),
            Some(value) => {
                if let Some(target) = value.strip_prefix(SYMREF_PREFIX) {
                    current_name = target.to_string();
                } else {
                    return Ok(Some(value.clone()));
                }
            }
        }
    }
    // Exceeded depth limit -- treat as unresolvable
    Ok(None)
}

/// Return the raw tag value without following symbolic refs.
pub fn get_raw(root: &Path, ns: &str, name: &str) -> Result<Option<String>, StoreError> {
    let path = index_path(root, ns);
    let index = read_index(&path)?;
    Ok(index.get(name).cloned())
}

/// Create a symbolic pointer: store "ref:{target}" as the value for `name`.
pub fn set_symbolic(root: &Path, ns: &str, name: &str, target: &str) -> Result<(), StoreError> {
    let path = index_path(root, ns);
    let mut index = read_index(&path)?;
    index.insert(name.to_string(), format!("{SYMREF_PREFIX}{target}"));
    write_index(&path, &index)
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

/// Atomically apply a batch of tag updates across one or more namespaces.
/// All CAS expectations are validated before any writes are applied.
/// If any check fails, no writes are applied and the failing index is returned.
pub fn set_batch(
    root: &Path,
    updates: &[crate::store::TagUpdate],
) -> Result<crate::store::BatchResult, StoreError> {
    use crate::store::BatchResult;

    if updates.is_empty() {
        return Ok(BatchResult::AllSucceeded);
    }

    // Group updates by namespace, preserving original index for error reporting.
    // Use BTreeMap so namespace iteration order is deterministic (deadlock prevention).
    let mut by_ns: std::collections::BTreeMap<String, Vec<(usize, &crate::store::TagUpdate)>> =
        std::collections::BTreeMap::new();
    for (i, u) in updates.iter().enumerate() {
        by_ns.entry(u.ns.clone()).or_default().push((i, u));
    }

    // Phase 1: read all indexes and validate all CAS expectations.
    let mut indexes: std::collections::BTreeMap<String, BTreeMap<String, String>> =
        std::collections::BTreeMap::new();
    for (ns, group) in &by_ns {
        let path = index_path(root, ns);
        let index = read_index(&path)?;

        for &(orig_idx, update) in group {
            match &update.expected {
                Some(exp) if exp.is_empty() => {
                    // Unconditional -- no CAS check
                }
                Some(exp) => {
                    // Must match current value
                    let current = index.get(&update.name);
                    if current.map(|s| s.as_str()) != Some(exp.as_str()) {
                        let reason = match current {
                            Some(cur) => format!("expected {}, current is {}", exp, cur),
                            None => format!("expected {}, tag does not exist", exp),
                        };
                        return Ok(BatchResult::Failed {
                            index: orig_idx,
                            reason,
                        });
                    }
                }
                None => {
                    // Create-if-absent -- tag must not exist
                    if index.contains_key(&update.name) {
                        return Ok(BatchResult::Failed {
                            index: orig_idx,
                            reason: "tag already exists".to_string(),
                        });
                    }
                }
            }
        }

        indexes.insert(ns.clone(), index);
    }

    // Phase 2: all validations passed -- apply all updates and write indexes.
    for (ns, group) in &by_ns {
        let index = indexes.get_mut(ns).unwrap();
        for &(_, update) in group {
            index.insert(update.name.clone(), update.new_kappa.clone());
        }
        let path = index_path(root, ns);
        write_index(&path, index)?;
    }

    Ok(BatchResult::AllSucceeded)
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
