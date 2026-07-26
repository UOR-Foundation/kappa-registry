use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::store::fs::{atomic_write, safe_name};
use crate::store::{IndexEntry, StoreError, TagEntry, TagListOpts, TagPage};

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn index_path(root: &Path, ns: &str) -> PathBuf {
    root.join("tags").join(safe_name(ns)).join("index.json")
}

fn read_index(path: &Path) -> Result<BTreeMap<String, IndexEntry>, StoreError> {
    match std::fs::read(path) {
        Ok(data) => {
            // Try new format first (IndexEntry with value+mtime)
            if let Ok(idx) = serde_json::from_slice::<BTreeMap<String, IndexEntry>>(&data) {
                return Ok(idx);
            }
            // Fall back to old format (bare string values) for migration
            let old: BTreeMap<String, String> = serde_json::from_slice(&data)?;
            Ok(old
                .into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        IndexEntry {
                            value: v,
                            mtime: 0,
                            version: 0,
                        },
                    )
                })
                .collect())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(e.into()),
    }
}

fn write_index(path: &Path, index: &BTreeMap<String, IndexEntry>) -> Result<(), StoreError> {
    let data =
        serde_json::to_vec_pretty(index).map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    atomic_write(path, &data)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn root_path(root: &Path, ns: &str) -> PathBuf {
    root.join("tags").join(safe_name(ns)).join("root.json")
}

fn compute_root(index: &BTreeMap<String, IndexEntry>) -> Option<String> {
    if index.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    for (name, entry) in index {
        // Root hash is over (name, value) pairs only -- mtime is excluded.
        let leaf = Sha256::digest(format!("{name}={}", entry.value).as_bytes());
        hasher.update(leaf);
    }
    let root_hash = hasher.finalize();
    let mut buf = [0u8; 71];
    buf[..7].copy_from_slice(b"sha256:");
    for (i, &byte) in root_hash.iter().enumerate() {
        buf[7 + 2 * i] = HEX[(byte >> 4) as usize];
        buf[7 + 2 * i + 1] = HEX[(byte & 0x0f) as usize];
    }
    Some(std::str::from_utf8(&buf).unwrap().to_string())
}

fn write_root(
    root: &Path,
    ns: &str,
    index: &BTreeMap<String, IndexEntry>,
) -> Result<(), StoreError> {
    let root_kappa = compute_root(index);
    let count = index.len();
    let data = serde_json::json!({
        "root": root_kappa,
        "count": count,
    });
    let bytes =
        serde_json::to_vec_pretty(&data).map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    atomic_write(&root_path(root, ns), &bytes)
}

pub fn set(root: &Path, ns: &str, name: &str, kappa: &str) -> Result<(), StoreError> {
    let path = index_path(root, ns);
    let mut index = read_index(&path)?;
    let new_version = index.get(name).map(|e| e.version + 1).unwrap_or(1);
    index.insert(
        name.to_string(),
        IndexEntry {
            value: kappa.to_string(),
            mtime: now_millis(),
            version: new_version,
        },
    );
    write_index(&path, &index)?;
    write_root(root, ns, &index)
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
            Some(entry) => {
                if let Some(target) = entry.value.strip_prefix(SYMREF_PREFIX) {
                    current_name = target.to_string();
                } else {
                    return Ok(Some(entry.value.clone()));
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
    Ok(index.get(name).map(|e| e.value.clone()))
}

/// Create a symbolic pointer: store "ref:{target}" as the value for `name`.
pub fn set_symbolic(root: &Path, ns: &str, name: &str, target: &str) -> Result<(), StoreError> {
    let path = index_path(root, ns);
    let mut index = read_index(&path)?;
    let new_version = index.get(name).map(|e| e.version + 1).unwrap_or(1);
    index.insert(
        name.to_string(),
        IndexEntry {
            value: format!("{SYMREF_PREFIX}{target}"),
            mtime: now_millis(),
            version: new_version,
        },
    );
    write_index(&path, &index)?;
    write_root(root, ns, &index)
}

pub fn list(root: &Path, ns: &str, opts: &TagListOpts) -> Result<TagPage, StoreError> {
    let path = index_path(root, ns);
    let index = read_index(&path)?;

    let mut entries: Vec<TagEntry> = index
        .iter()
        .map(|(name, entry)| TagEntry {
            name: name.clone(),
            kappa: entry.value.clone(),
            mtime: Some(entry.mtime),
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
    if index.remove(name).is_some() {
        write_index(&path, &index)?;
        write_root(root, ns, &index)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Per-tag version CAS (D-5).
/// expected_version = 0 means create-if-absent (tag must not exist).
/// expected_version > 0 means the tag's current version must equal it.
pub fn set_if(
    root: &Path,
    ns: &str,
    name: &str,
    kappa: &str,
    expected_version: u64,
) -> Result<bool, StoreError> {
    let path = index_path(root, ns);
    let mut index = read_index(&path)?;
    let current = index.get(name);

    if expected_version == 0 {
        // Create-if-absent: tag must not exist.
        if current.is_some() {
            return Ok(false);
        }
    } else {
        // Per-tag version CAS: current version must match.
        match current {
            Some(entry) if entry.version == expected_version => {}
            _ => return Ok(false),
        }
    }

    let new_version = current.map(|e| e.version + 1).unwrap_or(1);
    index.insert(
        name.to_string(),
        IndexEntry {
            value: kappa.to_string(),
            mtime: now_millis(),
            version: new_version,
        },
    );
    write_index(&path, &index)?;
    write_root(root, ns, &index)?;
    Ok(true)
}

pub fn find_by_kappa(root: &Path, ns: &str, kappa: &str) -> Result<Vec<String>, StoreError> {
    let path = index_path(root, ns);
    let index = read_index(&path)?;
    let names: Vec<String> = index
        .iter()
        .filter(|(_, e)| e.value.as_str() == kappa)
        .map(|(k, _)| k.clone())
        .collect();
    Ok(names)
}

/// Atomically apply a batch of tag updates within a single namespace.
/// All CAS expectations are validated before any writes are applied.
/// If any check fails, no writes are applied and the failing index is returned.
pub fn set_batch(
    root: &Path,
    ns: &str,
    updates: &[crate::store::TagUpdate],
) -> Result<crate::store::BatchResult, StoreError> {
    use crate::store::BatchResult;

    if updates.is_empty() {
        return Ok(BatchResult::AllSucceeded);
    }

    let path = index_path(root, ns);
    let mut index = read_index(&path)?;

    // Phase 1: validate all CAS expectations before any writes (D-5: per-tag version).
    for (i, update) in updates.iter().enumerate() {
        match update.expected_version {
            None => {
                // Unconditional -- no CAS check
            }
            Some(0) if index.contains_key(&update.name) => {
                return Ok(BatchResult::Failed {
                    index: i,
                    reason: "tag already exists".to_string(),
                });
            }
            Some(0) => {}

            Some(expected) => {
                let current = index.get(&update.name);
                match current {
                    Some(entry) if entry.version == expected => {}
                    Some(entry) => {
                        return Ok(BatchResult::Failed {
                            index: i,
                            reason: format!(
                                "version mismatch: expected {}, current is {}",
                                expected, entry.version
                            ),
                        });
                    }
                    None => {
                        return Ok(BatchResult::Failed {
                            index: i,
                            reason: format!(
                                "version mismatch: expected {}, tag does not exist",
                                expected
                            ),
                        });
                    }
                }
            }
        }
    }

    // Phase 2: all validations passed -- apply all updates.
    let ts = now_millis();
    for update in updates {
        let new_version = index.get(&update.name).map(|e| e.version + 1).unwrap_or(1);
        index.insert(
            update.name.clone(),
            IndexEntry {
                value: update.new_kappa.clone(),
                mtime: ts,
                version: new_version,
            },
        );
    }
    write_index(&path, &index)?;
    write_root(root, ns, &index)?;

    Ok(BatchResult::AllSucceeded)
}

/// Compute the exclusive upper bound for a prefix scan.
/// "abc" -> "abd", "az" -> "a{", all-0xFF -> empty (unbounded).
fn prefix_successor(prefix: &str) -> Option<String> {
    let mut bytes = prefix.as_bytes().to_vec();
    while let Some(last) = bytes.last_mut() {
        if *last < 0xFF {
            *last += 1;
            return String::from_utf8(bytes).ok();
        }
        bytes.pop();
    }
    None
}

pub fn list_prefix(root: &Path, ns: &str, prefix: &str) -> Result<Vec<TagEntry>, StoreError> {
    let path = index_path(root, ns);
    let index = read_index(&path)?;
    let iter: Box<dyn Iterator<Item = (&String, &IndexEntry)>> =
        if let Some(end) = prefix_successor(prefix) {
            Box::new(index.range::<String, _>(prefix.to_string()..end))
        } else {
            Box::new(index.range::<String, _>(prefix.to_string()..))
        };
    Ok(iter
        .map(|(name, entry)| TagEntry {
            name: name.clone(),
            kappa: entry.value.clone(),
            mtime: Some(entry.mtime),
        })
        .collect())
}

pub fn delete_prefix(root: &Path, ns: &str, prefix: &str) -> Result<usize, StoreError> {
    let path = index_path(root, ns);
    let mut index = read_index(&path)?;
    let keys: Vec<String> = if let Some(end) = prefix_successor(prefix) {
        index
            .range::<String, _>(prefix.to_string()..end)
            .map(|(k, _)| k.clone())
            .collect()
    } else {
        index
            .range::<String, _>(prefix.to_string()..)
            .map(|(k, _)| k.clone())
            .collect()
    };
    let count = keys.len();
    if count > 0 {
        for key in &keys {
            index.remove(key);
        }
        write_index(&path, &index)?;
        write_root(root, ns, &index)?;
    }
    Ok(count)
}

pub fn namespace_root(root: &Path, ns: &str) -> Result<(Option<String>, usize), StoreError> {
    let rp = root_path(root, ns);
    match std::fs::read(&rp) {
        Ok(data) => {
            let v: serde_json::Value = serde_json::from_slice(&data)
                .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
            let root_val = v["root"].as_str().map(|s| s.to_string());
            let count = v["count"].as_u64().unwrap_or(0) as usize;
            Ok((root_val, count))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((None, 0)),
        Err(e) => Err(e.into()),
    }
}

pub fn namespace_proof(
    root: &Path,
    ns: &str,
    name: &str,
) -> Result<Option<crate::store::NamespaceProof>, StoreError> {
    let path = index_path(root, ns);
    let index = read_index(&path)?;
    let value = match index.get(name) {
        Some(e) => e.value.clone(),
        None => return Ok(None),
    };
    let root_kappa = compute_root(&index).unwrap_or_default();
    let leaves: Vec<(String, String)> = index.into_iter().map(|(k, e)| (k, e.value)).collect();
    Ok(Some(crate::store::NamespaceProof {
        tag: name.to_string(),
        value,
        proof_format: "leaf_list".to_string(),
        leaves,
        root: root_kappa,
    }))
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
        all.extend(index.values().map(|e| e.value.clone()));
    }
    all.sort();
    all.dedup();
    Ok(all)
}
