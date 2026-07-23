use std::path::Path;

use crate::kappa::KappaLabel;
use crate::store::fs::{atomic_write, escape_namespace};
use crate::store::{FilterRecord, StoreError};

pub fn register(root: &Path, ns: &str, scope: &str, content: &[u8]) -> Result<String, StoreError> {
    let kappa = KappaLabel::sha256(content);

    super::blob::put(root, kappa.as_str(), content)?;

    let filter_dir = root.join("filters").join(escape_namespace(ns));
    std::fs::create_dir_all(&filter_dir)?;

    let record = serde_json::json!({
        "kappa": kappa.as_str(),
        "scope": scope,
        "rule": String::from_utf8_lossy(content),
    });
    let data =
        serde_json::to_vec_pretty(&record).map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    let path = filter_dir.join(format!("{scope}.json"));
    atomic_write(&path, &data)?;

    Ok(kappa.as_str().to_string())
}

pub fn list(root: &Path, ns: &str) -> Result<Vec<FilterRecord>, StoreError> {
    let filter_dir = root.join("filters").join(escape_namespace(ns));
    if !filter_dir.exists() {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    for entry in std::fs::read_dir(&filter_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        let data = std::fs::read(entry.path())?;
        if let Ok(record) = serde_json::from_slice::<serde_json::Value>(&data) {
            records.push(FilterRecord {
                scope: record["scope"].as_str().unwrap_or("").to_string(),
                kappa: record["kappa"].as_str().unwrap_or("").to_string(),
            });
        }
    }
    Ok(records)
}

pub fn remove(root: &Path, filter_kappa: &str) -> Result<bool, StoreError> {
    let filter_base = root.join("filters");
    if !filter_base.exists() {
        return Ok(false);
    }
    let mut found = false;
    for ns_entry in std::fs::read_dir(&filter_base)? {
        let ns_entry = ns_entry?;
        if !ns_entry.file_type()?.is_dir() {
            continue;
        }
        let ns_dir = ns_entry.path();
        let mut to_remove = Vec::new();
        for file_entry in std::fs::read_dir(&ns_dir)? {
            let file_entry = file_entry?;
            let name = file_entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".json") {
                continue;
            }
            let data = std::fs::read(file_entry.path())?;
            if let Ok(record) = serde_json::from_slice::<serde_json::Value>(&data) {
                if record["kappa"].as_str() == Some(filter_kappa) {
                    to_remove.push(file_entry.path());
                    found = true;
                }
            }
        }
        for path in to_remove {
            let _ = std::fs::remove_file(&path);
        }
    }
    Ok(found)
}

pub fn evaluate(root: &Path, ns: &str, content: &[u8]) -> Result<(), String> {
    let filter_dir = root.join("filters").join(escape_namespace(ns));
    if !filter_dir.exists() {
        return Ok(());
    }
    let entries = std::fs::read_dir(&filter_dir).map_err(|e| e.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        let data = std::fs::read(entry.path()).map_err(|e| e.to_string())?;
        let record: serde_json::Value = serde_json::from_slice(&data).map_err(|e| e.to_string())?;
        let rule = record["rule"].as_str().unwrap_or("");
        let kappa = record["kappa"].as_str().unwrap_or("");

        // deny:<bytes> rule: reject if content contains the bytes
        if let Some(needle) = rule.strip_prefix("deny:") {
            if !needle.is_empty() && contains_bytes(content, needle.as_bytes()) {
                return Err(format!("filter {kappa} rejected content"));
            }
        }

        // json-match rule: the stored filter content is JSON with accept_if.contains
        if rule.contains("json-match") || rule.contains("accept_if") {
            if let Ok(filter_json) = serde_json::from_str::<serde_json::Value>(rule) {
                if let Some(needle) = filter_json
                    .get("accept_if")
                    .and_then(|a| a.get("contains"))
                    .and_then(|c| c.as_str())
                {
                    let content_str = String::from_utf8_lossy(content);
                    if !content_str.contains(needle) {
                        let reason = filter_json
                            .get("reason")
                            .and_then(|r| r.as_str())
                            .unwrap_or("filter rejected");
                        return Err(format!("filter {kappa}: {reason}"));
                    }
                }
            }
        }
    }
    Ok(())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}
