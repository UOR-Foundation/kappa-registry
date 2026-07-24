use std::path::Path;

use crate::kappa::KappaLabel;
use crate::store::fs::{atomic_write, escape_namespace};
use crate::store::{SchemaRecord, StoreError};

pub fn register(root: &Path, ns: &str, scope: &str, content: &[u8]) -> Result<String, StoreError> {
    let kappa = KappaLabel::sha256(content);

    super::blob::put(root, kappa.as_str(), content)?;

    let schema_dir = root.join("schemas").join(escape_namespace(ns));
    std::fs::create_dir_all(&schema_dir)?;

    let record = serde_json::json!({
        "kappa": kappa.as_str(),
        "scope": scope,
        "content": String::from_utf8_lossy(content),
    });
    let data =
        serde_json::to_vec_pretty(&record).map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    let path = schema_dir.join(format!("{scope}.json"));
    atomic_write(&path, &data)?;

    Ok(kappa.as_str().to_string())
}

pub fn get(root: &Path, ns: &str, scope: &str) -> Result<Option<(String, Vec<u8>)>, StoreError> {
    let path = root
        .join("schemas")
        .join(escape_namespace(ns))
        .join(format!("{scope}.json"));
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read(&path)?;
    let record: serde_json::Value =
        serde_json::from_slice(&data).map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    let kappa = record["kappa"].as_str().unwrap_or("").to_string();
    let content = record["content"].as_str().unwrap_or("").as_bytes().to_vec();
    Ok(Some((kappa, content)))
}

pub fn list(root: &Path, ns: &str) -> Result<Vec<SchemaRecord>, StoreError> {
    let schema_dir = root.join("schemas").join(escape_namespace(ns));
    if !schema_dir.exists() {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    for entry in std::fs::read_dir(&schema_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        let data = std::fs::read(entry.path())?;
        if let Ok(record) = serde_json::from_slice::<serde_json::Value>(&data) {
            records.push(SchemaRecord {
                scope: record["scope"].as_str().unwrap_or("").to_string(),
                kappa: record["kappa"].as_str().unwrap_or("").to_string(),
            });
        }
    }
    Ok(records)
}
