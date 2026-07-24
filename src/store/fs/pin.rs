use std::path::Path;

use crate::kappa::KappaLabel;
use crate::store::fs::{atomic_write, escape_namespace};
use crate::store::StoreError;

pub fn pin(root: &Path, protected: &str, ttl: u64, ctrl: &str) -> Result<String, StoreError> {
    let pin_content = format!("pin:{protected}:{ttl}:{ctrl}");
    let pin_kappa = KappaLabel::sha256(pin_content.as_bytes());

    let pins_dir = root.join("gc").join("pins");
    std::fs::create_dir_all(&pins_dir)?;

    let record = serde_json::json!({
        "pin_kappa": pin_kappa.as_str(),
        "protected": protected,
        "ttl": ttl,
        "controller": ctrl,
    });
    let data =
        serde_json::to_vec_pretty(&record).map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    let path = pins_dir.join(format!("{}.json", escape_namespace(pin_kappa.as_str())));
    atomic_write(&path, &data)?;

    // Store pin blob itself
    super::blob::put(root, pin_kappa.as_str(), pin_content.as_bytes())?;
    super::blob::put_meta(root, pin_kappa.as_str(), "object-type", b"pin")?;

    Ok(pin_kappa.as_str().to_string())
}

pub fn unpin(root: &Path, pin_kappa: &str, release: bool) -> Result<(), StoreError> {
    let path = root
        .join("gc")
        .join("pins")
        .join(format!("{}.json", escape_namespace(pin_kappa)));

    if !path.exists() {
        return Err(StoreError::NotFound);
    }

    let data = std::fs::read(&path)?;
    let record: serde_json::Value =
        serde_json::from_slice(&data).map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    let controller = record["controller"].as_str().unwrap_or("");

    if !controller.is_empty() && !release {
        return Err(StoreError::Conflict("outstanding finalizer".to_string()));
    }

    if !controller.is_empty() && release {
        // Release clears the controller but keeps the pin so a subsequent
        // unpin (without release) can remove it.
        let mut updated = record.clone();
        updated["controller"] = serde_json::json!("");
        let data = serde_json::to_vec_pretty(&updated)
            .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
        atomic_write(&path, &data)?;
        return Ok(());
    }

    std::fs::remove_file(&path)?;
    Ok(())
}

pub fn roots(root: &Path) -> Result<Vec<String>, StoreError> {
    let pins_dir = root.join("gc").join("pins");
    if !pins_dir.exists() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    for entry in std::fs::read_dir(&pins_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        let data = std::fs::read(entry.path())?;
        if let Ok(record) = serde_json::from_slice::<serde_json::Value>(&data) {
            if let Some(protected) = record["protected"].as_str() {
                result.push(protected.to_string());
            }
        }
    }
    Ok(result)
}

pub fn finalizers(root: &Path) -> Result<Vec<(String, String)>, StoreError> {
    let pins_dir = root.join("gc").join("pins");
    if !pins_dir.exists() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    for entry in std::fs::read_dir(&pins_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        let data = std::fs::read(entry.path())?;
        if let Ok(record) = serde_json::from_slice::<serde_json::Value>(&data) {
            let ctrl = record["controller"].as_str().unwrap_or("");
            if !ctrl.is_empty() {
                let protected = record["protected"].as_str().unwrap_or("").to_string();
                result.push((protected, ctrl.to_string()));
            }
        }
    }
    Ok(result)
}
