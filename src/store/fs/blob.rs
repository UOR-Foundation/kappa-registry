use std::path::{Path, PathBuf};

use crate::store::fs::atomic_write;
use crate::store::StoreError;

fn blob_path(root: &Path, kappa: &str) -> PathBuf {
    let (axis, hex) = kappa.split_once(':').unwrap_or(("unknown", "00"));
    let shard = if hex.len() >= 2 { &hex[..2] } else { "xx" };
    root.join("blobs").join(axis).join(shard).join(kappa)
}

fn meta_path(root: &Path, kappa: &str) -> PathBuf {
    let mut p = blob_path(root, kappa);
    let name = format!("{}.meta", p.file_name().unwrap().to_str().unwrap());
    p.set_file_name(name);
    p
}

pub fn put(root: &Path, kappa: &str, content: &[u8]) -> Result<bool, StoreError> {
    let path = blob_path(root, kappa);
    if path.exists() {
        return Ok(false);
    }
    atomic_write(&path, content)?;
    Ok(true)
}

pub fn get(root: &Path, kappa: &str) -> Result<Option<Vec<u8>>, StoreError> {
    let path = blob_path(root, kappa);
    match std::fs::read(&path) {
        Ok(data) => Ok(Some(data)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn get_range(
    root: &Path,
    kappa: &str,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, StoreError> {
    use std::io::{Read, Seek, SeekFrom};
    let path = blob_path(root, kappa);
    let mut file = std::fs::File::open(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            StoreError::NotFound
        } else {
            StoreError::Io(e)
        }
    })?;
    let file_size = file.metadata().map_err(StoreError::Io)?.len();
    if offset >= file_size {
        return Err(StoreError::RangeNotSatisfiable { size: file_size });
    }
    let actual_length = std::cmp::min(length, file_size - offset) as usize;
    let mut buf = vec![0u8; actual_length];
    file.seek(SeekFrom::Start(offset)).map_err(StoreError::Io)?;
    file.read_exact(&mut buf).map_err(StoreError::Io)?;
    Ok(buf)
}

pub fn size(root: &Path, kappa: &str) -> Result<Option<u64>, StoreError> {
    let path = blob_path(root, kappa);
    match std::fs::metadata(&path) {
        Ok(m) => Ok(Some(m.len())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(StoreError::Io(e)),
    }
}

pub fn reader(root: &Path, kappa: &str) -> Result<Box<dyn std::io::Read + Send>, StoreError> {
    let path = blob_path(root, kappa);
    let file = std::fs::File::open(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            StoreError::NotFound
        } else {
            StoreError::Io(e)
        }
    })?;
    Ok(Box::new(file))
}

pub fn exists(root: &Path, kappa: &str) -> Result<bool, StoreError> {
    Ok(blob_path(root, kappa).exists())
}

pub fn remove(root: &Path, kappa: &str) -> Result<(), StoreError> {
    let p = blob_path(root, kappa);
    let m = meta_path(root, kappa);
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(&m);
    Ok(())
}

pub fn list(root: &Path, prefix: &str) -> Result<Vec<String>, StoreError> {
    let blobs_dir = root.join("blobs");
    if !blobs_dir.exists() {
        return Ok(Vec::new());
    }
    let mut results = Vec::new();
    for axis_entry in std::fs::read_dir(&blobs_dir)? {
        let axis_entry = axis_entry?;
        if !axis_entry.file_type()?.is_dir() {
            continue;
        }
        for shard_entry in std::fs::read_dir(axis_entry.path())? {
            let shard_entry = shard_entry?;
            if !shard_entry.file_type()?.is_dir() {
                continue;
            }
            for blob_entry in std::fs::read_dir(shard_entry.path())? {
                let blob_entry = blob_entry?;
                let name = blob_entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".meta") || name.ends_with(".tmp") {
                    continue;
                }
                if prefix.is_empty() || name.starts_with(prefix) {
                    results.push(name);
                }
            }
        }
    }
    results.sort();
    Ok(results)
}

pub fn put_meta(root: &Path, kappa: &str, key: &str, val: &[u8]) -> Result<(), StoreError> {
    let path = meta_path(root, kappa);
    let mut meta = read_meta(&path);
    meta.insert(
        key.to_string(),
        serde_json::Value::String(String::from_utf8_lossy(val).to_string()),
    );
    let data = serde_json::to_vec_pretty(&serde_json::Value::Object(meta))
        .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    atomic_write(&path, &data)
}

pub fn get_meta(root: &Path, kappa: &str, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
    let path = meta_path(root, kappa);
    let meta = read_meta(&path);
    Ok(meta
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.as_bytes().to_vec()))
}

pub fn list_by_meta(root: &Path, key: &str, value: &str) -> Result<Vec<String>, StoreError> {
    let blobs_dir = root.join("blobs");
    if !blobs_dir.exists() {
        return Ok(Vec::new());
    }
    let mut results = Vec::new();
    for axis_entry in std::fs::read_dir(&blobs_dir)? {
        let axis_entry = axis_entry?;
        if !axis_entry.file_type()?.is_dir() {
            continue;
        }
        for shard_entry in std::fs::read_dir(axis_entry.path())? {
            let shard_entry = shard_entry?;
            if !shard_entry.file_type()?.is_dir() {
                continue;
            }
            for file_entry in std::fs::read_dir(shard_entry.path())? {
                let file_entry = file_entry?;
                let name = file_entry.file_name().to_string_lossy().to_string();
                if !name.ends_with(".meta") {
                    continue;
                }
                let meta = read_meta(&file_entry.path());
                if meta.get(key).and_then(|v| v.as_str()) == Some(value) {
                    let kappa = name.strip_suffix(".meta").unwrap_or(&name).to_string();
                    results.push(kappa);
                }
            }
        }
    }
    results.sort();
    Ok(results)
}

fn read_meta(path: &Path) -> serde_json::Map<String, serde_json::Value> {
    match std::fs::read(path) {
        Ok(data) => serde_json::from_slice(&data).unwrap_or_default(),
        Err(_) => serde_json::Map::new(),
    }
}
