//! The session dataset: one JSONL record per measurement identifier.
//!
//! Records measured now replace their previous lines and every other line
//! is kept, so a partial or filtered run never erases what it did not
//! measure. The merged file is written beside the old one, synced, and
//! renamed over it, so a crash leaves either dataset whole. A run that
//! measured nothing leaves the file untouched.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use super::record::CalibrationPoint;
use super::session::SessionError;

/// Append one record to the dataset at `path`.
///
/// Creates the file if it does not exist. The record is written as a
/// single JSONL line, flushed and synced: a crash after this call
/// preserves the line. The full merge at finalize overwrites it with
/// the analyzed record.
pub fn append(path: &Path, point: &CalibrationPoint) -> Result<(), SessionError> {
    use std::io::Write as _;
    let io = |source| SessionError::Io {
        path: path.to_owned(),
        source,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(io)?;
    writeln!(file, "{}", point.to_jsonl()?).map_err(io)?;
    file.sync_all().map_err(io)?;
    Ok(())
}

/// Merge `measured` (canonical id to record) into the dataset at `path`.
/// Returns the path written, or `None` when nothing was measured.
pub fn merge(
    path: &Path,
    measured: &BTreeMap<&str, &CalibrationPoint>,
) -> Result<Option<PathBuf>, SessionError> {
    if measured.is_empty() {
        return Ok(None);
    }
    let io = |source| SessionError::Io {
        path: path.to_owned(),
        source,
    };
    let mut lines: BTreeMap<String, String> = BTreeMap::new();
    match std::fs::read_to_string(path) {
        Ok(content) => {
            for (index, line) in content
                .lines()
                .enumerate()
                .filter(|(_, l)| !l.trim().is_empty())
            {
                let point: CalibrationPoint =
                    serde_json::from_str(line).map_err(|source| SessionError::Dataset {
                        path: path.to_owned(),
                        line: index + 1,
                        source,
                    })?;
                if !measured.contains_key(point.id.as_str()) {
                    lines.insert(point.id, line.to_owned());
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => return Err(io(source)),
    }
    for (id, point) in measured {
        lines.insert((*id).to_owned(), point.to_jsonl()?);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    let tmp = path.with_extension("jsonl.tmp");
    let mut file = std::fs::File::create(&tmp).map_err(io)?;
    for line in lines.values() {
        writeln!(file, "{line}").map_err(io)?;
    }
    file.sync_all().map_err(io)?;
    std::fs::rename(&tmp, path).map_err(io)?;
    Ok(Some(path.to_owned()))
}
