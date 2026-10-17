//! Calibration datasets: `calibration_<session>.jsonl` in the dataset
//! directory, one `CalibrationPoint` per line, as `dataset::merge` writes
//! them.

use std::path::{Path, PathBuf};

use super::{ReportError, io_error};
use crate::calibrate::record::CalibrationPoint;

const PREFIX: &str = "calibration_";
const SUFFIX: &str = ".jsonl";

/// One session's dataset.
#[derive(Debug)]
pub struct Dataset {
    /// Session name (`floors`, `workloads`, `contention`, ...).
    pub name: String,
    pub path: PathBuf,
    pub points: Vec<CalibrationPoint>,
}

impl Dataset {
    pub fn measured(&self) -> impl Iterator<Item = &CalibrationPoint> {
        self.points.iter().filter(|point| point.value.is_some())
    }

    pub fn untrusted(&self) -> impl Iterator<Item = &CalibrationPoint> {
        self.points.iter().filter(|point| !point.trusted)
    }
}

/// Session name of a dataset file name, or `None` for any other file
/// (including the `.jsonl.tmp` a merge in progress writes).
fn session_name(file_name: &str) -> Option<&str> {
    file_name
        .strip_prefix(PREFIX)?
        .strip_suffix(SUFFIX)
        .filter(|name| {
            !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
}

/// Every dataset in `dataset_dir`, ordered by session name. A missing
/// directory holds no datasets; a malformed line is an error, never skipped.
pub fn load_all(dataset_dir: &Path) -> Result<Vec<Dataset>, ReportError> {
    let entries = match std::fs::read_dir(dataset_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(ReportError::Io {
                path: dataset_dir.to_owned(),
                source,
            });
        }
    };
    let mut datasets = Vec::new();
    for entry in entries {
        let entry = entry.map_err(io_error(dataset_dir))?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str().and_then(session_name) else {
            continue;
        };
        datasets.push(load(name, &entry.path())?);
    }
    datasets.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(datasets)
}

fn load(name: &str, path: &Path) -> Result<Dataset, ReportError> {
    let content = std::fs::read_to_string(path).map_err(io_error(path))?;
    let mut points = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        points.push(
            serde_json::from_str(line).map_err(|source| ReportError::Json {
                path: path.to_owned(),
                line: index + 1,
                source,
            })?,
        );
    }
    points.sort_by(|a: &CalibrationPoint, b| a.id.cmp(&b.id));
    Ok(Dataset {
        name: name.to_owned(),
        path: path.to_owned(),
        points,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calibrate::grammar::OscId;
    use crate::calibrate::platform::PlatformInfo;
    use crate::calibrate::profile::Profile;
    use crate::calibrate::record::Source;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn only_session_datasets_are_read() {
        assert_eq!(session_name("calibration_floors.jsonl"), Some("floors"));
        assert_eq!(session_name("calibration_floors.jsonl.tmp"), None);
        assert_eq!(session_name("calibration_.jsonl"), None);
        assert_eq!(session_name("calibration_Floors.jsonl"), None);
        assert_eq!(session_name(".calibration_floors.started"), None);
    }

    #[test]
    fn datasets_load_in_session_order_and_corruption_is_an_error() -> TestResult {
        let dir = tempfile::tempdir()?;
        assert!(load_all(&dir.path().join("absent"))?.is_empty());
        let id: OscId = "osc:lat/device.fsync?size=4k".parse()?;
        let mut point = CalibrationPoint::pending(
            &id,
            Profile::L6Graded,
            Source::Direct,
            None,
            PlatformInfo::detect(),
        );
        point.value = Some(2.0e6);
        let line = point.to_jsonl()?;
        std::fs::write(
            dir.path().join("calibration_workloads.jsonl"),
            format!("{line}\n"),
        )?;
        std::fs::write(
            dir.path().join("calibration_floors.jsonl"),
            format!("{line}\n\n"),
        )?;
        std::fs::write(dir.path().join("calibration_floors.jsonl.tmp"), "{")?;
        let datasets = load_all(dir.path())?;
        let names: Vec<_> = datasets.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["floors", "workloads"]);
        assert_eq!(datasets[0].measured().count(), 1);

        std::fs::write(
            dir.path().join("calibration_contention.jsonl"),
            "{not json\n",
        )?;
        assert!(matches!(
            load_all(dir.path()),
            Err(ReportError::Json { line: 1, .. })
        ));
        Ok(())
    }
}
