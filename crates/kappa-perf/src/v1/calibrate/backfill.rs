//! Reading criterion's results back into calibration records.
//!
//! Criterion 0.8 writes, per benchmark, `<dir>/new/benchmark.json` (the
//! serialized `BenchmarkId`: group, function, value, throughput and the
//! directory it chose, including `_2`-style suffixes added for uniqueness),
//! `estimates.json`, `sample.json`, `tukey.json`, and on comparison
//! `<dir>/change/estimates.json`. The directory is located through the
//! identity criterion itself recorded, never by re-deriving its file-name
//! sanitization. Results are accepted only when written during the current
//! session: a benchmark filtered out of this run still has last run's files
//! on disk, and reading them would report stale numbers as current.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::quantity::Work;
use super::record::{CriterionEstimates, HarnessCoords};

#[derive(Debug, thiserror::Error)]
pub enum BackfillError {
    #[error("reading {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing {path}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
}

#[derive(Debug, serde::Deserialize)]
enum ThroughputJson {
    Bits(u64),
    Bytes(u64),
    BytesDecimal(u64),
    Elements(u64),
    ElementsAndBytes { elements: u64, bytes: u64 },
}

impl From<&ThroughputJson> for Work {
    fn from(throughput: &ThroughputJson) -> Self {
        match *throughput {
            ThroughputJson::Bits(bits) => Self::Bits(bits),
            ThroughputJson::Bytes(bytes) | ThroughputJson::BytesDecimal(bytes) => {
                Self::Bytes(bytes)
            }
            ThroughputJson::Elements(elements) => Self::Elements(elements),
            ThroughputJson::ElementsAndBytes { elements, bytes } => {
                Self::ElementsAndBytes { elements, bytes }
            }
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct BenchmarkIdJson {
    group_id: String,
    function_id: Option<String>,
    value_str: Option<String>,
    throughput: Option<ThroughputJson>,
    directory_name: String,
}

#[derive(Debug, serde::Deserialize)]
struct ConfidenceIntervalJson {
    confidence_level: f64,
    lower_bound: f64,
    upper_bound: f64,
}

#[derive(Debug, serde::Deserialize)]
struct EstimateJson {
    confidence_interval: ConfidenceIntervalJson,
    point_estimate: f64,
    standard_error: f64,
}

#[derive(Debug, serde::Deserialize)]
struct EstimatesJson {
    mean: EstimateJson,
    median: EstimateJson,
    median_abs_dev: EstimateJson,
    slope: Option<EstimateJson>,
    std_dev: EstimateJson,
}

#[derive(Debug, serde::Deserialize)]
struct ChangeEstimatesJson {
    mean: EstimateJson,
    median: EstimateJson,
}

#[derive(Debug, serde::Deserialize)]
struct SampleJson {
    sampling_mode: String,
    iters: Vec<f64>,
    times: Vec<f64>,
}

type Key = (String, Option<String>, Option<String>);

/// One criterion result directory.
#[derive(Debug)]
pub struct Indexed {
    pub directory: PathBuf,
    pub work: Option<Work>,
}

/// Every benchmark criterion recorded under its output directory.
#[derive(Debug, Default)]
pub struct CriterionIndex {
    entries: BTreeMap<Key, Vec<Indexed>>,
}

/// Outcome of resolving one benchmark.
#[derive(Debug)]
pub enum Backfilled {
    Measured {
        estimates: Box<CriterionEstimates>,
        work: Option<Work>,
    },
    /// No result directory: criterion ran in test, list or profile mode, or
    /// the benchmark was filtered out.
    Missing,
    /// The result exists but predates this session.
    Stale { directory: PathBuf },
    /// Several directories claim the same benchmark identity.
    Ambiguous { directories: Vec<PathBuf> },
}

/// Criterion's output directory, resolved exactly as criterion resolves it.
///
/// Precedence: `$CRITERION_HOME`, else `$CARGO_TARGET_DIR/criterion`, else the target
/// directory reported by `cargo metadata`, else `target/criterion`.
pub fn criterion_home() -> PathBuf {
    if let Some(home) = std::env::var_os("CRITERION_HOME") {
        return PathBuf::from(home);
    }
    cargo_target_directory().map_or_else(
        || PathBuf::from("target/criterion"),
        |target| target.join("criterion"),
    )
}

/// The cargo target directory, by the same precedence criterion uses.
pub fn cargo_target_directory() -> Option<PathBuf> {
    #[derive(serde::Deserialize)]
    struct Metadata {
        target_directory: PathBuf,
    }
    if let Some(dir) = std::env::var_os("CARGO_TARGET_DIR") {
        return Some(PathBuf::from(dir));
    }
    let cargo = std::env::var_os("CARGO")?;
    let output = std::process::Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .ok()?;
    serde_json::from_slice::<Metadata>(&output.stdout)
        .ok()
        .map(|metadata| metadata.target_directory)
}

/// Directory holding the `calibration_<session>.jsonl` datasets:
/// `$KAPPA_PERF_DATASET_DIR`, else the cargo target directory.
///
/// A run directory keeps one run's datasets, and the floors its sessions
/// are graded against, apart from every other run's.
pub fn dataset_directory() -> Option<PathBuf> {
    resolve_dataset_directory(
        std::env::var_os("KAPPA_PERF_DATASET_DIR"),
        cargo_target_directory,
    )
}

fn resolve_dataset_directory(
    explicit: Option<std::ffi::OsString>,
    target: impl FnOnce() -> Option<PathBuf>,
) -> Option<PathBuf> {
    explicit
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .or_else(target)
}

/// The instant a session starts, on the filesystem's clock.
///
/// Result freshness is judged by file modification times, which Linux
/// takes from the coarse kernel clock; a fine-grained `SystemTime::now()`
/// can be later than the mtime of a file written just after it. Touching
/// a marker in `dataset_dir` and reading back its mtime puts both sides of
/// the comparison in [`CriterionIndex::resolve`] on the same clock.
pub fn session_mark(dataset_dir: &Path, name: &str) -> Result<SystemTime, BackfillError> {
    let marker = dataset_dir.join(format!(".calibration_{name}.started"));
    let io = |source| BackfillError::Io {
        path: marker.clone(),
        source,
    };
    std::fs::create_dir_all(dataset_dir).map_err(io)?;
    std::fs::write(&marker, b"").map_err(io)?;
    std::fs::metadata(&marker)
        .and_then(|m| m.modified())
        .map_err(io)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, BackfillError> {
    let bytes = std::fs::read(path).map_err(|source| BackfillError::Io {
        path: path.to_owned(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| BackfillError::Json {
        path: path.to_owned(),
        source,
    })
}

impl CriterionIndex {
    /// Index every `new/benchmark.json` under `root`. A missing root is an
    /// empty index (nothing has been benchmarked yet).
    pub fn build(root: &Path) -> Result<Self, BackfillError> {
        let mut index = Self::default();
        if root.is_dir() {
            index.walk(root, root)?;
        }
        Ok(index)
    }

    fn walk(&mut self, root: &Path, dir: &Path) -> Result<(), BackfillError> {
        let entries = std::fs::read_dir(dir).map_err(|source| BackfillError::Io {
            path: dir.to_owned(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| BackfillError::Io {
                path: dir.to_owned(),
                source,
            })?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|source| BackfillError::Io {
                path: path.clone(),
                source,
            })?;
            if file_type.is_dir() {
                self.walk(root, &path)?;
            } else if entry.file_name() == "benchmark.json"
                && dir.file_name().is_some_and(|name| name == "new")
            {
                let id: BenchmarkIdJson = read_json(&path)?;
                let key = (id.group_id, id.function_id, id.value_str);
                self.entries.entry(key).or_default().push(Indexed {
                    directory: root.join(&id.directory_name),
                    work: id.throughput.as_ref().map(Work::from),
                });
            }
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Resolve `coords`, accepting only results written at or after `since`.
    pub fn resolve(
        &self,
        coords: &HarnessCoords,
        since: SystemTime,
    ) -> Result<Backfilled, BackfillError> {
        let key = (
            coords.group.clone(),
            coords.function.clone(),
            coords.value.clone(),
        );
        let Some(candidates) = self.entries.get(&key) else {
            return Ok(Backfilled::Missing);
        };
        let [indexed] = candidates.as_slice() else {
            return Ok(Backfilled::Ambiguous {
                directories: candidates.iter().map(|c| c.directory.clone()).collect(),
            });
        };
        let new_dir = indexed.directory.join("new");
        let estimates_path = new_dir.join("estimates.json");
        let modified = std::fs::metadata(&estimates_path)
            .and_then(|metadata| metadata.modified())
            .map_err(|source| BackfillError::Io {
                path: estimates_path.clone(),
                source,
            })?;
        if modified < since {
            return Ok(Backfilled::Stale {
                directory: indexed.directory.clone(),
            });
        }
        let estimates: EstimatesJson = read_json(&estimates_path)?;
        let sample: SampleJson = read_json(&new_dir.join("sample.json"))?;
        let change_path = indexed.directory.join("change").join("estimates.json");
        // A change file older than this run's estimates belongs to an
        // earlier comparison.
        let change = match std::fs::metadata(&change_path).and_then(|m| m.modified()) {
            Ok(changed) if changed >= since => {
                Some(read_json::<ChangeEstimatesJson>(&change_path)?)
            }
            Ok(_) => None,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(source) => {
                return Err(BackfillError::Io {
                    path: change_path,
                    source,
                });
            }
        };
        let (typical, estimator) = estimates
            .slope
            .as_ref()
            .map_or((&estimates.mean, "criterion.mean"), |slope| {
                (slope, "criterion.slope")
            });
        Ok(Backfilled::Measured {
            estimates: Box::new(CriterionEstimates {
                typical_ns: typical.point_estimate,
                typical_estimator: estimator.to_owned(),
                ci_lower_ns: typical.confidence_interval.lower_bound,
                ci_upper_ns: typical.confidence_interval.upper_bound,
                confidence_level: typical.confidence_interval.confidence_level,
                standard_error_ns: typical.standard_error,
                slope_ns: estimates.slope.as_ref().map(|slope| slope.point_estimate),
                mean_ns: estimates.mean.point_estimate,
                median_ns: estimates.median.point_estimate,
                std_dev_ns: estimates.std_dev.point_estimate,
                median_abs_dev_ns: estimates.median_abs_dev.point_estimate,
                sampling_mode: sample.sampling_mode,
                samples: sample.iters.len(),
                iters: sample.iters,
                times_ns: sample.times,
                change_mean: change.as_ref().map(|c| c.mean.point_estimate),
                change_median: change.as_ref().map(|c| c.median.point_estimate),
                directory: indexed.directory.display().to_string(),
            }),
            work: indexed.work,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const ESTIMATE: &str = r#"{"confidence_interval":{"confidence_level":0.95,"lower_bound":90.0,"upper_bound":110.0},"point_estimate":100.0,"standard_error":5.0}"#;

    fn write_benchmark(
        root: &Path,
        dir: &str,
        id_json: &str,
        slope: bool,
    ) -> Result<(), std::io::Error> {
        let new_dir = root.join(dir).join("new");
        std::fs::create_dir_all(&new_dir)?;
        std::fs::write(new_dir.join("benchmark.json"), id_json)?;
        let slope = if slope { ESTIMATE } else { "null" };
        std::fs::write(
            new_dir.join("estimates.json"),
            format!(
                r#"{{"mean":{ESTIMATE},"median":{ESTIMATE},"median_abs_dev":{ESTIMATE},"slope":{slope},"std_dev":{ESTIMATE}}}"#
            ),
        )?;
        std::fs::write(
            new_dir.join("sample.json"),
            r#"{"sampling_mode":"Linear","iters":[1.0,2.0,3.0],"times":[100.0,200.0,300.0]}"#,
        )
    }

    fn coords(group: &str, function: Option<&str>, value: Option<&str>) -> HarnessCoords {
        HarnessCoords {
            group: group.into(),
            function: function.map(Into::into),
            value: value.map(Into::into),
        }
    }

    #[test]
    fn resolves_through_recorded_identity_including_unique_suffixes() -> TestResult {
        let root = tempfile::tempdir()?;
        let since = SystemTime::now() - std::time::Duration::from_secs(60);
        // Criterion renamed this directory for uniqueness; the identity file
        // is the only reliable mapping.
        write_benchmark(
            root.path(),
            "hash_64k/sha256_2",
            r#"{"group_id":"hash/64k","function_id":"sha256","value_str":null,"throughput":{"Bytes":65536},"full_id":"hash/64k/sha256","directory_name":"hash_64k/sha256_2","title":"hash/64k/sha256"}"#,
            true,
        )?;
        let index = CriterionIndex::build(root.path())?;
        assert_eq!(index.len(), 1);
        match index.resolve(&coords("hash/64k", Some("sha256"), None), since)? {
            Backfilled::Measured { estimates, work } => {
                assert_eq!(work, Some(Work::Bytes(65_536)));
                assert_eq!(estimates.typical_estimator, "criterion.slope");
                assert!((estimates.typical_ns - 100.0).abs() < f64::EPSILON);
                assert_eq!(estimates.samples, 3);
                assert_eq!(estimates.change_mean, None);
            }
            other => panic!("expected measured, got {other:?}"),
        }
        assert!(matches!(
            index.resolve(&coords("hash/64k", Some("sha512"), None), since)?,
            Backfilled::Missing
        ));
        Ok(())
    }

    #[test]
    fn flat_sampling_uses_the_mean_and_elements_throughput() -> TestResult {
        let root = tempfile::tempdir()?;
        let since = SystemTime::now() - std::time::Duration::from_secs(60);
        write_benchmark(
            root.path(),
            "publish/tags/100",
            r#"{"group_id":"publish","function_id":"tags","value_str":"100","throughput":{"ElementsAndBytes":{"elements":100,"bytes":4096}},"full_id":"publish/tags/100","directory_name":"publish/tags/100","title":"publish/tags/100"}"#,
            false,
        )?;
        let index = CriterionIndex::build(root.path())?;
        match index.resolve(&coords("publish", Some("tags"), Some("100")), since)? {
            Backfilled::Measured { estimates, work } => {
                assert_eq!(estimates.typical_estimator, "criterion.mean");
                assert_eq!(estimates.slope_ns, None);
                assert_eq!(
                    work,
                    Some(Work::ElementsAndBytes {
                        elements: 100,
                        bytes: 4096
                    })
                );
            }
            other => panic!("expected measured, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn results_older_than_the_session_are_stale() -> TestResult {
        let root = tempfile::tempdir()?;
        write_benchmark(
            root.path(),
            "g/f",
            r#"{"group_id":"g","function_id":"f","value_str":null,"throughput":null,"full_id":"g/f","directory_name":"g/f","title":"g/f"}"#,
            true,
        )?;
        let index = CriterionIndex::build(root.path())?;
        let future = SystemTime::now() + std::time::Duration::from_secs(3600);
        assert!(matches!(
            index.resolve(&coords("g", Some("f"), None), future)?,
            Backfilled::Stale { .. }
        ));
        Ok(())
    }

    #[test]
    fn duplicate_identities_are_ambiguous_and_missing_root_is_empty() -> TestResult {
        let root = tempfile::tempdir()?;
        let id = r#"{"group_id":"g","function_id":"f","value_str":null,"throughput":null,"full_id":"g/f","directory_name":"DIR","title":"g/f"}"#;
        write_benchmark(root.path(), "a", &id.replace("DIR", "a"), true)?;
        write_benchmark(root.path(), "b", &id.replace("DIR", "b"), true)?;
        let index = CriterionIndex::build(root.path())?;
        assert!(matches!(
            index.resolve(&coords("g", Some("f"), None), SystemTime::UNIX_EPOCH)?,
            Backfilled::Ambiguous { directories } if directories.len() == 2
        ));
        assert!(CriterionIndex::build(&root.path().join("absent"))?.is_empty());
        Ok(())
    }

    #[test]
    fn corrupt_identity_files_are_errors() -> TestResult {
        let root = tempfile::tempdir()?;
        let new_dir = root.path().join("x").join("new");
        std::fs::create_dir_all(&new_dir)?;
        std::fs::write(new_dir.join("benchmark.json"), "{")?;
        assert!(matches!(
            CriterionIndex::build(root.path()),
            Err(BackfillError::Json { .. })
        ));
        Ok(())
    }
}
