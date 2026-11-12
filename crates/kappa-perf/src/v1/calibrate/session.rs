//! `CalibratedSession`: dependency gating, value resolution, validation,
//! baseline comparison, roofline grading and dataset emission for one
//! benchmark binary.
//!
//! Lifecycle: create; for each measurement check its dependencies, then
//! record it (criterion-pending, histogram, or direct); finalize. Finalize
//! backfills criterion results written during this session, converts every
//! value into its quantity's unit, evaluates validation rules against every
//! measured value of this session and every same-host floor of the
//! baseline, compares against the baseline, grades against the roofline,
//! and merges the measured records into `calibration_<name>.jsonl`:
//! records re-measured now replace their previous lines, all other lines
//! are kept, and a run that measured nothing leaves the file untouched.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::backfill::{
    BackfillError, Backfilled, CriterionIndex, criterion_home, dataset_directory, session_mark,
};
use super::baseline::{Baseline, BaselineError, FloorMatch};
use super::dependency::DependencyGraph;
use super::grammar::OscId;
use super::histogram::{HistogramError, LatencyHistogram};
use super::platform::{PlatformInfo, RunConditions, StorageInfo};
use super::profile::Profile;
use super::quantity::{Quantity, Work};
use super::record::{
    BaselineComparison, CalibrationPoint, FaultSummary, HarnessCoords, Severity, Source,
};
use super::reference::compare;
use super::roofline::{RooflineClass, classes, grade};
use super::substrate::Substrate;
use super::summary::{ClassSummary, ReferenceLine, SkipDiagnosis, Summary};
use super::validate::{Established, Rule, evaluate, rules};

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("session name '{0}' must be [a-z0-9_]+")]
    InvalidName(String),
    #[error("runtime '{0}' is not a valid substrate runtime token")]
    InvalidRuntime(String),
    #[error("{0} recorded twice in one session")]
    Duplicate(String),
    #[error(
        "{id}: run conditions changed since the session started ({}); its measurements are no longer comparable, so nothing is recorded: run it again under fixed conditions",
        changes.join("; ")
    )]
    RunConditionsChanged { id: String, changes: Vec<String> },
    #[error("{id}: value {value} is not finite")]
    NonFinite { id: String, value: f64 },
    #[error("{id}: histogram is empty")]
    EmptyHistogram { id: String },
    #[error("{id}: {source}")]
    Conversion {
        id: String,
        source: super::quantity::ConversionError,
    },
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path}:{line}: {source}")]
    Dataset {
        path: PathBuf,
        line: usize,
        source: serde_json::Error,
    },
    #[error(transparent)]
    Baseline(#[from] BaselineError),
    #[error(transparent)]
    Backfill(#[from] BackfillError),
    #[error(transparent)]
    Histogram(#[from] HistogramError),
    #[error("serializing record: {0}")]
    Serialize(#[from] serde_json::Error),
}

struct Entry {
    id: OscId,
    point: CalibrationPoint,
}

pub struct CalibratedSession {
    name: String,
    profile: Profile,
    platform: PlatformInfo,
    substrate: Substrate,
    graph: DependencyGraph,
    rules: Vec<Rule>,
    classes: Vec<RooflineClass>,
    baseline: Baseline,
    /// Trusted same-host records of every other session's dataset. They
    /// establish dependencies, so gating never depends on bench order, but
    /// are never floors: ratios, bounds and grades use `baseline` alone.
    evidence: Vec<Baseline>,
    entries: Vec<Entry>,
    recorded_ops: BTreeSet<String>,
    skipped: Vec<SkipDiagnosis>,
    started: SystemTime,
    dataset_path: PathBuf,
    criterion_dir: PathBuf,
    storage: Option<StorageInfo>,
    /// Path to the `.running` marker, removed on finalize.
    running_marker: PathBuf,
    /// The run seed stamped on every record (`bench::seed`).
    seed: Option<u64>,
    /// The fault summary stamped on records pushed while it is set.
    fault: Option<FaultSummary>,
}

/// `calibration_<session>.jsonl` of every session other than `own` and
/// `floors` (the baseline) in `dataset_dir`, in name order. A missing
/// directory holds none.
fn other_session_datasets(dataset_dir: &Path, own: &str) -> Result<Vec<PathBuf>, SessionError> {
    let io = |source| SessionError::Io {
        path: dataset_dir.to_owned(),
        source,
    };
    let entries = match std::fs::read_dir(dataset_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(io(source)),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(io)?;
        let file_name = entry.file_name();
        let Some(session) = file_name
            .to_str()
            .and_then(|name| name.strip_prefix("calibration_"))
            .and_then(|name| name.strip_suffix(".jsonl"))
        else {
            continue;
        };
        if valid_token(session) && session != own && session != "floors" {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

/// The value at the 99th-percentile iteration time of a recorded
/// distribution, converted into the record's quantity exactly as its value
/// was. Records without a distribution have none. The conversion uses the
/// work and resource the value's own conversion already accepted, and a
/// distribution's percentiles are positive, so it fails only where the
/// value could not have been recorded.
#[allow(
    clippy::cast_precision_loss,
    reason = "nanosecond latencies are far below 2^53"
)]
fn tail(entry: &Entry) -> Option<f64> {
    let p99_ns = entry.point.latency.as_ref()?.p99_ns as f64;
    entry
        .id
        .quantity()
        .from_ns(p99_ns, entry.point.work, entry.id.conditions().get("res"))
        .ok()
}

fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

impl CalibratedSession {
    /// Session reading and writing datasets in [`dataset_directory`] and
    /// criterion results where criterion itself writes them.
    ///
    /// If a previous session of the same name left a `.running` marker
    /// (it crashed or was killed before [`finalize`](Self::finalize)), a
    /// warning is printed naming the session, so the operator sees that its
    /// records may be incomplete.
    pub fn new(name: &str, profile: Profile, runtime: &str) -> Result<Self, SessionError> {
        let datasets = dataset_directory().unwrap_or_else(|| PathBuf::from("target"));
        Self::with_dirs(name, profile, runtime, &datasets, &criterion_home())
    }

    pub fn with_dirs(
        name: &str,
        profile: Profile,
        runtime: &str,
        dataset_dir: &Path,
        criterion_dir: &Path,
    ) -> Result<Self, SessionError> {
        if !valid_token(name) {
            return Err(SessionError::InvalidName(name.to_owned()));
        }
        let running_marker = dataset_dir.join(format!(".calibration_{name}.running"));
        if running_marker.exists() {
            eprintln!(
                "calibration session '{name}': a previous run left {}, \
                 which means it crashed or was killed before finalize; \
                 its records may be incomplete",
                running_marker.display()
            );
        }
        let substrate = Substrate::detect(runtime)
            .ok_or_else(|| SessionError::InvalidRuntime(runtime.to_owned()))?;
        let platform = PlatformInfo::detect();
        let baseline = Baseline::load(&dataset_dir.join("calibration_floors.jsonl"), &platform)?;
        let evidence = other_session_datasets(dataset_dir, name)?
            .iter()
            .map(|path| Baseline::load(path, &platform))
            .collect::<Result<_, _>>()?;
        let started = session_mark(dataset_dir, name)?;
        let dataset_path = dataset_dir.join(format!("calibration_{name}.jsonl"));
        // Write the running marker after session_mark succeeds, so a
        // failure in construction does not leave a stale marker.
        let io = |source| SessionError::Io {
            path: running_marker.clone(),
            source,
        };
        std::fs::write(&running_marker, b"").map_err(io)?;
        Ok(Self {
            name: name.to_owned(),
            profile,
            platform,
            substrate,
            graph: DependencyGraph::seeded(),
            rules: rules(),
            classes: classes(),
            baseline,
            evidence,
            entries: Vec::new(),
            recorded_ops: BTreeSet::new(),
            skipped: Vec::new(),
            started,
            dataset_path,
            criterion_dir: criterion_dir.to_owned(),
            storage: None,
            running_marker,
            seed: None,
            fault: None,
        })
    }

    /// Attach the filesystem under `path` to subsequent device and store
    /// records.
    pub fn set_storage_path(&mut self, path: &Path) {
        self.storage = StorageInfo::for_path(path);
    }

    /// Stamp `seed` on every record pushed from now on. Set once, before
    /// the first measurement, from `bench::seed`.
    pub const fn set_seed(&mut self, seed: u64) {
        self.seed = Some(seed);
    }

    /// Stamp `fault` on records pushed while it is set; `None` clears it.
    /// A fault bench sets it right before recording a measurement taken
    /// under an injected fault and clears it after.
    pub fn set_fault(&mut self, fault: Option<FaultSummary>) {
        self.fault = fault;
    }

    pub const fn platform(&self) -> &PlatformInfo {
        &self.platform
    }

    pub const fn baseline(&self) -> &Baseline {
        &self.baseline
    }

    /// `Ok` when every transitive dependency was recorded in this session,
    /// has a trusted same-host floor in the baseline, or was measured,
    /// trusted, on this host by another session. Below L3 nothing is gated.
    pub fn check_deps(&self, id: &OscId) -> Result<(), SkipDiagnosis> {
        if self.profile < Profile::L3Accumulation {
            return Ok(());
        }
        let missing: Vec<String> = self
            .graph
            .deps_of(id.operation())
            .into_iter()
            .filter(|dep| {
                !self.recorded_ops.contains(*dep)
                    && !self.baseline.has_operation(dep)
                    && !self.evidence.iter().any(|other| other.has_operation(dep))
            })
            .map(str::to_owned)
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(SkipDiagnosis {
                id: id.canonical(),
                missing,
            })
        }
    }

    pub fn skip(&mut self, diagnosis: SkipDiagnosis) {
        self.skipped.push(diagnosis);
    }

    /// The run conditions now, refused when they differ from those the
    /// session's records state.
    fn check_run_conditions(&self, id: &OscId) -> Result<(), SessionError> {
        let changes = self
            .platform
            .run_conditions()
            .changes(&RunConditions::detect());
        if changes.is_empty() {
            Ok(())
        } else {
            Err(SessionError::RunConditionsChanged {
                id: id.canonical(),
                changes,
            })
        }
    }

    fn push(
        &mut self,
        id: &OscId,
        source: Source,
        work: Option<Work>,
        test_id: Option<&str>,
    ) -> Result<&mut CalibrationPoint, SessionError> {
        // Read again at every measurement: a record never states run
        // conditions it was not measured under.
        self.check_run_conditions(id)?;
        let id = if self.profile >= Profile::L2Substrate {
            id.with_substrate(&self.substrate)
        } else {
            id.clone()
        };
        if self.entries.iter().any(|entry| entry.id == id) {
            return Err(SessionError::Duplicate(id.canonical()));
        }
        let mut point =
            CalibrationPoint::pending(&id, self.profile, source, work, self.platform.clone());
        point.test_id = test_id.map(str::to_owned);
        point.seed = self.seed;
        point.fault.clone_from(&self.fault);
        if id.operation().domains().iter().any(|d| {
            matches!(
                *d,
                "device"
                    | "store"
                    | "redb"
                    | "txn"
                    | "recovery"
                    | "settlement"
                    | "repair"
                    | "reclaim"
            )
        }) {
            point.storage.clone_from(&self.storage);
        }
        self.recorded_ops
            .extend(id.operation().operands().iter().cloned());
        self.entries.push(Entry { id, point });
        let last = self.entries.len() - 1;
        Ok(&mut self.entries[last].point)
    }

    /// A criterion benchmark whose estimates are read back at finalize.
    pub fn record_criterion(
        &mut self,
        id: &OscId,
        harness: HarnessCoords,
        test_id: Option<&str>,
    ) -> Result<(), SessionError> {
        self.push(id, Source::Criterion, None, test_id)?.harness = Some(harness);
        Ok(())
    }

    /// A directly timed distribution. Latency reports the median; rates and
    /// bandwidths derive from the mean (total work over total time).
    pub fn record_histogram(
        &mut self,
        id: &OscId,
        histogram: &LatencyHistogram,
        work: Option<Work>,
        test_id: Option<&str>,
    ) -> Result<(), SessionError> {
        let percentiles = histogram
            .percentiles()
            .ok_or_else(|| SessionError::EmptyHistogram { id: id.canonical() })?;
        #[allow(
            clippy::cast_precision_loss,
            reason = "nanosecond latencies are far below 2^53"
        )]
        let ns = if id.quantity() == Quantity::Lat {
            percentiles.p50_ns as f64
        } else {
            percentiles.mean_ns
        };
        let value = id
            .quantity()
            .from_ns(ns, work, id.conditions().get("res"))
            .map_err(|source| SessionError::Conversion {
                id: id.canonical(),
                source,
            })?;
        let encoded = histogram.encode()?;
        {
            let point = self.push(id, Source::Histogram, work, test_id)?;
            point.value = Some(value);
            point.latency = Some(percentiles);
            point.histogram = Some(encoded);
        }
        // Write the raw record immediately so a crash preserves it;
        // finalize overwrites it with the fully analyzed record. The
        // mutable borrow through `push` ended above.
        let last = &self.entries[self.entries.len() - 1].point;
        super::dataset::append(&self.dataset_path, last)?;
        Ok(())
    }

    /// A value in the quantity's unit measured outside criterion (sizes,
    /// ratios, externally timed rates).
    pub fn record_direct(
        &mut self,
        id: &OscId,
        value: f64,
        test_id: Option<&str>,
    ) -> Result<(), SessionError> {
        if !value.is_finite() {
            return Err(SessionError::NonFinite {
                id: id.canonical(),
                value,
            });
        }
        {
            let point = self.push(id, Source::Direct, None, test_id)?;
            point.value = Some(value);
        }
        let last = &self.entries[self.entries.len() - 1].point;
        super::dataset::append(&self.dataset_path, last)?;
        Ok(())
    }

    fn backfill(&mut self) -> Result<(), SessionError> {
        if !self
            .entries
            .iter()
            .any(|e| e.point.source == Source::Criterion)
        {
            return Ok(());
        }
        let index = CriterionIndex::build(&self.criterion_dir)?;
        for entry in self
            .entries
            .iter_mut()
            .filter(|e| e.point.source == Source::Criterion)
        {
            let Some(coords) = entry.point.harness.clone() else {
                continue;
            };
            match index.resolve(&coords, self.started)? {
                Backfilled::Measured { estimates, work } => {
                    let res = entry.id.conditions().get("res");
                    match entry.id.quantity().from_ns(estimates.typical_ns, work, res) {
                        Ok(value) => entry.point.value = Some(value),
                        Err(error) => entry
                            .point
                            .diagnosis
                            .push(format!("unit conversion: {error}")),
                    }
                    entry.point.work = work;
                    entry.point.criterion = Some(*estimates);
                }
                Backfilled::Missing => entry.point.diagnosis.push(
                    "criterion wrote no estimates (test, list or profile mode, or filtered out)"
                        .to_owned(),
                ),
                Backfilled::Stale { directory } => entry.point.diagnosis.push(format!(
                    "criterion estimates in {} predate this session",
                    directory.display()
                )),
                Backfilled::Ambiguous { directories } => entry.point.diagnosis.push(format!(
                    "several criterion directories claim this benchmark: {directories:?}"
                )),
            }
        }
        Ok(())
    }

    /// Every measured record of this session, with its value and tail, then
    /// every baseline floor this session did not re-measure: the values
    /// validation, dependency attribution and grading are evaluated against.
    fn established_snapshot(&self) -> Vec<(OscId, f64, Option<f64>, bool)> {
        let session_ids: BTreeSet<String> = self
            .entries
            .iter()
            .filter(|e| e.point.value.is_some())
            .map(|e| e.id.strip_substrate().canonical())
            .collect();
        self.entries
            .iter()
            .filter_map(|e| e.point.value.map(|v| (e.id.clone(), v, tail(e), false)))
            .chain(
                self.baseline
                    .floors()
                    .filter(|floor| !session_ids.contains(&floor.id.canonical()))
                    .map(|floor| (floor.id.clone(), floor.value, None, true)),
            )
            .collect()
    }

    fn analyze(&mut self) {
        let snapshot = self.established_snapshot();
        let established: Vec<Established<'_>> = snapshot
            .iter()
            .map(|(id, value, tail, from_baseline)| Established {
                id,
                value: *value,
                tail: *tail,
                from_baseline: *from_baseline,
            })
            .collect();
        let unmeasured_ops: BTreeSet<String> = self
            .entries
            .iter()
            .filter(|e| e.point.value.is_none())
            .map(|e| e.id.operation().canonical())
            .collect();
        for entry in &mut self.entries {
            let Some(value) = entry.point.value else {
                continue;
            };
            if self.profile >= Profile::L3Accumulation {
                for dep in self.graph.deps_of(entry.id.operation()) {
                    let mut ids: Vec<String> = established
                        .iter()
                        .filter(|e| e.id.operation().canonical() == dep)
                        .map(|e| e.id.canonical())
                        .collect();
                    ids.sort();
                    if ids.is_empty() && unmeasured_ops.contains(dep) {
                        entry
                            .point
                            .diagnosis
                            .push(format!("dependency {dep} was recorded but not measured"));
                    }
                    entry.point.dependencies.extend(ids);
                }
            }
            if self.profile >= Profile::L4Validation {
                let subject = Established {
                    id: &entry.id,
                    value,
                    tail: tail(entry),
                    from_baseline: false,
                };
                entry.point.validations = evaluate(&self.rules, &subject, &established);
                for failed in entry
                    .point
                    .validations
                    .iter()
                    .filter(|v| !v.passed && v.severity == Severity::Error)
                {
                    entry.point.trusted = false;
                    entry.point.diagnosis.push(format!(
                        "{}: {}",
                        failed.rule,
                        failed.diagnosis.as_deref().unwrap_or("")
                    ));
                }
            }
            if self.profile >= Profile::L5Provenance {
                match self.baseline.lookup(&entry.id) {
                    FloorMatch::Exact(floor) | FloorMatch::Generalized(floor) => {
                        let quantity = entry.id.quantity();
                        entry.point.baseline =
                            quantity
                                .achieved_fraction(value, floor.value)
                                .map(|fraction| BaselineComparison {
                                    floor_id: floor.id.canonical(),
                                    floor_value: floor.value,
                                    ratio: value / floor.value,
                                    slowdown: 1.0 / fraction,
                                });
                    }
                    FloorMatch::Ambiguous(ids) => entry
                        .point
                        .diagnosis
                        .push(format!("ambiguous baseline floors: {ids:?}")),
                    FloorMatch::None => {}
                }
            }
            if self.profile >= Profile::L6Graded {
                match grade(&self.classes, &entry.id, value, &established) {
                    Ok(roofline) => entry.point.roofline = roofline,
                    Err(why) => entry.point.diagnosis.push(format!("roofline: {why}")),
                }
                let subject = Established {
                    id: &entry.id,
                    value,
                    tail: tail(entry),
                    from_baseline: false,
                };
                entry.point.reference = compare(&subject, &established);
            }
        }
    }

    /// Resolve, analyze and emit every record. Callable once per run.
    /// Removes the `.running` marker, so a subsequent session knows this
    /// one completed.
    pub fn finalize(&mut self) -> Result<Summary, SessionError> {
        self.backfill()?;
        self.analyze();
        let measured: BTreeMap<&str, &CalibrationPoint> = self
            .entries
            .iter()
            .filter(|e| e.point.value.is_some())
            .map(|e| (e.point.id.as_str(), &e.point))
            .collect();
        let dataset = super::dataset::merge(&self.dataset_path, &measured)?;
        // The merge succeeded: this session's records are persisted. Remove
        // the running marker so the next session does not report a crash.
        let _ = std::fs::remove_file(&self.running_marker);
        let classes = ClassSummary::aggregate(
            self.entries
                .iter()
                .filter_map(|e| e.point.roofline.as_ref()),
        );
        Ok(Summary {
            name: self.name.clone(),
            dataset,
            measured: self
                .entries
                .iter()
                .filter(|e| e.point.value.is_some())
                .count(),
            unmeasured: self
                .entries
                .iter()
                .filter(|e| e.point.value.is_none())
                .map(|e| (e.point.id.clone(), e.point.diagnosis.clone()))
                .collect(),
            untrusted: self
                .entries
                .iter()
                .filter(|e| !e.point.trusted)
                .map(|e| (e.point.id.clone(), e.point.diagnosis.clone()))
                .collect(),
            skipped: self.skipped.clone(),
            classes,
            references: self
                .entries
                .iter()
                .filter_map(|e| {
                    e.point.reference.as_ref().map(|r| ReferenceLine {
                        id: e.point.id.clone(),
                        implementation: r.implementation.clone(),
                        fraction: r.fraction,
                        meets: r.meets,
                    })
                })
                .collect(),
            baseline_floors: self.baseline.len(),
        })
    }

    /// Records in recording order (for inspection and tests).
    pub fn records(&self) -> impl Iterator<Item = &CalibrationPoint> {
        self.entries.iter().map(|e| &e.point)
    }
}
