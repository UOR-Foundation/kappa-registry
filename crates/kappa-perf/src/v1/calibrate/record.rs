//! `CalibrationPoint`: one dataset-grade measurement record, one JSONL line.
//!
//! The canonical OSC identifier is the primary key. A record states what
//! was measured (quantity, operation, conditions, substrate), the value in
//! the quantity's own unit, how certain it is (criterion's estimates and
//! confidence interval, or an `HdrHistogram` distribution), where it came
//! from (platform and toolchain), what it builds on (established
//! dependencies), whether it is physically plausible (validations), how it
//! compares to the floor baseline, and how close it comes to its roofline
//! (grade). A point that was never measured carries no value at all: zero
//! would read as data.

use super::grammar::{GRAMMAR_VERSION, OscId};
use super::histogram::Percentiles;
use super::platform::{PlatformInfo, StorageInfo};
use super::profile::Profile;
use super::quantity::{Quantity, Work};

/// Severity of a validation rule violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    /// Physically impossible: the record is untrusted.
    Error,
    /// Suspicious but possible: recorded, still trusted.
    Warn,
}

/// One validation rule evaluated against one record.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ValidationResult {
    pub rule: String,
    pub predicate: String,
    pub bound_id: String,
    pub observed: f64,
    pub bound: f64,
    pub passed: bool,
    pub severity: Severity,
    /// The bound came from the baseline, not this session.
    pub bound_from_baseline: bool,
    pub diagnosis: Option<String>,
}

/// Where criterion stored the benchmark that produced this record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HarnessCoords {
    pub group: String,
    pub function: Option<String>,
    pub value: Option<String>,
}

/// Criterion's statistical estimates, in nanoseconds per iteration.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CriterionEstimates {
    pub typical_ns: f64,
    pub typical_estimator: String,
    pub ci_lower_ns: f64,
    pub ci_upper_ns: f64,
    pub confidence_level: f64,
    pub standard_error_ns: f64,
    pub slope_ns: Option<f64>,
    pub mean_ns: f64,
    pub median_ns: f64,
    pub std_dev_ns: f64,
    pub median_abs_dev_ns: f64,
    pub sampling_mode: String,
    pub samples: usize,
    pub iters: Vec<f64>,
    pub times_ns: Vec<f64>,
    /// `new/base - 1` from `change/estimates.json`: negative is faster.
    pub change_mean: Option<f64>,
    pub change_median: Option<f64>,
    pub directory: String,
}

/// Comparison against the floor baseline.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BaselineComparison {
    pub floor_id: String,
    pub floor_value: f64,
    /// `value / floor_value` in the quantity's unit.
    pub ratio: f64,
    /// How many times worse than the floor, oriented by the quantity:
    /// 1.0 is at the floor, above 1.0 is slower or narrower.
    pub slowdown: f64,
}

/// KAPPA-PERF-001 section 1.2 grade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Grade {
    A,
    B,
    C,
    D,
    F,
}

impl Grade {
    /// A at 80% of the bound, B 60%, C 40%, D 20%, otherwise F.
    pub fn from_fraction(fraction: f64) -> Self {
        if fraction >= 0.80 {
            Self::A
        } else if fraction >= 0.60 {
            Self::B
        } else if fraction >= 0.40 {
            Self::C
        } else if fraction >= 0.20 {
            Self::D
        } else {
            Self::F
        }
    }
}

/// Roofline fraction against the calibrated bound of the operation class.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Roofline {
    pub class: String,
    pub bound_ids: Vec<String>,
    pub bound_value: f64,
    pub fraction: f64,
    pub grade: Grade,
}

/// The production path against the best reference implementation of the
/// same operation measured on this host (`reference::compare`).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReferenceComparison {
    pub reference_id: String,
    /// The reference's `impl` condition.
    pub implementation: String,
    pub reference_value: f64,
    /// Fraction of the reference achieved, oriented by the quantity: 1.0
    /// matches it, above meets and exceeds it, below is behind it.
    pub fraction: f64,
    /// The production path met or exceeded the reference.
    pub meets: bool,
    /// The reference came from the baseline, not this session.
    pub reference_from_baseline: bool,
}

/// How an injected fault was observed to take effect. A record under a
/// fault carries the evidence that the fault happened, never a count made
/// up to pass the gate.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Injection {
    /// A fault injected beneath redb: the counts over the fault backend's
    /// operation trace and the bytes a crash took back
    /// (`kappa_store_redb::test_support::Fired`).
    Backend {
        performed: u64,
        refused: u64,
        performed_then_failed: u64,
        lost_bytes: u64,
    },
    /// A fault injected on the filesystem outside the store (a directory
    /// renamed away, a database replaced by an empty file): `observed` names
    /// the store response that proves the fault reached it, such as
    /// `Unavailable` on a miss while discovery is incomplete, and
    /// `responses` counts the responses of that kind the bench received.
    Filesystem { observed: String, responses: u64 },
}

/// What the injected fault did while a measurement ran. A measurement
/// taken under a non-`none` `fault` condition whose summary shows nothing
/// fired measured nothing injected, and the bench refuses to record it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FaultSummary {
    /// The `fault` condition token the measurement was taken under.
    pub armed: String,
    pub injection: Injection,
}

impl FaultSummary {
    /// Whether the injection took effect: a backend fault refused,
    /// misreported or lost something; a filesystem fault produced at least
    /// one store response of the named kind.
    pub fn fired(&self) -> bool {
        match &self.injection {
            Injection::Backend {
                refused,
                performed_then_failed,
                lost_bytes,
                ..
            } => *refused > 0 || *performed_then_failed > 0 || *lost_bytes > 0,
            Injection::Filesystem {
                observed,
                responses,
            } => !observed.is_empty() && *responses > 0,
        }
    }
}

/// How the value was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Source {
    /// Criterion benchmark, backfilled from its output after the run.
    Criterion,
    /// Direct measurement with an `HdrHistogram` distribution.
    Histogram,
    /// Value recorded directly (sizes, ratios, counts).
    Direct,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CalibrationPoint {
    pub id: String,
    pub grammar_version: String,
    pub profile: Profile,
    pub quantity: Quantity,
    pub operation: String,
    pub conditions: Vec<(String, String)>,
    pub substrate: Option<String>,
    pub test_id: Option<String>,
    pub source: Source,
    pub work: Option<Work>,
    /// Value in `unit`; `None` until measured.
    pub value: Option<f64>,
    pub unit: String,
    pub criterion: Option<CriterionEstimates>,
    pub latency: Option<Percentiles>,
    /// V2+DEFLATE `HdrHistogram`, hex.
    pub histogram: Option<String>,
    pub harness: Option<HarnessCoords>,
    pub dependencies: Vec<String>,
    pub validations: Vec<ValidationResult>,
    pub baseline: Option<BaselineComparison>,
    pub roofline: Option<Roofline>,
    /// Against the best same-host reference implementation; datasets written
    /// before references were measured carry none.
    #[serde(default)]
    pub reference: Option<ReferenceComparison>,
    /// No `Error` validation failed. Independent of the grade
    /// (PERF-DOC-002): a correct, slow measurement is trusted and graded F.
    pub trusted: bool,
    /// Why the record has no value or is untrusted.
    pub diagnosis: Vec<String>,
    pub platform: PlatformInfo,
    pub storage: Option<StorageInfo>,
    pub timestamp_ns: u64,
    /// The run seed every deterministic choice of the session's benches
    /// drew from (`bench::seed`): what reproduces the run. Datasets
    /// written before seeds were recorded carry none.
    #[serde(default)]
    pub seed: Option<u64>,
    /// What the injected fault did, on records measured under one.
    #[serde(default)]
    pub fault: Option<FaultSummary>,
}

impl CalibrationPoint {
    /// A record for `id` awaiting its value.
    pub fn pending(
        id: &OscId,
        profile: Profile,
        source: Source,
        work: Option<Work>,
        platform: PlatformInfo,
    ) -> Self {
        Self {
            id: id.canonical(),
            grammar_version: GRAMMAR_VERSION.to_owned(),
            profile,
            quantity: id.quantity(),
            operation: id.operation().canonical(),
            conditions: id
                .conditions()
                .iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
            substrate: id.substrate().map(ToString::to_string),
            test_id: None,
            source,
            work,
            value: None,
            unit: id.quantity().unit().to_owned(),
            criterion: None,
            latency: None,
            histogram: None,
            harness: None,
            dependencies: Vec::new(),
            validations: Vec::new(),
            baseline: None,
            roofline: None,
            reference: None,
            trusted: true,
            diagnosis: Vec::new(),
            platform,
            storage: None,
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok())
                .unwrap_or(0),
            seed: None,
            fault: None,
        }
    }

    pub fn condition(&self, key: &str) -> Option<&str> {
        self.conditions
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn to_jsonl(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calibrate::condition::Conditions;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn grade_boundaries() {
        assert_eq!(Grade::from_fraction(0.80), Grade::A);
        assert_eq!(Grade::from_fraction(0.7999), Grade::B);
        assert_eq!(Grade::from_fraction(0.60), Grade::B);
        assert_eq!(Grade::from_fraction(0.40), Grade::C);
        assert_eq!(Grade::from_fraction(0.20), Grade::D);
        assert_eq!(Grade::from_fraction(0.1999), Grade::F);
        assert_eq!(Grade::from_fraction(1.4), Grade::A);
    }

    #[test]
    fn pending_records_have_no_value_and_roundtrip() -> TestResult {
        let id = OscId::new(
            Quantity::Bw,
            "store.blob_put",
            Conditions::parse("backend=redb")?.size(1 << 20),
        )?;
        let point = CalibrationPoint::pending(
            &id,
            Profile::L6Graded,
            Source::Criterion,
            Some(Work::Bytes(1 << 20)),
            PlatformInfo::detect(),
        );
        assert_eq!(point.value, None);
        assert_eq!(point.unit, "bytes/s");
        assert_eq!(point.condition("size"), Some("1m"));
        assert_eq!(point.condition("backend"), Some("redb"));
        let line = point.to_jsonl()?;
        assert!(!line.contains('\n'));
        let recovered: CalibrationPoint = serde_json::from_str(&line)?;
        assert_eq!(recovered, point);
        Ok(())
    }

    /// A dataset written before seeds and fault summaries existed still
    /// loads, with neither; a record carrying both keeps them.
    #[test]
    fn seed_and_fault_are_optional_and_round_trip() -> TestResult {
        let id = OscId::simple(Quantity::Lat, "recovery.open")?;
        let mut point = CalibrationPoint::pending(
            &id,
            Profile::L6Graded,
            Source::Histogram,
            None,
            PlatformInfo::detect(),
        );
        let line = point.to_jsonl()?;
        let mut stripped: serde_json::Value = serde_json::from_str(&line)?;
        let object = stripped.as_object_mut().ok_or("record is not an object")?;
        assert!(object.remove("seed").is_some());
        assert!(object.remove("fault").is_some());
        let old: CalibrationPoint = serde_json::from_value(stripped)?;
        assert_eq!(old.seed, None);
        assert_eq!(old.fault, None);

        point.seed = Some(0x5EED);
        point.fault = Some(FaultSummary {
            armed: "crash".into(),
            injection: Injection::Backend {
                performed: 7,
                refused: 2,
                performed_then_failed: 0,
                lost_bytes: 8192,
            },
        });
        let recovered: CalibrationPoint = serde_json::from_str(&point.to_jsonl()?)?;
        assert_eq!(recovered, point);
        assert!(recovered.fault.as_ref().is_some_and(FaultSummary::fired));
        let quiet = FaultSummary {
            armed: "none".into(),
            injection: Injection::Backend {
                performed: 3,
                refused: 0,
                performed_then_failed: 0,
                lost_bytes: 0,
            },
        };
        assert!(!quiet.fired(), "performed operations alone are not a fault");
        let seen = FaultSummary {
            armed: "lost_storage".into(),
            injection: Injection::Filesystem {
                observed: "Unavailable on a miss".into(),
                responses: 3,
            },
        };
        assert!(seen.fired());
        let named_but_never_received = FaultSummary {
            armed: "lost_storage".into(),
            injection: Injection::Filesystem {
                observed: "Unavailable on a miss".into(),
                responses: 0,
            },
        };
        assert!(
            !named_but_never_received.fired(),
            "a named response the bench never received is not evidence"
        );
        let unnamed = FaultSummary {
            armed: "lost_storage".into(),
            injection: Injection::Filesystem {
                observed: String::new(),
                responses: 3,
            },
        };
        assert!(
            !unnamed.fired(),
            "responses of no named kind are not evidence"
        );
        Ok(())
    }

    #[test]
    fn jsonl_escapes_control_characters() -> TestResult {
        let id = OscId::simple(Quantity::Lat, "store.publish")?;
        let mut point = CalibrationPoint::pending(
            &id,
            Profile::L0Core,
            Source::Direct,
            None,
            PlatformInfo::detect(),
        );
        point.diagnosis.push("tab\there\u{1}bell\"quote".to_owned());
        let line = point.to_jsonl()?;
        let recovered: CalibrationPoint = serde_json::from_str(&line)?;
        assert_eq!(recovered.diagnosis, point.diagnosis);
        Ok(())
    }
}
