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
