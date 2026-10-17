//! Floor baseline: measured, trusted records from a prior floors run on the
//! same host.
//!
//! Ratios to a floor are meaningful only on the hardware and toolchain that
//! produced the floor, so records from any other host are excluded rather
//! than compared (PERF-DOC-031 labels cross-hardware comparisons; it does not
//! mix them into ratios). Lookup is deterministic: the exact identifier, else
//! the single most specific record of the same quantity and operation whose
//! conditions the subject satisfies. Two equally specific candidates are an
//! ambiguity, reported, never resolved by whichever came first. A missing
//! file is an empty baseline; a corrupt line is an error.

use std::collections::BTreeMap;
use std::path::Path;

use super::grammar::{OscId, ParseError};
use super::platform::PlatformInfo;
use super::profile::Profile;
use super::record::CalibrationPoint;

#[derive(Debug, thiserror::Error)]
pub enum BaselineError {
    #[error("reading {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("{path}:{line}: {source}")]
    Json {
        path: String,
        line: usize,
        source: serde_json::Error,
    },
    #[error("{path}:{line}: identifier '{id}': {source}")]
    Identifier {
        path: String,
        line: usize,
        id: String,
        source: Box<ParseError>,
    },
}

/// One usable floor.
#[derive(Debug, Clone, PartialEq)]
pub struct Floor {
    pub id: OscId,
    pub value: f64,
}

/// Result of looking up the floor for a subject.
#[derive(Debug, Clone, PartialEq)]
pub enum FloorMatch<'a> {
    Exact(&'a Floor),
    /// The unique most specific generalization.
    Generalized(&'a Floor),
    /// Several equally specific candidates; their identifiers.
    Ambiguous(Vec<String>),
    None,
}

#[derive(Debug, Default)]
pub struct Baseline {
    /// Keyed by identifier without substrate.
    floors: BTreeMap<String, Floor>,
    excluded_other_hosts: usize,
    excluded_untrusted: usize,
}

impl Baseline {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn load(path: &Path, host: &PlatformInfo) -> Result<Self, BaselineError> {
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::empty()),
            Err(source) => {
                return Err(BaselineError::Io {
                    path: path.display().to_string(),
                    source,
                });
            }
        };
        let mut baseline = Self::empty();
        for (index, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let point: CalibrationPoint =
                serde_json::from_str(line).map_err(|source| BaselineError::Json {
                    path: path.display().to_string(),
                    line: index + 1,
                    source,
                })?;
            let id = OscId::parse(&point.id, Profile::L1Conditions).map_err(|source| {
                BaselineError::Identifier {
                    path: path.display().to_string(),
                    line: index + 1,
                    id: point.id.clone(),
                    source: Box::new(source),
                }
            })?;
            baseline.admit(&id, &point, host);
        }
        Ok(baseline)
    }

    /// Admit a record if it is a usable floor for `host`.
    pub fn admit(&mut self, id: &OscId, point: &CalibrationPoint, host: &PlatformInfo) {
        if !point.platform.same_host(host) {
            self.excluded_other_hosts += 1;
            return;
        }
        let Some(value) = point.value.filter(|_| point.trusted) else {
            self.excluded_untrusted += 1;
            return;
        };
        let key = id.strip_substrate().canonical();
        self.floors.insert(
            key,
            Floor {
                id: id.strip_substrate(),
                value,
            },
        );
    }

    pub fn lookup(&self, subject: &OscId) -> FloorMatch<'_> {
        let subject = subject.strip_substrate();
        if let Some(floor) = self.floors.get(&subject.canonical()) {
            return FloorMatch::Exact(floor);
        }
        let candidates: Vec<&Floor> = self
            .floors
            .values()
            .filter(|floor| subject.is_more_specific_than(&floor.id))
            .collect();
        let Some(best) = candidates.iter().map(|f| f.id.conditions().len()).max() else {
            return FloorMatch::None;
        };
        let most_specific: Vec<&Floor> = candidates
            .into_iter()
            .filter(|floor| floor.id.conditions().len() == best)
            .collect();
        match most_specific.as_slice() {
            [single] => FloorMatch::Generalized(single),
            many => FloorMatch::Ambiguous(many.iter().map(|f| f.id.canonical()).collect()),
        }
    }

    /// Whether any floor of `operation` was measured on this host.
    pub fn has_operation(&self, operation: &str) -> bool {
        self.floors
            .values()
            .any(|floor| floor.id.operation().canonical() == operation)
    }

    pub fn floors(&self) -> impl Iterator<Item = &Floor> {
        self.floors.values()
    }

    pub fn len(&self) -> usize {
        self.floors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.floors.is_empty()
    }

    pub const fn excluded_other_hosts(&self) -> usize {
        self.excluded_other_hosts
    }

    pub const fn excluded_untrusted(&self) -> usize {
        self.excluded_untrusted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calibrate::condition::Conditions;
    use crate::calibrate::quantity::Quantity;
    use crate::calibrate::record::Source;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn point(id: &OscId, value: Option<f64>, host: &PlatformInfo) -> CalibrationPoint {
        let mut point =
            CalibrationPoint::pending(id, Profile::L6Graded, Source::Direct, None, host.clone());
        point.value = value;
        point
    }

    fn baseline_of(points: &[(&str, f64)], host: &PlatformInfo) -> Result<Baseline, ParseError> {
        let mut baseline = Baseline::empty();
        for (raw, value) in points {
            let id: OscId = raw.parse()?;
            baseline.admit(&id, &point(&id, Some(*value), host), host);
        }
        Ok(baseline)
    }

    #[test]
    fn exact_then_most_specific_generalization() -> TestResult {
        let host = PlatformInfo::detect();
        let baseline = baseline_of(
            &[
                ("osc:bw/hash.sha256", 1.0),
                ("osc:bw/hash.sha256?size=64k", 2.0),
                ("osc:bw/hash.sha256?cache=l2&size=64k", 3.0),
            ],
            &host,
        )?;
        let exact: OscId = "osc:bw/hash.sha256?size=64k@x86_64.linux.std".parse()?;
        assert!(
            matches!(baseline.lookup(&exact), FloorMatch::Exact(f) if (f.value - 2.0).abs() < f64::EPSILON)
        );
        let specific: OscId = "osc:bw/hash.sha256?cache=l2&size=64k&variant=x".parse()?;
        assert!(
            matches!(baseline.lookup(&specific), FloorMatch::Generalized(f) if (f.value - 3.0).abs() < f64::EPSILON)
        );
        let unrelated: OscId = "osc:lat/hash.sha256?size=64k".parse()?;
        assert_eq!(baseline.lookup(&unrelated), FloorMatch::None);
        Ok(())
    }

    #[test]
    fn equally_specific_candidates_are_ambiguous() -> TestResult {
        let host = PlatformInfo::detect();
        let baseline = baseline_of(
            &[
                ("osc:bw/hash.sha256?size=64k", 2.0),
                ("osc:bw/hash.sha256?cache=l2", 3.0),
            ],
            &host,
        )?;
        let subject = OscId::new(
            Quantity::Bw,
            "hash.sha256",
            Conditions::parse("cache=l2")?.size(65_536),
        )?;
        match baseline.lookup(&subject) {
            FloorMatch::Ambiguous(ids) => assert_eq!(ids.len(), 2),
            other => panic!("expected ambiguity, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn other_hosts_and_unmeasured_records_are_excluded() -> TestResult {
        let host = PlatformInfo::detect();
        let mut other = host.clone();
        other.microcode = Some("0xdifferent".into());
        let id: OscId = "osc:lat/device.fsync".parse()?;
        let mut baseline = Baseline::empty();
        baseline.admit(&id, &point(&id, Some(10.0), &other), &host);
        baseline.admit(&id, &point(&id, None, &host), &host);
        let mut untrusted = point(&id, Some(10.0), &host);
        untrusted.trusted = false;
        baseline.admit(&id, &untrusted, &host);
        assert!(baseline.is_empty());
        assert_eq!(baseline.excluded_other_hosts(), 1);
        assert_eq!(baseline.excluded_untrusted(), 2);
        Ok(())
    }

    #[test]
    fn load_missing_is_empty_and_corruption_is_an_error() -> TestResult {
        let host = PlatformInfo::detect();
        let dir = tempfile::tempdir()?;
        assert!(Baseline::load(&dir.path().join("absent.jsonl"), &host)?.is_empty());

        let id: OscId = "osc:lat/device.fsync".parse()?;
        let good = point(&id, Some(42.0), &host).to_jsonl()?;
        let path = dir.path().join("floors.jsonl");
        std::fs::write(&path, format!("{good}\n\n"))?;
        let loaded = Baseline::load(&path, &host)?;
        assert_eq!(loaded.len(), 1);
        assert!(loaded.has_operation("device.fsync"));

        std::fs::write(&path, format!("{good}\n{{not json\n"))?;
        assert!(matches!(
            Baseline::load(&path, &host),
            Err(BaselineError::Json { line: 2, .. })
        ));
        Ok(())
    }
}
