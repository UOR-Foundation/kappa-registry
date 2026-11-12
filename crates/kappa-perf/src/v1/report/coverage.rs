//! Coverage on the recorded datasets.
//!
//! Test coverage: every test ID the calibration records name, with how many
//! of its records were measured and passed physical validation, were
//! measured and failed it, or were never measured, plus the records that
//! name no test ID. Completeness: every operation the calibration framework
//! registers (`SEEDED_OPERATIONS`) that no record measured.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::datasets::Dataset;
use crate::calibrate::operation::SEEDED_OPERATIONS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CoverageStatus {
    /// At least one measured record passed physical validation.
    Measured,
    /// Measured, but every value failed physical validation.
    FailedValidation,
    /// Recorded, never measured (skipped, filtered, or not backfilled).
    Unmeasured,
}

impl CoverageStatus {
    pub const ALL: [Self; 3] = [Self::Measured, Self::FailedValidation, Self::Unmeasured];
}

impl fmt::Display for CoverageStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Measured => "measured",
            Self::FailedValidation => "failed validation only",
            Self::Unmeasured => "recorded, unmeasured",
        })
    }
}

/// Records naming one test ID.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub passed: usize,
    pub failed: usize,
    pub unmeasured: usize,
}

impl Counts {
    pub const fn status(self) -> CoverageStatus {
        if self.passed > 0 {
            CoverageStatus::Measured
        } else if self.failed > 0 {
            CoverageStatus::FailedValidation
        } else {
            CoverageStatus::Unmeasured
        }
    }

    const fn add(&mut self, measured: bool, passed: bool) {
        match (measured, passed) {
            (true, true) => self.passed += 1,
            (true, false) => self.failed += 1,
            (false, _) => self.unmeasured += 1,
        }
    }
}

#[derive(Debug, Default)]
pub struct Coverage {
    /// Records per test ID, ordered by ID.
    pub tests: BTreeMap<String, Counts>,
    /// Records that name no test ID.
    pub unattributed: Counts,
    /// Registered operations no record measured, in registry order.
    pub unmeasured_operations: Vec<&'static str>,
}

impl Coverage {
    pub fn of(datasets: &[Dataset]) -> Self {
        let mut coverage = Self::default();
        let mut measured_operations = BTreeSet::new();
        for point in datasets.iter().flat_map(|dataset| &dataset.points) {
            let counts = match point.test_id.as_deref() {
                Some(test_id) => coverage.tests.entry(test_id.to_owned()).or_default(),
                None => &mut coverage.unattributed,
            };
            counts.add(point.value.is_some(), point.trusted);
            if point.value.is_some() {
                // A composed operation `a+b` measures each operand.
                measured_operations.extend(point.operation.split('+'));
            }
        }
        coverage.unmeasured_operations = SEEDED_OPERATIONS
            .iter()
            .copied()
            .filter(|operation| !measured_operations.contains(operation))
            .collect();
        coverage
    }

    /// Test IDs whose records have `status`.
    pub fn count(&self, status: CoverageStatus) -> usize {
        self.tests
            .values()
            .filter(|counts| counts.status() == status)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calibrate::grammar::OscId;
    use crate::calibrate::platform::PlatformInfo;
    use crate::calibrate::profile::Profile;
    use crate::calibrate::record::{CalibrationPoint, Source};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn point(
        raw: &str,
        test_id: Option<&str>,
        value: Option<f64>,
        trusted: bool,
    ) -> Result<CalibrationPoint, Box<dyn std::error::Error>> {
        let id: OscId = raw.parse()?;
        let mut point = CalibrationPoint::pending(
            &id,
            Profile::L6Graded,
            Source::Direct,
            None,
            PlatformInfo::detect(),
        );
        point.test_id = test_id.map(str::to_owned);
        point.value = value;
        point.trusted = trusted;
        Ok(point)
    }

    #[test]
    fn tests_take_their_strongest_evidence_and_unmeasured_operations_are_listed() -> TestResult {
        let datasets = vec![Dataset {
            name: "floors".into(),
            path: "calibration_floors.jsonl".into(),
            run: "target".into(),
            points: vec![
                point(
                    "osc:lat/device.fsync?size=4k",
                    Some("PERF-CAL-017"),
                    Some(2e6),
                    true,
                )?,
                point(
                    "osc:lat/device.fdatasync?size=4k",
                    Some("PERF-CAL-017"),
                    None,
                    true,
                )?,
                point(
                    "osc:bw/mem.copy?size=16k",
                    Some("PERF-CAL-012"),
                    Some(5e10),
                    false,
                )?,
                point("osc:lat/sys.getpid", Some("PERF-CAL-021"), None, true)?,
                point("osc:lat/sys.futex", None, Some(1.0), true)?,
                point(
                    "osc:lat/crypto.sign.ed25519+store.tag_put",
                    None,
                    Some(1.0),
                    true,
                )?,
            ],
        }];
        let coverage = Coverage::of(&datasets);
        let status: Vec<_> = coverage.tests.values().map(|c| c.status()).collect();
        assert_eq!(
            status,
            [
                CoverageStatus::FailedValidation,
                CoverageStatus::Measured,
                CoverageStatus::Unmeasured,
            ],
            "ordered PERF-CAL-012, -017, -021"
        );
        assert_eq!(coverage.tests["PERF-CAL-017"].unmeasured, 1);
        assert_eq!(coverage.unattributed.passed, 2);
        assert_eq!(coverage.count(CoverageStatus::Measured), 1);
        for measured in [
            "device.fsync",
            "mem.copy",
            "sys.futex",
            "crypto.sign.ed25519",
            "store.tag_put",
        ] {
            assert!(
                !coverage.unmeasured_operations.contains(&measured),
                "{measured} was measured"
            );
        }
        for unmeasured in ["device.fdatasync", "sys.getpid", "gc.sweep"] {
            assert!(
                coverage.unmeasured_operations.contains(&unmeasured),
                "{unmeasured} has no measured record"
            );
        }
        assert_eq!(
            coverage.unmeasured_operations.len(),
            SEEDED_OPERATIONS.len() - 5
        );
        Ok(())
    }
}
