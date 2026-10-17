//! What a finalized session reports: measurements skipped for missing
//! dependencies, the grade aggregate per operation class (PERF-DOC-001),
//! and the session summary printed after criterion's own.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use super::record::{Grade, Roofline};

/// A measurement skipped because its dependencies were not established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkipDiagnosis {
    pub id: String,
    pub missing: Vec<String>,
}

impl fmt::Display for SkipDiagnosis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SKIPPED {}: missing {}",
            self.id,
            self.missing.join(", ")
        )
    }
}

impl std::error::Error for SkipDiagnosis {}

/// Grade aggregate for one operation class (PERF-DOC-001).
#[derive(Debug, Clone, PartialEq)]
pub struct ClassSummary {
    pub class: String,
    pub points: usize,
    pub min_fraction: f64,
    pub median_fraction: f64,
    pub worst: Grade,
}

impl ClassSummary {
    /// One aggregate per class over every graded record, ordered by class.
    /// The worst grade is the grade of the lowest achieved fraction.
    pub fn aggregate<'a>(rooflines: impl IntoIterator<Item = &'a Roofline>) -> Vec<Self> {
        let mut by_class: BTreeMap<&str, Vec<f64>> = BTreeMap::new();
        for roofline in rooflines {
            by_class
                .entry(roofline.class.as_str())
                .or_default()
                .push(roofline.fraction);
        }
        by_class
            .into_iter()
            .filter_map(|(class, mut fractions)| {
                fractions.sort_by(f64::total_cmp);
                let min_fraction = *fractions.first()?;
                Some(Self {
                    class: class.to_owned(),
                    points: fractions.len(),
                    min_fraction,
                    median_fraction: fractions[fractions.len() / 2],
                    worst: Grade::from_fraction(min_fraction),
                })
            })
            .collect()
    }
}

/// One production record against its best same-host reference.
#[derive(Debug, Clone, PartialEq)]
pub struct ReferenceLine {
    pub id: String,
    pub implementation: String,
    pub fraction: f64,
    pub meets: bool,
}

/// Outcome of a finalized session.
#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub name: String,
    pub dataset: Option<PathBuf>,
    pub measured: usize,
    pub unmeasured: Vec<(String, Vec<String>)>,
    pub untrusted: Vec<(String, Vec<String>)>,
    pub skipped: Vec<SkipDiagnosis>,
    pub classes: Vec<ClassSummary>,
    /// Production records paired with a reference implementation.
    pub references: Vec<ReferenceLine>,
    pub baseline_floors: usize,
}

impl fmt::Display for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "calibration {}: {} measured, {} unmeasured, {} untrusted, {} skipped, {} baseline floors",
            self.name,
            self.measured,
            self.unmeasured.len(),
            self.untrusted.len(),
            self.skipped.len(),
            self.baseline_floors
        )?;
        match &self.dataset {
            Some(path) => writeln!(f, "  dataset: {}", path.display())?,
            None => writeln!(f, "  dataset: not written (nothing measured)")?,
        }
        for class in &self.classes {
            writeln!(
                f,
                "  {}: {} points, worst {:?} (min {:.3}, median {:.3})",
                class.class, class.points, class.worst, class.min_fraction, class.median_fraction
            )?;
        }
        if !self.references.is_empty() {
            writeln!(
                f,
                "  references: {} of {} production measurements meet or exceed their best reference",
                self.references.iter().filter(|r| r.meets).count(),
                self.references.len()
            )?;
            for line in self.references.iter().filter(|r| !r.meets) {
                writeln!(
                    f,
                    "  behind {}: {} at {:.3} of it",
                    line.implementation, line.id, line.fraction
                )?;
            }
        }
        for (id, why) in self.unmeasured.iter().chain(&self.untrusted) {
            writeln!(f, "  {id}: {}", why.join("; "))?;
        }
        for skip in &self.skipped {
            writeln!(f, "  {skip}")?;
        }
        Ok(())
    }
}
