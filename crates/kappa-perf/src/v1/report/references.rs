//! Production paths against reference implementations.
//!
//! Every production record the calibration paired with a reference
//! implementation (`CalibrationPoint::reference`): the reference, the
//! fraction of it achieved and the verdict, worst first. Then every
//! measured production record of an operation that has a reference on its
//! host but none at its conditions, so an unpaired measurement is visible
//! rather than silently unjudged.

use std::fmt::{self, Write as _};

use super::datasets::Dataset;
use super::format::{cell, value};
use crate::calibrate::record::{CalibrationPoint, ReferenceComparison};
use crate::calibrate::reference::IMPL;

/// A production record and the reference it was judged against.
#[derive(Debug)]
pub struct Paired<'a> {
    pub session: &'a str,
    pub point: &'a CalibrationPoint,
    pub comparison: &'a ReferenceComparison,
}

/// Every judgement against a reference in the recorded datasets.
#[derive(Debug, Default)]
pub struct References<'a> {
    /// Paired production records, lowest fraction first.
    pub paired: Vec<Paired<'a>>,
    /// Measured production records of an operation with a same-host
    /// reference, but none at their conditions.
    pub unpaired: Vec<(&'a str, &'a CalibrationPoint)>,
    /// Whether any measured record in the datasets carries an `impl`
    /// condition: a reference implementation was measured. When true and
    /// `paired` is empty, every reference record crashed or failed to
    /// pair with a production path, and the gate must fail rather than
    /// silently passing on "0 of 0".
    pub has_references: bool,
}

fn is_reference(point: &CalibrationPoint) -> bool {
    point.condition(IMPL).is_some()
}

impl<'a> References<'a> {
    pub fn of(datasets: &'a [Dataset]) -> Self {
        let measured: Vec<(&str, &CalibrationPoint)> = datasets
            .iter()
            .flat_map(|d| d.measured().map(move |p| (d.name.as_str(), p)))
            .collect();
        let references: Vec<&CalibrationPoint> = measured
            .iter()
            .map(|(_, p)| *p)
            .filter(|p| is_reference(p))
            .collect();
        let mut out = Self {
            has_references: !references.is_empty(),
            ..Self::default()
        };
        for (session, point) in &measured {
            if is_reference(point) {
                continue;
            }
            if let Some(comparison) = &point.reference {
                out.paired.push(Paired {
                    session,
                    point,
                    comparison,
                });
            } else if references.iter().any(|r| {
                r.quantity == point.quantity
                    && r.operation == point.operation
                    && r.platform.same_host(&point.platform)
            }) {
                out.unpaired.push((session, point));
            }
        }
        out.paired.sort_by(|a, b| {
            a.comparison
                .fraction
                .total_cmp(&b.comparison.fraction)
                .then_with(|| a.point.id.cmp(&b.point.id))
        });
        out
    }

    pub fn meeting(&self) -> usize {
        self.paired.iter().filter(|p| p.comparison.meets).count()
    }
}

/// The verdict of one judgement, in words.
pub fn verdict(comparison: &ReferenceComparison) -> String {
    if comparison.meets {
        format!(
            "meets: {:.3}x {}",
            comparison.fraction, comparison.implementation
        )
    } else {
        format!(
            "behind: {:.3} of {}",
            comparison.fraction, comparison.implementation
        )
    }
}

pub fn render(out: &mut String, references: &References<'_>) -> fmt::Result {
    writeln!(
        out,
        "## Production paths against reference implementations\n"
    )?;
    if references.paired.is_empty() && references.unpaired.is_empty() {
        return writeln!(out, "No reference implementation was measured.\n");
    }
    writeln!(
        out,
        "{} of {} paired production measurements meet or exceed the best reference implementation measured on their host. A fraction is the share of the reference achieved, oriented so that 1.0 matches it.\n",
        references.meeting(),
        references.paired.len()
    )?;
    if !references.paired.is_empty() {
        writeln!(
            out,
            "| Session | Production path | Value | Reference | Reference value | Fraction | Verdict |"
        )?;
        writeln!(out, "|---|---|---:|---|---:|---:|---|")?;
        for paired in &references.paired {
            let measured = paired.point.value.map_or_else(
                || "-".into(),
                |measured| value(measured, &paired.point.unit),
            );
            writeln!(
                out,
                "| {} | `{}` | {measured} | `{}` | {} | {:.3} | {} |",
                paired.session,
                cell(&paired.point.id),
                cell(&paired.comparison.reference_id),
                value(paired.comparison.reference_value, &paired.point.unit),
                paired.comparison.fraction,
                verdict(paired.comparison)
            )?;
        }
        writeln!(out)?;
    }
    if !references.unpaired.is_empty() {
        writeln!(
            out,
            "Production measurements of an operation with a reference on their host, but none at their conditions ({}):\n",
            references.unpaired.len()
        )?;
        for (session, point) in &references.unpaired {
            writeln!(out, "- {session}: `{}`", cell(&point.id))?;
        }
        writeln!(out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calibrate::grammar::OscId;
    use crate::calibrate::platform::PlatformInfo;
    use crate::calibrate::profile::Profile;
    use crate::calibrate::record::Source;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn point(
        raw: &str,
        value: f64,
        reference: Option<ReferenceComparison>,
    ) -> Result<CalibrationPoint, Box<dyn std::error::Error>> {
        let id: OscId = raw.parse()?;
        let mut point = CalibrationPoint::pending(
            &id,
            Profile::L6Graded,
            Source::Direct,
            None,
            PlatformInfo::detect(),
        );
        point.value = Some(value);
        point.reference = reference;
        Ok(point)
    }

    fn against(fraction: f64) -> ReferenceComparison {
        ReferenceComparison {
            reference_id: "osc:bw/hash.sha256?impl=aws_lc&size=64k".into(),
            implementation: "aws_lc".into(),
            reference_value: 4.6e8,
            fraction,
            meets: fraction >= 1.0,
            reference_from_baseline: false,
        }
    }

    #[test]
    fn judgements_order_worst_first_and_unpaired_production_paths_are_listed() -> TestResult {
        let datasets = vec![Dataset {
            name: "floors".into(),
            path: "calibration_floors.jsonl".into(),
            points: vec![
                point("osc:bw/hash.sha256?size=64k", 1.4e8, Some(against(0.304)))?,
                point("osc:bw/hash.blake3?size=64k", 4.0e9, Some(against(1.05)))?,
                point("osc:bw/hash.sha256?impl=aws_lc&size=64k", 4.6e8, None)?,
                point("osc:bw/hash.sha256?size=4k", 1.3e8, None)?,
                point("osc:bw/mem.read?size=64k", 1e10, None)?,
            ],
        }];
        let references = References::of(&datasets);
        assert_eq!(references.paired.len(), 2);
        assert!(
            references.paired[0].comparison.fraction < 1.0,
            "worst first"
        );
        assert_eq!(references.meeting(), 1);
        let unpaired: Vec<&str> = references
            .unpaired
            .iter()
            .map(|(_, p)| p.id.as_str())
            .collect();
        assert_eq!(
            unpaired,
            ["osc:bw/hash.sha256?size=4k"],
            "operations without any reference are not listed"
        );
        assert!(references.has_references);
        let mut rendered = String::new();
        render(&mut rendered, &references)?;
        assert!(rendered.contains("1 of 2 paired production measurements"));
        assert!(rendered.contains("behind: 0.304 of aws_lc"));
        assert!(rendered.contains("meets: 1.050x aws_lc"));
        Ok(())
    }

    #[test]
    fn has_references_is_false_when_no_impl_records_exist() -> TestResult {
        let datasets = vec![Dataset {
            name: "floors".into(),
            path: "calibration_floors.jsonl".into(),
            points: vec![
                point("osc:bw/hash.sha256?size=64k", 1.4e8, None)?,
                point("osc:bw/mem.read?size=64k", 1e10, None)?,
            ],
        }];
        let references = References::of(&datasets);
        assert!(!references.has_references);
        assert!(references.paired.is_empty());
        assert!(references.unpaired.is_empty());
        Ok(())
    }

    #[test]
    fn has_references_is_true_even_when_none_paired() -> TestResult {
        // A reference record exists but no production record shares its
        // conditions minus `impl`: the crash-or-missing-production scenario.
        let datasets = vec![Dataset {
            name: "floors".into(),
            path: "calibration_floors.jsonl".into(),
            points: vec![
                point("osc:bw/hash.sha256?impl=aws_lc&size=64k", 4.6e8, None)?,
                // No production osc:bw/hash.sha256?size=64k
                point("osc:bw/mem.read?size=64k", 1e10, None)?,
            ],
        }];
        let references = References::of(&datasets);
        assert!(references.has_references);
        assert!(references.paired.is_empty());
        // mem.read has no reference at all, so it is not unpaired
        assert!(references.unpaired.is_empty());
        Ok(())
    }
}
