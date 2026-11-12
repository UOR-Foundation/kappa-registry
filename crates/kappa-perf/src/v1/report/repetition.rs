//! Repetition across runs.
//!
//! One run directory holds one process's records of each measurement.
//! Criterion's confidence interval is a within-process interval, resampled
//! from one process's samples with a wall-clock seed, so it says nothing
//! about run-to-run variance; a defensible interval over a measurement
//! needs the measurement repeated in separate processes. When the report
//! is given several run directories, every identifier measured in more than
//! one of them is aggregated here: how many runs, the median, the least and
//! greatest value, and the seed of each run, so a run that disagrees can be
//! reproduced from its seed. One run renders as one run, n = 1 stated.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

use super::datasets::Dataset;
use super::format::{cell, value};
use crate::calibrate::record::CalibrationPoint;

/// One identifier's measured values across runs.
#[derive(Debug)]
pub struct Repeated<'a> {
    pub session: &'a str,
    pub id: &'a str,
    pub unit: &'a str,
    /// (run directory, value, seed), in run order.
    pub runs: Vec<(&'a std::path::Path, f64, Option<u64>)>,
}

impl Repeated<'_> {
    pub fn n(&self) -> usize {
        self.runs.len()
    }

    fn sorted_values(&self) -> Vec<f64> {
        let mut values: Vec<f64> = self.runs.iter().map(|(_, value, _)| *value).collect();
        values.sort_by(f64::total_cmp);
        values
    }

    /// The median of the runs' values: the middle value, or the mean of
    /// the two middle values.
    pub fn median(&self) -> Option<f64> {
        let values = self.sorted_values();
        let n = values.len();
        if n == 0 {
            return None;
        }
        Some(if n.is_multiple_of(2) {
            f64::midpoint(values[n / 2 - 1], values[n / 2])
        } else {
            values[n / 2]
        })
    }

    pub fn min(&self) -> Option<f64> {
        self.sorted_values().first().copied()
    }

    pub fn max(&self) -> Option<f64> {
        self.sorted_values().last().copied()
    }

    /// Greatest value over least: how far the runs disagree.
    pub fn spread(&self) -> Option<f64> {
        let (min, max) = (self.min()?, self.max()?);
        (min > 0.0).then(|| max / min)
    }
}

/// Every identifier measured in more than one run.
#[derive(Debug, Default)]
pub struct Repetitions<'a> {
    /// Ordered by session then identifier.
    pub repeated: Vec<Repeated<'a>>,
    /// Distinct run directories the datasets came from.
    pub runs: usize,
}

impl<'a> Repetitions<'a> {
    pub fn of(datasets: &'a [Dataset]) -> Self {
        let mut runs: Vec<&std::path::Path> = Vec::new();
        let mut by_id: BTreeMap<(&str, &str), Repeated<'a>> = BTreeMap::new();
        for dataset in datasets {
            if !runs.contains(&dataset.run.as_path()) {
                runs.push(dataset.run.as_path());
            }
            for point in dataset.measured() {
                let Some(measured) = point.value else {
                    continue;
                };
                by_id
                    .entry((dataset.name.as_str(), point.id.as_str()))
                    .or_insert_with(|| Repeated {
                        session: dataset.name.as_str(),
                        id: point.id.as_str(),
                        unit: point.unit.as_str(),
                        runs: Vec::new(),
                    })
                    .runs
                    .push((dataset.run.as_path(), measured, point.seed));
            }
        }
        Self {
            repeated: by_id
                .into_values()
                .filter(|repeated| repeated.n() > 1)
                .collect(),
            runs: runs.len(),
        }
    }
}

/// The seed of a point as shown in the seeds column.
fn seed_text(point: Option<u64>) -> String {
    point.map_or_else(|| "-".into(), |seed| format!("{seed:#x}"))
}

pub fn render(out: &mut String, repetitions: &Repetitions<'_>) -> fmt::Result {
    writeln!(out, "## Repetition across runs\n")?;
    if repetitions.runs < 2 {
        return writeln!(
            out,
            "One run: every value is n = 1, and its criterion interval is a within-process interval only. Give several run directories to aggregate across processes.\n"
        );
    }
    writeln!(
        out,
        "{} run directories; {} identifiers measured in more than one run. Median, least and greatest are over the runs' recorded values; the seeds reproduce each run.\n",
        repetitions.runs,
        repetitions.repeated.len()
    )?;
    if repetitions.repeated.is_empty() {
        return writeln!(out);
    }
    writeln!(
        out,
        "| Session | Identifier | n | Median | Least | Greatest | Greatest / least | Seeds |"
    )?;
    writeln!(out, "|---|---|---:|---:|---:|---:|---:|---|")?;
    for repeated in &repetitions.repeated {
        let shown = |value_of: Option<f64>| {
            value_of.map_or_else(|| "-".into(), |v| value(v, repeated.unit))
        };
        let seeds: Vec<String> = repeated
            .runs
            .iter()
            .map(|(_, _, seed)| seed_text(*seed))
            .collect();
        writeln!(
            out,
            "| {} | `{}` | {} | {} | {} | {} | {} | {} |",
            repeated.session,
            cell(repeated.id),
            repeated.n(),
            shown(repeated.median()),
            shown(repeated.min()),
            shown(repeated.max()),
            repeated
                .spread()
                .map_or_else(|| "-".into(), |spread| format!("{spread:.3}")),
            cell(&seeds.join(" "))
        )?;
    }
    writeln!(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calibrate::grammar::OscId;
    use crate::calibrate::platform::PlatformInfo;
    use crate::calibrate::profile::Profile;
    use crate::calibrate::record::Source;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn dataset(
        run: &str,
        values: &[(&str, f64, u64)],
    ) -> Result<Dataset, Box<dyn std::error::Error>> {
        let mut points = Vec::new();
        for (raw, measured, seed) in values {
            let id: OscId = raw.parse()?;
            let mut point = CalibrationPoint::pending(
                &id,
                Profile::L6Graded,
                Source::Direct,
                None,
                PlatformInfo::detect(),
            );
            point.value = Some(*measured);
            point.seed = Some(*seed);
            points.push(point);
        }
        Ok(Dataset {
            name: "floors".into(),
            path: format!("{run}/calibration_floors.jsonl").into(),
            run: run.into(),
            points,
        })
    }

    #[test]
    fn identifiers_measured_in_several_runs_aggregate_with_their_seeds() -> TestResult {
        let datasets = vec![
            dataset(
                "run-a",
                &[
                    ("osc:lat/device.fsync?size=4k", 1_000.0, 1),
                    ("osc:bw/mem.read?size=1m", 1e10, 1),
                ],
            )?,
            dataset("run-b", &[("osc:lat/device.fsync?size=4k", 3_000.0, 2)])?,
            dataset("run-c", &[("osc:lat/device.fsync?size=4k", 2_000.0, 3)])?,
        ];
        let repetitions = Repetitions::of(&datasets);
        assert_eq!(repetitions.runs, 3);
        assert_eq!(repetitions.repeated.len(), 1, "mem.read ran once");
        let fsync = &repetitions.repeated[0];
        assert_eq!(fsync.n(), 3);
        assert_eq!(fsync.median(), Some(2_000.0));
        assert_eq!(fsync.min(), Some(1_000.0));
        assert_eq!(fsync.max(), Some(3_000.0));
        assert_eq!(fsync.spread(), Some(3.0));
        let mut rendered = String::new();
        render(&mut rendered, &repetitions)?;
        assert!(rendered.contains("3 run directories"), "{rendered}");
        assert!(
            rendered.contains("| 3 | 2.000 us | 1.000 us | 3.000 us | 3.000 | 0x1 0x2 0x3 |"),
            "{rendered}"
        );

        let one = Repetitions::of(&datasets[..1]);
        assert_eq!(one.runs, 1);
        assert!(one.repeated.is_empty());
        let mut rendered = String::new();
        render(&mut rendered, &one)?;
        assert!(rendered.contains("One run"), "{rendered}");
        Ok(())
    }

    #[test]
    fn an_even_count_takes_the_mean_of_the_middle_two() -> TestResult {
        let datasets = vec![
            dataset("a", &[("osc:lat/device.fsync?size=4k", 1_000.0, 1)])?,
            dataset("b", &[("osc:lat/device.fsync?size=4k", 2_000.0, 2)])?,
            dataset("c", &[("osc:lat/device.fsync?size=4k", 4_000.0, 3)])?,
            dataset("d", &[("osc:lat/device.fsync?size=4k", 8_000.0, 4)])?,
        ];
        let repetitions = Repetitions::of(&datasets);
        assert_eq!(repetitions.repeated[0].median(), Some(3_000.0));
        Ok(())
    }
}
