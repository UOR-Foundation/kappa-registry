//! Succinct scale runs: the `results.tsv` that `scripts/succinct-scale.sh`
//! writes, one row per rung with the run's `scale_result` fields in named
//! columns.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{ReportError, io_error};

/// Columns every results.tsv carries.
const REQUIRED: [&str; 4] = ["keys", "population", "exit_status", "log"];

/// One rung: a population at a key count, run in its own resource-capped
/// scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaleRung {
    pub keys: u64,
    pub population: String,
    pub exit_status: i32,
    pub log: String,
    /// The run's `scale_result` fields by column name; empty when the run
    /// failed before recording them.
    pub metrics: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaleRun {
    pub path: PathBuf,
    /// Metric columns in file order.
    pub columns: Vec<String>,
    pub rungs: Vec<ScaleRung>,
}

pub fn load(path: &Path) -> Result<ScaleRun, ReportError> {
    let content = std::fs::read_to_string(path).map_err(io_error(path))?;
    parse(path, &content)
}

fn parse(path: &Path, content: &str) -> Result<ScaleRun, ReportError> {
    let error = |line: usize, reason: String| ReportError::Scale {
        path: path.to_owned(),
        line,
        reason,
    };
    let mut lines = content.lines().enumerate();
    let header: Vec<&str> = lines
        .next()
        .ok_or_else(|| error(1, "empty results file".into()))?
        .1
        .split('\t')
        .collect();
    if header[..header.len().min(REQUIRED.len())] != REQUIRED {
        return Err(error(
            1,
            format!("header must begin with {REQUIRED:?}, found {header:?}"),
        ));
    }
    let columns: Vec<String> = header[REQUIRED.len()..]
        .iter()
        .map(|&column| column.to_owned())
        .collect();
    let mut rungs = Vec::new();
    for (index, line) in lines {
        if line.is_empty() {
            continue;
        }
        let number = index + 1;
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != header.len() {
            return Err(error(
                number,
                format!("{} fields for {} columns", fields.len(), header.len()),
            ));
        }
        let keys = fields[0]
            .parse()
            .map_err(|_| error(number, format!("keys '{}' is not a count", fields[0])))?;
        let exit_status = fields[2].parse().map_err(|_| {
            error(
                number,
                format!("exit status '{}' is not an integer", fields[2]),
            )
        })?;
        let mut metrics = BTreeMap::new();
        for (column, value) in columns.iter().zip(&fields[REQUIRED.len()..]) {
            if value.is_empty() {
                continue;
            }
            let value = value
                .parse()
                .map_err(|_| error(number, format!("{column} '{value}' is not an integer")))?;
            metrics.insert(column.clone(), value);
        }
        if exit_status == 0 && metrics.len() != columns.len() {
            return Err(error(
                number,
                "a successful rung must record every metric column".into(),
            ));
        }
        rungs.push(ScaleRung {
            keys,
            population: fields[1].to_owned(),
            exit_status,
            log: fields[3].to_owned(),
            metrics,
        });
    }
    Ok(ScaleRun {
        path: path.to_owned(),
        columns,
        rungs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rungs_parse_with_metrics_and_failures_keep_their_row() -> Result<(), ReportError> {
        let content = "keys\tpopulation\texit_status\tlog\telapsed_ns\tpeak_rss_kib\n\
                       512\tsha256\t0\t/tmp/a.log\t779700000\t35636\n\
                       1000000\tsha512\t137\t/tmp/b.log\t\t\n";
        let run = parse(Path::new("results.tsv"), content)?;
        assert_eq!(run.columns, ["elapsed_ns", "peak_rss_kib"]);
        assert_eq!(run.rungs.len(), 2);
        assert_eq!(run.rungs[0].metrics.get("peak_rss_kib"), Some(&35_636));
        assert_eq!(run.rungs[1].exit_status, 137);
        assert!(run.rungs[1].metrics.is_empty());
        Ok(())
    }

    #[test]
    fn malformed_results_are_errors() {
        for bad in [
            "",
            "population\tkeys\texit_status\tlog\n",
            "keys\tpopulation\texit_status\tlog\telapsed_ns\n512\tsha256\t0\t/a\n",
            "keys\tpopulation\texit_status\tlog\telapsed_ns\n512\tsha256\t0\t/a\t\n",
            "keys\tpopulation\texit_status\tlog\telapsed_ns\n512\tsha256\t0\t/a\t1.5\n",
            "keys\tpopulation\texit_status\tlog\nmany\tsha256\t0\t/a\n",
        ] {
            assert!(
                matches!(
                    parse(Path::new("results.tsv"), bad),
                    Err(ReportError::Scale { .. })
                ),
                "{bad:?} must be rejected"
            );
        }
    }
}
