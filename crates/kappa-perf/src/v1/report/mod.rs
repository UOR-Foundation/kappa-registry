//! The performance report.
//!
//! A pure function of recorded result artifacts: every
//! `calibration_<session>.jsonl` dataset in one dataset directory and
//! the `results.tsv` of each succinct scale run given. Renders one document
//! with the host calibration attached to the numbers measured on it. No
//! number enters the report by hand, and nothing recorded is left out:
//! records that failed validation or were never measured are listed with
//! their diagnoses, every production path is judged against the best
//! reference implementation measured on its host, test coverage comes from
//! the test IDs the records name, and completeness is checked against the
//! operations the calibration framework registers.

pub mod coverage;
pub mod datasets;
pub mod format;
pub mod hosts;
pub mod references;
pub mod render;
pub mod repetition;
pub mod scale;

use std::path::{Path, PathBuf};

pub use coverage::{Coverage, CoverageStatus};
pub use datasets::Dataset;
pub use references::References;
pub use scale::ScaleRun;

#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path}:{line}: {source}")]
    Json {
        path: PathBuf,
        line: usize,
        source: serde_json::Error,
    },
    #[error("{path}:{line}: {reason}")]
    Scale {
        path: PathBuf,
        line: usize,
        reason: String,
    },
    #[error("rendering: {0}")]
    Render(#[from] std::fmt::Error),
}

pub(crate) fn io_error(path: &Path) -> impl FnOnce(std::io::Error) -> ReportError + '_ {
    move |source| ReportError::Io {
        path: path.to_owned(),
        source,
    }
}

/// The result artifacts the report reads.
#[derive(Debug, Clone)]
pub struct Inputs {
    /// Directories holding `calibration_*.jsonl`, one per run: a single
    /// run's directory (or the cargo target directory), or several runs of
    /// the same benches whose records the report aggregates across runs.
    /// Criterion's confidence interval is within one process; an interval
    /// over repeated processes exists only when more than one directory is
    /// given.
    pub dataset_dirs: Vec<PathBuf>,
    /// `results.tsv` of each succinct scale run to include.
    pub scale: Vec<PathBuf>,
}

/// Everything the report contains.
#[derive(Debug)]
pub struct Report {
    /// Every session dataset of every run, in run order then session order.
    pub datasets: Vec<Dataset>,
    pub scale: Vec<ScaleRun>,
}

impl Report {
    pub fn collect(inputs: &Inputs) -> Result<Self, ReportError> {
        let mut datasets = Vec::new();
        for dir in &inputs.dataset_dirs {
            datasets.extend(datasets::load_all(dir)?);
        }
        Ok(Self {
            datasets,
            scale: inputs
                .scale
                .iter()
                .map(|path| scale::load(path))
                .collect::<Result<_, _>>()?,
        })
    }

    /// Records of one identifier across runs: the across-process
    /// repetition the report aggregates (`repetition::Repetitions`).
    pub fn repetitions(&self) -> repetition::Repetitions<'_> {
        repetition::Repetitions::of(&self.datasets)
    }

    /// Test coverage and completeness of the recorded datasets.
    pub fn coverage(&self) -> Coverage {
        Coverage::of(&self.datasets)
    }

    /// Production paths judged against reference implementations.
    pub fn references(&self) -> References<'_> {
        References::of(&self.datasets)
    }
}
