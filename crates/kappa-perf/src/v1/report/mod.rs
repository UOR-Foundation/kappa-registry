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
    /// Directory holding `calibration_*.jsonl`: one run's directory, or
    /// the cargo target directory.
    pub dataset_dir: PathBuf,
    /// `results.tsv` of each succinct scale run to include.
    pub scale: Vec<PathBuf>,
}

/// Everything the report contains.
#[derive(Debug)]
pub struct Report {
    pub datasets: Vec<Dataset>,
    pub scale: Vec<ScaleRun>,
}

impl Report {
    pub fn collect(inputs: &Inputs) -> Result<Self, ReportError> {
        Ok(Self {
            datasets: datasets::load_all(&inputs.dataset_dir)?,
            scale: inputs
                .scale
                .iter()
                .map(|path| scale::load(path))
                .collect::<Result<_, _>>()?,
        })
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
