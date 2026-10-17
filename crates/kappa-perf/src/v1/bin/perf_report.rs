//! perf-report: render the kappa-registry performance report from recorded
//! result artifacts only, then gate on it: a production path behind the
//! best reference implementation measured on its host fails the run, after
//! the report naming it is written.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use kappa_perf::calibrate::backfill::dataset_directory;
use kappa_perf::report::{CoverageStatus, Dataset, Inputs, Report, references, render};

const USAGE: &str = "\
Usage: perf-report [--datasets DIR] [--scale RESULTS_TSV]... [--out FILE]

  --datasets DIR  directory holding calibration_*.jsonl
                  (default: $KAPPA_PERF_DATASET_DIR, else the cargo target directory)
  --scale FILE    results.tsv of a succinct scale run; repeatable
  --out FILE      markdown report to write (default: <datasets>/perf-report.md)

Exit status: 0 every paired production path meets or exceeds its reference;
3 the report is written and at least one production path is behind its
reference; 1 the report could not be produced; 2 usage error.";

/// Exit status of a written report whose gate failed.
const GATE_FAILED: u8 = 3;

struct Args {
    inputs: Inputs,
    out: PathBuf,
}

fn set_once(slot: &mut Option<PathBuf>, flag: &str, value: Option<String>) -> Result<(), String> {
    let value = value.ok_or_else(|| format!("{flag} needs a value"))?;
    if slot.replace(PathBuf::from(value)).is_some() {
        return Err(format!("{flag} given twice"));
    }
    Ok(())
}

/// `Ok(None)` asks for usage.
fn parse(mut args: impl Iterator<Item = String>) -> Result<Option<Args>, String> {
    let (mut datasets, mut out) = (None, None);
    let mut scale = Vec::new();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "-h" | "--help" => return Ok(None),
            "--datasets" => set_once(&mut datasets, "--datasets", args.next())?,
            "--out" => set_once(&mut out, "--out", args.next())?,
            "--scale" => scale.push(PathBuf::from(args.next().ok_or("--scale needs a value")?)),
            other => {
                return Err(format!(
                    "unknown argument '{other}' (valid: --datasets, --scale, --out, --help)"
                ));
            }
        }
    }
    let dataset_dir = datasets
        .or_else(dataset_directory)
        .unwrap_or_else(|| PathBuf::from("target"));
    let out = out.unwrap_or_else(|| dataset_dir.join("perf-report.md"));
    Ok(Some(Args {
        inputs: Inputs { dataset_dir, scale },
        out,
    }))
}

/// Write the report; returns how many production paths are behind their
/// reference.
fn run(args: &Args) -> Result<usize, Box<dyn std::error::Error>> {
    let report = Report::collect(&args.inputs)?;
    let generated = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let document = render::markdown(&report, &args.inputs, generated)?;
    std::fs::write(&args.out, document)
        .map_err(|error| format!("{}: {error}", args.out.display()))?;

    let records: usize = report.datasets.iter().map(|d| d.points.len()).sum();
    let measured: usize = report.datasets.iter().map(|d| d.measured().count()).sum();
    let failed: usize = report.datasets.iter().map(|d| d.untrusted().count()).sum();
    eprintln!(
        "report: {} datasets, {records} records, {measured} measured, {failed} failed validation, {} scale runs",
        report.datasets.len(),
        report.scale.len()
    );
    let coverage = report.coverage();
    for status in CoverageStatus::ALL {
        eprintln!(
            "tests: {} of {} {status}",
            coverage.count(status),
            coverage.tests.len()
        );
    }
    eprintln!(
        "operations: {} registered operations without a measured record",
        coverage.unmeasured_operations.len()
    );
    let judged = report.references();
    eprintln!(
        "references: {} of {} paired production measurements meet or exceed their reference; {} unpaired",
        judged.meeting(),
        judged.paired.len(),
        judged.unpaired.len()
    );
    for paired in judged.paired.iter().filter(|p| !p.comparison.meets) {
        eprintln!(
            "  {}: {}",
            paired.point.id,
            references::verdict(paired.comparison)
        );
    }
    eprintln!("written: {}", args.out.display());
    let behind = judged.paired.len() - judged.meeting();
    // Reference records exist but none paired with a production path: the
    // reference session crashed (SIGILL, OOM, timeout) or no production
    // path was measured at the reference's conditions. Either way, "0 of 0
    // paired" must not silently pass.
    if judged.has_references && judged.paired.is_empty() {
        let reference_count = report
            .datasets
            .iter()
            .flat_map(Dataset::measured)
            .filter(|p| p.condition("impl").is_some())
            .count();
        eprintln!(
            "perf-report: gate failed: {reference_count} reference record{} exist but none paired with a production path; \
             the reference session may have crashed before recording, or no production path was measured at the reference's conditions",
            if reference_count == 1 { "" } else { "s" }
        );
        return Ok(reference_count.max(1));
    }
    Ok(behind)
}

fn main() -> ExitCode {
    match parse(std::env::args().skip(1)) {
        Ok(None) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Some(args)) => match run(&args) {
            Ok(0) => ExitCode::SUCCESS,
            Ok(behind) => {
                eprintln!(
                    "perf-report: gate failed: {behind} production path{} behind the reference implementation",
                    if behind == 1 { " is" } else { "s are" }
                );
                ExitCode::from(GATE_FAILED)
            }
            Err(error) => {
                eprintln!("perf-report: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("perf-report: {error}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}
