//! The report as one markdown document.

use std::fmt::{self, Write as _};

use super::coverage::{Coverage, CoverageStatus};
use super::datasets::Dataset;
use super::format::{cell, duration, ns, value};
use super::hosts::{Host, hosts};
use super::references;
use super::scale::ScaleRun;
use super::{Inputs, Report, ReportError};
use crate::calibrate::record::CalibrationPoint;
use crate::calibrate::summary::ClassSummary;

pub fn markdown(
    report: &Report,
    inputs: &Inputs,
    generated_unix_s: u64,
) -> Result<String, ReportError> {
    let mut out = String::new();
    header(&mut out, report, inputs, generated_unix_s)?;
    let hosts = hosts(&report.datasets);
    for host in &hosts {
        host_section(&mut out, report, host)?;
    }
    measurements(&mut out, report)?;
    references::render(&mut out, &report.references())?;
    problems(&mut out, report)?;
    for run in &report.scale {
        scale_section(&mut out, run)?;
    }
    coverage_section(&mut out, &report.coverage())?;
    Ok(out)
}

fn header(
    out: &mut String,
    report: &Report,
    inputs: &Inputs,
    generated_unix_s: u64,
) -> fmt::Result {
    writeln!(out, "# kappa-registry performance report\n")?;
    writeln!(
        out,
        "Generated from recorded results only at unix time {generated_unix_s}.\n"
    )?;
    writeln!(
        out,
        "- Calibration datasets: `{}`",
        inputs.dataset_dir.display()
    )?;
    for path in &inputs.scale {
        writeln!(out, "- Scale run: `{}`", path.display())?;
    }
    writeln!(out)?;
    if report.datasets.is_empty() {
        writeln!(out, "No calibration dataset was found.\n")?;
        return Ok(());
    }
    writeln!(out, "## Datasets\n")?;
    writeln!(
        out,
        "| Session | File | Records | Measured | Unmeasured | Untrusted |"
    )?;
    writeln!(out, "|---|---|---:|---:|---:|---:|")?;
    for dataset in &report.datasets {
        let measured = dataset.measured().count();
        writeln!(
            out,
            "| {} | `{}` | {} | {measured} | {} | {} |",
            dataset.name,
            dataset.path.display(),
            dataset.points.len(),
            dataset.points.len() - measured,
            dataset.untrusted().count()
        )?;
    }
    writeln!(out)
}

const fn yes_no(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "on",
        Some(false) => "off",
        None => "not exposed",
    }
}

#[allow(
    clippy::cast_precision_loss,
    reason = "byte counts displayed with three decimals; exact above 2^53 is not needed"
)]
fn host_section(out: &mut String, report: &Report, host: &Host<'_>) -> fmt::Result {
    let p = host.platform;
    let shown = |value: Option<&str>| value.unwrap_or("not exposed").to_owned();
    writeln!(
        out,
        "## Host {}\n",
        p.hostname.as_deref().unwrap_or("(unnamed)")
    )?;
    let caches: Vec<String> = p
        .caches
        .iter()
        .map(|c| {
            format!(
                "L{} {} {}",
                c.level,
                c.kind,
                value(c.size_bytes as f64, "bytes")
            )
        })
        .collect();
    let affected: Vec<String> = p
        .mitigations
        .iter()
        .filter(|(_, status)| status != "Not affected")
        .map(|(name, status)| format!("{name}: {status}"))
        .collect();
    let rows: [(&str, String); 16] = [
        ("CPU", shown(p.cpu_model.as_deref())),
        ("Microcode", shown(p.microcode.as_deref())),
        ("Host class", format!("{:?}", p.host_class)),
        ("Dispatch ISA", p.dispatch_flags.join(" ")),
        (
            "Topology",
            format!(
                "{} sockets, {} cores, {} logical CPUs, {} NUMA nodes",
                p.sockets.map_or_else(|| "?".into(), |n| n.to_string()),
                p.physical_cores
                    .map_or_else(|| "?".into(), |n| n.to_string()),
                p.logical_cpus,
                p.numa_nodes.map_or_else(|| "?".into(), |n| n.to_string())
            ),
        ),
        ("Caches", caches.join(", ")),
        (
            "Memory",
            p.memory_bytes
                .map_or_else(|| "not exposed".into(), |b| value(b as f64, "bytes")),
        ),
        ("Kernel", shown(p.kernel.as_deref())),
        ("Governor", shown(p.governor.as_deref())),
        ("Turbo", yes_no(p.turbo_enabled).to_owned()),
        ("SMT", yes_no(p.smt_active).to_owned()),
        (
            "Transparent huge pages",
            shown(p.transparent_hugepages.as_deref()),
        ),
        ("Isolated CPUs", shown(p.isolated_cpus.as_deref())),
        ("Mitigations in effect", affected.join("; ")),
        (
            "Toolchain",
            format!(
                "{}, profile {}, opt-level {}, target {}, RUSTFLAGS '{}'",
                p.toolchain.rustc,
                p.toolchain.profile,
                p.toolchain.opt_level,
                p.toolchain.target,
                p.toolchain.rustflags
            ),
        ),
        (
            "Accelerators",
            format!("{} GPUs, {} RDMA devices", p.gpus, p.rdma_devices),
        ),
    ];
    writeln!(out, "| Property | Value |\n|---|---|")?;
    for (name, text) in rows {
        writeln!(out, "| {name} | {} |", cell(&text))?;
    }
    let sessions: Vec<String> = host
        .sessions
        .iter()
        .map(|(name, count)| format!("{name} ({count})"))
        .collect();
    writeln!(out, "\nMeasured here: {}.\n", sessions.join(", "))?;
    let findings = host.findings();
    if findings.is_empty() {
        writeln!(out, "Run conditions admit gated grades.\n")?;
    } else {
        writeln!(out, "Run conditions that bar gated grades on this host:\n")?;
        for finding in findings {
            writeln!(out, "- {finding}")?;
        }
        writeln!(out)?;
    }
    grades(out, report, host)
}

/// Grade aggregate per roofline operation class for one host.
fn grades(out: &mut String, report: &Report, host: &Host<'_>) -> fmt::Result {
    let classes = ClassSummary::aggregate(
        report
            .datasets
            .iter()
            .flat_map(Dataset::measured)
            .filter(|point| point.platform.same_host(host.platform))
            .filter_map(|point| point.roofline.as_ref()),
    );
    if classes.is_empty() {
        return writeln!(out, "No measurement on this host was graded.\n");
    }
    writeln!(
        out,
        "| Operation class | Graded points | Worst grade | Min fraction | Median fraction |"
    )?;
    writeln!(out, "|---|---:|---|---:|---:|")?;
    for class in &classes {
        writeln!(
            out,
            "| {} | {} | {:?} | {:.3} | {:.3} |",
            class.class, class.points, class.worst, class.min_fraction, class.median_fraction
        )?;
    }
    if let Some(worst) = classes
        .iter()
        .min_by(|a, b| a.min_fraction.total_cmp(&b.min_fraction))
    {
        writeln!(
            out,
            "\nAggregate: worst grade {:?} ({} at {:.3} of its bound).\n",
            worst.worst, worst.class, worst.min_fraction
        )?;
    }
    Ok(())
}

fn distribution(point: &CalibrationPoint) -> String {
    if let Some(p) = &point.latency {
        return format!(
            "p50 {}, p90 {}, p99 {}, p99.9 {}, max {}, n={}",
            ns(p.p50_ns),
            ns(p.p90_ns),
            ns(p.p99_ns),
            ns(p.p999_ns),
            ns(p.max_ns),
            p.count
        );
    }
    if let Some(c) = &point.criterion {
        let change = c.change_mean.map_or_else(String::new, |change| {
            format!(", change {:+.2}%", change * 100.0)
        });
        return format!(
            "{} {} per iteration [{}, {}] at {:.0}%, {} samples{change}",
            c.typical_estimator,
            duration(c.typical_ns),
            duration(c.ci_lower_ns),
            duration(c.ci_upper_ns),
            c.confidence_level * 100.0,
            c.samples
        );
    }
    "recorded directly".into()
}

fn measurements(out: &mut String, report: &Report) -> fmt::Result {
    for dataset in &report.datasets {
        writeln!(out, "## Measurements: {}\n", dataset.name)?;
        writeln!(
            out,
            "| Identifier | Test | Value | Distribution | Roofline | Against floor | Against reference | Trusted |"
        )?;
        writeln!(out, "|---|---|---:|---|---|---|---|---|")?;
        for point in dataset.measured() {
            let Some(measured) = point.value else {
                continue;
            };
            let roofline = point.roofline.as_ref().map_or_else(
                || "-".into(),
                |r| format!("{} {:?} ({:.3})", r.class, r.grade, r.fraction),
            );
            let floor = point.baseline.as_ref().map_or_else(
                || "-".into(),
                |b| format!("{:.3}x slower than {}", b.slowdown, b.floor_id),
            );
            let failed: Vec<&str> = point
                .validations
                .iter()
                .filter(|v| !v.passed)
                .map(|v| v.rule.as_str())
                .collect();
            let trusted = if point.trusted && failed.is_empty() {
                "yes".to_owned()
            } else if point.trusted {
                format!("yes; warned: {}", failed.join(", "))
            } else {
                format!("no: {}", failed.join(", "))
            };
            let against_reference = point
                .reference
                .as_ref()
                .map_or_else(|| "-".into(), references::verdict);
            writeln!(
                out,
                "| `{}` | {} | {} | {} | {} | {} | {} | {} |",
                cell(&point.id),
                point.test_id.as_deref().unwrap_or("-"),
                value(measured, &point.unit),
                cell(&distribution(point)),
                cell(&roofline),
                cell(&floor),
                cell(&against_reference),
                cell(&trusted)
            )?;
        }
        writeln!(out)?;
    }
    Ok(())
}

fn problems(out: &mut String, report: &Report) -> fmt::Result {
    let listed: Vec<(&str, &CalibrationPoint)> = report
        .datasets
        .iter()
        .flat_map(|d| d.points.iter().map(move |p| (d.name.as_str(), p)))
        .filter(|(_, p)| p.value.is_none() || !p.trusted || !p.diagnosis.is_empty())
        .collect();
    writeln!(out, "## Untrusted, unmeasured and diagnosed records\n")?;
    if listed.is_empty() {
        return writeln!(out, "None.\n");
    }
    writeln!(
        out,
        "| Session | Identifier | State | Diagnosis |\n|---|---|---|---|"
    )?;
    for (session, point) in listed {
        let state = match (point.value.is_some(), point.trusted) {
            (false, _) => "unmeasured",
            (true, false) => "untrusted",
            (true, true) => "measured",
        };
        writeln!(
            out,
            "| {session} | `{}` | {state} | {} |",
            cell(&point.id),
            cell(&point.diagnosis.join("; "))
        )?;
    }
    writeln!(out)
}

/// A scale metric column by its unit suffix: `_ns` is time, `_kib` is
/// memory, anything else is a count.
#[allow(
    clippy::cast_precision_loss,
    reason = "byte counts displayed with three decimals; exact above 2^53 is not needed"
)]
fn metric(column: &str, raw: u64) -> String {
    if column.ends_with("_ns") {
        ns(raw)
    } else if column.ends_with("_kib") {
        value(raw.saturating_mul(1024) as f64, "bytes")
    } else {
        raw.to_string()
    }
}

fn scale_section(out: &mut String, run: &ScaleRun) -> fmt::Result {
    writeln!(out, "## Succinct scale run `{}`\n", run.path.display())?;
    write!(out, "| Keys | Population | Exit |")?;
    for column in &run.columns {
        write!(out, " {column} |")?;
    }
    write!(out, "\n|---:|---|---:|")?;
    for _ in &run.columns {
        write!(out, "---:|")?;
    }
    writeln!(out)?;
    for rung in &run.rungs {
        write!(
            out,
            "| {} | {} | {} |",
            rung.keys, rung.population, rung.exit_status
        )?;
        for column in &run.columns {
            let shown = rung
                .metrics
                .get(column)
                .map_or_else(|| "-".into(), |raw| metric(column, *raw));
            write!(out, " {shown} |")?;
        }
        writeln!(out)?;
    }
    writeln!(out)
}

fn coverage_section(out: &mut String, coverage: &Coverage) -> fmt::Result {
    writeln!(out, "## Test coverage\n")?;
    let summary: Vec<String> = CoverageStatus::ALL
        .iter()
        .map(|status| format!("{} {status}", coverage.count(*status)))
        .collect();
    writeln!(
        out,
        "{} test IDs named by records: {}.\n",
        coverage.tests.len(),
        summary.join(", ")
    )?;
    writeln!(
        out,
        "| Test | Status | Passed validation | Failed validation | Unmeasured |"
    )?;
    writeln!(out, "|---|---|---:|---:|---:|")?;
    for (test, counts) in &coverage.tests {
        writeln!(
            out,
            "| {test} | {} | {} | {} | {} |",
            counts.status(),
            counts.passed,
            counts.failed,
            counts.unmeasured
        )?;
    }
    let u = coverage.unattributed;
    writeln!(
        out,
        "\nRecords naming no test ID: {} passed validation, {} failed it, {} unmeasured.\n",
        u.passed, u.failed, u.unmeasured
    )?;
    writeln!(out, "## Completeness against registered operations\n")?;
    if coverage.unmeasured_operations.is_empty() {
        return writeln!(out, "Every registered operation has a measured record.\n");
    }
    writeln!(
        out,
        "Registered operations with no measured record ({}):\n",
        coverage.unmeasured_operations.len()
    )?;
    for operation in &coverage.unmeasured_operations {
        writeln!(out, "- `{operation}`")?;
    }
    writeln!(out)
}
