//! Recording gated on the fault having fired: a measurement under a fault
//! whose summary shows nothing took effect measured nothing injected and is
//! an error, never a record. Distributions too small to have a tail are
//! recorded as their median, so no tail rule reads a tail that is not there.

use std::time::Duration;

use kappa_perf::bench::BenchResult;
use kappa_perf::calibrate::record::FaultSummary;
use kappa_perf::calibrate::{CalibratedSession, LatencyHistogram, OscId};
use kappa_store::Settlement;
use kappa_store::work::Dimension;

use crate::maintenance::Sample;
use crate::store::{FaultToken, id};

/// Samples below which a distribution's tail is noise: such a record is
/// written as a direct value (its median) so no tail rule reads it.
pub const MIN_TAIL_SAMPLES: usize = 32;

/// Record `durations` as the distribution of `id` under `summary`, unless
/// `id`'s floors are not established. A summary showing nothing fired
/// under a fault other than `none` is an error: the measurement did not
/// measure the injected fault. Fewer than [`MIN_TAIL_SAMPLES`] samples
/// are recorded as the direct median.
pub fn record_under_fault(
    s: &mut CalibratedSession,
    id: &OscId,
    durations: &[Duration],
    test_id: &str,
    summary: &FaultSummary,
) -> BenchResult {
    if summary.armed != FaultToken::None.as_str() && !summary.fired() {
        return Err(format!("{id}: fault {} did not fire: {summary:?}", summary.armed).into());
    }
    if durations.is_empty() {
        return Err(format!("{id}: nothing was measured").into());
    }
    if let Err(skip) = s.check_deps(id) {
        eprintln!("{skip}");
        s.skip(skip);
        return Ok(());
    }
    s.set_fault(Some(summary.clone()));
    let recorded = if durations.len() < MIN_TAIL_SAMPLES {
        let mut sorted: Vec<u64> = durations
            .iter()
            .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
            .collect();
        sorted.sort_unstable();
        #[allow(
            clippy::cast_precision_loss,
            reason = "nanosecond latencies far below 2^53"
        )]
        let median = sorted[sorted.len() / 2] as f64;
        eprintln!(
            "{id}: {} samples, below {MIN_TAIL_SAMPLES}: recorded as its median, no tail",
            durations.len()
        );
        s.record_direct(id, median, Some(test_id))
    } else {
        let mut histogram = LatencyHistogram::new()?;
        for duration in durations {
            histogram.record_duration(*duration)?;
        }
        s.record_histogram(id, &histogram, None, Some(test_id))
    };
    s.set_fault(None);
    recorded?;
    Ok(())
}

/// Record the settlement steps of one or more passes: their latency
/// distribution and the bytes read per pass, both under `summary`. A size
/// record whose floors are not established is skipped with its diagnosis
/// recorded, as the latency record is.
pub fn record_settlement(
    s: &mut CalibratedSession,
    conditions: &[(&str, &str)],
    passes: &[Vec<Sample<Settlement>>],
    test_id: &str,
    summary: &FaultSummary,
) -> BenchResult {
    let durations: Vec<Duration> = passes.iter().flatten().map(|step| step.elapsed).collect();
    record_under_fault(
        s,
        &id("lat", "settlement.step", conditions)?,
        &durations,
        test_id,
        summary,
    )?;
    if passes.is_empty() {
        return Ok(());
    }
    #[allow(clippy::cast_precision_loss, reason = "byte counts far below 2^53")]
    let bytes_read = passes
        .iter()
        .map(|pass| {
            pass.iter()
                .map(|step| step.consumed.get(Dimension::BytesRead))
                .sum::<u64>() as f64
        })
        .sum::<f64>()
        / passes.len() as f64;
    let mut with_resource = conditions.to_vec();
    with_resource.push(("res", "bytes_read"));
    let size = id("size", "settlement.step", &with_resource)?;
    if let Err(skip) = s.check_deps(&size) {
        eprintln!("{skip}");
        s.skip(skip);
        return Ok(());
    }
    s.set_fault(Some(summary.clone()));
    let recorded = s.record_direct(&size, bytes_read, Some(test_id));
    s.set_fault(None);
    recorded?;
    Ok(())
}
