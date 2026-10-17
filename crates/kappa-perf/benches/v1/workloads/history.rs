//! History and collection workloads (PERF-STO-030, PERF-EPO-024,
//! PERF-STO-029, PERF-CUR-005).
//!
//! `replay.ledger` reconstructs a namespace from its signed epoch chain and
//! reports mutations per second (target: at least 10^6/s). `gc.sweep` times
//! the server's sweep exactly as `POST /v2/{ns}/gc/sweep` runs it: a
//! snapshot of every stored blob identity (`blob_snapshot`) and the
//! store-wide sweep (`gc_sweep`), which retires every unreachable identity
//! through executions in the maintenance namespace. The store holds a
//! population of which 90% is reachable through tags, plus every epoch
//! root, ledger and linking edge its publications wrote; the sweep must
//! classify every stored blob and retire exactly the unreachable 10%, so a
//! sweep that retired epoch history fails the run. The retired 10% is
//! reinstalled outside the timed region so every run sweeps the same
//! store, and the run's peak resident growth is recorded as its working
//! memory (C-12: growth below 10x for 100x blobs). The transaction staging
//! workloads are `staging`.

use std::time::Instant;

use kappa_handler::clock::{Clock, WallClock};
use kappa_perf::calibrate::CalibratedSession;
use kappa_store::gc::{GcConfig, blob_snapshot, gc_sweep};
use kappa_store::{
    Axis, EpochMutation, KappaStore, NamespaceRef, TagUpdate, VerifiedContent, from_canonical,
    replay_to,
};

use kappa_perf::bench::fixture::{POPULATE_BATCH, Target, create_ns, stamp, tag_name, tag_target};
use kappa_perf::bench::{BenchResult, Tier, distribution, elements, osc, pattern};

/// Identities retired per sweep publication, as the server configures it.
const RETIRE_BATCH: usize = 256;

pub fn register<S: KappaStore>(
    s: &mut CalibratedSession,
    tier: Tier,
    clock: &WallClock,
    target: &Target<'_, S>,
) -> BenchResult {
    replay(s, tier, clock, target)?;
    sweep(s, tier, clock, target)
}

fn replay<S: KappaStore>(
    s: &mut CalibratedSession,
    tier: Tier,
    clock: &WallClock,
    target: &Target<'_, S>,
) -> BenchResult {
    let store = target.store;
    let ns = create_ns(store, clock, "replay")?;
    let (epochs, width) = tier.pick((16usize, 64usize), (64, 1024), (256, 4096));
    for round in 0..epochs {
        let mut execution = store.begin_execution(&ns, clock)?;
        for index in 0..width {
            execution.tag_put(
                &tag_name(index),
                &TagUpdate::Set {
                    kappa: tag_target(index, round as u64),
                },
            )?;
        }
        execution.publish()?;
    }
    let (current, _) = store.epoch_current(&ns)?;
    let mut mutations = 0usize;
    for number in 1..=current {
        let root = store.epoch_get(&store.epoch_get_by_number(&ns, number)?)?;
        let ledger: Vec<EpochMutation> = from_canonical(&store.blob_get(root.ledger_root())?)?;
        mutations += ledger.len();
    }
    let id = osc(&format!(
        "osc:ops/replay.ledger?backend={}&mutations={mutations}",
        target.backend
    ))?;
    distribution(
        s,
        &id,
        tier.pick(3, 5, 10),
        elements(mutations),
        Some("PERF-STO-030"),
        || {
            let start = Instant::now();
            let state = replay_to(store, &ns, current)?;
            let elapsed = start.elapsed();
            if state.tags.len() != width {
                return Err(format!(
                    "replay reconstructed {} tags, published {width}",
                    state.tags.len()
                )
                .into());
            }
            Ok(elapsed)
        },
    )?;
    Ok(())
}

/// `VmRSS` or `VmHWM` of this process, in bytes.
fn status_bytes(field: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status
        .lines()
        .find(|line| line.starts_with(field))
        .ok_or_else(|| format!("/proc/self/status has no {field}"))?;
    let kib: u64 = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("malformed {field} line"))?
        .parse()?;
    Ok(kib * 1024)
}

/// Reset the peak resident set to the current resident set.
fn reset_peak() -> Result<(), std::io::Error> {
    std::fs::write("/proc/self/clear_refs", "5")
}

const fn sweep_populations(tier: Tier) -> &'static [usize] {
    tier.pick(&[10_000], &[100_000], &[100_000, 1_000_000, 10_000_000])
}

/// Install `records` as verified records in executions of
/// [`POPULATE_BATCH`] each, published in `ns`.
fn install_records<S: KappaStore>(
    store: &S,
    clock: &WallClock,
    ns: &NamespaceRef,
    records: &[VerifiedContent],
) -> BenchResult {
    for batch in records.chunks(POPULATE_BATCH) {
        let mut execution = store.begin_execution(ns, clock)?;
        for record in batch {
            execution.blob_put(record)?;
        }
        execution.publish()?;
    }
    Ok(())
}

/// Install `keys` distinct records in `ns` and tag all but every tenth;
/// returns the untagged, unreachable tenth.
fn populate_sweep<S: KappaStore>(
    store: &S,
    clock: &WallClock,
    ns: &NamespaceRef,
    keys: usize,
) -> Result<Vec<VerifiedContent>, Box<dyn std::error::Error>> {
    let mut content = pattern(64, 50);
    let mut records = Vec::with_capacity(keys);
    let mut garbage = Vec::with_capacity(keys / 10 + 1);
    for index in 0..keys {
        stamp(&mut content, ((keys as u64) << 32) | index as u64);
        records.push(VerifiedContent::compute(Axis::Sha256, &content)?);
        if index % 10 == 0 {
            garbage.push(content.clone());
        }
    }
    install_records(store, clock, ns, &records)?;
    let unreachable = garbage
        .iter()
        .map(|bytes| VerifiedContent::compute(Axis::Sha256, bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let reachable: Vec<(String, TagUpdate)> = records
        .iter()
        .enumerate()
        .filter(|(index, _)| index % 10 != 0)
        .map(|(index, record)| {
            (
                tag_name(index),
                TagUpdate::Set {
                    kappa: record.kappa().clone(),
                },
            )
        })
        .collect();
    for batch in reachable.chunks(POPULATE_BATCH) {
        let mut execution = store.begin_execution(ns, clock)?;
        execution.tag_batch_update(batch)?;
        execution.publish()?;
    }
    Ok(unreachable)
}

fn sweep<S: KappaStore>(
    s: &mut CalibratedSession,
    tier: Tier,
    clock: &WallClock,
    target: &Target<'_, S>,
) -> BenchResult {
    let store = target.store;
    let maintenance = create_ns(store, clock, "_gc")?;
    for &keys in sweep_populations(tier) {
        let ns = create_ns(store, clock, &format!("gc-{keys}"))?;
        let unreachable = populate_sweep(store, clock, &ns, keys)?;
        // Every blob the store holds, as the server's sweep sees it: the
        // population, and every epoch root, ledger and edge the store's
        // publications wrote. The sweep must classify all of them.
        let stored = blob_snapshot(store)?.key_table.len();
        let config = GcConfig {
            max_blob_count: 0,
            retire_batch: RETIRE_BATCH,
        };
        let mut peak_growth = 0u64;
        let id = osc(&format!(
            "osc:ops/gc.sweep?backend={}&keys={stored}",
            target.backend
        ))?;
        let measured = distribution(
            s,
            &id,
            tier.pick(3, 5, 5),
            elements(stored),
            Some("PERF-EPO-024"),
            || {
                reset_peak()?;
                let resident = status_bytes("VmRSS:")?;
                let start = Instant::now();
                let snapshot = blob_snapshot(store)?;
                let result = gc_sweep(store, &snapshot, &config, clock, clock.now()?)?;
                let elapsed = start.elapsed();
                peak_growth = peak_growth.max(status_bytes("VmHWM:")?.saturating_sub(resident));
                if result.objects_scanned != stored as u64
                    || result.objects_retired != unreachable.len() as u64
                    || result.objects_skipped != 0
                    || result.objects_absent != 0
                {
                    return Err(format!(
                        "sweep scanned {} of {stored} stored blobs, retired {}, skipped {} \
                         and found {} absent; expected exactly {} unreachable",
                        result.objects_scanned,
                        result.objects_retired,
                        result.objects_skipped,
                        result.objects_absent,
                        unreachable.len()
                    )
                    .into());
                }
                install_records(store, clock, &ns, &unreachable)?;
                Ok(elapsed)
            },
        )?;
        // The reinstalled garbage belongs to this population only; a later
        // population's sweep must not retire it.
        for batch in unreachable.chunks(RETIRE_BATCH) {
            let mut execution = store.begin_execution(&maintenance, clock)?;
            for record in batch {
                execution.content_retire(record.kappa())?;
            }
            execution.publish()?;
        }
        if measured {
            #[allow(clippy::cast_precision_loss, reason = "resident bytes far below 2^53")]
            let growth = peak_growth as f64;
            s.record_direct(
                &osc(&format!(
                    "osc:size/gc.sweep?backend={}&keys={stored}",
                    target.backend
                ))?,
                growth,
                Some("PERF-STO-029"),
            )?;
        }
    }
    Ok(())
}
