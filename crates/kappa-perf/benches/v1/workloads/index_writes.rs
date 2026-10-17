//! Succinct index write workloads (PERF-SUC-034, PERF-SUC-035,
//! PERF-SUC-038), over kappa keys.
//!
//! Rebuild is measured three ways: construction from the sorted key set
//! (`build`), publication of a base plus a 1/16 overflow (`merge`, the
//! Path A trigger), and publication of one fixed base at growing overflow
//! depths, which shows how rebuild cost follows the overflow it absorbs.
//! Insert is the overflow write path on a built base. Every rebuild checks
//! the work it claims: the built key count, and an overflow that holds
//! every insert before publication and none after.

use std::time::{Duration, Instant};

use kappa_perf::bench::{BenchResult, Tier, distribution, elements, osc};
use kappa_perf::calibrate::CalibratedSession;
use kappa_succinct::{LoudsDsTrie, TrieConfig, TrieIndex};

use crate::index::{KAPPA_DEPTH, kappa_key};

/// Inserts per timed overflow batch, and batches per distribution.
const INSERT_BATCH: usize = 256;
const INSERT_BATCHES: usize = 64;
/// Base of the overflow-depth rebuilds, and the depths absorbed into it.
const DEPTH_BASE: usize = 100_000;
const OVERFLOW_DEPTHS: [usize; 3] = [1_000, 10_000, 50_000];

/// Build, merge and insert over `keys`, the sorted kappa population.
pub fn register(s: &mut CalibratedSession, tier: Tier, keys: &[Vec<u8>]) -> BenchResult {
    rebuild(s, tier, keys)?;
    insert(s, keys)
}

fn rebuild(s: &mut CalibratedSession, tier: Tier, keys: &[Vec<u8>]) -> BenchResult {
    let n = keys.len();
    let bytes = n * KAPPA_DEPTH;
    let runs = tier.pick(5, 10, 10);
    let id = osc(&format!(
        "osc:lat/index.rebuild?keys={n}&size={bytes}&variant=build"
    ))?;
    distribution(s, &id, runs, None, Some("PERF-SUC-035"), || {
        let start = Instant::now();
        let trie = LoudsDsTrie::build(&TrieConfig::default(), keys.iter().map(Vec::as_slice))?;
        let elapsed = start.elapsed();
        if trie.key_count() != n as u64 {
            return Err(format!("built {} of {n} keys", trie.key_count()).into());
        }
        Ok(elapsed)
    })?;
    let overflow = keys.iter().step_by(16).count();
    let id = osc(&format!(
        "osc:lat/index.rebuild?keys={n}&overflow={overflow}&size={bytes}&variant=merge"
    ))?;
    distribution(s, &id, runs, None, Some("PERF-SUC-034"), || {
        let index = TrieIndex::new(TrieConfig::default());
        index.build_initial(
            keys.iter()
                .enumerate()
                .filter(|(i, _)| i % 16 != 0)
                .map(|(_, k)| k.as_slice()),
        )?;
        for k in keys.iter().step_by(16) {
            index.insert(k.clone())?;
        }
        if index.overflow_size()? != overflow {
            return Err(format!(
                "overflow holds {} of {overflow} inserts before rebuild",
                index.overflow_size()?
            )
            .into());
        }
        let start = Instant::now();
        index.rebuild()?;
        let elapsed = start.elapsed();
        if index.overflow_size()? != 0 {
            return Err("rebuild left overflow behind".into());
        }
        Ok(elapsed)
    })?;
    Ok(())
}

/// Publication of one sorted base of `DEPTH_BASE` keys after absorbing each
/// overflow depth. Base and overflow keys are disjoint serials, so every
/// overflow insert is a new key and the published index holds exactly
/// `DEPTH_BASE + depth` keys.
pub fn rebuild_depths(s: &mut CalibratedSession, tier: Tier) -> BenchResult {
    let runs = tier.pick(20, 100, 100);
    let mut base: Vec<Vec<u8>> = (0..DEPTH_BASE as u64).map(kappa_key).collect();
    base.sort_unstable();
    for depth in OVERFLOW_DEPTHS {
        let overflow: Vec<Vec<u8>> = (0..depth)
            .map(|i| kappa_key((DEPTH_BASE + i) as u64))
            .collect();
        let total = DEPTH_BASE + depth;
        let bytes = total * KAPPA_DEPTH;
        let id = osc(&format!(
            "osc:lat/index.rebuild?keys={total}&overflow={depth}&size={bytes}&variant=merge"
        ))?;
        distribution(s, &id, runs, None, Some("PERF-SUC-034"), || {
            let index = TrieIndex::new(TrieConfig::default());
            index.build_initial(base.iter().map(Vec::as_slice))?;
            for k in &overflow {
                index.insert(k.clone())?;
            }
            if index.overflow_size()? != depth {
                return Err(format!(
                    "overflow holds {} of {depth} inserts before rebuild",
                    index.overflow_size()?
                )
                .into());
            }
            let start = Instant::now();
            index.rebuild()?;
            let elapsed = start.elapsed();
            if index.overflow_size()? != 0 {
                return Err("rebuild left overflow behind".into());
            }
            Ok(elapsed)
        })?;
    }
    Ok(())
}

fn insert(s: &mut CalibratedSession, keys: &[Vec<u8>]) -> BenchResult {
    let n = keys.len();
    let index = TrieIndex::new(TrieConfig::default());
    index.build_initial(keys.iter().map(Vec::as_slice))?;
    let fresh: Vec<Vec<u8>> = (0..INSERT_BATCH * INSERT_BATCHES)
        .map(|i| kappa_key((2 * n + i) as u64))
        .collect();
    let mut batches = fresh.chunks(INSERT_BATCH);
    let id = osc(&format!("osc:lat/index.insert?keys={n}&state=warm"))?;
    let measured = distribution(
        s,
        &id,
        INSERT_BATCHES,
        elements(INSERT_BATCH),
        Some("PERF-SUC-038"),
        || {
            let batch = batches.next().ok_or("insert batches exhausted")?;
            let mut elapsed = Duration::ZERO;
            for k in batch {
                let owned = k.clone();
                let start = Instant::now();
                index.insert(owned)?;
                elapsed += start.elapsed();
            }
            Ok(elapsed)
        },
    )?;
    if measured && index.overflow_size()? != INSERT_BATCH * INSERT_BATCHES {
        return Err(format!(
            "overflow holds {} of {} inserts",
            index.overflow_size()?,
            INSERT_BATCH * INSERT_BATCHES
        )
        .into());
    }
    Ok(())
}
