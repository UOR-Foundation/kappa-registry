//! Succinct index contention curves (PERF-SUC-037, PERF-SUC-038): readers
//! retaining snapshots, quiescent and during continuous rebuild, and
//! overflow writers toggling disjoint keys.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use criterion::Criterion;
use kappa_cursor::KappaCursor;
use kappa_perf::bench::{BenchResult, Failure, SplitMix, Tier, bench, elements, osc};
use kappa_perf::calibrate::{CalibratedGroup, CalibratedSession};
use kappa_store::Kappa;
use kappa_succinct::{TrieConfig, TrieIndex};

use crate::load::{Background, Load, Worker, under};

/// Sorted present keys readers seek, generated before timing.
const PROBES: usize = 4096;
/// Seeks per retained index snapshot.
const SNAPSHOT_SEEKS: usize = 64;
/// Distinct keys each overflow writer toggles.
const TOGGLE_POOL: usize = 4096;
/// SHA-256 kappa key bytes.
const KEY_BYTES: usize = 33;

/// A key no SHA-256 population contains: axis byte, owner, serial, padding.
fn owned_key(owner: u32, serial: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(KEY_BYTES);
    key.push(0);
    key.extend_from_slice(&owner.to_be_bytes());
    key.extend_from_slice(&serial.to_be_bytes());
    key.resize(KEY_BYTES, 0xa5);
    key
}

/// Continuous rebuild: insert one fresh key, publish a new base, repeat.
fn rebuild_load(index: &Arc<TrieIndex>, failure: &Arc<Failure>) -> Load {
    let (index, failure) = (Arc::clone(index), Arc::clone(failure));
    Arc::new(move |_, stop: &AtomicBool| {
        let mut rebuilds = 0u64;
        while !stop.load(Ordering::Acquire) {
            if failure
                .ok(index.insert(owned_key(u32::MAX, rebuilds)))
                .is_none()
                || failure.ok(index.rebuild()).is_none()
            {
                break;
            }
            rebuilds += 1;
        }
        rebuilds
    })
}

/// Readers each retaining one snapshot per `SNAPSHOT_SEEKS` ascending seeks.
fn seek_worker(
    index: &Arc<TrieIndex>,
    probes: &Arc<Vec<Vec<u8>>>,
    failure: &Arc<Failure>,
) -> Worker {
    let (index, probes, failure) = (Arc::clone(index), Arc::clone(probes), Arc::clone(failure));
    Arc::new(move |thread, n| {
        let mut remaining = usize::try_from(n).unwrap_or(usize::MAX);
        let mut chunk = thread;
        while remaining > 0 {
            let Some(snapshot) = failure.ok(index.trie_snapshot()) else {
                return;
            };
            let mut cursor = snapshot.cursor();
            let start = (chunk * SNAPSHOT_SEEKS) % PROBES;
            chunk += 1;
            let take = remaining.min(SNAPSHOT_SEEKS);
            for target in &probes[start..start + take] {
                if cursor.seek(target) != target.as_slice() {
                    failure.fail("a present key was not found under concurrent rebuild");
                    return;
                }
            }
            remaining -= take;
        }
    })
}

pub fn register(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    tier: Tier,
    threads: &[usize],
) -> BenchResult {
    let n = tier.pick(10_000usize, 1_000_000, 1_000_000);
    let mut keys: Vec<Vec<u8>> = (0..n as u64)
        .map(|i| Kappa::sha256(&i.to_le_bytes()).key_bytes())
        .collect();
    keys.sort_unstable();
    let index = Arc::new(TrieIndex::new(TrieConfig::default()));
    index.build_initial(keys.iter().map(Vec::as_slice))?;
    let mut rng = SplitMix(90);
    let mut probes: Vec<Vec<u8>> = (0..PROBES).map(|_| keys[rng.below(n)].clone()).collect();
    probes.sort_unstable();
    let probes = Arc::new(probes);
    let failure = Arc::new(Failure::default());
    readers(c, s, threads, n, &index, &probes, &failure)?;
    writers(c, s, threads, n, &index, &failure)
}

fn readers(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    threads: &[usize],
    n: usize,
    index: &Arc<TrieIndex>,
    probes: &Arc<Vec<Vec<u8>>>,
    failure: &Arc<Failure>,
) -> BenchResult {
    CalibratedGroup::scope(c, "index_readers", |group| -> BenchResult {
        for contention in ["none", "1w"] {
            let background = (contention == "1w").then(|| {
                (
                    Background::start(1, &rebuild_load(index, failure)),
                    "background rebuild",
                )
            });
            under(background, || {
                for &count in threads {
                    let id = osc(&format!(
                        "osc:ops/index.seek?contention={contention}&hit=hit&keys={n}&mode=lower_bound&threads={count}t"
                    ))?;
                    group.bench_contended(
                        s,
                        &bench(id, contention, count.to_string(), None, "PERF-SUC-037"),
                        count,
                        &seek_worker(index, probes, failure),
                    )?;
                    failure.check("index.seek contended")?;
                }
                Ok(())
            })?;
            failure.check("background rebuild")?;
        }
        Ok(())
    })
}

fn writers(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    threads: &[usize],
    n: usize,
    index: &Arc<TrieIndex>,
    failure: &Arc<Failure>,
) -> BenchResult {
    let widest = threads.iter().copied().max().ok_or("no thread counts")?;
    let pools: Arc<Vec<Vec<Vec<u8>>>> = Arc::new(
        (0..widest)
            .map(|owner| {
                u32::try_from(owner).map(|owner| {
                    (0..TOGGLE_POOL as u64)
                        .map(|serial| owned_key(owner, serial))
                        .collect()
                })
            })
            .collect::<Result<_, _>>()?,
    );
    CalibratedGroup::scope(c, "index_writers", |group| -> BenchResult {
        for &count in threads {
            let (worker_index, worker_failure, pools) =
                (Arc::clone(index), Arc::clone(failure), Arc::clone(&pools));
            // Each iteration inserts one owned key into the overlay and
            // deletes it again: two overlay mutations, with the overlay
            // bounded by the pools.
            let worker: Worker = Arc::new(move |thread, n| {
                for key in pools[thread]
                    .iter()
                    .cycle()
                    .take(usize::try_from(n).unwrap_or(usize::MAX))
                {
                    if worker_failure
                        .ok(worker_index.insert(key.clone()))
                        .is_none()
                        || worker_failure
                            .ok(worker_index.delete(key.clone()))
                            .is_none()
                    {
                        return;
                    }
                }
            });
            let id = osc(&format!(
                "osc:ops/index.insert?keys={n}&threads={count}t&variant=toggle"
            ))?;
            group.bench_contended(
                s,
                &bench(id, "toggle", count.to_string(), elements(2), "PERF-SUC-038"),
                count,
                &worker,
            )?;
            failure.check("index.insert contended")?;
        }
        Ok(())
    })
}
