//! Succinct index read workloads (PERF-SUC-031, PERF-SUC-032,
//! PERF-SUC-036), over two key shapes.
//!
//! The production shape is SHA-256 kappa key bytes (33 bytes: axis
//! discriminant plus digest), so every descent is 33 levels deep. The word
//! shape is 8-byte keys, distinct 64-bit words: the same trie at a quarter
//! of the depth, which separates per-level cost from per-key cost. Every
//! identifier carries its key depth. Seeks are graded against `depth x` the
//! dependent-load latency of the cache level the serialized trie fits in,
//! as the host reports its cache geometry; on a host that reports none,
//! the cache condition is absent and the record carries the roofline
//! diagnosis instead of a guessed level.
//!
//! Exact seeks are point descents (`ordinal`) of present and absent keys.
//! Lower-bound seeks walk one cursor through a sorted batch of targets, as
//! an intersection drives it. Advance enumerates the whole index. `first`
//! is the time to the first result, cursor construction to its positioned
//! smallest key, recorded as a distribution of individually timed
//! positionings so its tail is measured: each sample includes one clock
//! read pair. Rebuild and insert, the write side, are in `index_writes`.

use std::collections::BTreeSet;
use std::hint::black_box;
use std::time::Instant;

use criterion::Criterion;
use kappa_cursor::{KappaCursor, TERMINATED};
use kappa_perf::calibrate::platform::PlatformInfo;
use kappa_perf::calibrate::{CalibratedGroup, CalibratedSession};
use kappa_store::Kappa;
use kappa_succinct::{LoudsDsTrie, TrieConfig, TrieCursor};

use kappa_perf::bench::{BenchResult, Failure, SplitMix, Tier, bench, distribution, elements, osc};

use crate::index_writes;

/// Key bytes per SHA-256 kappa, one trie level each.
pub const KAPPA_DEPTH: usize = 33;
/// Key bytes per word key.
const WORD_DEPTH: usize = 8;
/// Targets per lower-bound cursor walk.
const SEEK_BATCH: usize = 1024;
/// Distinct probe keys cycled by exact seeks.
const PROBES: usize = 1 << 16;
/// Timed positionings per time-to-first-result distribution, preceded by
/// as many untimed ones.
const FIRST_SAMPLES: usize = 100_000;

/// The key population a trie is built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// SHA-256 kappa key bytes, as the registry indexes them.
    Kappa,
    /// Distinct 64-bit words, big-endian.
    Word,
}

impl Shape {
    const ALL: [Self; 2] = [Self::Kappa, Self::Word];

    const fn depth(self) -> usize {
        match self {
            Self::Kappa => KAPPA_DEPTH,
            Self::Word => WORD_DEPTH,
        }
    }

    /// The key of `serial`. Distinct serials give distinct keys in both
    /// shapes: SHA-256 by collision resistance, words because the
    /// `SplitMix64` output function is a bijection of its state.
    fn key(self, serial: u64) -> Vec<u8> {
        match self {
            Self::Kappa => kappa_key(serial),
            Self::Word => {
                let mut bytes = SplitMix(serial).next_u64().to_be_bytes();
                // Keep the first byte in the kappa axis-discriminant range
                // (0-5) so TERMINATED ([0xFF]) remains a valid sentinel
                // that byte-compares greater than every key.
                bytes[0] %= 6;
                bytes.to_vec()
            }
        }
    }
}

/// The kappa key bytes of `serial`.
pub fn kappa_key(serial: u64) -> Vec<u8> {
    Kappa::sha256(&serial.to_le_bytes()).key_bytes()
}

const fn populations(tier: Tier) -> &'static [usize] {
    tier.pick(
        &[10_000],
        &[10_000, 100_000, 1_000_000],
        &[10_000, 100_000, 1_000_000, 10_000_000],
    )
}

/// Smallest data or unified cache level holding `bytes`; `dram` beyond the
/// last level; `None` when the host reports no cache geometry.
fn resident_cache(platform: &PlatformInfo, bytes: usize) -> Option<&'static str> {
    if platform.caches.is_empty() {
        return None;
    }
    let bytes = bytes as u64;
    for (level, token) in [(1u8, "l1"), (2, "l2"), (3, "l3")] {
        let fits = platform.caches.iter().any(|cache| {
            cache.level == level && cache.kind != "Instruction" && cache.size_bytes >= bytes
        });
        if fits {
            return Some(token);
        }
    }
    Some("dram")
}

/// Every read workload over both shapes at every population, the write
/// workloads over the kappa shape, then rebuild at fixed overflow depths.
pub fn register(c: &mut Criterion, s: &mut CalibratedSession, tier: Tier) -> BenchResult {
    for shape in Shape::ALL {
        for &n in populations(tier) {
            let mut keys: Vec<Vec<u8>> = (0..n as u64).map(|serial| shape.key(serial)).collect();
            keys.sort_unstable();
            let trie = LoudsDsTrie::build(&TrieConfig::default(), keys.iter().map(Vec::as_slice))?;
            let cache = resident_cache(s.platform(), trie.serialize()?.len())
                .map_or_else(String::new, |level| format!("cache={level}&"));
            let mut rng = SplitMix(60 + n as u64);
            let present: Vec<Vec<u8>> = (0..PROBES).map(|_| keys[rng.below(n)].clone()).collect();
            let absent: Vec<Vec<u8>> = (0..PROBES).map(|i| shape.key((n + i) as u64)).collect();
            if let Some(found) = absent.iter().find(|probe| trie.ordinal(probe).is_some()) {
                return Err(format!("absent probe {} is present", hex::encode(found)).into());
            }
            exact(c, s, &trie, shape, &cache, &present, &absent)?;
            lower_bound(c, s, &trie, shape, &keys, &cache)?;
            first(s, &trie, shape, n)?;
            advance(c, s, &trie, shape, n)?;
            if shape == Shape::Kappa {
                index_writes::register(s, tier, &keys)?;
            }
        }
    }
    index_writes::rebuild_depths(s, tier)
}

fn exact(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    trie: &LoudsDsTrie,
    shape: Shape,
    cache: &str,
    present: &[Vec<u8>],
    absent: &[Vec<u8>],
) -> BenchResult {
    let n = trie.key_count();
    let depth = shape.depth();
    let failure = Failure::default();
    CalibratedGroup::scope(
        c,
        &format!("index_seek_exact_{depth}_{n}"),
        |group| -> BenchResult {
            for (hit, probes) in [("hit", present), ("miss", absent)] {
                let id = osc(&format!(
                    "osc:lat/index.seek?{cache}depth={depth}&hit={hit}&keys={n}&mode=exact&state=warm"
                ))?;
                let mut next = 0usize;
                group.bench(
                    s,
                    &bench(id, hit, n.to_string(), None, "PERF-SUC-031"),
                    |iters| {
                        let start = Instant::now();
                        for _ in 0..iters {
                            let found = trie.ordinal(black_box(&probes[next % PROBES])).is_some();
                            next += 1;
                            if found != (hit == "hit") {
                                failure.fail(format!("exact seek {hit} answered the other way"));
                                break;
                            }
                        }
                        start.elapsed()
                    },
                )?;
                failure.check("index.seek exact")?;
            }
            Ok(())
        },
    )
}

/// `PROBES / SEEK_BATCH` sorted batches of exactly `SEEK_BATCH` distinct
/// targets each, so every walk does the declared work.
fn seek_batches(mut draw: impl FnMut() -> Vec<u8>) -> Vec<Vec<Vec<u8>>> {
    (0..PROBES / SEEK_BATCH)
        .map(|_| {
            let mut batch = BTreeSet::new();
            while batch.len() < SEEK_BATCH {
                batch.insert(draw());
            }
            batch.into_iter().collect()
        })
        .collect()
}

fn lower_bound(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    trie: &LoudsDsTrie,
    shape: Shape,
    keys: &[Vec<u8>],
    cache: &str,
) -> BenchResult {
    let n = keys.len();
    let depth = shape.depth();
    let mut rng = SplitMix(70 + n as u64);
    let present = seek_batches(|| keys[rng.below(n)].clone());
    let mut serial = (3 * n) as u64;
    let absent = seek_batches(|| {
        serial += 1;
        shape.key(serial)
    });
    if absent
        .iter()
        .flatten()
        .any(|target| trie.ordinal(target).is_some())
    {
        return Err("an absent lower-bound target is present".into());
    }
    let failure = Failure::default();
    CalibratedGroup::scope(
        c,
        &format!("index_seek_lower_{depth}_{n}"),
        |group| -> BenchResult {
            for (hit, batches) in [("hit", &present), ("miss", &absent)] {
                let id = osc(&format!(
                    "osc:lat/index.seek?{cache}depth={depth}&hit={hit}&keys={n}&mode=lower_bound&state=warm"
                ))?;
                let mut next = 0usize;
                group.bench(
                    s,
                    &bench(id, hit, n.to_string(), elements(SEEK_BATCH), "PERF-SUC-032"),
                    |iters| {
                        let start = Instant::now();
                        for _ in 0..iters {
                            let batch = &batches[next % batches.len()];
                            next += 1;
                            let mut cursor = TrieCursor::new(trie);
                            for target in batch {
                                let landed = cursor.seek(target);
                                let exact = landed == target.as_slice();
                                if landed < target.as_slice() || exact != (hit == "hit") {
                                    failure.fail(format!("lower-bound seek {hit} landed wrong"));
                                    break;
                                }
                            }
                            if failure.failed() {
                                break;
                            }
                        }
                        start.elapsed()
                    },
                )?;
                failure.check("index.seek lower_bound")?;
            }
            Ok(())
        },
    )
}

/// Time to first result: a fresh cursor positioned on the smallest key,
/// each positioning timed on its own so the distribution carries p99.
fn first(s: &mut CalibratedSession, trie: &LoudsDsTrie, shape: Shape, n: usize) -> BenchResult {
    let depth = shape.depth();
    let smallest = TrieCursor::new(trie).key().to_vec();
    if smallest.as_slice() == TERMINATED {
        return Err(format!("a cursor over {n} keys found no first key").into());
    }
    for _ in 0..FIRST_SAMPLES {
        let cursor = TrieCursor::new(black_box(trie));
        if black_box(cursor.key()) != smallest.as_slice() {
            return Err("a fresh cursor was not positioned on the smallest key".into());
        }
    }
    let id = osc(&format!(
        "osc:lat/index.advance?depth={depth}&keys={n}&state=warm&variant=first"
    ))?;
    distribution(s, &id, FIRST_SAMPLES, None, None, || {
        let start = Instant::now();
        let cursor = TrieCursor::new(black_box(trie));
        let positioned = black_box(cursor.key());
        let elapsed = start.elapsed();
        if positioned != smallest.as_slice() {
            return Err("a fresh cursor was not positioned on the smallest key".into());
        }
        Ok(elapsed)
    })?;
    Ok(())
}

fn advance(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    trie: &LoudsDsTrie,
    shape: Shape,
    n: usize,
) -> BenchResult {
    let depth = shape.depth();
    let failure = Failure::default();
    let id = osc(&format!(
        "osc:lat/index.advance?depth={depth}&keys={n}&order=sequential&state=warm"
    ))?;
    CalibratedGroup::scope(
        c,
        &format!("index_advance_{depth}_{n}"),
        |group| -> BenchResult {
            group.bench(
                s,
                &bench(id, "enumerate", n.to_string(), elements(n), "PERF-SUC-036"),
                |iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        let mut cursor = TrieCursor::new(trie);
                        let mut count = 0usize;
                        while cursor.key() != TERMINATED {
                            count += 1;
                            cursor.advance();
                        }
                        if count != n {
                            failure.fail(format!("enumerated {count} of {n} keys"));
                            break;
                        }
                    }
                    start.elapsed()
                },
            )?;
            failure.check("index.advance")
        },
    )
}
