//! redb engine floors (PERF-STO-021 inputs, PERF-SYS-001 floor).
//!
//! Single-writer commit latency as a distribution, at `Durability::None`
//! (in-memory commit, no fsync) and `Durability::Immediate` (the durable
//! commit every redb publication performs), and point-read latency on a
//! populated table inside one read transaction. The database lives in the
//! device directory, so commits pay the same device the device floors
//! measured.

use std::hint::black_box;
use std::time::Instant;

use criterion::Criterion;
use kappa_perf::calibrate::{CalibratedGroup, CalibratedSession, LatencyHistogram};
use redb::{Database, Durability, ReadableDatabase, TableDefinition};

use kappa_perf::bench::{
    BenchResult, Failure, SplitMix, Tier, bench, device_dir, osc, pattern, timed,
};

const TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("floors");
const VALUE: usize = 64;
const COMMIT_SAMPLES: usize = 2_000;
const COMMIT_WARMUP: usize = 100;

pub fn register(c: &mut Criterion, s: &mut CalibratedSession, tier: Tier) -> BenchResult {
    let path = device_dir()?.join("floors.redb");
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    let db = Database::create(&path)?;
    commits(s, &db)?;
    reads(c, s, &db, tier)?;
    drop(db);
    std::fs::remove_file(&path)?;
    Ok(())
}

fn commits(s: &mut CalibratedSession, db: &Database) -> BenchResult {
    let value = pattern(VALUE, 14);
    let mut key = 0u64;
    for (token, durability) in [
        ("none", Durability::None),
        ("immediate", Durability::Immediate),
    ] {
        let id = osc(&format!(
            "osc:lat/redb.commit?durability={token}&size={VALUE}"
        ))?;
        if let Err(skip) = s.check_deps(&id) {
            s.skip(skip);
            continue;
        }
        let mut histogram = LatencyHistogram::new()?;
        for sample in 0..COMMIT_WARMUP + COMMIT_SAMPLES {
            let start = Instant::now();
            let mut txn = db.begin_write()?;
            txn.set_durability(durability)?;
            {
                let mut table = txn.open_table(TABLE)?;
                table.insert(key, value.as_slice())?;
            }
            txn.commit()?;
            let elapsed = start.elapsed();
            key += 1;
            if sample >= COMMIT_WARMUP {
                histogram.record_duration(elapsed)?;
            }
        }
        s.record_histogram(&id, &histogram, None, Some("PERF-STO-021"))?;
    }
    // A durable commit after non-durable ones persists them; leave the
    // database in a durable state before reads.
    let txn = db.begin_write()?;
    txn.commit()?;
    Ok(())
}

fn reads(c: &mut Criterion, s: &mut CalibratedSession, db: &Database, tier: Tier) -> BenchResult {
    let keys = tier.pick(10_000u64, 1_000_000, 10_000_000);
    let value = pattern(VALUE, 15);
    let txn = db.begin_write()?;
    {
        let mut table = txn.open_table(TABLE)?;
        for key in 0..keys {
            table.insert(key | (1 << 62), value.as_slice())?;
        }
    }
    txn.commit()?;

    let read = db.begin_read()?;
    let table = read.open_table(TABLE)?;
    let mut rng = SplitMix(16);
    let failure = Failure::default();
    let id = osc(&format!("osc:lat/redb.read?hit=hit&keys={keys}&state=warm"))?;
    let span = usize::try_from(keys)?;
    CalibratedGroup::scope(c, "redb_read", |group| -> BenchResult {
        group.bench(
            s,
            &bench(id, "point_get", keys.to_string(), None, "PERF-STO-024"),
            |iters| {
                timed(iters, || {
                    let key = rng.below(span) as u64 | (1 << 62);
                    match failure.ok(table.get(key)) {
                        Some(Some(found)) => {
                            black_box(found.value().len());
                        }
                        Some(None) => failure.fail("populated key missing"),
                        None => {}
                    }
                })
            },
        )?;
        failure.check("redb.read")
    })
}
