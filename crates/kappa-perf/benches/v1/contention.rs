//! Calibrated contention: scaling curves of the shared structures every
//! concurrent request crosses, recorded to
//! `target/calibration_contention.jsonl` (KAPPA-PERF-001 section 16.5,
//! PERF-STO-027, PERF-CON-013, PERF-SUC-037, PERF-SUC-038).
//!
//! - Writer mutex under N execution publishers, on disjoint namespaces and
//!   on one shared tag.
//! - Tag compare-and-swap on one key: attempt rate and success ratio.
//! - Readers under concurrent publication: `tag_get` quiescent and with one
//!   background publisher (`ArcSwap` generations in memory, MVCC read
//!   transactions in redb).
//! - The single writer under N background readers.
//! - Succinct index readers quiescent and during continuous rebuild, and
//!   overflow writers toggling disjoint keys.
//!
//! Workers start together behind a barrier and divide each sample's
//! iterations evenly; background load starts before and stops after the
//! measured scaling curve, and must make progress or the curve is refused.
//!
//! Run after the floors bench: `cargo bench -p kappa-perf --bench contention`.

#[path = "contention/index.rs"]
mod index;
#[path = "contention/load.rs"]
mod load;
#[path = "contention/mixed.rs"]
mod mixed;
#[path = "contention/stores.rs"]
mod stores;

use std::sync::Arc;

use kappa_handler::clock::WallClock;
use kappa_perf::bench::fixture::Fixture;
use kappa_perf::bench::{BenchResult, Tier, device_dir};
use kappa_perf::calibrate::{CalibratedSession, Profile, Summary, calibrated_criterion, finalize};

use load::Shared;

fn main() -> BenchResult {
    let summary = run(Tier::from_env()?)?;
    if summary.untrusted.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} contention measurements violated physical bounds; see the summary above",
            summary.untrusted.len()
        )
        .into())
    }
}

fn run(tier: Tier) -> Result<Summary, Box<dyn std::error::Error>> {
    let mut criterion = calibrated_criterion();
    let mut session = CalibratedSession::new("contention", Profile::L6Graded, "std")?;
    let device = device_dir()?;
    session.set_storage_path(&device);
    let threads = tier.thread_counts(session.platform().logical_cpus);
    let clock = Arc::new(WallClock::new());
    let fixture = Fixture::new(&device)?;

    let memory = Shared {
        store: Arc::new(fixture.memory("contention-memory")?),
        clock: Arc::clone(&clock),
        backend: "memory",
        durability: "none",
    };
    stores::register(&mut criterion, &mut session, &threads, &memory)?;
    mixed::register(&mut criterion, &mut session, &threads, &memory)?;
    let redb = Shared {
        store: Arc::new(fixture.redb("contention-redb", false)?),
        clock: Arc::clone(&clock),
        backend: "redb",
        durability: "immediate",
    };
    stores::register(&mut criterion, &mut session, &threads, &redb)?;
    mixed::register(&mut criterion, &mut session, &threads, &redb)?;
    index::register(&mut criterion, &mut session, tier, &threads)?;

    Ok(finalize(&mut session, &criterion)?)
}
