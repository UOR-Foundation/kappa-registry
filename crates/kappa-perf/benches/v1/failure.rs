//! Calibrated failure paths: what a client pays after a crash, a faulted
//! commit, lost storage or an unreadable database, and what it pays to be
//! refused, recorded to `target/calibration_failure.jsonl` and validated
//! against the same-host floors (PERF-SYS-003, PERF-SYS-008,
//! PERF-SYS-020..023).
//!
//! Every fault is injected through a public seam of the redb store: the
//! `StorageBackend` the store's databases are opened through
//! (`test_support::FaultBackend`, one control over the registry and the
//! namespace database, so a crash reaches both at one instant), and the
//! filesystem under a namespace's directory. Every measurement is taken
//! through the public store contract after the fault, and every recovery
//! is verified before it is recorded: the acknowledged publications are the
//! ground truth, never the crashed handle's view, and a fault that did not
//! fire is an error, never a record.
//!
//! Run after the floors bench: `cargo bench -p kappa-perf --bench failure`.
//! Scale: `KAPPA_PERF_TIER=smoke|standard|full` (default standard).
//! Seed: `KAPPA_PERF_SEED` (decimal, 0x hex, or a 40-hex commit); printed
//! and recorded on every point.

#[path = "failure/crash.rs"]
mod crash;
#[path = "failure/faults.rs"]
mod faults;
#[path = "failure/maintenance.rs"]
mod maintenance;
#[path = "failure/recording.rs"]
mod recording;
#[path = "failure/refusal.rs"]
mod refusal;
#[path = "failure/storage.rs"]
mod storage;
#[path = "failure/store.rs"]
mod store;

use kappa_fixture::FixtureRoot;
use kappa_perf::bench::{BenchResult, Tier, device_dir, seed};
use kappa_perf::calibrate::{CalibratedSession, Profile, Summary};

/// Committed epochs left unsettled before each crash, per tier.
const fn pending_counts(tier: Tier) -> &'static [usize] {
    tier.pick(&[8], &[8, 64], &[8, 64, 512])
}

/// Entry budgets of one bounded maintenance step, per tier.
const fn budgets(tier: Tier) -> &'static [u64] {
    tier.pick(&[64], &[8, 64, 4096], &[1, 8, 64, 4096])
}

/// Crash, restore and reopen cycles per recorded distribution.
const fn cycles(tier: Tier) -> u64 {
    tier.pick(2, 3, 5)
}

fn main() -> BenchResult {
    let summary = run(Tier::from_env()?)?;
    if summary.untrusted.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} failure measurements violated physical bounds; see the summary above",
            summary.untrusted.len()
        )
        .into())
    }
}

fn run(tier: Tier) -> Result<Summary, Box<dyn std::error::Error>> {
    let seed = seed()?;
    eprintln!("seed={seed}");
    let mut session = CalibratedSession::new("failure", Profile::L6Graded, "std")?;
    session.set_seed(seed);
    let device = device_dir()?;
    session.set_storage_path(&device);
    let root = FixtureRoot::within(&device, "failure-")?;
    let scale = store::Scale {
        pending: pending_counts(tier),
        budgets: budgets(tier),
        cycles: cycles(tier),
        seed,
    };

    crash::register(&mut session, &root, &scale)?;
    faults::register(&mut session, &root, &scale)?;
    storage::register(&mut session, &root, &scale)?;
    refusal::register(&mut session, &root, &scale)?;

    let summary = session.finalize()?;
    eprint!("{summary}");
    Ok(summary)
}
