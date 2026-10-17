//! Calibrated floors: the constituent costs that bound every composite
//! kappa operation, measured on this host and written to
//! `target/calibration_floors.jsonl`, which later sessions load as their
//! same-host baseline.
//!
//! Tiers run in dependency order so every floor's own floors are already
//! established when it is measured (profile L6 gates on them):
//! memory, synchronization, digests, commitments, the device, the redb
//! engine on that device, then signatures, typed boundaries and AEAD, then
//! the reference implementations every production digest and signature
//! floor is judged against.
//!
//! Run: `cargo bench -p kappa-perf --bench floors`
//! Scale: `KAPPA_PERF_TIER=smoke|standard|full` (default standard).
//! Device: `KAPPA_PERF_DEVICE_DIR` selects the filesystem under test.
//! Filter: criterion arguments pass through (`-- device_`).

#[path = "floors/commit.rs"]
mod commit;
#[path = "floors/crypto.rs"]
mod crypto;
#[path = "floors/device.rs"]
mod device;
#[path = "floors/engine.rs"]
mod engine;
#[path = "floors/hash.rs"]
mod hash;
#[path = "floors/mem.rs"]
mod mem;
#[path = "floors/reference.rs"]
mod reference;
#[path = "floors/sync.rs"]
mod sync;

use kappa_perf::bench::{BenchResult, Tier, device_dir};
use kappa_perf::calibrate::{CalibratedSession, Profile, Summary, calibrated_criterion, finalize};

fn main() -> BenchResult {
    let summary = run(Tier::from_env()?)?;
    if summary.untrusted.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} floors violated physical bounds; see the summary above",
            summary.untrusted.len()
        )
        .into())
    }
}

fn run(tier: Tier) -> Result<Summary, Box<dyn std::error::Error>> {
    let mut criterion = calibrated_criterion();
    let mut session = CalibratedSession::new("floors", Profile::L6Graded, "std")?;

    mem::register(&mut criterion, &mut session)?;
    sync::register(&mut criterion, &mut session)?;
    hash::register(&mut criterion, &mut session, tier)?;
    commit::register(&mut criterion, &mut session, tier)?;

    session.set_storage_path(&device_dir()?);
    device::register(
        &mut criterion,
        &mut session,
        &device::Device::prepare(tier)?,
        tier,
    )?;
    engine::register(&mut criterion, &mut session, tier)?;

    crypto::register(&mut criterion, &mut session)?;
    reference::register(&mut criterion, &mut session, tier)?;

    Ok(finalize(&mut session, &criterion)?)
}
