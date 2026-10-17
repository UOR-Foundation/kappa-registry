//! Calibrated workloads: composite kappa operations through the production
//! store contracts on both backends, recorded to
//! `target/calibration_workloads.jsonl` and validated, compared and graded
//! against the same-host floors in `target/calibration_floors.jsonl`.
//!
//! Every workload's constituent floors must be established, by the floors
//! bench on this host, before it is measured (profile L6 gates on them).
//! Order follows the dependency graph: the succinct index before the sweep
//! that cursors over it; blob ingest before the transactions and multipart
//! completions that ingest; tag writes and reads before publication;
//! epoch retrieval before operation replay.
//!
//! Run: `cargo bench -p kappa-perf --bench floors` first, then
//! `cargo bench -p kappa-perf --bench workloads`.
//! Scale: `KAPPA_PERF_TIER=smoke|standard|full` (default standard).
//! Device: `KAPPA_PERF_DEVICE_DIR` selects the filesystem the stores use.

#[path = "workloads/blobs.rs"]
mod blobs;
#[path = "workloads/history.rs"]
mod history;
#[path = "workloads/index.rs"]
mod index;
#[path = "workloads/index_writes.rs"]
mod index_writes;
#[path = "workloads/objects.rs"]
mod objects;
#[path = "workloads/publish.rs"]
mod publish;
#[path = "workloads/staging.rs"]
mod staging;

use kappa_handler::clock::WallClock;
use kappa_perf::bench::fixture::{Fixture, encrypted_target, memory_target, redb_target};
use kappa_perf::bench::{BenchResult, Tier, device_dir};
use kappa_perf::calibrate::{CalibratedSession, Profile, Summary, calibrated_criterion, finalize};

fn main() -> BenchResult {
    let summary = run(Tier::from_env()?)?;
    if summary.untrusted.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} workload measurements violated physical bounds; see the summary above",
            summary.untrusted.len()
        )
        .into())
    }
}

fn run(tier: Tier) -> Result<Summary, Box<dyn std::error::Error>> {
    let mut criterion = calibrated_criterion();
    let mut session = CalibratedSession::new("workloads", Profile::L6Graded, "std")?;
    let device = device_dir()?;
    session.set_storage_path(&device);
    let clock = WallClock::new();
    let fixture = Fixture::new(&device)?;

    index::register(&mut criterion, &mut session, tier)?;
    blob_workloads(&mut criterion, &mut session, tier, &clock, &fixture)?;
    staging_workloads(&mut criterion, &mut session, tier, &clock, &fixture)?;

    {
        let memory = fixture.memory("namespaces-memory")?;
        let redb = fixture.redb("namespaces-redb", false)?;
        publish::register(
            &mut criterion,
            &mut session,
            tier,
            &clock,
            &memory_target(&memory),
        )?;
        publish::register(
            &mut criterion,
            &mut session,
            tier,
            &clock,
            &redb_target(&redb),
        )?;
        objects::register(
            &mut criterion,
            &mut session,
            tier,
            &clock,
            &memory_target(&memory),
        )?;
        objects::register(
            &mut criterion,
            &mut session,
            tier,
            &clock,
            &redb_target(&redb),
        )?;
    }

    {
        let memory = fixture.memory("history-memory")?;
        let redb = fixture.redb("history-redb", false)?;
        history::register(&mut session, tier, &clock, &memory_target(&memory))?;
        history::register(&mut session, tier, &clock, &redb_target(&redb))?;
    }

    Ok(finalize(&mut session, &criterion)?)
}

/// Blob ingest and reads on the memory, redb and encrypted redb stores.
fn blob_workloads(
    criterion: &mut criterion::Criterion,
    session: &mut CalibratedSession,
    tier: Tier,
    clock: &WallClock,
    fixture: &Fixture,
) -> BenchResult {
    let memory = fixture.memory("blobs-memory")?;
    let redb = fixture.redb("blobs-redb", false)?;
    let encrypted = fixture.redb("blobs-encrypted", true)?;
    blobs::register(criterion, session, tier, clock, &memory_target(&memory))?;
    blobs::register(criterion, session, tier, clock, &redb_target(&redb))?;
    blobs::register(
        criterion,
        session,
        tier,
        clock,
        &encrypted_target(&encrypted),
    )
}

/// Resource staging and its promotion on the memory and redb stores.
fn staging_workloads(
    criterion: &mut criterion::Criterion,
    session: &mut CalibratedSession,
    tier: Tier,
    clock: &WallClock,
    fixture: &Fixture,
) -> BenchResult {
    let memory = fixture.memory("promote-memory")?;
    let redb = fixture.redb("promote-redb", false)?;
    staging::staging(criterion, session, tier, clock, &memory_target(&memory))?;
    staging::staging(criterion, session, tier, clock, &redb_target(&redb))?;
    staging::promotion(criterion, session, tier, clock, &memory_target(&memory))?;
    staging::promotion(criterion, session, tier, clock, &redb_target(&redb))
}
