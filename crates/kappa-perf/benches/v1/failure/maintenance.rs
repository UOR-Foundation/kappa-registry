//! Bounded maintenance passes driven to completion through the public
//! `MaintenanceStore` contract: one driver over every `Progress<T>` pass,
//! and the settle, reclaim and repair passes the fault families measure,
//! settlement ending on the client-observable coverage oracle.

use std::time::Duration;

use kappa_perf::bench::time_once;
use kappa_store::work::{Work, WorkLimit};
use kappa_store::{
    BlobStore, Continuation, Kappa, MaintenanceStore, Progress, Settlement, StoreError,
};
use kappa_store_redb::PersistentStore;

/// One bounded step's measurement.
pub struct Sample<T> {
    pub elapsed: Duration,
    pub outcome: T,
    pub consumed: Work,
}

/// Drive one maintenance pass to completion: `step` from no continuation
/// to `None`, each step timed and checked by `check`. A step that consumed
/// nothing, did nothing by `idle` and still returned a continuation is a
/// limit that cannot admit a mandatory unit (the store refuses such a limit
/// for its own recovery step at open, `validate_settlement`), reported at
/// once rather than looped on.
pub fn drive<T>(
    mut step: impl FnMut(Option<Continuation>) -> Result<Progress<T>, StoreError>,
    check: impl Fn(&T) -> Result<(), String>,
    idle: impl Fn(&T) -> bool,
) -> Result<Vec<Sample<T>>, Box<dyn std::error::Error>> {
    let mut continuation = None;
    let mut samples = Vec::new();
    loop {
        let (progress, elapsed) = time_once(|| step(continuation.take()));
        let progress = progress?;
        check(&progress.outcome)?;
        let stalled = idle(&progress.outcome)
            && progress.consumed == Work::default()
            && progress.continuation.is_some();
        samples.push(Sample {
            elapsed,
            outcome: progress.outcome,
            consumed: progress.consumed,
        });
        if stalled {
            return Err(
                "a step consumed nothing and did nothing yet did not finish: the limit cannot admit a mandatory unit"
                    .into(),
            );
        }
        match progress.continuation {
            Some(next) => continuation = Some(next),
            None => return Ok(samples),
        }
    }
}

/// Settle until the pass is complete, then prove coverage complete the one
/// way a client can: a miss on an identity never written is `NotFound`,
/// not `Unavailable`.
pub fn settle_to_completion(
    store: &PersistentStore,
    limit: &WorkLimit,
    absent: &Kappa,
) -> Result<Vec<Sample<Settlement>>, Box<dyn std::error::Error>> {
    let steps = drive(
        |from| store.settle(limit, from),
        |_| Ok(()),
        |settled| settled.epochs == 0,
    )?;
    match store.blob_get(absent) {
        Err(StoreError::NotFound(_)) => Ok(steps),
        Err(StoreError::Unavailable(why)) => {
            Err(format!("settle reported idle with discovery incomplete: {why}").into())
        }
        other => Err(format!("absent identity: expected NotFound, got {other:?}").into()),
    }
}

/// Every bounded `reclaim_unowned` step to completion: nothing failed and
/// nothing was unrecognized.
pub fn reclaim_to_completion(
    store: &PersistentStore,
    limit: &WorkLimit,
) -> Result<Vec<Duration>, Box<dyn std::error::Error>> {
    let steps = drive(
        |from| store.reclaim_unowned(limit, from),
        |reclaimed| {
            if reclaimed.failed != 0 || reclaimed.unrecognized != 0 {
                return Err(format!(
                    "reclaim left {} failed and {} unrecognized entries",
                    reclaimed.failed, reclaimed.unrecognized
                ));
            }
            Ok(())
        },
        |reclaimed| reclaimed.files == 0 && reclaimed.retained() == 0 && reclaimed.absent == 0,
    )?;
    Ok(steps.into_iter().map(|sample| sample.elapsed).collect())
}

/// Every bounded `repair_indexes` step to completion: no divergence found,
/// recovery having left the derived indexes agreeing with committed state.
pub fn repair_to_completion(
    store: &PersistentStore,
    limit: &WorkLimit,
) -> Result<Vec<Duration>, Box<dyn std::error::Error>> {
    let steps = drive(
        |from| store.repair_indexes(limit, from),
        |repair| {
            if repair.diverged {
                return Err(format!(
                    "repair found diverged indexes after recovery ({} entries rebuilt)",
                    repair.entries
                ));
            }
            Ok(())
        },
        |repair| repair.entries == 0,
    )?;
    Ok(steps.into_iter().map(|sample| sample.elapsed).collect())
}
