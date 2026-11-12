//! Bounded, fair background maintenance: settlement of published epochs,
//! repair of derived indexes, physical inventory of content storage, and
//! eviction of expired session rows.
//!
//! A publication is acknowledged when its namespace committed; its effects
//! on the registry's shared projections (catalog, ownership, directory) are
//! settled here. Representations no committed row owns are settled by the
//! store's bounded inventory, which decides every entry from its
//! installer's committed state. A backend that recorded a divergence of
//! its derived indexes repairs them here, in bounded steps.
//!
//! Every tick gives each operation one step of its own quantum: a
//! [`WorkLimit`] finite on every dimension (`MaintenanceLimits`, entries
//! from the batch) and its own share of the tick's interval as a deadline.
//! The deadline is an admission deadline: no new unit of work starts after
//! it; a blocking unit already admitted may finish afterwards, and the work
//! it completed is reported. The operation that runs first rotates from
//! tick to tick, so no operation can take the others' share by always
//! running first. Each operation's continuation is carried to the next
//! tick independently; a step that fails drops its own continuation, and
//! its pass starts over, without withholding the others.

use std::sync::Arc;
use std::time::{Duration, Instant};

use kappa_handler::clock::Clock;
use kappa_store::traits::KappaStore;
use kappa_store::work::{Dimension, WorkLimit};
use kappa_store::{Continuation, Progress, StoreError};

use crate::config::MaintenanceLimits;

/// One maintenance operation the loop schedules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Settle,
    Repair,
    Reclaim,
    Evict,
}

impl Operation {
    /// Every operation, in the order of tick zero.
    pub const ALL: [Self; 4] = [Self::Settle, Self::Repair, Self::Reclaim, Self::Evict];
}

/// The order operations run in at `tick`: the order of tick zero rotated
/// by `tick`, so each operation runs first every fourth tick.
pub fn order(tick: u64) -> [Operation; 4] {
    let mut order = Operation::ALL;
    let shift = usize::try_from(tick % Operation::ALL.len() as u64).unwrap_or(0);
    order.rotate_left(shift);
    order
}

/// The work limit of one operation's step: `limits` on every dimension,
/// `entries` examined, and the admission deadline `deadline`.
pub fn quantum(limits: &MaintenanceLimits, entries: u64, deadline: Instant) -> WorkLimit {
    WorkLimit::unbounded()
        .with(Dimension::Entries, entries)
        .with(Dimension::BytesRead, limits.bytes_read)
        .with(Dimension::BytesDecoded, limits.bytes_decoded)
        .with(Dimension::BytesAllocated, limits.bytes_allocated)
        .with(Dimension::BytesHashed, limits.bytes_hashed)
        .with(Dimension::Signatures, limits.signatures)
        .with(Dimension::Handles, limits.handles)
        .with(Dimension::Candidates, limits.candidates)
        .with_deadline(deadline)
}

/// The continuations the loop carries from tick to tick, one per
/// operation.
#[derive(Default)]
struct Passes {
    settle: Option<Continuation>,
    repair: Option<Continuation>,
    reclaim: Option<Continuation>,
}

/// The continuation of `step` for the next tick: kept on progress, dropped
/// on failure (the pass starts over).
fn resume<T>(step: &mut Result<Progress<T>, StoreError>) -> Option<Continuation> {
    step.as_mut()
        .ok()
        .and_then(|progress| progress.continuation.take())
}

/// What one tick's steps returned.
#[derive(Default)]
struct Tick {
    settlement: Option<Result<Progress<kappa_store::Settlement>, StoreError>>,
    repair: Option<Result<Progress<kappa_store::IndexRepair>, StoreError>>,
    reclamation: Option<Result<Progress<kappa_store::Reclamation>, StoreError>>,
    evicted: Option<Result<u64, StoreError>>,
}

/// Run one tick: each operation in `order(tick)`, each with its own
/// quantum and its own slice of `period` as its deadline.
fn run_tick<S>(
    store: &S,
    clock: &dyn Clock,
    passes: &mut Passes,
    tick: u64,
    period: Duration,
    limits: &MaintenanceLimits,
    entries: u64,
) -> Tick
where
    S: KappaStore + ?Sized,
{
    let slice = period / u32::try_from(Operation::ALL.len()).unwrap_or(1);
    let mut outcome = Tick::default();
    for operation in order(tick) {
        let limit = quantum(limits, entries, Instant::now() + slice);
        match operation {
            Operation::Settle => {
                let mut step = store.settle(&limit, passes.settle.take());
                passes.settle = resume(&mut step);
                outcome.settlement = Some(step);
            }
            Operation::Repair => {
                let mut step = store.repair_indexes(&limit, passes.repair.take());
                passes.repair = resume(&mut step);
                outcome.repair = Some(step);
            }
            Operation::Reclaim => {
                let mut step = store.reclaim_unowned(&limit, passes.reclaim.take());
                passes.reclaim = resume(&mut step);
                outcome.reclamation = Some(step);
            }
            Operation::Evict => {
                outcome.evicted = Some(
                    clock
                        .now()
                        .map_err(|error| StoreError::Internal(error.to_string()))
                        .and_then(|now| store.session_evict(now)),
                );
            }
        }
    }
    outcome
}

fn report(tick: &Tick, passes: &Passes) {
    match &tick.evicted {
        Some(Ok(count)) if *count > 0 => {
            tracing::info!(sessions = count, "expired sessions evicted");
        }
        Some(Err(error)) => tracing::warn!(%error, "session eviction failed"),
        _ => {}
    }
    match &tick.settlement {
        Some(Ok(step)) if step.outcome.epochs > 0 => tracing::info!(
            epochs = step.outcome.epochs,
            complete = passes.settle.is_none(),
            "settlement step"
        ),
        Some(Err(error)) => tracing::warn!(%error, "settlement step failed"),
        _ => {}
    }
    match &tick.repair {
        Some(Ok(step)) if step.outcome.diverged => tracing::warn!(
            entries = step.outcome.entries,
            complete = passes.repair.is_none(),
            "derived indexes repaired from committed state"
        ),
        Some(Err(error)) => tracing::warn!(%error, "derived index repair failed"),
        _ => {}
    }
    match &tick.reclamation {
        Some(Ok(step)) if step.outcome.files > 0 || step.outcome.unrecognized > 0 => {
            let found = step.outcome;
            tracing::info!(
                files = found.files,
                bytes = found.bytes,
                owned = found.owned,
                protected = found.protected,
                unrecognized = found.unrecognized,
                absent = found.absent,
                failed = found.failed,
                complete = passes.reclaim.is_none(),
                "content inventory step"
            );
        }
        Some(Err(error)) => tracing::warn!(%error, "content inventory failed"),
        _ => {}
    }
}

pub async fn run_inventory_loop<S>(
    store: Arc<S>,
    clock: Arc<dyn Clock>,
    interval_secs: u64,
    batch: usize,
    limits: MaintenanceLimits,
) where
    S: KappaStore + 'static + ?Sized,
{
    let period = Duration::from_secs(interval_secs.max(1));
    let mut interval = tokio::time::interval(period);
    let entries = u64::try_from(batch).unwrap_or(u64::MAX);
    let mut passes = Passes::default();
    let mut tick = 0u64;
    loop {
        interval.tick().await;
        let s = store.clone();
        let c = clock.clone();
        let mut carried = std::mem::take(&mut passes);
        let number = tick;
        tick = tick.wrapping_add(1);
        match tokio::task::spawn_blocking(move || {
            let outcome = run_tick(&*s, &*c, &mut carried, number, period, &limits, entries);
            (outcome, carried)
        })
        .await
        {
            Ok((outcome, carried)) => {
                passes = carried;
                report(&outcome, &passes);
            }
            // The task panicked: its continuations are gone with it, and
            // every pass starts over at the next tick.
            Err(error) => tracing::warn!(%error, "maintenance task failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Over any four consecutive ticks every operation runs first exactly
    /// once and every operation runs in every tick.
    #[test]
    fn every_operation_leads_once_every_four_ticks() {
        for start in [0u64, 1, 7, u64::MAX - 3] {
            let mut leaders = Vec::new();
            for offset in 0..4 {
                let tick = order(start.wrapping_add(offset));
                let mut sorted = tick.to_vec();
                sorted.sort_by_key(|operation| Operation::ALL.iter().position(|o| o == operation));
                assert_eq!(sorted, Operation::ALL.to_vec(), "every operation runs");
                leaders.push(tick[0]);
            }
            for operation in Operation::ALL {
                assert_eq!(
                    leaders
                        .iter()
                        .filter(|leader| **leader == operation)
                        .count(),
                    1,
                    "{operation:?} leads once from tick {start}"
                );
            }
        }
    }

    /// Whether `step` consumed no more than `limit` on any dimension.
    fn within<T>(step: &Progress<T>, limit: &WorkLimit) -> bool {
        Dimension::ALL
            .iter()
            .all(|dimension| step.consumed.get(*dimension) <= limit.limit(*dimension))
    }

    /// Under a settlement backlog that grows every tick and reclaimable
    /// residue present from the start, small quanta give both operations
    /// measured progress: settlement settles epochs while reclamation
    /// deletes the residue, and no step passes its quantum on any
    /// dimension.
    #[test]
    fn a_sustained_backlog_and_residue_both_make_progress() -> Result<(), Box<dyn std::error::Error>>
    {
        use kappa_store::{ClockMs, NamespaceRef};
        use kappa_store::{
            ContentIdentity, ContentPreparation, Kappa, PreparationBounds, TagUpdate,
        };

        const RESIDUE: u8 = 6;
        const TICKS: u64 = 64;
        let fixture = kappa_store_redb::test_support::persistent_store()?;
        let store = fixture.store();
        let ns = NamespaceRef::deterministic("maintenance-fairness");
        let mut time = 1_000i64;
        let mut publish =
            |store: &kappa_store_redb::PersistentStore| -> Result<(), Box<dyn std::error::Error>> {
                time += 1;
                let clock = kappa_handler::clock_at(ClockMs::from_raw(time))?;
                let mut execution = store.begin_epoch_execution(&ns, &clock, None)?;
                execution.tag_put(
                    "head",
                    &TagUpdate::Set {
                        kappa: Kappa::sha256(&time.to_be_bytes()),
                    },
                )?;
                execution.publish()?;
                Ok(())
            };
        for _ in 0..8 {
            publish(store)?;
        }
        for fill in 0..RESIDUE {
            // Prepared and never installed: an allocation no row owns.
            let bytes = vec![fill; 64 * 1024];
            let prepared = store.prepare_content(
                ContentIdentity::Verified(Kappa::sha256(&bytes)),
                &mut bytes.as_slice(),
                PreparationBounds {
                    maximum: bytes.len() as u64,
                    deadline: Instant::now() + Duration::from_secs(30),
                },
            )?;
            drop(prepared);
        }
        let limits = MaintenanceLimits {
            bytes_read: 64 * 1024 * 1024,
            bytes_decoded: 64 * 1024 * 1024,
            bytes_allocated: 16 * 1024 * 1024,
            bytes_hashed: 64 * 1024 * 1024,
            signatures: 8,
            // Every shard of the inventory and every visit of settlement
            // opens a handle: 64 a step spreads one inventory pass over
            // several ticks.
            handles: 64,
            candidates: 64,
        };
        let entries = 8;
        let clock = kappa_handler::clock_at(ClockMs::from_raw(1_000_000))?;
        let mut passes = Passes::default();
        let (mut settled, mut reclaimed) = (0u64, 0u64);
        let (mut settled_ticks, mut reclaimed_ticks) = (0u64, 0u64);
        for tick in 0..TICKS {
            // The backlog grows while maintenance runs.
            publish(store)?;
            let outcome = run_tick(
                store,
                &clock,
                &mut passes,
                tick,
                Duration::from_secs(40),
                &limits,
                entries,
            );
            let limit = quantum(&limits, entries, Instant::now());
            let settlement = outcome.settlement.ok_or("settlement did not run")??;
            assert!(within(&settlement, &limit), "settlement passed its quantum");
            settled += settlement.outcome.epochs;
            settled_ticks += u64::from(settlement.outcome.epochs > 0);
            let reclamation = outcome.reclamation.ok_or("reclamation did not run")??;
            assert!(
                within(&reclamation, &limit),
                "reclamation passed its quantum"
            );
            reclaimed += reclamation.outcome.files;
            reclaimed_ticks += u64::from(reclamation.outcome.files > 0);
            let repair = outcome.repair.ok_or("repair did not run")??;
            assert!(within(&repair, &limit), "repair passed its quantum");
            outcome.evicted.ok_or("eviction did not run")??;
        }
        assert!(
            settled > 0 && settled_ticks > 1,
            "settlement progressed: {settled}"
        );
        assert_eq!(
            reclaimed,
            u64::from(RESIDUE),
            "every residual allocation was reclaimed under the backlog"
        );
        assert!(reclaimed_ticks >= 1);
        Ok(())
    }

    /// A quantum is finite on every dimension the configuration names.
    #[test]
    fn a_quantum_is_finite_on_every_dimension() {
        let limits = MaintenanceLimits {
            bytes_read: 1,
            bytes_decoded: 2,
            bytes_allocated: 3,
            bytes_hashed: 4,
            signatures: 5,
            handles: 6,
            candidates: 7,
        };
        let limit = quantum(&limits, 8, Instant::now());
        for dimension in Dimension::ALL {
            assert_ne!(limit.limit(dimension), u64::MAX, "{dimension:?} unbounded");
        }
        assert!(limit.deadline().is_some());
    }
}
