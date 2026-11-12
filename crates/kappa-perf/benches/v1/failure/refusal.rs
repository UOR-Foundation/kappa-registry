//! Publication at the admission ceiling: the per-namespace bound on
//! unsettled epochs filled, then every further publication of that
//! namespace timed and recorded under the outcome it returns. The store's
//! contract allows admission at the bound either to refuse
//! (`CapacityExceeded`, nothing committed) or to run a bounded settlement
//! of that namespace itself and admit (`MaintenanceStore::settle` doc):
//! `outcome=refused_capacity` and `outcome=admitted_after_settlement`,
//! each beside the admitted publication of the same shape on an
//! unsaturated store on the same I/O path, so `refused_le_admitted` judges
//! the refusal against the work it refused. The production I/O path is
//! measured too, so the admitted baseline exists where no fault backend
//! sits in the way.

use std::time::Duration;

use kappa_perf::bench::{BenchResult, backend_fault, outcome, time_once};
use kappa_perf::calibrate::CalibratedSession;
use kappa_store::{EpochStore, MaintenanceStore};
use kappa_store_redb::test_support::Fired;

use crate::maintenance::settle_to_completion;
use crate::recording::record_under_fault;
use crate::store::{FaultToken, Io, SIGNATURES, Scale, Site, budget, id, publish};

/// The per-namespace unsettled bound of the saturated store.
const CEILING: usize = 3;
/// Publications timed per cycle at the ceiling.
const AT_CEILING: usize = 256;
/// Admitted publications timed per cycle on the unsaturated store.
const ADMITTED: usize = 64;

pub fn register(
    s: &mut CalibratedSession,
    root: &kappa_fixture::FixtureRoot,
    scale: &Scale,
) -> BenchResult {
    for io in [Io::File, Io::Fault] {
        one_path(s, root, scale, io)?;
    }
    Ok(())
}

fn one_path(
    s: &mut CalibratedSession,
    root: &kappa_fixture::FixtureRoot,
    scale: &Scale,
    io: Io,
) -> BenchResult {
    let site = Site::prepare(root, &format!("refusal-{}", io.as_str()))?;
    let mut admitted = Vec::with_capacity(ADMITTED);
    let mut at_ceiling: Vec<(&'static str, Duration)> = Vec::with_capacity(AT_CEILING);
    for round in 0..scale.cycles {
        {
            // Unsaturated: the default bound, settled after the batch so no
            // publication meets the ceiling.
            let store = site.open(io, |_| {})?;
            for index in 0..ADMITTED {
                let (result, elapsed) =
                    time_once(|| publish(&store, &site.clock, &site.ns, index, round));
                if outcome(&result)? != "admitted" {
                    return Err(format!("unsaturated publication {index}: {result:?}").into());
                }
                admitted.push(elapsed);
            }
            settle_to_completion(&store, &budget(4096, SIGNATURES), &site.absent)?;
        }
        let store = site.open(io, |config| config.max_unsettled_epochs = CEILING)?;
        for index in 0..CEILING {
            let result = publish(&store, &site.clock, &site.ns, index, round + 1_000);
            if outcome(&result)? != "admitted" {
                return Err(format!("publication {index} below the ceiling: {result:?}").into());
            }
        }
        let (mut head, _) = store.epoch_current(&site.ns)?;
        for index in 0..AT_CEILING {
            let (result, elapsed) = time_once(|| {
                publish(
                    &store,
                    &site.clock,
                    &site.ns,
                    CEILING + index,
                    round + 1_000,
                )
            });
            let token = outcome(&result)?;
            let (now, _) = store.epoch_current(&site.ns)?;
            let recorded = match token {
                "refused_capacity" => {
                    if now != head {
                        return Err("a refused publication moved the head".into());
                    }
                    "refused_capacity"
                }
                "admitted" => {
                    if now != head + 1 {
                        return Err(format!(
                            "an admitted publication at the ceiling moved the head from {head} to {now}"
                        )
                        .into());
                    }
                    head = now;
                    "admitted_after_settlement"
                }
                other => {
                    return Err(format!(
                        "at the ceiling a publication returned {other}; the contract allows refusal or admission under the store's own settlement"
                    )
                    .into());
                }
            };
            at_ceiling.push((recorded, elapsed));
        }
        // One explicit step relieves the namespace; publication resumes.
        let progress = store.settle(&budget(4096, SIGNATURES), None)?;
        if progress.outcome.epochs == 0 {
            return Err("the relieving settlement step settled nothing".into());
        }
        let result = publish(
            &store,
            &site.clock,
            &site.ns,
            CEILING + AT_CEILING,
            round + 1_000,
        );
        if outcome(&result)? != "admitted" {
            return Err(format!("after relief a publication returned {result:?}").into());
        }
        settle_to_completion(&store, &budget(4096, SIGNATURES), &site.absent)?;
    }
    let none = backend_fault(FaultToken::None.as_str(), Fired::default());
    let shape = |token: &'static str| -> [(&'static str, &'static str); 6] {
        [
            ("backend", "redb"),
            ("durability", "immediate"),
            ("fault", FaultToken::None.as_str()),
            ("io", io.as_str()),
            ("mutations", "1"),
            ("outcome", token),
        ]
    };
    record_under_fault(
        s,
        &id("lat", "store.publish", &shape("admitted"))?,
        &admitted,
        "PERF-SYS-020",
        &none,
    )?;
    for token in ["refused_capacity", "admitted_after_settlement"] {
        let durations: Vec<Duration> = at_ceiling
            .iter()
            .filter(|(seen, _)| *seen == token)
            .map(|(_, elapsed)| *elapsed)
            .collect();
        eprintln!(
            "at the ceiling on io={}: {} {token}",
            io.as_str(),
            durations.len()
        );
        if durations.is_empty() {
            continue;
        }
        record_under_fault(
            s,
            &id("lat", "store.publish", &shape(token))?,
            &durations,
            "PERF-SYS-020",
            &none,
        )?;
    }
    Ok(())
}
