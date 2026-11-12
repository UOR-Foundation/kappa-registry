//! A faulted commit without a crash: writes refused before the file, the
//! sync refused after the writes landed, or the sync performed and reported
//! failed. Each leaves the namespace fenced; the refusal every further
//! publication of that namespace meets is the measured hot path
//! (`store.publish?outcome=refused_conflict`, the whole publish attempt
//! timed, one identifier per fault), then the reopen that resolves the
//! fence (`recovery.open`), verified against what each fault leaves durable
//! (epoch_recovery_tests: refused writes leave the previous epoch; a
//! performed sync reported failed leaves the new one; a refused sync after
//! written pages leaves either), then resolution of the retained candidate
//! before publication resumes.

use kappa_perf::bench::{BenchResult, backend_fault, outcome, time_once};
use kappa_perf::calibrate::CalibratedSession;
use kappa_store::work::WorkMeter;
use kappa_store::{ExecutionStore, PublicationResolution};
use kappa_store_redb::test_support::{Fault, Fired};

use crate::maintenance::settle_to_completion;
use crate::recording::{record_settlement, record_under_fault};
use crate::store::{
    FaultToken, Io, SIGNATURES, Scale, Site, Tail, budget, id, publish, publish_acknowledged,
    verify_recovered,
};

struct Case {
    token: FaultToken,
    fault: Fault,
    tail: Tail,
}

const CASES: [Case; 3] = [
    Case {
        token: FaultToken::RefuseWrites,
        fault: Fault::RefuseWrites,
        tail: Tail::Lost,
    },
    Case {
        token: FaultToken::SyncBefore,
        fault: Fault::FailSyncBefore,
        tail: Tail::MaySurvive,
    },
    Case {
        token: FaultToken::SyncAfter,
        fault: Fault::FailSyncAfter,
        tail: Tail::Survives,
    },
];

/// Publication attempts timed against a fenced namespace per cycle.
const REFUSALS: usize = 256;

pub fn register(
    s: &mut CalibratedSession,
    root: &kappa_fixture::FixtureRoot,
    scale: &Scale,
) -> BenchResult {
    for case in &CASES {
        one_case(s, root, scale, case)?;
    }
    Ok(())
}

fn one_case(
    s: &mut CalibratedSession,
    root: &kappa_fixture::FixtureRoot,
    scale: &Scale,
    case: &Case,
) -> BenchResult {
    let site = Site::prepare(root, case.token.as_str())?;
    let mut opens = Vec::new();
    let mut refusals = Vec::with_capacity(REFUSALS);
    let mut passes = Vec::new();
    let mut fired = Fired::default();
    for round in 0..scale.cycles {
        let store = site.open(Io::Fault, |_| {})?;
        let acknowledged = publish_acknowledged(&store, &site.clock, &site.ns, 1, round)?;
        site.control.arm(case.fault);
        let faulted = publish(&store, &site.clock, &site.ns, 1, round);
        site.control.disarm();
        let token = outcome(&faulted)?;
        if !matches!(token, "indeterminate" | "recovery_required" | "retained") {
            return Err(format!(
                "{}: the faulted publication returned {token}, not a publication fault",
                case.token.as_str()
            )
            .into());
        }
        // The fenced namespace refuses every further publication before any
        // work: the whole attempt, as a client makes it, is the measured path.
        for _ in 0..REFUSALS {
            let (refused, elapsed) = time_once(|| publish(&store, &site.clock, &site.ns, 2, round));
            let token = outcome(&refused)?;
            if token != "refused_conflict" {
                return Err(format!(
                    "{}: a fenced namespace answered {token}, expected refused_conflict",
                    case.token.as_str()
                )
                .into());
            }
            refusals.push(elapsed);
        }
        drop(store);
        fired = fired.plus(site.control.fired());
        if !site
            .namespace_dir()
            .join("publication.fenced")
            .try_exists()?
        {
            return Err(format!(
                "{}: the fence did not survive the handle",
                case.token.as_str()
            )
            .into());
        }
        site.evict_page_cache()?;
        let (reopened, open) = time_once(|| site.open(Io::Fault, |_| {}));
        let reopened = reopened?;
        opens.push(open);
        verify_recovered(&reopened, &site.ns, &acknowledged, case.tail)?;
        passes.push(settle_to_completion(
            &reopened,
            &budget(4096, SIGNATURES),
            &site.absent,
        )?);
        resume(&reopened, &site, case, &acknowledged, round)?;
    }
    let summary = backend_fault(case.token.as_str(), fired);
    record_under_fault(
        s,
        &id(
            "lat",
            "store.publish",
            &[
                ("backend", "redb"),
                ("durability", "immediate"),
                ("fault", case.token.as_str()),
                ("io", Io::Fault.as_str()),
                ("mutations", "1"),
                ("outcome", "refused_conflict"),
            ],
        )?,
        &refusals,
        "PERF-SYS-020",
        &summary,
    )?;
    record_under_fault(
        s,
        &id(
            "lat",
            "recovery.open",
            &[
                ("backend", "redb"),
                ("fault", case.token.as_str()),
                ("io", Io::Fault.as_str()),
                ("pending", "1"),
                ("state", "cold"),
            ],
        )?,
        &opens,
        "PERF-SYS-003",
        &summary,
    )?;
    record_settlement(
        s,
        &[
            ("backend", "redb"),
            ("budget", "4096"),
            ("fault", case.token.as_str()),
            ("io", Io::Fault.as_str()),
            ("pending", "1"),
        ],
        &passes,
        "PERF-SYS-003",
        &summary,
    )
}

/// Publication resumes after recovery. A publication whose writes were
/// refused keeps its signed candidate in custody, and the namespace refuses
/// a replacement until that exact candidate is resolved and published
/// (epoch_recovery_tests: the old head proves noncommit, not permission to
/// replace), so a refusal here is followed by resolution and a retry.
fn resume(
    store: &kappa_store_redb::PersistentStore,
    site: &Site,
    case: &Case,
    acknowledged: &crate::store::Acknowledged,
    round: u64,
) -> BenchResult {
    let after = publish(store, &site.clock, &site.ns, 2, round);
    match outcome(&after)? {
        "admitted" => Ok(()),
        "refused_conflict" => {
            let resolution = ExecutionStore::resolve_publication(
                store,
                &site.ns,
                &site.clock,
                &mut WorkMeter::unbounded(),
            )?;
            let PublicationResolution::Published(resolved) = resolution else {
                return Err(format!(
                    "{}: the retained publication did not resolve: {resolution:?}",
                    case.token.as_str()
                )
                .into());
            };
            let expected = acknowledged.last()? + 1;
            if resolved.epoch_number != expected {
                return Err(format!(
                    "{}: resolution published epoch {}, the retained candidate was {expected}",
                    case.token.as_str(),
                    resolved.epoch_number
                )
                .into());
            }
            publish(store, &site.clock, &site.ns, 2, round)?;
            Ok(())
        }
        token => Err(format!(
            "{}: after recovery a publication returned {token}",
            case.token.as_str()
        )
        .into()),
    }
}
