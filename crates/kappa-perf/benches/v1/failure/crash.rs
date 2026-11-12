//! Crash inside a publication: `pending` publications acknowledged, then
//! the next one crashed at the first sync of the named database
//! (`Fault::CrashAtSync { role, nth: 1 }`: the registry's registration of
//! the publication, or the namespace's commit), the unsynced sectors of
//! every file lost entirely or each independently from the run seed, the
//! store dropped, the files restored to what reached the medium, the page
//! cache evicted, and the reopen timed (`recovery.open`). Recovery is
//! verified against the acknowledged history before anything is recorded;
//! then settlement, reclamation and index repair run to completion under
//! each budget and are recorded, each budget's records carrying only the
//! faults of its own cycles. A reopen with nothing lost, on the production
//! I/O path, is the baseline.

use kappa_perf::bench::{BenchResult, backend_fault, outcome, time_once};
use kappa_perf::calibrate::CalibratedSession;
use kappa_store::BlobStore;
use kappa_store_redb::test_support::{Fault, Fired, Loss, Role};

use crate::maintenance::{
    Sample, reclaim_to_completion, repair_to_completion, settle_to_completion,
};
use crate::recording::{record_settlement, record_under_fault};
use crate::store::{
    Acknowledged, FaultToken, Io, SIGNATURES, Scale, Site, Tail, budget, id, publish,
    publish_acknowledged, verify_recovered,
};

/// How a cycle's crash loses the unsynced sectors.
struct Mode {
    token: FaultToken,
    loss: fn(u64) -> Loss,
    tail: Tail,
}

const MODES: [Mode; 2] = [
    Mode {
        token: FaultToken::Crash,
        loss: |_| Loss::All,
        tail: Tail::Lost,
    },
    Mode {
        token: FaultToken::CrashPartial,
        loss: |seed| Loss::Independent { percent: 50, seed },
        tail: Tail::MaySurvive,
    },
];

const ROLES: [Role; 2] = [Role::Namespace, Role::Registry];

pub fn register(
    s: &mut CalibratedSession,
    root: &kappa_fixture::FixtureRoot,
    scale: &Scale,
) -> BenchResult {
    for mode in &MODES {
        for role in ROLES {
            for &pending in scale.pending {
                cycle_set(s, root, scale, mode, role, pending)?;
            }
        }
    }
    for &pending in scale.pending {
        clean_baseline(s, root, scale, pending)?;
    }
    Ok(())
}

/// What one crash cycle produced, with the store reopened after it.
struct Cycle {
    store: kappa_store_redb::PersistentStore,
    open: std::time::Duration,
    fired: Fired,
    acknowledged: Acknowledged,
}

/// Publish `pending` epochs, crash the next at the named database's sync,
/// restore, evict, reopen, verify.
fn one_cycle(
    site: &Site,
    mode: &Mode,
    role: Role,
    pending: usize,
    round: u64,
    seed: u64,
) -> Result<Cycle, Box<dyn std::error::Error>> {
    let store = site.open(Io::Fault, |_| {})?;
    site.control.track_unsynced(true);
    let acknowledged = publish_acknowledged(&store, &site.clock, &site.ns, pending, round)?;
    site.control.arm(Fault::CrashAtSync { role, nth: 1 });
    let faulted = publish(&store, &site.clock, &site.ns, pending, round);
    let token = outcome(&faulted)?;
    if token == "admitted" {
        return Err("the publication whose sync crashed was acknowledged".into());
    }
    if !site.control.crashed() {
        return Err(format!(
            "publication {pending} returned {token} but no {} sync was met: {:?}",
            role.as_str(),
            site.control.trace()
        )
        .into());
    }
    let selected = site.control.crash((mode.loss)(seed ^ round));
    drop(store);
    let fired = site.control.fired();
    if fired.refused == 0 {
        return Err(format!("crash did not fire: {fired:?}").into());
    }
    if matches!((mode.loss)(seed), Loss::All) && selected == 0 {
        return Err("a crash at the commit's sync found nothing unsynced".into());
    }
    site.control.restore()?;
    site.evict_page_cache()?;
    let (reopened, open) = time_once(|| site.open(Io::Fault, |_| {}));
    let reopened = reopened?;
    verify_recovered(&reopened, &site.ns, &acknowledged, mode.tail)?;
    Ok(Cycle {
        store: reopened,
        open,
        fired,
        acknowledged,
    })
}

fn cycle_set(
    s: &mut CalibratedSession,
    root: &kappa_fixture::FixtureRoot,
    scale: &Scale,
    mode: &Mode,
    role: Role,
    pending: usize,
) -> BenchResult {
    let site = Site::prepare(
        root,
        &format!("{}-{}-{pending}", mode.token.as_str(), role.as_str()),
    )?;
    let pending_text = pending.to_string();
    let base: Vec<(&str, &str)> = vec![
        ("backend", "redb"),
        ("crash_at", role.as_str()),
        ("fault", mode.token.as_str()),
        ("io", Io::Fault.as_str()),
        ("pending", &pending_text),
    ];
    let mut opens = Vec::new();
    let mut opens_fired = Fired::default();
    // Every budget settles its own cycles so each budget's steps are
    // measured from the same unsettled backlog, and each budget's records
    // carry only the faults of its own cycles.
    for &entries in scale.budgets {
        let limit = budget(entries, SIGNATURES);
        let mut settle_passes: Vec<Vec<Sample<_>>> = Vec::new();
        let mut reclaim_steps = Vec::new();
        let mut repair_steps = Vec::new();
        let mut fired = Fired::default();
        for round in 0..scale.cycles {
            let cycle = one_cycle(&site, mode, role, pending, round, scale.seed)?;
            opens.push(cycle.open);
            fired = fired.plus(cycle.fired);
            settle_passes.push(settle_to_completion(&cycle.store, &limit, &site.absent)?);
            // The acknowledged state is intact after settlement too.
            verify_recovered(&cycle.store, &site.ns, &cycle.acknowledged, mode.tail)?;
            reclaim_steps.extend(reclaim_to_completion(&cycle.store, &limit)?);
            repair_steps.extend(repair_to_completion(&cycle.store, &limit)?);
        }
        opens_fired = opens_fired.plus(fired);
        let summary = backend_fault(mode.token.as_str(), fired);
        let budget_text = entries.to_string();
        let mut conditions = base.clone();
        conditions.push(("budget", &budget_text));
        record_settlement(s, &conditions, &settle_passes, "PERF-SYS-003", &summary)?;
        let maintenance = [
            ("backend", "redb"),
            ("budget", budget_text.as_str()),
            ("crash_at", role.as_str()),
            ("fault", mode.token.as_str()),
            ("io", Io::Fault.as_str()),
        ];
        record_under_fault(
            s,
            &id("lat", "reclaim.unowned", &maintenance)?,
            &reclaim_steps,
            "PERF-SYS-003",
            &summary,
        )?;
        record_under_fault(
            s,
            &id("lat", "repair.index", &maintenance)?,
            &repair_steps,
            "PERF-SYS-003",
            &summary,
        )?;
    }
    let mut conditions = base;
    conditions.push(("state", "cold"));
    record_under_fault(
        s,
        &id("lat", "recovery.open", &conditions)?,
        &opens,
        "PERF-SYS-003",
        &backend_fault(mode.token.as_str(), opens_fired),
    )
}

/// A reopen with nothing lost, for the same backlog, through redb's own
/// file backend: the cost of recovery at open on the production I/O path.
fn clean_baseline(
    s: &mut CalibratedSession,
    root: &kappa_fixture::FixtureRoot,
    scale: &Scale,
    pending: usize,
) -> BenchResult {
    let site = Site::prepare(root, &format!("clean-{pending}"))?;
    let mut opens = Vec::new();
    for round in 0..scale.cycles {
        let acknowledged = {
            let store = site.open(Io::File, |_| {})?;
            publish_acknowledged(&store, &site.clock, &site.ns, pending, round)?
        };
        site.evict_page_cache()?;
        let (reopened, open) = time_once(|| site.open(Io::File, |_| {}));
        let reopened = reopened?;
        opens.push(open);
        verify_recovered(&reopened, &site.ns, &acknowledged, Tail::Lost)?;
        settle_to_completion(&reopened, &budget(4096, SIGNATURES), &site.absent)?;
        match reopened.blob_get(&site.absent) {
            Err(kappa_store::StoreError::NotFound(_)) => {}
            other => return Err(format!("clean reopen oracle: {other:?}").into()),
        }
    }
    let pending_text = pending.to_string();
    record_under_fault(
        s,
        &id(
            "lat",
            "recovery.open",
            &[
                ("backend", "redb"),
                ("fault", FaultToken::None.as_str()),
                ("io", Io::File.as_str()),
                ("pending", &pending_text),
                ("state", "cold"),
            ],
        )?,
        &opens,
        "PERF-SYS-003",
        &backend_fault(FaultToken::None.as_str(), Fired::default()),
    )
}
