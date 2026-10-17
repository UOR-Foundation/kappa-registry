//! PERF-CON-004: the causal time authority never issues backwards, never
//! reissues a timestamp across restart, and never issues past its durable
//! reservation.
//!
//! The process-local cases run `WallClock` over a controlled physical
//! source. The durable cases run `WallClock::durable` over the redb
//! `PersistentStore`, drop both, and reopen the same database: recovery
//! must start above every reservation and every committed timestamp, issue
//! immediately even while physical time lags that floor, never run past its
//! durable ceiling, and hold exclusive ownership of the backend for the
//! authority's lifetime.

use std::sync::Arc;

use kappa_fixture::{FixtureRoot, SetupError};
use kappa_handler::clock::{Clock, ClockError, ControlledSource, WallClock, clock_at};
use kappa_store::StoreError;
use kappa_store::clock::{CausalTime, ClockMs, DurationMs, UnixTimeMs};
use kappa_store::{ExecutionStore, NamespaceRef};
use kappa_store_redb::PersistentStore;

use crate::common::{TestResult, redb_store_in};

fn source_at(ms: i64) -> Arc<ControlledSource> {
    Arc::new(ControlledSource::new(UnixTimeMs::from_millis(ms)))
}

fn causal(clock: &dyn Clock) -> Result<CausalTime, ClockError> {
    clock.now().map(CausalTime::from_encoded)
}

fn durable(
    source: &Arc<ControlledSource>,
    store: &Arc<PersistentStore>,
    headroom_ms: u64,
) -> Result<WallClock, ClockError> {
    WallClock::durable(
        Arc::clone(source) as Arc<dyn kappa_handler::clock::PhysicalSource>,
        Arc::clone(store) as Arc<dyn kappa_store::time::TimeReservationStore>,
        DurationMs::from_millis(headroom_ms),
    )
}

/// Open, or reopen, the shared store in `root` as the clock's backend.
fn reopen(root: &FixtureRoot) -> Result<Arc<PersistentStore>, SetupError> {
    redb_store_in(root).map(Arc::new)
}

// -- Process-local authority --

#[test]
fn wall_clock_strictly_monotonic() -> TestResult {
    let clock = WallClock::new();
    let mut prev = causal(&clock)?;
    for _ in 0..10_000 {
        let next = causal(&clock)?;
        assert!(
            next > prev,
            "must strictly increase: prev={prev:?}, next={next:?}"
        );
        prev = next;
    }
    Ok(())
}

#[test]
fn physical_regression_preserves_causal_time() -> TestResult {
    let source = source_at(5000);
    let clock = WallClock::recovered(source.clone(), CausalTime::new(0, 0)?);
    let t1 = clock.now()?;
    assert_eq!(t1.physical_ms(), 5000);

    source.advance(DurationMs::from_millis(1000))?;
    let t2 = clock.now()?;
    assert_eq!(t2.physical_ms(), 6000);

    // Physical regression: causal time keeps the 6000 ms component and
    // advances the logical counter.
    source.set(UnixTimeMs::from_millis(4000));
    let t3 = CausalTime::from_encoded(clock.now()?);
    assert_eq!(t3, CausalTime::new(6000, 1)?);
    assert_eq!(clock.physical_now()?.as_millis(), 4000);
    Ok(())
}

#[test]
fn recovered_clock_starts_above_floor() -> TestResult {
    let floor = CausalTime::new(8_000, 3)?;
    let clock = WallClock::recovered(source_at(10_000), floor);
    assert_eq!(causal(&clock)?, CausalTime::new(10_000, 0)?);
    Ok(())
}

#[test]
fn recovered_clock_advances_past_physical() -> TestResult {
    // The floor is ahead of physical time: issuance continues the floor's
    // physical component instead of jumping back to the source.
    let floor = CausalTime::new(6000, 0)?;
    let clock = WallClock::recovered(source_at(5000), floor);
    assert_eq!(causal(&clock)?, CausalTime::new(6000, 1)?);
    assert_eq!(causal(&clock)?, CausalTime::new(6000, 2)?);
    assert_eq!(clock.physical_now()?.as_millis(), 5000);
    Ok(())
}

#[test]
fn concurrent_issuance_all_unique() -> TestResult {
    const THREADS: usize = 8;
    const PER_THREAD: usize = 2048;
    let clock = Arc::new(WallClock::recovered(
        source_at(200),
        CausalTime::new(200, 0)?,
    ));
    let workers: Vec<_> = (0..THREADS)
        .map(|_| {
            let clock = Arc::clone(&clock);
            std::thread::spawn(move || {
                (0..PER_THREAD)
                    .map(|_| causal(&*clock))
                    .collect::<Result<Vec<_>, ClockError>>()
            })
        })
        .collect();
    let mut all = Vec::with_capacity(THREADS * PER_THREAD);
    for worker in workers {
        all.extend(worker.join().map_err(|_| "issuance worker panicked")??);
    }
    all.sort_unstable();
    all.dedup();
    assert_eq!(
        all.len(),
        THREADS * PER_THREAD,
        "duplicate timestamps issued"
    );
    // Physical time never moved: every issuance consumed one logical step,
    // so no CAS winner was lost.
    let issued = u16::try_from(THREADS * PER_THREAD)?;
    assert_eq!(clock.issued_floor(), CausalTime::new(200, issued)?);
    Ok(())
}

#[test]
fn physical_now_independent_of_causal() -> TestResult {
    let source = source_at(1000);
    let clock = WallClock::recovered(source.clone(), CausalTime::new(500, 0)?);
    for _ in 0..10 {
        causal(&clock)?;
    }
    assert_eq!(clock.physical_now()?.as_millis(), 1000);
    source.set(UnixTimeMs::from_millis(2000));
    assert_eq!(clock.physical_now()?.as_millis(), 2000);
    Ok(())
}

#[test]
fn diskless_authority_cannot_renew() {
    assert!(matches!(
        WallClock::new().renew_reservation(DurationMs::from_millis(10)),
        Err(ClockError::DisklessAuthority)
    ));
}

// -- Durable authority over redb --

#[test]
fn durable_restart_never_reissues_reserved_time() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let source = source_at(10_000);
    let mut issued = Vec::new();
    {
        let store = reopen(&root)?;
        let clock = durable(&source, &store, 1000)?;
        for _ in 0..100 {
            issued.push(causal(&clock)?);
        }
    }
    let last = *issued.last().ok_or("nothing issued")?;
    assert_eq!(last, CausalTime::new(10_000, 99)?);

    // The reservation (11_000, 0) is the restart floor. With physical time
    // still at 10_000 recovery issues at once, above the floor, under a new
    // ceiling one millisecond past it.
    let store = reopen(&root)?;
    assert_eq!(store.recovered_time_floor()?, CausalTime::new(11_000, 0)?);
    let clock = durable(&source, &store, 1000)?;
    assert_eq!(store.recovered_time_floor()?, CausalTime::new(11_001, 0)?);
    let first = causal(&clock)?;
    assert!(first > last && first > CausalTime::new(11_000, 0)?);
    assert_eq!(first, CausalTime::new(11_000, 1)?);
    Ok(())
}

#[test]
fn lagging_restart_carries_within_ceiling_then_fails_closed() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let source = source_at(10_000);
    {
        let store = reopen(&root)?;
        causal(&durable(&source, &store, 1)?)?;
    }
    // Restart floor (10_001, 0); physical frozen at 10_000; ceiling
    // (10_002, 0). The floor millisecond's logical range carries into the
    // ceiling millisecond and no further.
    let store = reopen(&root)?;
    let clock = durable(&source, &store, 1)?;
    for _ in 0..u16::MAX {
        causal(&clock)?;
    }
    assert_eq!(clock.issued_floor(), CausalTime::new(10_001, u16::MAX)?);
    assert_eq!(causal(&clock)?, CausalTime::new(10_002, 0)?);
    assert!(matches!(clock.now(), Err(ClockError::ReservationExhausted)));
    clock.renew_reservation(DurationMs::from_millis(1))?;
    assert!(matches!(clock.now(), Err(ClockError::ReservationExhausted)));
    source.set(UnixTimeMs::from_millis(10_002));
    clock.renew_reservation(DurationMs::from_millis(1))?;
    assert_eq!(causal(&clock)?, CausalTime::new(10_002, 1)?);
    Ok(())
}

#[test]
fn durable_authority_holds_exclusive_ownership() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let store = reopen(&root)?;
    let source = source_at(10_000);
    let owner = durable(&source, &store, 100)?;
    assert!(matches!(
        durable(&source, &store, 100),
        Err(ClockError::Persistence(StoreError::Conflict(_)))
    ));
    let last = causal(&owner)?;
    drop(owner);

    // Ownership is released with the authority; the successor recovers
    // above the reservation (10_100, 0) with physical time unchanged.
    let successor = durable(&source, &store, 100)?;
    assert!(causal(&successor)? > last);
    Ok(())
}

#[test]
fn reservation_exhaustion_blocks_until_renewed() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let source = source_at(10_000);
    {
        let store = reopen(&root)?;
        let clock = durable(&source, &store, 10)?;
        causal(&clock)?;

        // Physical time passes the (10_010, 0) ceiling: issuing there would
        // outrun the durable restart bound.
        source.set(UnixTimeMs::from_millis(10_011));
        let floor = clock.issued_floor();
        assert!(matches!(clock.now(), Err(ClockError::ReservationExhausted)));
        assert_eq!(
            clock.issued_floor(),
            floor,
            "a refused issuance moved state"
        );

        clock.renew_reservation(DurationMs::from_millis(10))?;
        assert_eq!(causal(&clock)?, CausalTime::new(10_011, 0)?);
        // The renewed ceiling is durable before it is usable.
        assert_eq!(store.recovered_time_floor()?, CausalTime::new(10_021, 0)?);
    }
    let store = reopen(&root)?;
    assert_eq!(store.recovered_time_floor()?, CausalTime::new(10_021, 0)?);
    Ok(())
}

#[test]
fn restart_floor_covers_committed_history() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let committed = CausalTime::new(50_000, 7)?;
    {
        let store = reopen(&root)?;
        let ns = NamespaceRef::generate("committed-floor", committed.encoded())?;
        let mut execution = store.begin_execution(&ns, &clock_at(committed.encoded())?)?;
        execution.namespace_create(None, None)?;
        execution.publish()?;
        assert_eq!(store.committed_time_floor()?, committed);
    }
    // No reservation was ever made; the committed timestamp alone is the
    // restart floor, and a source behind it still issues above it.
    let store = reopen(&root)?;
    assert_eq!(store.recovered_time_floor()?, committed);
    let source = source_at(20_000);
    let clock = durable(&source, &store, 1000)?;
    assert_eq!(causal(&clock)?, CausalTime::new(50_000, 8)?);
    Ok(())
}

#[test]
fn restart_behind_reservation_holds_and_releases_ownership() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let store = reopen(&root)?;
    let source = source_at(10_000);
    drop(durable(&source, &store, 1000)?);
    // Behind the reservation: recovery succeeds and owns the backend.
    let successor = durable(&source, &store, 1000)?;
    assert!(matches!(
        durable(&source, &store, 1000),
        Err(ClockError::Persistence(StoreError::Conflict(_)))
    ));
    drop(successor);
    durable(&source, &store, 1000)?;
    Ok(())
}

#[test]
fn encoded_order_matches_causal_order() -> TestResult {
    // ClockMs packs (physical << 16 | logical); the packed integer must
    // order exactly as the decoded components across the logical boundary.
    let pairs = [
        (CausalTime::new(1, u16::MAX)?, CausalTime::new(2, 0)?),
        (CausalTime::new(2, 0)?, CausalTime::new(2, 1)?),
        (CausalTime::new(0, 0)?, CausalTime::new(0, 1)?),
    ];
    for (lower, higher) in pairs {
        assert!(lower < higher);
        assert!(lower.encoded().as_i64() < higher.encoded().as_i64());
        assert_eq!(CausalTime::from_encoded(lower.encoded()), lower);
    }
    assert_eq!(ClockMs::from_raw(1000).physical_ms(), 0);
    Ok(())
}
