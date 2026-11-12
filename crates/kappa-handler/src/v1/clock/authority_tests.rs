use super::*;
use kappa_store::clock::UnixTimeMs;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn source(physical: i64) -> Arc<ControlledSource> {
    Arc::new(ControlledSource::new(UnixTimeMs::from_millis(physical)))
}

struct ReservationBackend {
    occupied: Arc<std::sync::atomic::AtomicBool>,
    floor: std::sync::Mutex<CausalTime>,
    fail: std::sync::atomic::AtomicBool,
}

impl ReservationBackend {
    fn new() -> Result<Self, TimeError> {
        Ok(Self {
            occupied: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            floor: std::sync::Mutex::new(CausalTime::new(100, 0)?),
            fail: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn floor(&self) -> Result<CausalTime, kappa_store::StoreError> {
        self.floor
            .lock()
            .map(|floor| *floor)
            .map_err(|_| kappa_store::StoreError::Internal("test backend lock poisoned".into()))
    }
}

impl kappa_store::time::TimeReservationStore for ReservationBackend {
    fn acquire_time_authority(
        &self,
    ) -> Result<kappa_store::time::TimeAuthorityLease, kappa_store::StoreError> {
        kappa_store::time::TimeAuthorityLease::acquire(self.occupied.clone())
    }

    fn recover_time(&self) -> Result<CausalTime, kappa_store::StoreError> {
        self.floor()
    }

    fn reserve_time(&self, ceiling: CausalTime) -> Result<(), kappa_store::StoreError> {
        if self.fail.load(Ordering::Acquire) {
            return Err(kappa_store::StoreError::Internal(
                "injected reservation failure".into(),
            ));
        }
        let mut floor = self
            .floor
            .lock()
            .map_err(|_| kappa_store::StoreError::Internal("test backend lock poisoned".into()))?;
        *floor = (*floor).max(ceiling);
        drop(floor);
        Ok(())
    }
}

#[test]
fn durable_authority_owns_backend_through_last_reference() -> TestResult {
    let backend = Arc::new(ReservationBackend::new()?);
    let source = source(101);
    let clock = Arc::new(WallClock::durable(
        source.clone(),
        backend.clone(),
        DurationMs::from_millis(100),
    )?);
    let retained = clock.retain();
    drop(clock);
    assert!(
        WallClock::durable(
            source.clone(),
            backend.clone(),
            DurationMs::from_millis(100)
        )
        .is_err()
    );
    let issued = CausalTime::from_encoded(retained.now()?);
    drop(retained);
    assert!(!backend.occupied.load(Ordering::Acquire));
    // Physical time (101) still lags the reservation (201, 0): the successor
    // resumes above it at once instead of waiting for physical progress.
    let replacement = WallClock::durable(source, backend, DurationMs::from_millis(100))?;
    let resumed = CausalTime::from_encoded(replacement.now()?);
    assert!(resumed > issued);
    assert_eq!(resumed, CausalTime::new(201, 1)?);
    Ok(())
}

#[test]
fn exhausted_millisecond_carries_only_within_reservation() -> TestResult {
    let source = source(200);
    let clock = WallClock::reserved(
        source,
        CausalTime::new(200, u16::MAX)?,
        CausalTime::new(201, 1)?,
    )?;
    assert_eq!(
        CausalTime::from_encoded(clock.now()?),
        CausalTime::new(201, 0)?
    );
    assert_eq!(
        CausalTime::from_encoded(clock.now()?),
        CausalTime::new(201, 1)?
    );
    assert!(matches!(clock.now(), Err(ClockError::ReservationExhausted)));
    assert_eq!(clock.issued_floor(), CausalTime::new(201, 1)?);
    Ok(())
}

#[test]
fn renewal_bounds_lead_by_physical_time() -> TestResult {
    let backend = Arc::new(ReservationBackend::new()?);
    let source = source(101);
    let headroom = DurationMs::from_millis(1);
    let clock = WallClock::durable(source.clone(), backend.clone(), headroom)?;
    for _ in 0..=u16::MAX {
        clock.now()?;
    }
    assert_eq!(clock.issued_floor(), CausalTime::new(101, u16::MAX)?);
    assert_eq!(
        CausalTime::from_encoded(clock.now()?),
        CausalTime::new(102, 0)?
    );
    assert!(matches!(clock.now(), Err(ClockError::ReservationExhausted)));
    // Frozen physical time: renewal cannot extend past physical + headroom,
    // so carried issuance fails closed rather than ratcheting lead forward.
    clock.renew_reservation(headroom)?;
    assert!(matches!(clock.now(), Err(ClockError::ReservationExhausted)));
    assert_eq!(backend.floor()?, CausalTime::new(102, 0)?);
    source.set(UnixTimeMs::from_millis(102));
    clock.renew_reservation(headroom)?;
    assert_eq!(
        CausalTime::from_encoded(clock.now()?),
        CausalTime::new(102, 1)?
    );
    assert_eq!(backend.floor()?, CausalTime::new(103, 0)?);
    Ok(())
}

#[test]
fn failed_initialization_releases_ownership_without_reserving() -> TestResult {
    let backend = Arc::new(ReservationBackend::new()?);
    backend.fail.store(true, Ordering::Release);
    let source = source(101);
    assert!(
        WallClock::durable(
            source.clone(),
            backend.clone(),
            DurationMs::from_millis(100)
        )
        .is_err()
    );
    assert!(!backend.occupied.load(Ordering::Acquire));
    assert_eq!(backend.floor()?, CausalTime::new(100, 0)?);
    backend.fail.store(false, Ordering::Release);
    let clock = WallClock::durable(source, backend, DurationMs::from_millis(100))?;
    assert!(clock.now().is_ok());
    Ok(())
}

#[test]
fn failed_reservation_extension_cannot_enable_issuance() -> TestResult {
    let source = source(200);
    let floor = CausalTime::new(200, 0)?;
    let bound = CausalTime::new(200, 1)?;
    let clock = WallClock::reserved(source, floor, bound)?;
    assert_eq!(CausalTime::from_encoded(clock.now()?), bound);
    let extension = CausalTime::new(201, 0)?;
    assert!(
        clock
            .extend_reservation(extension, |_| {
                Err(kappa_store::StoreError::Internal(
                    "injected persistence failure".into(),
                ))
            })
            .is_err()
    );
    assert!(matches!(clock.now(), Err(ClockError::ReservationExhausted)));
    assert_eq!(clock.issued_floor(), bound);
    clock.extend_reservation(extension, |_| Ok(()))?;
    assert!(CausalTime::from_encoded(clock.now()?) > bound);
    Ok(())
}

#[test]
fn restart_skips_issued_but_uncommitted_reservation() -> TestResult {
    let source = source(100);
    let committed = CausalTime::new(100, 0)?;
    let reservation = CausalTime::new(200, 0)?;
    let old = WallClock::reserved(source.clone(), committed, reservation)?;
    let issued = CausalTime::from_encoded(old.now()?);
    let recovered = CausalTime::recovery_floor(committed, Some(reservation));
    let restarted = WallClock::reserved(source, recovered, CausalTime::new(300, 0)?)?;
    assert!(CausalTime::from_encoded(restarted.now()?) > issued);
    assert_eq!(restarted.physical_now()?.as_millis(), 100);
    Ok(())
}

#[test]
fn recovered_floor_survives_rollback_without_changing_physical_time() -> TestResult {
    let source = source(100);
    let floor = CausalTime::new(200, 7)?;
    let clock = WallClock::recovered(source.clone(), floor);
    let issued = CausalTime::from_encoded(clock.now()?);
    assert!(issued > floor);
    assert_eq!(issued.physical_ms(), 200);
    assert_eq!(clock.physical_now()?.as_millis(), 100);
    source.set(UnixTimeMs::from_millis(50));
    assert!(CausalTime::from_encoded(clock.now()?) > issued);
    assert_eq!(clock.physical_now()?.as_millis(), 50);
    Ok(())
}

#[test]
fn source_failure_does_not_advance_state_and_can_recover() -> TestResult {
    let source = source(-1);
    let floor = CausalTime::new(200, 7)?;
    let clock = WallClock::recovered(source.clone(), floor);
    assert!(matches!(clock.now(), Err(ClockError::BeforeUnixEpoch)));
    assert_eq!(clock.issued_floor(), floor);
    source.set(UnixTimeMs::from_millis(201));
    assert!(CausalTime::from_encoded(clock.now()?) > floor);
    Ok(())
}

#[test]
fn logical_exhaustion_preserves_state_until_physical_time_advances() -> TestResult {
    let source = source(200);
    let floor = CausalTime::new(200, u16::MAX)?;
    let clock = WallClock::recovered(source.clone(), floor);
    assert!(matches!(
        clock.now(),
        Err(ClockError::Time(TimeError::LogicalExhausted))
    ));
    assert_eq!(clock.issued_floor(), floor);
    source.set(UnixTimeMs::from_millis(201));
    assert_eq!(
        CausalTime::from_encoded(clock.now()?),
        CausalTime::new(201, 0)?
    );
    Ok(())
}

#[test]
fn concurrent_issuance_has_no_duplicates_or_lost_progress() -> TestResult {
    let clock = Arc::new(WallClock::recovered(source(200), CausalTime::new(200, 0)?));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let clock = clock.retain();
            std::thread::spawn(move || {
                (0..512)
                    .map(|_| clock.now().map(CausalTime::from_encoded))
                    .collect::<Result<Vec<_>, ClockError>>()
            })
        })
        .collect();
    let mut issued = Vec::with_capacity(4096);
    for worker in workers {
        issued.extend(worker.join().map_err(|_| "issuance worker panicked")??);
    }
    issued.sort_unstable();
    issued.dedup();
    assert_eq!(issued.len(), 4096);
    assert_eq!(clock.issued_floor(), CausalTime::new(200, 4096)?);
    Ok(())
}
