use kappa_types::clock::{CausalTime, DurationMs, TimeError, UnixTimeMs};

#[test]
fn restart_does_not_add_a_full_window_to_future_recovery() -> Result<(), TimeError> {
    let physical = UnixTimeMs::from_millis(1000);
    let window = DurationMs::from_millis(60_000);
    let initial = CausalTime::new(1000, 0)?;
    let first = initial.reservation_ceiling(physical, window)?;
    assert_eq!(first.physical_ms(), 61_000);
    let restarted = first.reservation_ceiling(physical, window)?;
    assert_eq!(restarted.physical_ms(), 61_001);
    assert!(restarted > first);
    Ok(())
}

#[test]
fn reservation_cannot_wrap_the_physical_domain() -> Result<(), TimeError> {
    let floor = CausalTime::new(CausalTime::MAX_PHYSICAL_MS, 0)?;
    assert_eq!(
        floor.reservation_ceiling(UnixTimeMs::from_millis(0), DurationMs::from_millis(1000)),
        Err(TimeError::OutOfRange)
    );
    Ok(())
}
