use kappa_types::clock::{DurationMs, TimeError, UnixTimeMs};

#[test]
fn physical_deadlines_do_not_wrap_or_extend_validity() -> Result<(), TimeError> {
    assert_eq!(
        UnixTimeMs::from_millis(i64::MAX).checked_add(DurationMs::from_millis(1)),
        Err(TimeError::OutOfRange)
    );
    assert_eq!(
        UnixTimeMs::from_millis(i64::MIN).checked_add(DurationMs::from_millis(u64::MAX))?,
        UnixTimeMs::from_millis(i64::MAX)
    );
    let deadline = UnixTimeMs::from_millis(1000).checked_add(DurationMs::from_millis(5000))?;
    assert!(!UnixTimeMs::from_millis(5999).has_reached(deadline));
    assert!(deadline.has_reached(deadline));
    assert_eq!(
        DurationMs::try_from_signed(-1),
        Err(TimeError::NegativeDuration)
    );
    Ok(())
}

#[test]
fn pre_epoch_seconds_use_floor_division() {
    assert_eq!(UnixTimeMs::from_millis(-1).unix_seconds(), -1);
    assert_eq!(UnixTimeMs::from_millis(-1001).unix_seconds(), -2);
}
