use std::time::Duration;

use super::*;

fn limits() -> DurabilityLimits {
    DurabilityLimits {
        queue_entries: 4,
        queue_bytes: 1000,
        batch_entries: 2,
        batch_bytes: 500,
    }
}

fn coordinator(fsync: bool) -> Result<(tempfile::TempDir, Durability), StoreError> {
    let dir = tempfile::tempdir()?;
    let durability = Durability::new(dir.path().to_path_buf(), fsync, limits())?;
    Ok((dir, durability))
}

#[test]
fn limits_are_validated() {
    assert!(
        DurabilityLimits {
            queue_entries: 1,
            queue_bytes: 1,
            batch_entries: 2,
            batch_bytes: 1,
        }
        .validate()
        .is_err()
    );
    assert!(limits().validate().is_ok());
}

#[test]
fn reservation_is_bounded_and_a_duplicate_changes_nothing() -> Result<(), StoreError> {
    let (_dir, durability) = coordinator(true)?;
    let ids: Vec<AllocationId> = (0..5)
        .map(|_| AllocationId::generate())
        .collect::<Result<_, _>>()?;
    for id in &ids[..3] {
        durability.reserve(*id, 100)?;
    }
    assert_eq!(durability.charged(), (3, 300));
    assert!(matches!(
        durability.reserve(ids[0], 1),
        Err(StoreError::Internal(_))
    ));
    assert_eq!(durability.charged(), (3, 300));
    assert!(matches!(
        durability.reserve(ids[3], 701),
        Err(StoreError::CapacityExceeded(_))
    ));
    assert!(matches!(
        durability.reserve(ids[3], 1001),
        Err(StoreError::CapacityExceeded(_))
    ));
    durability.reserve(ids[3], 100)?;
    assert!(matches!(
        durability.reserve(ids[4], 1),
        Err(StoreError::CapacityExceeded(_))
    ));
    durability.abandon(&ids[0])?;
    assert_eq!(durability.charged(), (3, 300));
    durability.reserve(ids[4], 100)?;
    Ok(())
}

#[test]
fn volatile_store_never_claims_durability() -> Result<(), StoreError> {
    let (_dir, durability) = coordinator(false)?;
    let id = AllocationId::generate()?;
    durability.reserve(id, 10)?;
    let (capability, outcome) = durability.establish(id, Instant::now() + Duration::from_secs(1));
    assert_eq!(capability, Capability::Volatile);
    assert!(matches!(outcome, DurabilityOutcome::Established));
    assert_eq!(durability.charged(), (0, 0));
    Ok(())
}

#[test]
fn unadmitted_and_expired_requests_are_typed_and_release_capacity() -> Result<(), StoreError> {
    let (_dir, durability) = coordinator(true)?;
    let (capability, outcome) = durability.establish(AllocationId::generate()?, Instant::now());
    assert_eq!(capability, Capability::Volatile);
    assert!(matches!(outcome, DurabilityOutcome::NotEstablished(_)));
    let id = AllocationId::generate()?;
    durability.reserve(id, 10)?;
    let past = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .ok_or_else(|| StoreError::Internal("no instant precedes now".into()))?;
    let (capability, outcome) = durability.establish(id, past);
    assert_eq!(capability, Capability::Volatile);
    assert!(matches!(outcome, DurabilityOutcome::DeadlineExceeded));
    assert_eq!(durability.charged(), (0, 0));
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn a_lone_ready_allocation_is_established_and_a_reserved_one_is_not_covered()
-> Result<(), StoreError> {
    let (_dir, durability) = coordinator(true)?;
    let ready = AllocationId::generate()?;
    let reserved = AllocationId::generate()?;
    durability.reserve(reserved, 10)?;
    durability.reserve(ready, 10)?;
    let (capability, outcome) =
        durability.establish(ready, Instant::now() + Duration::from_secs(5));
    assert_eq!(capability, Capability::Durable);
    assert!(matches!(outcome, DurabilityOutcome::Established));
    // The reserved allocation was never frozen: it is still charged and
    // still Reserved, so it cannot have been reported durable.
    assert_eq!(durability.charged(), (1, 10));
    durability.abandon(&reserved)?;
    assert_eq!(durability.charged(), (0, 0));
    Ok(())
}

#[test]
fn freezing_is_admission_ordered_and_bounded() -> Result<(), StoreError> {
    let mut state = State::default();
    let ids: Vec<AllocationId> = (0..4)
        .map(|_| AllocationId::generate())
        .collect::<Result<_, _>>()?;
    for (sequence, (id, bytes)) in (0u64..).zip(ids.iter().zip([400u64, 400, 50, 50])) {
        state.entries.insert(
            *id,
            Entry {
                bytes,
                phase: Phase::Ready,
                sequence,
                failure: None,
            },
        );
    }
    let batch = Durability::freeze(&mut state, limits());
    assert_eq!(batch, vec![ids[0]], "second 400 would exceed 500 bytes");
    let batch = Durability::freeze(&mut state, limits());
    assert_eq!(batch, vec![ids[1], ids[2]], "entries bound of two");
    let batch = Durability::freeze(&mut state, limits());
    assert_eq!(batch, vec![ids[3]]);
    assert!(Durability::freeze(&mut state, limits()).is_empty());
    let big = AllocationId::generate()?;
    state.entries.insert(
        big,
        Entry {
            bytes: 900,
            phase: Phase::Ready,
            sequence: 9,
            failure: None,
        },
    );
    assert_eq!(Durability::freeze(&mut state, limits()), vec![big]);
    Ok(())
}
