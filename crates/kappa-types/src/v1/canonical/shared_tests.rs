use super::*;
use crate::axis::Axis;
use crate::canonical::{bounded_record, decode_cost};
use crate::namespace_state::NamespaceState;
use crate::verified::VerifiedContent;
use crate::work::{Work, WorkLimit, WorkMeter};
use dcbor::prelude::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn state(pool: &Arc<CapacityPool>) -> Result<Record<NamespaceState>, StoreError> {
    let mut map = Map::new();
    map.insert(0u64, 1u64);
    map.insert(1u64, ByteString::from([1; 16]));
    map.insert(2u64, ByteString::from([2; 16]));
    map.insert(3u64, crate::kappa::Kappa::sha256(b"authority"));
    map.insert(4u64, ByteString::from([3; 32]));
    map.insert(5u64, ByteString::from([4; 32]));
    map.insert(6u64, 7u64);
    let evidence = VerifiedContent::compute_owned(Axis::Sha256, CBOR::from(map).to_cbor_data())?;
    let cost = decode_cost::<NamespaceState>(evidence.len() as u64)?;
    let mut limit = WorkLimit::unbounded();
    for dimension in Dimension::ALL {
        limit = limit.with(dimension, cost.work.get(dimension));
    }
    bounded_record(&evidence, &mut WorkMeter::new(limit), pool)
}

#[test]
fn shared_allocation_is_held_across_threads_until_last_owner() -> TestResult {
    let arena = Arc::new(CapacityPool::new("state arena", 65536));
    let record = state(&arena)?;
    assert_eq!(arena.used(), 0);
    let bytes = SharedRecord::<NamespaceState>::allocation_bytes();
    let pool = Arc::new(CapacityPool::new("shared state", bytes));
    let bound = Work::default().with(Dimension::BytesAllocated, bytes);
    let mut meter = WorkMeter::new(WorkLimit::unbounded());
    let shared = {
        let mut unit = meter.admit(&bound.as_bound())?;
        SharedRecord::new(record, &mut unit, &pool)?
    };
    assert_eq!(pool.used(), bytes);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let owner = shared.clone();
            scope.spawn(move || {
                for _ in 0..128 {
                    let clone = owner.clone();
                    assert_eq!(clone.value().history_size(), 7);
                }
            });
        }
    });
    assert_eq!(pool.used(), bytes);
    let used = *meter.used();
    drop(shared);
    assert_eq!(pool.used(), 0);
    assert_eq!(*meter.used(), used);
    Ok(())
}

#[test]
fn shared_capacity_refusal_is_distinct_and_keeps_work_consumed() -> TestResult {
    let arena = Arc::new(CapacityPool::new("state arena", 65536));
    let record = state(&arena)?;
    let bytes = SharedRecord::<NamespaceState>::allocation_bytes();
    let pool = Arc::new(CapacityPool::new("shared state", bytes - 1));
    let mut meter = WorkMeter::new(WorkLimit::unbounded());
    {
        let bound = Work::default().with(Dimension::BytesAllocated, bytes);
        let mut unit = meter.admit(&bound.as_bound())?;
        assert!(matches!(
            SharedRecord::new(record, &mut unit, &pool),
            Err(StoreError::CapacityExceeded(_))
        ));
    }
    assert_eq!(pool.used(), 0);
    assert_eq!(arena.used(), 0);
    assert_eq!(meter.used().get(Dimension::BytesAllocated), bytes);
    Ok(())
}
