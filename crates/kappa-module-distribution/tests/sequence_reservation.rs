//! Sequence reservation publishes its evidence and stays monotonic across
//! executions.

use kappa_handler::{MutationEventOp, OperationResult, Outcome, clock_at, events_from_ledger};
use kappa_module_distribution::sequence::{SequenceValue, reserve_next};
use kappa_store::canonical::from_canonical;
use kappa_store::{
    BlobStore, ClockMs, EpochMutation, EpochStore, ExecutionStore, Kappa, NamespaceRef,
    SequenceStore,
};
use kappa_store_memory::{InMemoryStore, test_support};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Reserve the next value of `name` in its own published execution.
fn reserve(
    store: &InMemoryStore,
    namespace: &NamespaceRef,
    name: &str,
    now: ClockMs,
) -> Result<(u64, Kappa), Box<dyn std::error::Error>> {
    let mut execution = store.begin_execution(namespace, &clock_at(now)?)?;
    let mut work = reserve_next(name.to_string());
    let Outcome::Publish(SequenceValue(value)) = work(&mut *execution)? else {
        return Err("a sequence reservation must publish".into());
    };
    Ok((value, execution.publish()?.root))
}

/// Operations and contexts of the mutations an epoch published.
fn ledger(
    store: &InMemoryStore,
    namespace: &NamespaceRef,
    root: &Kappa,
) -> Result<Vec<(MutationEventOp, String)>, Box<dyn std::error::Error>> {
    let epoch = store.epoch_get(root)?;
    let mutations: Vec<EpochMutation> =
        from_canonical(&store.blob_get_verified(epoch.ledger_root())?)?;
    Ok(events_from_ledger(
        namespace.display_name(),
        epoch.epoch_number(),
        root,
        &mutations,
    )?
    .into_iter()
    .map(|event| (event.operation, event.name))
    .collect())
}

#[test]
fn reservations_publish_sequence_updates_with_monotonic_values() -> TestResult {
    let store = test_support::test_store()?.into_store();
    let namespace = NamespaceRef::deterministic("sequences");

    let (first, first_root) = reserve(&store, &namespace, "builds", ClockMs::from_raw(1000))?;
    let (second, second_root) = reserve(&store, &namespace, "builds", ClockMs::from_raw(2000))?;

    assert_eq!(second, first + 1);
    assert_eq!(store.sequence_current(&namespace, "builds")?, second);
    let expected = vec![(MutationEventOp::SequenceUpdate, "builds".to_string())];
    assert_eq!(ledger(&store, &namespace, &first_root)?, expected);
    assert_eq!(ledger(&store, &namespace, &second_root)?, expected);
    assert_eq!(
        store.epoch_get(&second_root)?.prev_identifier(),
        Some(&first_root)
    );
    Ok(())
}

#[test]
fn sequence_value_receipt_round_trips_and_rejects_other_lengths() -> TestResult {
    let value = SequenceValue(0x0102_0304_0506_0708);
    assert_eq!(value.encode(), vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(SequenceValue::decode(&value.encode())?, value);
    assert!(SequenceValue::decode(&[1, 2, 3]).is_err());
    assert!(SequenceValue::decode(&[0; 9]).is_err());
    Ok(())
}
