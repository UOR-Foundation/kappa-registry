//! Private access: `PersistentStore` construction through `super::*` and the
//! crate-internal `NamespaceRef`/`Kappa`/`StoreError` imports of `operation.rs`.

use super::*;
use kappa_handler::clock_at;
use kappa_store::{
    ClockMs, EpochStore, Execution, ExecutionStore, OperationAdmission, TagStore, TagUpdate,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn execute<'a>(
    admission: OperationAdmission<'a>,
    context: &str,
) -> Result<Box<dyn Execution + 'a>, Box<dyn std::error::Error>> {
    match admission {
        OperationAdmission::Execute(execution) => Ok(execution),
        OperationAdmission::Replay { epoch, .. } => Err(format!(
            "{context}: expected a fresh execution, replayed epoch {}",
            epoch.epoch_number()
        )
        .into()),
    }
}

#[test]
fn lost_acknowledgement_replays_original_epoch_and_result_after_reopen() -> TestResult {
    let spec = crate::test_support::PersistentSpec::new()
        .in_root(&kappa_fixture::FixtureRoot::temporary()?)
        .db_file("state.redb");
    let store = spec.clone().acquire()?.into_store();
    let namespace = NamespaceRef::deterministic("idempotent-operation");
    let identity = [7; 32];
    let request = Kappa::sha256(b"request fingerprint");
    let mut execution = execute(
        ExecutionStore::begin_operation(
            &store,
            &namespace,
            identity,
            request.clone(),
            &clock_at(ClockMs::from_raw(1000))?,
        )?,
        "first admission",
    )?;
    execution.tag_put(
        "head",
        &TagUpdate::Set {
            kappa: Kappa::sha256(b"first"),
        },
    )?;
    let original = execution.publish_result(b"original response".to_vec())?;
    let mut later = store.begin_execution(&namespace, &clock_at(ClockMs::from_raw(1001))?)?;
    later.tag_put(
        "head",
        &TagUpdate::Set {
            kappa: Kappa::sha256(b"second"),
        },
    )?;
    let current = later.publish()?;
    drop(store);
    let store = spec.acquire()?.into_store();
    let OperationAdmission::Replay { epoch, receipt } = ExecutionStore::begin_operation(
        &store,
        &namespace,
        identity,
        request,
        &clock_at(ClockMs::from_raw(1002))?,
    )?
    else {
        return Err("retry executed again instead of replaying".into());
    };
    assert_eq!(
        (epoch.epoch_number(), epoch.kappa().clone()),
        (original.epoch_number, original.root)
    );
    assert_eq!(receipt.result(), b"original response");
    assert_eq!(
        store.epoch_current(&namespace)?,
        (current.epoch_number, current.root)
    );
    assert_eq!(
        store.tag_get_raw(&namespace, "head")?.kappa,
        Kappa::sha256(b"second")
    );
    assert!(matches!(
        ExecutionStore::begin_operation(
            &store,
            &namespace,
            identity,
            Kappa::sha256(b"different request"),
            &clock_at(ClockMs::from_raw(1003))?,
        ),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(
        kappa_store::replay_to(&store, &namespace, 2)?.tags["head"],
        Kappa::sha256(b"second")
    );
    Ok(())
}

#[test]
fn abort_does_not_reserve_an_operation_identity() -> TestResult {
    let store = crate::test_support::PersistentSpec::new()
        .db_file("state.redb")
        .acquire()?
        .into_store();
    let namespace = NamespaceRef::deterministic("aborted-operation");
    let identity = [9; 32];
    let request = Kappa::sha256(b"aborted request");

    let mut aborted = execute(
        store.begin_operation(
            &namespace,
            identity,
            request.clone(),
            &clock_at(ClockMs::from_raw(1000))?,
        )?,
        "first admission",
    )?;
    aborted.tag_put(
        "head",
        &TagUpdate::Set {
            kappa: Kappa::sha256(b"discarded"),
        },
    )?;
    aborted.abort()?;
    assert!(
        store
            .resolve_operation(&namespace, &identity, &request)?
            .is_none(),
        "an aborted operation must leave no committed outcome"
    );
    assert!(matches!(
        store.tag_get_raw(&namespace, "head"),
        Err(StoreError::NotFound(_))
    ));

    // The aborted identity binds nothing: a different request under the same
    // key executes rather than conflicting.
    let different = Kappa::sha256(b"different request");
    let mut retried = execute(
        store.begin_operation(
            &namespace,
            identity,
            different.clone(),
            &clock_at(ClockMs::from_raw(1001))?,
        )?,
        "admission after abort",
    )?;
    retried.tag_put(
        "head",
        &TagUpdate::Set {
            kappa: Kappa::sha256(b"kept"),
        },
    )?;
    let published = retried.publish_result(b"kept response".to_vec())?;
    let (epoch, receipt) = store
        .resolve_operation(&namespace, &identity, &different)?
        .ok_or("published operation did not resolve")?;
    assert_eq!(epoch.epoch_number(), published.epoch_number);
    assert_eq!(receipt.result(), b"kept response");
    assert_eq!(
        store.tag_get_raw(&namespace, "head")?.kappa,
        Kappa::sha256(b"kept")
    );
    Ok(())
}
