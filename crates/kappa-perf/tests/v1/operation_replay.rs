//! PERF-STO-003: operation identity and replay. An operation publishes
//! once; a retry with the same identity and request replays the committed
//! receipt without executing; a different request under the same identity
//! conflicts; an abort reserves nothing. Committed outcomes survive a
//! restart of the durable backend.

use kappa_handler::clock_at;
use kappa_store::{
    ClockMs, ExecutionStore, Kappa, OperationAdmission, StoreError, TagUpdate, replay_to,
};

use kappa_fixture::FixtureRoot;

use crate::common::{TestResult, create_ns, on_both_backends, redb_store_in};

#[test]
fn operation_publishes_once_and_replays() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "op-replay")?;
        let identity = [7; 32];
        let request = Kappa::sha256(b"idempotent-request");

        let OperationAdmission::Execute(mut execution) = store.begin_operation(
            &ns,
            identity,
            request.clone(),
            &clock_at(ClockMs::from_raw(2000))?,
        )?
        else {
            return Err("first admission must execute".into());
        };
        execution.tag_put(
            "op-tag",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"op-content"),
            },
        )?;
        let published = execution.publish_result(b"response-body".to_vec())?;
        assert_eq!(
            store.tag_get(&ns, "op-tag")?.kappa,
            Kappa::sha256(b"op-content")
        );

        for at in [3000, 4000] {
            let OperationAdmission::Replay { epoch, receipt } = store.begin_operation(
                &ns,
                identity,
                request.clone(),
                &clock_at(ClockMs::from_raw(at))?,
            )?
            else {
                return Err("retry must replay, not execute".into());
            };
            assert_eq!(epoch.epoch_number(), published.epoch_number);
            assert_eq!(epoch.kappa(), &published.root);
            assert_eq!(receipt.result(), b"response-body");
        }
        // Replays publish nothing.
        assert_eq!(
            store.epoch_current(&ns)?,
            (published.epoch_number, published.root.clone())
        );
        let resolved = store
            .resolve_operation(&ns, &identity, &request)?
            .ok_or("committed operation unresolved")?;
        assert_eq!(resolved.1.result(), b"response-body");

        assert!(matches!(
            store.begin_operation(
                &ns,
                identity,
                Kappa::sha256(b"different-request"),
                &clock_at(ClockMs::from_raw(5000))?
            ),
            Err(StoreError::Conflict(_))
        ));
        // The receipt is part of authenticated history.
        let replayed = replay_to(store, &ns, published.epoch_number)?;
        assert!(replayed.operations.contains_key(&identity));
        Ok(())
    })
}

#[test]
fn aborted_operation_reserves_nothing() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "op-abort")?;
        let identity = [9; 32];

        let OperationAdmission::Execute(mut execution) = store.begin_operation(
            &ns,
            identity,
            Kappa::sha256(b"aborted-request"),
            &clock_at(ClockMs::from_raw(2000))?,
        )?
        else {
            return Err("first admission must execute".into());
        };
        execution.tag_put(
            "aborted-tag",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"discarded"),
            },
        )?;
        execution.abort()?;
        assert!(matches!(
            store.tag_get(&ns, "aborted-tag"),
            Err(StoreError::NotFound(_))
        ));
        assert_eq!(
            store
                .resolve_operation(&ns, &identity, &Kappa::sha256(b"aborted-request"))?
                .map(|_| ()),
            None
        );

        // Not reserved: a different request under the identity executes.
        let OperationAdmission::Execute(mut execution) = store.begin_operation(
            &ns,
            identity,
            Kappa::sha256(b"different-after-abort"),
            &clock_at(ClockMs::from_raw(3000))?,
        )?
        else {
            return Err("admission after abort must execute".into());
        };
        execution.tag_put(
            "after-abort",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"kept"),
            },
        )?;
        execution.publish_result(b"kept-response".to_vec())?;
        assert_eq!(
            store.tag_get(&ns, "after-abort")?.kappa,
            Kappa::sha256(b"kept")
        );
        Ok(())
    })
}

#[test]
fn committed_operations_replay_after_restart() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let identity = [11; 32];
    let request = Kappa::sha256(b"durable-request");
    let (ns, published) = {
        let store = redb_store_in(&root)?;
        let ns = create_ns(&store, "op-durable")?;
        let OperationAdmission::Execute(mut execution) = store.begin_operation(
            &ns,
            identity,
            request.clone(),
            &clock_at(ClockMs::from_raw(2000))?,
        )?
        else {
            return Err("first admission must execute".into());
        };
        execution.tag_put(
            "durable",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"durable"),
            },
        )?;
        (ns, execution.publish_result(b"durable-response".to_vec())?)
    };
    let store = redb_store_in(&root)?;
    let OperationAdmission::Replay { epoch, receipt } =
        store.begin_operation(&ns, identity, request, &clock_at(ClockMs::from_raw(3000))?)?
    else {
        return Err("restarted store must replay the committed operation".into());
    };
    assert_eq!(epoch.kappa(), &published.root);
    assert_eq!(receipt.result(), b"durable-response");
    Ok(())
}
