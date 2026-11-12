//! Failure schedules at the live-to-durable custody boundary.

use super::*;
use crate::custody::{CustodyParts, CustodySigning};
use kappa_store::{Axis, NamespaceRef, work::WorkMeter};

#[test]
fn returned_signature_replaces_a_prepared_live_override() -> Result<(), Box<dyn std::error::Error>>
{
    let store = crate::test_support::persistent_store()?.into_store();
    let namespace = NamespaceRef::deterministic("custody-live-progress");
    let writer = store.test_writer(&namespace)?;
    let instance = writer.active.controller().instance;
    let mut record = CustodyRecord::new(CustodyParts {
        namespace: *namespace.id(),
        incarnation: instance.known_incarnation("custody test")?,
        epoch_number: 1,
        predecessor: None,
        unsigned: Kappa::compute(Axis::Sha256, b"candidate")?,
        now_ms: 1000,
        activation: None,
        transitions: Vec::new(),
        reads: Vec::new(),
        work: Work::default(),
    });
    store.store_custody(&writer.writer, &instance, &record)?;
    let failure = StoreError::Unavailable("persistence retry schedule".into());
    assert!(matches!(
        store.retain(&writer.writer, &instance, &mut record, &failure),
        StoreError::PublicationRetained(_)
    ));
    record.signing = CustodySigning::Invoked;
    store.store_custody(&writer.writer, &instance, &record)?;
    record.signing = CustodySigning::Returned {
        signature: vec![37; 64],
    };
    store.store_custody(&writer.writer, &instance, &record)?;
    let loaded = store
        .load_custody(&instance, &mut WorkMeter::unbounded())?
        .ok_or("live custody missing")?;
    assert_eq!(loaded.signing, record.signing);
    store
        .live_custody
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    let durable = store
        .load_custody(&instance, &mut WorkMeter::unbounded())?
        .ok_or("durable custody missing")?;
    assert_eq!(durable.signing, record.signing);
    Ok(())
}

#[test]
fn resolution_accounts_only_its_attempt_and_preserves_prior_custody_work()
-> Result<(), Box<dyn std::error::Error>> {
    use kappa_store::{ClockMs, ExecutionStore, PublicationResolution};

    let store = crate::test_support::persistent_store()?.into_store();
    let namespace = NamespaceRef::deterministic("custody-work-isolation");
    let writer = store.test_writer(&namespace)?;
    let instance = writer.active.controller().instance;
    let earlier = Work::default().with(Dimension::Entries, 7);
    let mut record = CustodyRecord::new(CustodyParts {
        namespace: *namespace.id(),
        incarnation: instance.known_incarnation("custody accounting test")?,
        epoch_number: 1,
        predecessor: None,
        unsigned: Kappa::sha256(b"invoked candidate"),
        now_ms: 1000,
        activation: None,
        transitions: Vec::new(),
        reads: Vec::new(),
        work: earlier,
    });
    // An invocation without returned bytes must remain retained. This exit
    // still accounts loading and classification on every resolution attempt.
    record.signing = CustodySigning::Invoked;
    store.store_custody(&writer.writer, &instance, &record)?;
    drop(writer);

    let clock = kappa_handler::clock_at(ClockMs::from_raw(1001))?;
    let mut meter = WorkMeter::unbounded();
    meter.charge(Dimension::Entries, 123)?;
    meter.charge(Dimension::BytesRead, 456)?;
    let mut cumulative = earlier;
    for _ in 0..2 {
        let before = *meter.used();
        assert!(matches!(
            store.resolve_publication(&namespace, &clock, &mut meter)?,
            PublicationResolution::Retained(_)
        ));
        let spent = meter.used().since(&before);
        assert!(spent.get(Dimension::Handles) > 0);
        cumulative = cumulative.saturating_add(&spent);
        let loaded = store
            .load_custody(&instance, &mut WorkMeter::unbounded())?
            .ok_or("retained custody disappeared")?;
        assert_eq!(loaded.work()?, cumulative);
        assert_eq!(loaded.signing, CustodySigning::Invoked);
    }
    Ok(())
}
