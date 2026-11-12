//! Settlement consumes evidence produced by real executions, including
//! deletion records whose identity differs from the removed payload.

use super::{Reads, Staged, stage_mutation};
use crate::PersistentStore;
use crate::control_plane::ASSIGNMENT_KEY;
use crate::storage::IncarnationUse;
use crate::tables::BLOB_INDEX;
use kappa_store::canonical::from_canonical;
use kappa_store::work::WorkMeter;
use kappa_store::{
    Axis, BlobStore, ClockMs, EpochMutation, EpochStore, ExecutionStore, Kappa, NamespaceRef,
    Published, Retirement, StoreError, VerifiedContent,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn stage(
    store: &PersistentStore,
    ns: &NamespaceRef,
    mutations: &[EpochMutation],
) -> Result<Vec<Staged>, StoreError> {
    let snapshot = store.namespace_snapshot(ns)?;
    let index = snapshot.table(BLOB_INDEX)?;
    let reads = Reads {
        view: snapshot.view(),
        txn: snapshot.transaction(),
        index: &index,
        ns: ns.clone(),
        incarnation: snapshot
            .controller()
            .logical_incarnation(IncarnationUse::Settlement)?,
        limit: store.settlement_limits.record_bytes(),
    };
    let mut effects = Vec::new();
    for mutation in mutations {
        stage_mutation(
            &reads,
            mutation,
            &mut WorkMeter::unbounded(),
            &mut |effect| {
                effects.push(effect);
                Ok(())
            },
        )?;
    }
    Ok(effects)
}

fn ledger(
    store: &PersistentStore,
    published: &Published,
) -> Result<Vec<EpochMutation>, StoreError> {
    let root = store.epoch_get(&published.root)?;
    Ok(from_canonical(&store.blob_get(root.ledger_root())?)?)
}

#[test]
fn record_admission_and_retirement_project_the_payload_not_the_evidence() -> TestResult {
    let store = crate::test_support::persistent_store()?.into_store();
    let ns = NamespaceRef::deterministic("settlement-content-evidence");
    let clock = kappa_handler::clock_at(ClockMs::from_raw(1000))?;
    let content = VerifiedContent::compute(Axis::Sha256, b"logical payload")?;
    let mut execution = store.begin_execution(&ns, &clock)?;
    execution.namespace_create(None, None)?;
    execution.blob_put(&content)?;
    let published = execution.publish()?;
    let mutations = ledger(&store, &published)?;
    assert!(stage(&store, &ns, &mutations)?.iter().any(|effect| {
        matches!(effect, Staged::Admitted { identity, .. } if identity == content.kappa())
    }));

    let mut execution = store.begin_execution(&ns, &clock)?;
    assert_eq!(
        execution.content_retire(content.kappa())?,
        Retirement::Retired
    );
    let retired = execution.publish()?;
    let mutations = ledger(&store, &retired)?;
    let removal = mutations
        .iter()
        .find(|mutation| mutation.op == kappa_store::MutationOp::ContentRetire)
        .ok_or("retirement did not emit evidence")?;
    assert_ne!(&removal.kappa, content.kappa());
    let effects = stage(&store, &ns, &mutations)?;
    assert!(effects.iter().any(|effect| {
        matches!(effect, Staged::Retired(identity) if identity == content.kappa())
    }));
    assert!(
        effects.iter().any(|effect| {
            matches!(effect, Staged::Admitted { identity, .. } if identity == &removal.kappa)
        }),
        "retirement evidence remains discoverable"
    );
    Ok(())
}

#[test]
fn blob_metadata_cannot_become_an_assignment_and_scope_substitution_is_refused() -> TestResult {
    let store = crate::test_support::persistent_store()?.into_store();
    let ns = NamespaceRef::deterministic("settlement-metadata-subject");
    let clock = kappa_handler::clock_at(ClockMs::from_raw(1000))?;
    let content = VerifiedContent::compute(Axis::Sha256, b"metadata owner")?;
    let mut execution = store.begin_execution(&ns, &clock)?;
    execution.namespace_create(None, None)?;
    execution.blob_put(&content)?;
    execution.blob_meta_put(content.kappa(), ASSIGNMENT_KEY, b"not an assignment")?;
    let published = execution.publish()?;
    let mutations = ledger(&store, &published)?;
    let metadata = mutations
        .iter()
        .find(|mutation| {
            mutation.op == kappa_store::MutationOp::MetadataUpdate
                && mutation.context.as_deref() == Some(ASSIGNMENT_KEY)
        })
        .ok_or("blob metadata transition absent")?;
    let effects = stage(&store, &ns, std::slice::from_ref(metadata))?;
    assert!(
        !effects
            .iter()
            .any(|effect| matches!(effect, Staged::Assignment(_)))
    );
    let mut substituted = metadata.clone();
    substituted.context = Some("another-key".into());
    assert!(matches!(
        stage(&store, &ns, &[substituted]),
        Err(StoreError::Rejected(_))
    ));
    assert_ne!(metadata.kappa, Kappa::sha256(b"not an assignment"));
    Ok(())
}
