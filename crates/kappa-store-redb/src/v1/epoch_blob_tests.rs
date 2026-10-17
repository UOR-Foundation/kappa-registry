//! Store-produced records through the real execution path: installed
//! inside the epoch's transaction with no evidence mutation of their own,
//! and readable from the namespace once the epoch publishes.

use std::sync::Arc;

use kappa_handler::clock_at;
use kappa_store::{Axis, BlobStore, ClockMs, NamespaceRef, StoreError, VerifiedContent};

use crate::PersistentStore;
use crate::control_plane::{ASSIGNMENT_KEY, AssignmentRecord, Guarantee, Guarantees};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn store() -> Result<PersistentStore, kappa_fixture::SetupError> {
    Ok(crate::test_support::PersistentSpec::new()
        .acquire()?
        .into_store())
}

fn create(store: &PersistentStore, name: &str) -> Result<NamespaceRef, StoreError> {
    let ns = NamespaceRef::deterministic(name);
    let plane = Arc::clone(store.namespaces.planes().local());
    let assignment = AssignmentRecord {
        namespace_id: ns.id().to_vec(),
        plane: plane.id.0.to_vec(),
        generation: 0,
        requires: Guarantees::NONE
            .with(Guarantee::TotalOrder)
            .with(Guarantee::LinearizableReads),
    };
    let clock = clock_at(ClockMs::from_raw(1000))?;
    let mut execution = store.begin_creation_execution(&ns, plane, &clock, None)?;
    execution.namespace_create(None, None)?;
    execution.namespace_put_meta(
        ASSIGNMENT_KEY,
        &kappa_store::canonical::canonical_bytes(&assignment),
    )?;
    execution.publish()?;
    Ok(ns)
}

/// Publish `content` as a store-produced record of `ns`.
fn publish_record(
    store: &PersistentStore,
    ns: &NamespaceRef,
    content: &VerifiedContent,
) -> Result<bool, StoreError> {
    let clock = clock_at(ClockMs::from_raw(2000))?;
    let mut execution = store.begin_epoch_execution(ns, &clock, None)?;
    let new = execution.blob_put(content)?;
    execution.publish()?;
    Ok(new)
}

/// A record whose encoded row exceeds the inline limit is prepared as an
/// external allocation bounded by its exact length: no reservation
/// arithmetic on an unbounded maximum refuses it before installation.
#[test]
fn a_record_above_the_inline_limit_installs_externally_and_reads_back() -> TestResult {
    let store = store()?;
    let ns = create(&store, "external-record")?;
    let bytes = vec![0x5a; 256 * 1024];
    let content = VerifiedContent::compute(Axis::Sha256, &bytes)?;
    assert!(publish_record(&store, &ns, &content)?);
    assert_eq!(store.blob_get_in(&ns, content.kappa())?, bytes);
    Ok(())
}

/// A record supplied under an axis that sorts after a mandatory axis is
/// held under the mandatory one and aliased under the supplied one: it
/// resolves under both, inline and external alike.
#[test]
fn a_record_resolves_under_the_identity_its_caller_supplied() -> TestResult {
    let store = store()?;
    let ns = create(&store, "aliased-record")?;
    for bytes in [
        b"inline record under blake3".to_vec(),
        vec![0x3c; 256 * 1024],
    ] {
        let supplied = VerifiedContent::compute(Axis::Blake3, &bytes)?;
        let mandatory = VerifiedContent::compute(Axis::Sha256, &bytes)?;
        assert!(publish_record(&store, &ns, &supplied)?);
        assert_eq!(store.blob_get_in(&ns, supplied.kappa())?, bytes);
        assert_eq!(store.blob_get_in(&ns, mandatory.kappa())?, bytes);
    }
    Ok(())
}
