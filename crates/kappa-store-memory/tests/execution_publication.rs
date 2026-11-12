//! Execution-only capabilities through the public contract: metadata ledger
//! evidence, and prepared content held by the execution until publication.

use std::time::{Duration, Instant};

use kappa_handler::clock_at;
use kappa_store::canonical::from_canonical;
use kappa_store::epoch::{EpochMutation, MutationOp};
use kappa_store::{
    BlobStore, ClockMs, ContentIdentity, ContentPreparation, EpochStore, Execution, ExecutionStore,
    Kappa, NamespaceRef, PreparationBounds, Published, StoreError, TagUpdate,
};
use kappa_store_memory::{InMemoryStore, test_support};
use kappa_types::{MetadataSubject, MetadataTransition};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn publication_rechecks_session_and_grace_expiry_with_the_retained_clock() -> TestResult {
    use kappa_handler::clock::{ControlledSource, WallClock};
    use kappa_store::clock::{CausalTime, UnixTimeMs};
    use std::sync::Arc;

    for grace in [false, true] {
        let store = test_support::test_store()?.into_store();
        let ns = create(&store, "temporal-authorization")?;
        let owner = Kappa::sha256(b"owner");
        publish(&store, &ns, now2(), |execution| {
            execution.session_put("session", &owner, now3().as_i64(), b"metadata")?;
            execution.credential_put("credential", &owner, b"old")?;
            execution.credential_rotate("credential", &owner, b"new", 1000)
        })?;
        let before = store.epoch_current(&ns)?;
        let source = Arc::new(ControlledSource::new(UnixTimeMs::from_millis(
            1_700_000_001_500,
        )));
        let clock = WallClock::recovered(source.clone(), CausalTime::from_encoded(now2()));
        let mut execution = store.begin_execution(&ns, &clock)?;
        if grace {
            let credential = execution
                .credential_get("credential")?
                .ok_or("credential absent")?;
            assert!(credential.2.is_some());
        } else {
            assert!(execution.session_get("session")?.is_some());
        }
        execution.namespace_put_meta("must-not-publish", b"expired authorization")?;
        // The execution must retain the authority, rather than its admission
        // timestamp or a new clock with independent issuance state.
        drop(clock);
        source.set(UnixTimeMs::from_millis(1_700_000_003_000));
        assert!(matches!(execution.publish(), Err(StoreError::Conflict(_))));
        assert_eq!(store.epoch_current(&ns)?, before);
    }
    Ok(())
}

#[test]
fn filtered_grace_does_not_expire_a_current_credential_read() -> TestResult {
    use kappa_handler::clock::{ControlledSource, WallClock};
    use kappa_store::clock::{CausalTime, UnixTimeMs};
    use std::sync::Arc;
    let store = test_support::test_store()?.into_store();
    let ns = create(&store, "current-credential")?;
    let owner = Kappa::sha256(b"owner");
    publish(&store, &ns, now2(), |execution| {
        execution.credential_put("credential", &owner, b"old")?;
        execution.credential_rotate("credential", &owner, b"new", 1000)
    })?;
    let source = Arc::new(ControlledSource::new(UnixTimeMs::from_millis(
        1_700_000_003_000,
    )));
    let clock = WallClock::recovered(source.clone(), CausalTime::from_encoded(now3()));
    let mut execution = store.begin_execution(&ns, &clock)?;
    let credential = execution
        .credential_get("credential")?
        .ok_or("credential absent")?;
    assert_eq!(credential.1, b"new");
    assert!(credential.2.is_none());
    execution.namespace_put_meta("authorized", b"current secret")?;
    source.set(UnixTimeMs::from_millis(1_700_000_004_000));
    let published = execution.publish()?;
    assert_eq!(
        store.epoch_current(&ns)?,
        (published.epoch_number, published.root)
    );
    Ok(())
}

const fn now() -> ClockMs {
    ClockMs::from_raw(1_700_000_000_000i64 << 16)
}

const fn now2() -> ClockMs {
    ClockMs::from_raw(1_700_000_001_000i64 << 16)
}

const fn now3() -> ClockMs {
    ClockMs::from_raw(1_700_000_002_000i64 << 16)
}

/// Run `write` in one execution against `ns` and publish it.
fn publish(
    store: &InMemoryStore,
    ns: &NamespaceRef,
    at: ClockMs,
    write: impl FnOnce(&mut dyn Execution) -> Result<(), StoreError>,
) -> Result<Published, StoreError> {
    let mut execution = store.begin_execution(ns, &clock_at(at)?)?;
    write(&mut *execution)?;
    execution.publish()
}

/// A namespace created in its own published execution.
fn create(store: &InMemoryStore, name: &str) -> Result<NamespaceRef, StoreError> {
    let ns = NamespaceRef::generate(name, now())?;
    publish(store, &ns, now(), |execution| {
        execution.namespace_create(None, None)
    })?;
    Ok(ns)
}

fn ledger(store: &InMemoryStore, root: &Kappa) -> Result<Vec<EpochMutation>, StoreError> {
    let root = store.epoch_get(root)?;
    Ok(from_canonical(
        &store.blob_get_verified(root.ledger_root())?,
    )?)
}

fn metadata_record(
    store: &InMemoryStore,
    identity: &Kappa,
) -> Result<MetadataTransition, StoreError> {
    Ok(from_canonical(&store.blob_get_verified(identity)?)?)
}

fn prepared(
    store: &InMemoryStore,
    bytes: &[u8],
) -> Result<Box<dyn kappa_store::PreparedContent>, StoreError> {
    store.prepare_content(
        ContentIdentity::Computed(kappa_store::Axis::Sha256),
        &mut &bytes[..],
        PreparationBounds {
            maximum: 1024 * 1024,
            deadline: Instant::now() + Duration::from_secs(30),
        },
    )
}

#[test]
fn metadata_changes_are_committed_by_the_epoch_ledger() -> TestResult {
    let s = test_support::test_store()?.into_store();
    let ns = create(&s, "metadata")?;

    let set = publish(&s, &ns, now2(), |e| {
        e.namespace_put_meta("versioning", b"enabled")
    })?;
    let mutations = ledger(&s, &set.root)?;
    assert_eq!(mutations.len(), 1);
    assert_eq!(mutations[0].op, MutationOp::MetadataUpdate);
    assert_eq!(mutations[0].context.as_deref(), Some("versioning"));
    let record = metadata_record(&s, &mutations[0].kappa)?;
    assert_eq!(record.namespace(), ns.id());
    assert_eq!(record.subject(), &MetadataSubject::Namespace);
    assert_eq!(record.key(), "versioning");
    assert_eq!(record.value(), Some(&b"enabled"[..]));

    let deleted = publish(&s, &ns, now3(), |e| e.namespace_delete_meta("versioning"))?;
    let mutations = ledger(&s, &deleted.root)?;
    assert_eq!(mutations.len(), 1);
    assert_eq!(mutations[0].op, MutationOp::MetadataUpdate);
    assert_eq!(metadata_record(&s, &mutations[0].kappa)?.value(), None);

    let absent = publish(&s, &ns, now3(), |e| e.namespace_delete_meta("versioning"))?;
    assert!(
        ledger(&s, &absent.root)?.is_empty(),
        "deleting an absent key records nothing"
    );

    let replayed = kappa_store::replay::replay_to(&s, &ns, set.epoch_number)?;
    assert_eq!(
        replayed.metadata.get("versioning").map(Vec::as_slice),
        Some(&b"enabled"[..])
    );
    assert!(
        kappa_store::replay::replay_to(&s, &ns, absent.epoch_number)?
            .metadata
            .is_empty()
    );
    Ok(())
}

#[test]
fn installed_content_is_private_until_publication() -> TestResult {
    let s = test_support::test_store()?.into_store();
    let ns = create(&s, "installation")?;
    let content = b"installed object";
    let identity = Kappa::sha256(content);

    // Abort discards the installation; the content never became visible
    // and the preparation is released with the execution.
    let mut aborted = s.begin_execution(&ns, &clock_at(now2())?)?;
    let installed = aborted.content_install(prepared(&s, content)?)?;
    assert_eq!(installed.kappa, identity);
    assert!(installed.newly_stored);
    assert!(
        !s.blob_exists(&identity)?,
        "content is private to the execution"
    );
    aborted.abort()?;
    assert!(!s.blob_exists(&identity)?);

    // Dropping discards as well.
    let mut dropped = s.begin_execution(&ns, &clock_at(now2())?)?;
    dropped.content_install(prepared(&s, content)?)?;
    drop(dropped);
    assert!(!s.blob_exists(&identity)?);

    // Publication makes the content visible with the tag naming it.
    let published = publish(&s, &ns, now2(), |e| {
        let ingest = e.content_install(prepared(&s, content)?)?;
        e.tag_put(
            "object",
            &TagUpdate::Set {
                kappa: ingest.kappa,
            },
        )
    })?;
    assert!(s.blob_exists(&identity)?);
    assert_eq!(s.blob_get(&identity)?, content);
    let mutations = ledger(&s, &published.root)?;
    assert_eq!(
        mutations
            .iter()
            .filter(|m| m.op == MutationOp::TagSet)
            .count(),
        1,
        "the object tag"
    );

    // Installing the same bytes again is not new, and the aliases bound to
    // the holder are evidenced in the ledger of the namespace that
    // published them.
    let again = publish(&s, &ns, now3(), |e| {
        let ingest = e.content_install(prepared(&s, content)?)?;
        assert!(!ingest.newly_stored);
        Ok(())
    })?;
    let _ = again;
    Ok(())
}

#[test]
fn foreign_preparation_latches_failure_even_when_content_is_already_present() -> TestResult {
    let source = test_support::test_store()?.into_store();
    let destination = test_support::test_store()?.into_store();
    let ns = create(&destination, "preparation-owner")?;
    for bytes in [b"absent".as_slice(), b"present".as_slice()] {
        if bytes == b"present" {
            publish(&destination, &ns, now2(), |e| {
                e.content_install(prepared(&destination, bytes)?)?;
                Ok(())
            })?;
        }
        let before = destination.epoch_current(&ns)?;
        let mut execution = destination.begin_execution(&ns, &clock_at(now3())?)?;
        execution.namespace_put_meta("must-not-publish", bytes)?;
        assert!(matches!(
            execution.content_install(prepared(&source, bytes)?),
            Err(StoreError::Rejected(_))
        ));
        assert!(
            execution.publish().is_err(),
            "installation rejection must latch"
        );
        assert_eq!(destination.epoch_current(&ns)?, before);
    }
    assert!(!destination.blob_exists(&Kappa::sha256(b"absent"))?);
    assert_eq!(
        destination.blob_get(&Kappa::sha256(b"present"))?,
        b"present"
    );
    Ok(())
}

#[test]
fn retirement_is_refused_while_a_committed_reference_names_the_content() -> TestResult {
    use kappa_store::execution::Retirement;
    let s = test_support::test_store()?.into_store();
    let ns = create(&s, "retirement")?;
    let content = b"retire me";
    let identity = Kappa::sha256(content);
    publish(&s, &ns, now2(), |e| {
        let ingest = e.content_install(prepared(&s, content)?)?;
        e.tag_put(
            "kept",
            &TagUpdate::Set {
                kappa: ingest.kappa,
            },
        )
    })?;
    let retained = publish(&s, &ns, now3(), |e| {
        assert_eq!(e.content_retire(&identity)?, Retirement::Retained);
        Ok(())
    });
    assert!(retained.is_ok());
    assert!(s.blob_exists(&identity)?);

    publish(&s, &ns, now3(), |e| e.tag_delete("kept"))?;
    publish(&s, &ns, now3(), |e| {
        assert_eq!(e.content_retire(&identity)?, Retirement::Retired);
        Ok(())
    })?;
    assert!(!s.blob_exists(&identity)?);
    publish(&s, &ns, now3(), |e| {
        assert_eq!(e.content_retire(&identity)?, Retirement::Absent);
        Ok(())
    })?;
    Ok(())
}
