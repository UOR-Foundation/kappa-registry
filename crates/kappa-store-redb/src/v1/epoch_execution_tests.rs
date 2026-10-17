use super::*;
use kappa_handler::clock_at;
use kappa_store::{
    BlobStore, EpochStore, ExecutionWrites, NamespaceStore, ProtocolId, SequenceStore, TagStore,
    TagUpdate,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn namespace_deletion_preserves_other_scopes_and_aborts_atomically()
-> Result<(), Box<dyn std::error::Error>> {
    let store = store()?;
    let first = ProtocolId::new("first")?;
    let second = ProtocolId::new("second")?;
    let ns = create(&store, "shared", None, &first)?;
    let other = create(&store, "shared", None, &second)?;
    let mut execution =
        store.begin_epoch_execution(&ns, &clock_at(ClockMs::from_raw(1001))?, None)?;
    execution.namespace_add_alias("secondary", Some(&second))?;
    execution.publish()?;
    {
        let mut execution =
            store.begin_epoch_execution(&ns, &clock_at(ClockMs::from_raw(1003))?, None)?;
        execution.namespace_delete()?;
        assert!(
            execution
                .namespace_info()?
                .ok_or("namespace absent from execution")?
                .tombstoned
        );
        assert_eq!(store.namespace_resolve("shared", Some(&first))?, ns);
        assert_eq!(store.namespace_resolve("secondary", Some(&second))?, ns);
        execution.abort()?;
    }
    assert!(!store.namespace_info(&ns)?.tombstoned);
    let mut execution =
        store.begin_epoch_execution(&ns, &clock_at(ClockMs::from_raw(1004))?, None)?;
    execution.namespace_delete()?;
    let (number, _) = execution.publish()?;
    assert!(store.namespace_resolve("shared", Some(&first)).is_err());
    assert!(store.namespace_resolve("secondary", Some(&second)).is_err());
    assert_eq!(store.namespace_resolve("shared", Some(&second))?, other);
    let state = kappa_store::replay_to(&store, &ns, number)?;
    let identity = state
        .namespace_record
        .ok_or("replay omitted namespace deletion")?;
    let record: kappa_store::NamespaceInfo =
        kappa_store::canonical::from_canonical(&store.blob_get_in(&ns, &identity)?)?;
    assert!(record.tombstoned);
    assert_eq!(record.ns, ns);
    Ok(())
}

#[test]
fn sequence_reservations_are_private_and_released_on_abort()
-> Result<(), Box<dyn std::error::Error>> {
    let store = store()?;
    let ns = NamespaceRef::deterministic("sequence-abort");
    let mut execution =
        store.begin_epoch_execution(&ns, &clock_at(ClockMs::from_raw(1000))?, None)?;
    assert_eq!(execution.sequence_next("revision")?, 1);
    assert_eq!(execution.sequence_next("revision")?, 2);
    assert_eq!(execution.sequence_current("revision")?, 2);
    assert_eq!(store.sequence_current(&ns, "revision")?, 0);
    assert!(execution.tag_delete("missing").is_err());
    assert!(execution.publish().is_err());
    assert_eq!(store.sequence_current(&ns, "revision")?, 0);
    let mut execution =
        store.begin_epoch_execution(&ns, &clock_at(ClockMs::from_raw(1001))?, None)?;
    assert_eq!(execution.sequence_next("revision")?, 1);
    execution.publish()?;
    assert_eq!(store.sequence_current(&ns, "revision")?, 1);
    let replayed = kappa_store::replay_to(&store, &ns, 1)?;
    assert_eq!(replayed.sequences.get("revision"), Some(&1));
    Ok(())
}

#[test]
fn published_edge_history_reconstructs_creation_and_deletion()
-> Result<(), Box<dyn std::error::Error>> {
    let store = store()?;
    let ns = NamespaceRef::deterministic("edge-history");
    let input = kappa_store::EdgeInput {
        source: Kappa::sha256(b"source"),
        target: Kappa::sha256(b"target"),
        relation: kappa_store::EdgeRelation::Builtin(kappa_store::BuiltinRelation::Owns),
        asserter: Kappa::sha256(b"authority"),
        created_at_ms: 1000,
        metadata: None,
    };
    let mut execution =
        store.begin_epoch_execution(&ns, &clock_at(ClockMs::from_raw(1000))?, None)?;
    let edge = execution.edge_put(&input)?;
    execution.publish()?;
    let mut execution =
        store.begin_epoch_execution(&ns, &clock_at(ClockMs::from_raw(1001))?, None)?;
    execution.edge_delete(&edge)?;
    execution.publish()?;
    assert!(
        kappa_store::replay_to(&store, &ns, 1)?
            .edges
            .contains(&edge)
    );
    assert!(kappa_store::replay_to(&store, &ns, 2)?.edges.is_empty());
    assert!(kappa_store::replay_to(&store, &ns, 0)?.edges.is_empty());
    Ok(())
}

#[test]
fn namespace_transfer_is_private_and_aborts_with_a_failed_tag()
-> Result<(), Box<dyn std::error::Error>> {
    let store = store()?;
    let original = Kappa::sha256(b"original-owner");
    let replacement = Kappa::sha256(b"replacement-owner");
    let ns = NamespaceRef::generate("owned-namespace", ClockMs::from_raw(1000))?;
    let mut execution =
        store.begin_epoch_execution(&ns, &clock_at(ClockMs::from_raw(1000))?, None)?;
    execution.namespace_create(Some(&original), None)?;
    execution.publish()?;
    let mut execution =
        store.begin_epoch_execution(&ns, &clock_at(ClockMs::from_raw(1002))?, None)?;
    execution.namespace_transfer(&replacement)?;
    assert_eq!(
        execution
            .namespace_info()?
            .ok_or("namespace absent from execution")?
            .owner_anchor,
        Some(replacement)
    );
    assert_eq!(
        store.namespace_info(&ns)?.owner_anchor,
        Some(original.clone())
    );
    assert!(execution.tag_delete("missing").is_err());
    assert!(execution.publish().is_err());
    assert_eq!(store.namespace_info(&ns)?.owner_anchor, Some(original));
    assert_eq!(store.epoch_current(&ns)?.0, 1);
    Ok(())
}

#[test]
fn private_symbolic_reads_and_failed_batch_abort_the_entire_epoch()
-> Result<(), Box<dyn std::error::Error>> {
    let store = store()?;
    let ns = NamespaceRef::deterministic("private-batch");
    let mut execution =
        store.begin_epoch_execution(&ns, &clock_at(ClockMs::from_raw(1000))?, None)?;
    let identity = Kappa::sha256(b"private-target");
    execution.tag_batch_update(&[
        (
            "target".into(),
            TagUpdate::Set {
                kappa: identity.clone(),
            },
        ),
        (
            "HEAD".into(),
            TagUpdate::SetSymref {
                target: "target".into(),
            },
        ),
    ])?;
    let resolved = execution.tag_get("HEAD")?.ok_or("HEAD absent")?;
    assert_eq!(resolved.name, "HEAD");
    assert_eq!(resolved.kappa, identity);
    assert_eq!(
        execution
            .tag_get_raw("HEAD")?
            .and_then(|entry| entry.symref)
            .as_deref(),
        Some("target")
    );
    assert!(matches!(
        execution.tag_batch_update(&[
            (
                "earlier".into(),
                TagUpdate::Set {
                    kappa: identity.clone()
                }
            ),
            (
                "target".into(),
                TagUpdate::CompareAndSwap {
                    kappa: identity,
                    expected_version: 0
                }
            ),
        ]),
        Err(StoreError::VersionMismatch { .. })
    ));
    assert!(execution.publish().is_err());
    for name in ["target", "HEAD", "earlier"] {
        assert!(matches!(
            store.tag_get_raw(&ns, name),
            Err(StoreError::NotFound(_))
        ));
    }
    assert!(matches!(
        store.epoch_current(&ns),
        Err(StoreError::NotFound(_))
    ));
    assert_eq!(store.epoch_state(&ns)?.1, 0);
    Ok(())
}

/// A store retaining its own scope, laid out as the server lays it out.
fn store() -> Result<PersistentStore, kappa_fixture::SetupError> {
    Ok(crate::test_support::PersistentSpec::new()
        .db_file("state.redb")
        .acquire()?
        .into_store())
}

/// Create `name` within `protocol` in its own published execution.
fn create(
    store: &PersistentStore,
    name: &str,
    owner: Option<&Kappa>,
    protocol: &ProtocolId,
) -> Result<NamespaceRef, StoreError> {
    let ns = NamespaceRef::generate(name, ClockMs::from_raw(1000))?.with_protocol(protocol.clone());
    let mut execution =
        store.begin_epoch_execution(&ns, &clock_at(ClockMs::from_raw(1000))?, None)?;
    execution.namespace_create(owner, Some(protocol))?;
    execution.publish()?;
    Ok(ns)
}

#[test]
fn execution_reads_private_writes_and_drop_aborts() -> TestResult {
    let store = store()?;
    let ns = NamespaceRef::deterministic("private-execution");
    let mut execution =
        store.begin_epoch_execution(&ns, &clock_at(ClockMs::from_raw(1000))?, None)?;
    let identity = Kappa::sha256(b"private");
    execution.tag_put(
        "head",
        &TagUpdate::Set {
            kappa: identity.clone(),
        },
    )?;
    assert_eq!(
        execution.tag_get("head")?.map(|entry| entry.kappa),
        Some(identity)
    );
    assert!(matches!(
        store.tag_get_raw(&ns, "head"),
        Err(StoreError::NotFound(_))
    ));
    drop(execution);
    assert!(matches!(
        store.tag_get_raw(&ns, "head"),
        Err(StoreError::NotFound(_))
    ));
    assert!(matches!(
        store.epoch_current(&ns),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

#[test]
fn ignored_mutation_error_cannot_publish_partial_execution() -> TestResult {
    let store = store()?;
    let ns = NamespaceRef::deterministic("failed-execution");
    let mut execution =
        store.begin_epoch_execution(&ns, &clock_at(ClockMs::from_raw(1000))?, None)?;
    execution.tag_put(
        "head",
        &TagUpdate::Set {
            kappa: Kappa::sha256(b"private"),
        },
    )?;
    assert!(execution.tag_delete("missing").is_err());
    assert!(matches!(execution.publish(), Err(StoreError::Conflict(_))));
    assert!(matches!(
        store.tag_get_raw(&ns, "head"),
        Err(StoreError::NotFound(_))
    ));
    assert!(matches!(
        store.epoch_current(&ns),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

fn prepare_verified(
    store: &PersistentStore,
    identity: &Kappa,
    bytes: &[u8],
) -> Result<Box<dyn kappa_store::PreparedContent>, StoreError> {
    kappa_store::ContentPreparation::prepare_content(
        store,
        kappa_store::ContentIdentity::Verified(identity.clone()),
        &mut &bytes[..],
        kappa_store::PreparationBounds {
            maximum: 1024 * 1024,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
        },
    )
}

#[test]
fn prepared_content_and_tags_publish_in_one_epoch() -> TestResult {
    let store = store()?;
    let ns = NamespaceRef::deterministic("streamed-execution");
    let bytes = vec![42; crate::BLOB_CHUNK_SIZE * 2 + 7];
    let identity = Kappa::sha256(&bytes);
    let prepared = prepare_verified(&store, &identity, &bytes)?;
    let mut execution =
        store.begin_epoch_execution(&ns, &clock_at(ClockMs::from_raw(1000))?, None)?;
    assert!(execution.content_install(prepared)?.newly_stored);
    assert!(!store.blob_exists_in(&ns, &identity)?);
    assert_eq!(
        execution.blob_get_verified(&identity, bytes.len() as u64)?,
        Some(bytes.clone())
    );
    execution.tag_put(
        "head",
        &TagUpdate::Set {
            kappa: identity.clone(),
        },
    )?;
    let published = execution.publish()?;
    assert_eq!(store.epoch_current(&ns)?, published);
    // Namespace-bound and identity-only reads are current with the commit:
    // the identity is registered before the commit (`store_access`), and
    // settlement hands it to the catalog without changing any answer.
    assert_eq!(store.blob_get_in(&ns, &identity)?, bytes);
    assert!(store.blob_exists(&identity)?);
    assert_eq!(store.blob_get(&identity)?, bytes);
    store.settle_all()?;
    assert!(store.blob_exists(&identity)?);
    assert_eq!(store.blob_get(&identity)?, bytes);
    assert_eq!(store.tag_get_raw(&ns, "head")?.kappa, identity);
    Ok(())
}

#[test]
fn rejected_preparation_installs_nothing_and_leaves_the_execution_usable() -> TestResult {
    let store = store()?;
    let ns = NamespaceRef::deterministic("rejected-stream");
    let identity = Kappa::sha256(b"expected");
    let mut execution =
        store.begin_epoch_execution(&ns, &clock_at(ClockMs::from_raw(1000))?, None)?;
    execution.tag_put(
        "head",
        &TagUpdate::Set {
            kappa: identity.clone(),
        },
    )?;
    // Preparation runs outside the writer: a rejected stream touches
    // neither the store nor the execution's private writes.
    assert!(matches!(
        prepare_verified(&store, &identity, b"different"),
        Err(StoreError::Rejected(_))
    ));
    assert!(!store.blob_exists_in(&ns, &identity)?);
    execution.tag_put(
        "after-rejection",
        &TagUpdate::Set {
            kappa: identity.clone(),
        },
    )?;
    execution.abort()?;
    assert!(!store.blob_exists_in(&ns, &identity)?);
    assert!(store.tag_get_raw(&ns, "head").is_err());
    assert!(store.tag_get_raw(&ns, "after-rejection").is_err());
    Ok(())
}

#[test]
fn ignored_private_read_failure_aborts_all_owned_state() -> Result<(), Box<dyn std::error::Error>> {
    let store = store()?;
    // Absence is a value: it neither latches nor prevents publication.
    {
        let ns = NamespaceRef::deterministic("missing-tag");
        let mut execution =
            store.begin_epoch_execution(&ns, &clock_at(ClockMs::from_raw(1000))?, None)?;
        assert!(execution.tag_get_raw("missing")?.is_none());
        assert!(execution.tag_get("missing")?.is_none());
        assert!(execution.namespace_get_meta("missing")?.is_none());
        execution.tag_put(
            "head",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"present"),
            },
        )?;
        execution.publish()?;
        assert_eq!(
            store.tag_get_raw(&ns, "head")?.kappa,
            Kappa::sha256(b"present")
        );
    }
    for failure in ["bounded-blob", "symbolic-cycle"] {
        let ns = NamespaceRef::deterministic(failure);
        let content = kappa_store::VerifiedContent::compute(kappa_store::Axis::Sha256, b"private")?;
        let mut execution =
            store.begin_epoch_execution(&ns, &clock_at(ClockMs::from_raw(1000))?, None)?;
        execution.blob_put(&content)?;
        execution.sequence_next("revision")?;
        execution.tag_put(
            "head",
            &TagUpdate::Set {
                kappa: content.kappa().clone(),
            },
        )?;
        if failure == "bounded-blob" {
            assert!(execution.blob_get_verified(content.kappa(), 1).is_err());
        } else {
            execution.tag_put(
                "cycle",
                &TagUpdate::SetSymref {
                    target: "cycle".into(),
                },
            )?;
            assert!(execution.tag_get("cycle").is_err());
        }
        assert!(execution.sequence_next("revision").is_err());
        assert!(execution.publish().is_err());
        assert!(store.tag_get_raw(&ns, "head").is_err());
        assert_eq!(store.sequence_current(&ns, "revision")?, 0);
        assert!(!store.blob_exists_in(&ns, content.kappa())?);
        assert!(store.epoch_current(&ns).is_err());
    }
    Ok(())
}
