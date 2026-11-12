use kappa_types::axis::Axis;
use kappa_types::clock::ClockMs;
use kappa_types::content::{
    ContentAdmission, ContentAdmissionEvidence, ContentAdmissionRecord, ContentAlias,
    ContentComponent, ContentComposition, ContentRetirementRecord, MetadataTransition,
};
use kappa_types::epoch::SequenceRecord;

use super::*;

type TestResult = Result<(), StoreError>;

fn ns() -> NamespaceRef {
    NamespaceRef::deterministic("replayed-transitions")
}

const INCARNATION: [u8; 16] = [5; 16];

fn domain() -> TransitionDomain {
    TransitionDomain::new(*ns().id(), LogicalIncarnation::from_bytes(INCARNATION))
}

/// The ledger mutation and evidence bytes a writer derives for `record`.
fn ledgered(record: RecordTransition) -> Result<(EpochMutation, Vec<u8>), StoreError> {
    let bytes = record.canonical_bytes();
    let evidence = VerifiedContent::compute(Axis::Sha256, &bytes)?;
    let prepared = PreparedTransition::bind(domain(), record, evidence, ClockMs::from_raw(1))?;
    Ok((prepared.mutation().clone(), bytes))
}

fn apply(
    state: &mut ReplayedNamespaceState,
    record: RecordTransition,
) -> Result<Change, StoreError> {
    let (mutation, bytes) = ledgered(record)?;
    state.apply(domain(), &mutation, &bytes)
}

/// Apply `record` expecting a refusal that leaves the state unchanged.
fn refused(state: &mut ReplayedNamespaceState, record: RecordTransition) -> TestResult {
    let before = state.clone();
    let (mutation, bytes) = ledgered(record)?;
    assert!(state.apply(domain(), &mutation, &bytes).is_err());
    assert_eq!(*state, before, "a refusal changes nothing");
    Ok(())
}

fn admission(identity: &Kappa, size: u64) -> ContentAdmission {
    ContentAdmission::new(*ns().id(), INCARNATION, identity.clone(), size)
}

fn bytes_admission(content: &[u8]) -> Result<ContentAdmissionRecord, StoreError> {
    ContentAdmissionRecord::new(
        admission(&Kappa::sha256(content), content.len() as u64),
        ContentAdmissionEvidence::VerifiedBytes,
    )
}

fn alias_admission(content: &[u8]) -> Result<ContentAdmissionRecord, StoreError> {
    let alias = Kappa::compute(Axis::Blake3, content)?;
    let holder = Kappa::sha256(content);
    ContentAdmissionRecord::new(
        admission(&alias, content.len() as u64),
        ContentAdmissionEvidence::Alias(ContentAlias::new(alias, holder, content.len() as u64)?),
    )
}

fn edge() -> kappa_types::EdgeInput {
    kappa_types::EdgeInput {
        source: Kappa::sha256(b"source"),
        target: Kappa::sha256(b"target"),
        relation: kappa_types::EdgeRelation::Builtin(kappa_types::BuiltinRelation::Owns),
        asserter: Kappa::sha256(b"authority"),
        created_at_ms: 1,
        metadata: None,
    }
}

#[test]
fn edge_membership_requires_a_preceding_publication() -> TestResult {
    let mut state = ReplayedNamespaceState::default();
    refused(&mut state, RecordTransition::EdgeDelete(edge()))?;
    apply(&mut state, RecordTransition::EdgePut(edge()))?;
    assert_eq!(state.edges.len(), 1);
    refused(&mut state, RecordTransition::EdgePut(edge()))?;
    let removal = apply(&mut state, RecordTransition::EdgeDelete(edge()))?;
    assert!(removal.1.is_none());
    assert!(state.edges.is_empty());
    assert!(
        state.index.is_empty(),
        "membership leaves the index with the edge"
    );
    Ok(())
}

/// A ledger scope the evidence does not derive is refused at decode.
#[test]
fn evidence_and_ledger_scope_must_agree() -> TestResult {
    let mut state = ReplayedNamespaceState::default();
    let (mut mutation, bytes) = ledgered(RecordTransition::EdgePut(edge()))?;
    mutation.context = Some("different-relation".into());
    assert!(state.apply(domain(), &mutation, &bytes).is_err());
    let (mutation, _) = ledgered(RecordTransition::EdgePut(edge()))?;
    assert!(state.apply(domain(), &mutation, b"other bytes").is_err());
    assert_eq!(state, ReplayedNamespaceState::default());
    Ok(())
}

#[test]
fn an_operation_is_published_once() -> TestResult {
    let receipt = || {
        kappa_types::OperationReceipt::new(
            &ns(),
            &INCARNATION,
            &[23; 32],
            Kappa::sha256(b"request"),
            b"result".to_vec(),
        )
    };
    let mut state = ReplayedNamespaceState::default();
    apply(&mut state, RecordTransition::OperationPublish(receipt()?))?;
    assert!(state.operations.contains_key(&[23; 32]));
    refused(&mut state, RecordTransition::OperationPublish(receipt()?))?;
    Ok(())
}

/// Admission, aliasing and retirement in the order backends emit them; a
/// retirement decodes from its own record after the payload is gone.
#[test]
fn content_lifecycle_follows_admissions_exactly() -> TestResult {
    let content = b"admitted content";
    let mut state = ReplayedNamespaceState::default();
    refused(
        &mut state,
        RecordTransition::ContentAlias(alias_admission(content)?),
    )?;
    let holder = apply(
        &mut state,
        RecordTransition::ContentPublish(bytes_admission(content)?),
    )?;
    assert_eq!(
        holder,
        (
            state_key::path(
                state_key::Family::Content,
                &Kappa::sha256(content).key_bytes()
            ),
            Some(state_key::value(&canonical_bytes(&admission(
                &Kappa::sha256(content),
                content.len() as u64
            ))))
        ),
        "the index commits the admission, not its evidence envelope"
    );
    refused(
        &mut state,
        RecordTransition::RecordPublish(bytes_admission(content)?),
    )?;
    apply(
        &mut state,
        RecordTransition::ContentAlias(alias_admission(content)?),
    )?;
    let holder_retirement =
        ContentRetirementRecord::new(admission(&Kappa::sha256(content), content.len() as u64));
    refused(
        &mut state,
        RecordTransition::ContentRetire(holder_retirement.clone()),
    )?;
    refused(
        &mut state,
        RecordTransition::ContentRetire(ContentRetirementRecord::new(admission(
            &Kappa::compute(Axis::Blake3, content)?,
            content.len() as u64 + 1,
        ))),
    )?;
    apply(
        &mut state,
        RecordTransition::ContentRetire(ContentRetirementRecord::new(admission(
            &Kappa::compute(Axis::Blake3, content)?,
            content.len() as u64,
        ))),
    )?;
    apply(
        &mut state,
        RecordTransition::ContentRetire(holder_retirement),
    )?;
    assert!(state.admissions.is_empty());
    assert!(state.index.is_empty());
    Ok(())
}

#[test]
fn a_composite_needs_its_components_and_holds_them() -> TestResult {
    let mut state = ReplayedNamespaceState::default();
    let part = |bytes: &[u8]| ContentComponent {
        identity: Kappa::sha256(bytes),
        length: bytes.len() as u64,
    };
    let whole = Kappa::sha256(b"hello world");
    let composite = ContentAdmissionRecord::new(
        admission(&whole, 11),
        ContentAdmissionEvidence::Composition(ContentComposition::new(
            whole.clone(),
            vec![part(b"hello "), part(b"world")],
            11,
        )?),
    )?;
    refused(
        &mut state,
        RecordTransition::ContentCompose(composite.clone()),
    )?;
    apply(
        &mut state,
        RecordTransition::ContentPublish(bytes_admission(b"hello ")?),
    )?;
    apply(
        &mut state,
        RecordTransition::ContentPublish(bytes_admission(b"world")?),
    )?;
    apply(&mut state, RecordTransition::ContentCompose(composite))?;
    assert_eq!(state.compositions.get(&whole).map(BTreeSet::len), Some(1));
    refused(
        &mut state,
        RecordTransition::ContentRetire(ContentRetirementRecord::new(admission(
            &Kappa::sha256(b"world"),
            5,
        ))),
    )?;
    Ok(())
}

/// Blob metadata is its own subject: a blob key equal to a namespace key
/// does not touch namespace metadata, and a retirement is refused while
/// the retired identity still holds metadata.
#[test]
fn blob_metadata_is_separate_and_removed_before_retirement() -> TestResult {
    let content = b"described content";
    let identity = Kappa::sha256(content);
    let mut state = ReplayedNamespaceState::default();
    apply(
        &mut state,
        RecordTransition::ContentPublish(bytes_admission(content)?),
    )?;
    apply(
        &mut state,
        RecordTransition::Metadata(MetadataTransition::blob_meta(
            *ns().id(),
            INCARNATION,
            identity.clone(),
            "_assign".into(),
            Some(b"type".to_vec()),
        )),
    )?;
    assert!(
        state.metadata.is_empty(),
        "blob metadata is not namespace metadata"
    );
    let retirement = RecordTransition::ContentRetire(ContentRetirementRecord::new(admission(
        &identity,
        content.len() as u64,
    )));
    refused(&mut state, retirement)?;
    apply(
        &mut state,
        RecordTransition::Metadata(MetadataTransition::blob_meta(
            *ns().id(),
            INCARNATION,
            identity.clone(),
            "_assign".into(),
            None,
        )),
    )?;
    apply(
        &mut state,
        RecordTransition::ContentRetire(ContentRetirementRecord::new(admission(
            &identity,
            content.len() as u64,
        ))),
    )?;
    refused(
        &mut state,
        RecordTransition::Metadata(MetadataTransition::namespace_meta(
            *ns().id(),
            INCARNATION,
            "absent".into(),
            None,
        )),
    )?;
    Ok(())
}

#[test]
fn a_tag_removal_names_the_held_entry() -> TestResult {
    let entry = |kappa: &[u8], version| TagEntry {
        name: "head".into(),
        kappa: Kappa::sha256(kappa),
        version,
        created_at_ms: 1,
        updated_at_ms: 1,
        symref: None,
    };
    let mut state = ReplayedNamespaceState::default();
    apply(&mut state, RecordTransition::TagSet(entry(b"current", 1)))?;
    refused(&mut state, RecordTransition::TagDelete(entry(b"other", 1)))?;
    refused(
        &mut state,
        RecordTransition::TagDelete(entry(b"current", 2)),
    )?;
    apply(
        &mut state,
        RecordTransition::TagDelete(entry(b"current", 1)),
    )?;
    assert!(state.tags.is_empty() && state.tag_entries.is_empty());
    Ok(())
}

/// Evidence of another incarnation of the namespace is refused, however
/// its bytes are presented.
#[test]
fn another_incarnation_is_refused() -> TestResult {
    let foreign = ContentAdmissionRecord::new(
        ContentAdmission::new(*ns().id(), [6; 16], Kappa::sha256(b"x"), 1),
        ContentAdmissionEvidence::VerifiedBytes,
    )?;
    let record = RecordTransition::ContentPublish(foreign);
    let bytes = record.canonical_bytes();
    let foreign_domain = TransitionDomain::new(*ns().id(), LogicalIncarnation::from_bytes([6; 16]));
    let evidence = VerifiedContent::compute(Axis::Sha256, &bytes)?;
    let mutation =
        PreparedTransition::bind(foreign_domain, record, evidence, ClockMs::from_raw(1))?
            .mutation()
            .clone();
    let mut state = ReplayedNamespaceState::default();
    assert!(state.apply(domain(), &mutation, &bytes).is_err());
    assert_eq!(state, ReplayedNamespaceState::default());
    Ok(())
}

#[test]
fn sequences_advance_by_one_in_their_namespace() -> TestResult {
    let mut state = ReplayedNamespaceState::default();
    let sequence = |namespace: &NamespaceRef, value| {
        RecordTransition::Sequence(SequenceRecord {
            namespace_id: namespace.id().to_vec(),
            name: "revision".into(),
            value,
        })
    };
    apply(&mut state, sequence(&ns(), 1))?;
    refused(&mut state, sequence(&ns(), 3))?;
    assert!(ledgered(sequence(&NamespaceRef::deterministic("other"), 2)).is_err());
    apply(&mut state, sequence(&ns(), 2))?;
    assert_eq!(state.sequences.get("revision"), Some(&2));
    Ok(())
}
