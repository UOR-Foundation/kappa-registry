use super::*;
use crate::identity_scope::session_id;
use kappa_types::{Axis, Kappa};

/// The instance every transition here is bound to.
const INCARNATION: LogicalIncarnation = LogicalIncarnation::from_bytes([7; 16]);

fn namespace() -> NamespaceRef {
    NamespaceRef::deterministic("canonical-transition-correspondence")
}

fn domain() -> TransitionDomain {
    TransitionDomain::new(*namespace().id(), INCARNATION)
}

fn prepared(record: RecordTransition) -> Result<PreparedTransition, StoreError> {
    let evidence = VerifiedContent::compute(Axis::Sha256, &record.canonical_bytes())?;
    PreparedTransition::bind(domain(), record, evidence, ClockMs::from_raw(10))
}

#[test]
fn deletion_preserves_authorization_evidence_but_removes_tag_membership() -> Result<(), StoreError>
{
    let session = prepared(RecordTransition::Session(SessionTransition::deleted(
        session_id("retired-session-token"),
        Kappa::sha256(b"owner"),
    )))?;
    assert!(session.index_change().1.is_some());
    let tag = prepared(RecordTransition::TagDelete(TagEntry {
        name: "head".into(),
        kappa: Kappa::sha256(b"payload"),
        version: 2,
        created_at_ms: 1,
        updated_at_ms: 2,
        symref: None,
    }))?;
    assert!(tag.index_change().1.is_none());
    assert_eq!(tag.mutation().kappa, *tag.evidence().kappa());
    Ok(())
}

#[test]
fn ledger_scope_cannot_substitute_another_session() -> Result<(), StoreError> {
    let transition = prepared(RecordTransition::Session(SessionTransition::set(
        session_id("first-token"),
        Kappa::sha256(b"owner"),
        20,
        b"metadata",
    )))?;
    let (_, evidence, mut mutation, _) = transition.into_parts(&namespace(), &INCARNATION)?;
    mutation.context = Some(
        AnchorScope::Session {
            id: session_id("second-token"),
        }
        .to_context(),
    );
    assert!(PreparedTransition::decode(domain(), &mutation, evidence).is_err());
    Ok(())
}

#[test]
fn prepared_bytes_cannot_be_substituted() -> Result<(), StoreError> {
    let record = RecordTransition::Session(SessionTransition::deleted(
        session_id("token"),
        Kappa::sha256(b"owner"),
    ));
    let evidence = VerifiedContent::compute(Axis::Sha256, b"unrelated bytes")?;
    assert!(PreparedTransition::bind(domain(), record, evidence, ClockMs::from_raw(10)).is_err());
    Ok(())
}

#[test]
fn application_refuses_a_recreated_namespace() -> Result<(), StoreError> {
    let transition = prepared(RecordTransition::Session(SessionTransition::deleted(
        session_id("incarnation-bound-token"),
        Kappa::sha256(b"owner"),
    )))?;
    let recreated = LogicalIncarnation::from_bytes([8; 16]);
    assert!(transition.into_parts(&namespace(), &recreated).is_err());
    Ok(())
}

#[test]
fn device_removal_roundtrips_without_reactivating_membership() -> Result<(), StoreError> {
    use kappa_types::identity::DeviceBinding;
    let record = DeviceBinding {
        anchor: Kappa::sha256(b"device-owner"),
        device_key: vec![1, 2, 3],
        algorithm: "test-algorithm".into(),
        bound_at_ms: 1,
        cose_signature: kappa_types::SignedPayload::empty(),
    };
    let put = prepared(RecordTransition::Member(MemberTransition::DevicePut(
        record.clone(),
    )))?;
    let removal = prepared(RecordTransition::Member(MemberTransition::DeviceRevoke(
        record,
    )))?;
    assert_eq!(put.index_change().0, removal.index_change().0);
    assert!(put.index_change().1.is_some());
    assert!(removal.index_change().1.is_none());
    assert_ne!(put.evidence().kappa(), removal.evidence().kappa());
    let (_, evidence, mutation, expected) = removal.into_parts(&namespace(), &INCARNATION)?;
    let decoded = PreparedTransition::decode(domain(), &mutation, evidence)?;
    assert_eq!(decoded.index_change(), expected);
    assert!(matches!(
        decoded.record(),
        RecordTransition::Member(MemberTransition::DeviceRevoke(_))
    ));
    Ok(())
}

fn content_record(
    incarnation: [u8; 16],
) -> Result<kappa_types::content::ContentAdmissionRecord, StoreError> {
    use kappa_types::content::{
        ContentAdmission, ContentAdmissionEvidence, ContentAdmissionRecord,
    };
    ContentAdmissionRecord::new(
        ContentAdmission::new(*namespace().id(), incarnation, Kappa::sha256(b"payload"), 7),
        ContentAdmissionEvidence::VerifiedBytes,
    )
}

#[test]
fn content_index_commits_admission_not_evidence_envelope() -> Result<(), StoreError> {
    let record = content_record([7; 16])?;
    let expected = kappa_types::state_key::content_entry(
        record.admission().identity(),
        &canonical_bytes(record.admission()),
    );
    let transition = prepared(RecordTransition::ContentPublish(record))?;
    assert_eq!(transition.index_change(), (expected.0, Some(expected.1)));
    assert_ne!(
        expected.1,
        kappa_types::state_key::value(transition.evidence().content())
    );
    Ok(())
}

#[test]
fn foreign_incarnation_cannot_be_rebound_to_current_domain() -> Result<(), StoreError> {
    assert!(prepared(RecordTransition::ContentPublish(content_record([8; 16])?)).is_err());
    let metadata = kappa_types::content::MetadataTransition::namespace_meta(
        *namespace().id(),
        [8; 16],
        "key".into(),
        Some(vec![1]),
    );
    assert!(prepared(RecordTransition::Metadata(metadata)).is_err());
    Ok(())
}

#[test]
fn content_operation_cannot_substitute_alias_for_verified_bytes() -> Result<(), StoreError> {
    let transition = prepared(RecordTransition::ContentPublish(content_record([7; 16])?))?;
    let (_, evidence, mut mutation, _) = transition.into_parts(&namespace(), &INCARNATION)?;
    mutation.op = MutationOp::ContentAlias;
    assert!(PreparedTransition::decode(domain(), &mutation, evidence).is_err());
    Ok(())
}

#[test]
fn explicit_record_operation_survives_roundtrip() -> Result<(), StoreError> {
    let transition = prepared(RecordTransition::RecordPublish(content_record([7; 16])?))?;
    let (_, evidence, mutation, expected) = transition.into_parts(&namespace(), &INCARNATION)?;
    let decoded = PreparedTransition::decode(domain(), &mutation, evidence)?;
    assert_eq!(decoded.mutation().op, MutationOp::RecordPublish);
    assert_eq!(decoded.index_change(), expected);
    Ok(())
}

#[test]
fn empty_metadata_key_preserves_set_delete_and_ledger_scope() -> Result<(), StoreError> {
    use kappa_types::MetadataTransition;

    let mut path = None;
    for value in [Some(vec![1]), None] {
        let present = value.is_some();
        let transition = prepared(RecordTransition::Metadata(
            MetadataTransition::namespace_meta(*namespace().id(), [7; 16], String::new(), value),
        ))?;
        assert_eq!(transition.mutation().context.as_deref(), Some(""));
        let (_, evidence, mutation, expected) =
            transition.into_parts(&namespace(), &INCARNATION)?;
        let decoded = PreparedTransition::decode(domain(), &mutation, evidence)?;
        assert_eq!(decoded.index_change(), expected);
        assert_eq!(expected.1.is_some(), present);
        if let Some(path) = path {
            assert_eq!(expected.0, path);
        }
        path = Some(expected.0);

        let (_, evidence, _, _) = decoded.into_parts(&namespace(), &INCARNATION)?;
        let mut substituted = mutation;
        substituted.context = None;
        assert!(PreparedTransition::decode(domain(), &substituted, evidence).is_err());
    }
    Ok(())
}
