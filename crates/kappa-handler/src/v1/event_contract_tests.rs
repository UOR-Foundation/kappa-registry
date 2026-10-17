use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::{EpochMutation, MutationOp, StoreError};

use super::*;
use crate::event_feed::PublicationFeed;
use crate::event_stream::Position;

#[test]
fn operation_json_roundtrips_the_protocol_vocabulary() -> Result<(), serde_json::Error> {
    for operation in [
        MutationEventOp::TagSet,
        MutationEventOp::TagDelete,
        MutationEventOp::EdgePut,
        MutationEventOp::EdgeDelete,
        MutationEventOp::AssertionPublish,
        MutationEventOp::RevocationPublish,
        MutationEventOp::AnchorOrigin,
        MutationEventOp::OperationPublish,
        MutationEventOp::NamespaceUpdate,
        MutationEventOp::SequenceUpdate,
        MutationEventOp::MetadataUpdate,
        MutationEventOp::ContentPublish,
        MutationEventOp::ContentAlias,
        MutationEventOp::ContentCompose,
        MutationEventOp::ContentRetire,
        MutationEventOp::RecordPublish,
    ] {
        let wire = serde_json::to_value(operation)?;
        assert_eq!(wire, operation.as_str());
        assert_eq!(serde_json::from_value::<MutationEventOp>(wire)?, operation);
    }
    assert!(serde_json::from_str::<MutationEventOp>("\"unknown\"").is_err());
    Ok(())
}

#[test]
fn every_ledger_operation_has_an_event_form_at_its_history_coordinates() -> Result<(), StoreError> {
    let identity = Kappa::sha256(b"content");
    let root = Kappa::sha256(b"root");
    let mutations: Vec<EpochMutation> = [
        (MutationOp::TagSet, Some("head")),
        (MutationOp::TagDelete, Some("head")),
        (MutationOp::EdgePut, Some("owns")),
        (MutationOp::EdgeDelete, Some("owns")),
        (MutationOp::AssertionPublish, None),
        (MutationOp::RevocationPublish, None),
        (MutationOp::AnchorOrigin, None),
        (MutationOp::OperationPublish, None),
        (MutationOp::NamespaceUpdate, None),
        (MutationOp::SequenceUpdate, Some("revision")),
        (MutationOp::MetadataUpdate, Some("versioning")),
        (MutationOp::ContentPublish, None),
        (MutationOp::ContentAlias, None),
        (MutationOp::ContentCompose, None),
        (MutationOp::ContentRetire, None),
        (MutationOp::RecordPublish, None),
    ]
    .into_iter()
    .map(|(op, context)| EpochMutation {
        op,
        kappa: identity.clone(),
        timestamp_ms: kappa_store::clock::ClockMs::from_raw(0)
            .add_physical_ms(86_400_000)
            .as_i64(),
        context: context.map(str::to_string),
    })
    .collect();
    let events = events_from_ledger("repo", 7, &root, &mutations)?;
    assert_eq!(events.len(), mutations.len());
    for ((event, mutation), index) in events.iter().zip(&mutations).zip(0u64..) {
        assert_eq!(event.operation, MutationEventOp::try_from(mutation.op)?);
        assert_eq!(event.epoch, 7);
        assert_eq!(event.index, index);
        assert_eq!(event.root, root.to_string());
        assert_eq!(event.mtime_ms, 86_400_000);
        let expected_name = mutation
            .context
            .clone()
            .unwrap_or_else(|| identity.to_string());
        assert_eq!(event.name, expected_name);
        assert_eq!(event.id(), format!("7.{}.{root}", index + 1));
    }
    let deleted = &events[1];
    assert_eq!(deleted.value, None);
    assert_eq!(deleted.prev_value, Some(identity.to_string()));
    assert_eq!(events[0].value, Some(identity.to_string()));
    Ok(())
}

#[test]
fn an_event_id_parses_back_to_the_position_after_it() -> Result<(), StoreError> {
    let root = Kappa::sha256(b"root");
    let mutation = EpochMutation {
        op: MutationOp::TagSet,
        kappa: Kappa::sha256(b"value"),
        timestamp_ms: 0,
        context: Some("tag".into()),
    };
    let events = events_from_ledger("repo", 3, &root, &[mutation.clone(), mutation])?;
    let position = Position::parse(&events[1].id()).map_err(StoreError::Rejected)?;
    assert_eq!(position, Position::after(&events[1]));
    assert_eq!(position.consumed, 2);
    assert_eq!(position.id(), events[1].id());
    assert_eq!(
        Position::parse("0").map_err(StoreError::Rejected)?,
        Position::start()
    );
    assert_eq!(Position::start().id(), "0");
    Ok(())
}

#[test]
fn malformed_and_overflowing_cursors_are_refused() {
    let root = Kappa::sha256(b"root");
    for value in [
        String::new(),
        "1".into(),
        "1.1".into(),
        "0.0.x".into(),
        format!("0.1.{root}"),
        format!("+1.1.{root}"),
        format!("1.-1.{root}"),
        format!(" 1.1.{root}"),
        "1.1.not-a-kappa".into(),
        format!("18446744073709551616.1.{root}"),
        format!("1.18446744073709551616.{root}"),
    ] {
        assert!(Position::parse(&value).is_err(), "accepted {value:?}");
    }
}

fn namespace(name: &str) -> NamespaceRef {
    NamespaceRef::deterministic(name)
}

#[test]
fn notices_hold_one_feed_sequence_per_mutation_and_resume_inside_a_notice() {
    let feed = PublicationFeed::new(16, 100);
    let root = Kappa::sha256(b"root");
    feed.publish(&namespace("a"), 1, &root, 3);
    feed.publish(&namespace("b"), 1, &root, 0);
    feed.publish(&namespace("a"), 2, &root, 2);
    let all = feed.after(99, 10);
    assert_eq!(all.next, 105);
    assert_eq!(all.oldest, 100);
    let ranges: Vec<_> = all
        .notices
        .iter()
        .map(|notice| (notice.sequence, notice.last()))
        .collect();
    assert_eq!(
        ranges,
        [(100, 102), (103, 104)],
        "an empty epoch holds no sequence"
    );
    let inside = feed.after(101, 10);
    assert_eq!(
        inside.notices[0].sequence, 100,
        "the notice holding 102 is returned"
    );
    assert!(feed.after(104, 10).notices.is_empty());
}

#[test]
fn the_ring_is_bounded_and_reports_what_it_discarded() {
    let feed = PublicationFeed::new(2, 1);
    let root = Kappa::sha256(b"root");
    for epoch in 1..=5 {
        feed.publish(&namespace("a"), epoch, &root, 1);
    }
    let batch = feed.after(0, 10);
    assert_eq!(batch.notices.len(), 2);
    assert_eq!(batch.oldest, 4, "sequences 1-3 were discarded");
    assert_eq!(batch.next, 6);
}

#[test]
fn namespace_watches_wake_only_their_namespace_and_unwatched_entries_are_dropped() {
    let feed = PublicationFeed::new(4, 1);
    let root = Kappa::sha256(b"root");
    let mut a = feed.watch(&namespace("a"));
    let b = feed.watch(&namespace("b"));
    a.borrow_and_update();
    feed.publish(&namespace("a"), 9, &root, 1);
    assert!(matches!(a.has_changed(), Ok(true)));
    assert_eq!(*a.borrow(), 9);
    assert!(matches!(b.has_changed(), Ok(false)));
    assert_eq!(feed.watched(), 2);
    drop(b);
    feed.publish(&namespace("b"), 1, &root, 1);
    assert_eq!(
        feed.watched(),
        1,
        "a publication to an unwatched namespace drops its entry"
    );
}
