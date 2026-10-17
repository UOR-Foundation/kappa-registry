//! The WebSocket filter vocabulary is exactly the mutation event names.

use kappa_handler::MutationEventOp;
use kappa_module_distribution::ws_events::KNOWN_EVENT_TYPES;

/// Declaration position of every variant. Exhaustive: a variant added to
/// `MutationEventOp` fails to compile here until the vocabulary covers it.
const fn position(operation: MutationEventOp) -> usize {
    match operation {
        MutationEventOp::TagSet => 0,
        MutationEventOp::TagDelete => 1,
        MutationEventOp::EdgePut => 2,
        MutationEventOp::EdgeDelete => 3,
        MutationEventOp::AssertionPublish => 4,
        MutationEventOp::RevocationPublish => 5,
        MutationEventOp::AnchorOrigin => 6,
        MutationEventOp::OperationPublish => 7,
        MutationEventOp::NamespaceUpdate => 8,
        MutationEventOp::SequenceUpdate => 9,
        MutationEventOp::MetadataUpdate => 10,
        MutationEventOp::ContentPublish => 11,
        MutationEventOp::ContentAlias => 12,
        MutationEventOp::ContentCompose => 13,
        MutationEventOp::ContentRetire => 14,
        MutationEventOp::RecordPublish => 15,
    }
}

const ALL: [MutationEventOp; 16] = [
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
];

#[test]
fn filter_vocabulary_names_every_mutation_event_exactly() -> Result<(), serde_json::Error> {
    assert_eq!(KNOWN_EVENT_TYPES.len(), ALL.len());
    for operation in ALL {
        let name = KNOWN_EVENT_TYPES[position(operation)];
        assert_eq!(name, operation.as_str());
        // The serialized event carries the same name subscribers filter on.
        assert_eq!(
            serde_json::to_value(operation)?,
            serde_json::Value::String(name.to_string())
        );
    }
    assert_eq!(
        KNOWN_EVENT_TYPES,
        [
            "tag_set",
            "tag_delete",
            "edge_put",
            "edge_delete",
            "assertion_publish",
            "revocation_publish",
            "anchor_origin",
            "operation_publish",
            "namespace_update",
            "sequence_update",
            "metadata_update",
            "content_publish",
            "content_alias",
            "content_compose",
            "content_retire",
            "record_publish",
        ]
    );
    Ok(())
}
