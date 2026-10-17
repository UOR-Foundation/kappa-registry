//! Firehose frame classification and encoding of mutation events.

use kappa_handler::{MutationEvent, MutationEventOp};
use kappa_module_atproto::sync::frame::{
    classify, extract_handle, info_cbor, info_json, op_to_action, outdated_cursor_cbor,
    outdated_cursor_json, to_cbor, to_json,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn event(ns: &str, name: &str, op: MutationEventOp) -> MutationEvent {
    MutationEvent {
        namespace: ns.to_owned(),
        name: name.to_owned(),
        value: Some(kappa_store::Kappa::sha256(b"record").to_string()),
        prev_value: None,
        epoch: 1,
        index: 0,
        root: kappa_store::Kappa::sha256(b"root").to_string(),
        mtime_ms: 1000,
        operation: op,
    }
}

fn json_frame(event: &MutationEvent, seq: u64) -> Result<String, Box<dyn std::error::Error>> {
    Ok(to_json(event, seq)?.ok_or("event produced no JSON frame")?)
}

fn cbor_frame(event: &MutationEvent, seq: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(to_cbor(event, seq)?.ok_or("event produced no CBOR frame")?)
}

/// A bookkeeping event has no frame type, no commit action, and encodes to
/// no frame in either wire form.
fn assert_no_frame(event: &MutationEvent) -> TestResult {
    assert_eq!(classify(event), None);
    assert_eq!(op_to_action(event.operation), None);
    assert_eq!(to_json(event, 7)?, None);
    assert_eq!(to_cbor(event, 7)?, None);
    Ok(())
}

// -- classify tests --

#[test]
fn classify_tag_set_is_commit() {
    assert_eq!(
        classify(&event("repo", "record/a/b", MutationEventOp::TagSet)),
        Some("#commit")
    );
}

#[test]
fn classify_tag_delete_is_commit() {
    assert_eq!(
        classify(&event("repo", "record/a/b", MutationEventOp::TagDelete)),
        Some("#commit")
    );
}

#[test]
fn classify_edge_put_is_identity() {
    assert_eq!(
        classify(&event("repo", "edge/x", MutationEventOp::EdgePut)),
        Some("#identity")
    );
}

#[test]
fn classify_edge_delete_is_identity() {
    assert_eq!(
        classify(&event("repo", "edge/x", MutationEventOp::EdgeDelete)),
        Some("#identity")
    );
}

#[test]
fn classify_assertion_is_identity() {
    assert_eq!(
        classify(&event(
            "repo",
            "assertion/x",
            MutationEventOp::AssertionPublish
        )),
        Some("#identity")
    );
}

#[test]
fn classify_revocation_is_identity() {
    assert_eq!(
        classify(&event(
            "repo",
            "revocation/x",
            MutationEventOp::RevocationPublish
        )),
        Some("#identity")
    );
}

#[test]
fn classify_anchor_origin_is_identity() {
    assert_eq!(
        classify(&event("repo", "anchor", MutationEventOp::AnchorOrigin)),
        Some("#identity")
    );
}

#[test]
fn classify_handles_namespace_is_handle() {
    assert_eq!(
        classify(&event(
            "_handles",
            "handle:atproto:alice.example.com",
            MutationEventOp::TagSet
        )),
        Some("#handle"),
    );
}

#[test]
fn classify_tombstone_tag_is_tombstone() {
    assert_eq!(
        classify(&event("repo", "_tombstone", MutationEventOp::TagSet)),
        Some("#tombstone")
    );
}

#[test]
fn classify_tombstone_prefix_is_tombstone() {
    assert_eq!(
        classify(&event(
            "repo",
            "_tombstone/reason",
            MutationEventOp::TagDelete
        )),
        Some("#tombstone")
    );
}

#[test]
fn classify_handles_namespace_non_handle_tag_is_commit() {
    // A tag in _handles that does not start with "handle:" is a commit, not a handle frame.
    assert_eq!(
        classify(&event("_handles", "config/key", MutationEventOp::TagSet)),
        Some("#commit"),
    );
}

// -- bookkeeping operations produce no frame --

#[test]
fn operation_publish_produces_no_frame() -> TestResult {
    assert_no_frame(&event(
        "repo",
        "operation-receipt",
        MutationEventOp::OperationPublish,
    ))
}

#[test]
fn namespace_update_produces_no_frame() -> TestResult {
    assert_no_frame(&event("repo", "repo", MutationEventOp::NamespaceUpdate))
}

#[test]
fn sequence_update_produces_no_frame() -> TestResult {
    assert_no_frame(&event(
        "_system",
        "_atproto_seq",
        MutationEventOp::SequenceUpdate,
    ))
}

#[test]
fn metadata_update_produces_no_frame_even_under_handle_and_tombstone_names() -> TestResult {
    assert_no_frame(&event(
        "_handles",
        "_did:handle_did:atproto:alice.test",
        MutationEventOp::MetadataUpdate,
    ))?;
    assert_no_frame(&event(
        "_handles",
        "handle:atproto:alice.test",
        MutationEventOp::MetadataUpdate,
    ))?;
    assert_no_frame(&event(
        "repo",
        "_tombstone",
        MutationEventOp::MetadataUpdate,
    ))
}

#[test]
fn content_commitment_alias_and_composition_produce_no_frame() -> TestResult {
    assert_no_frame(&event("repo", "content", MutationEventOp::ContentPublish))?;
    assert_no_frame(&event("repo", "content", MutationEventOp::ContentAlias))?;
    assert_no_frame(&event("repo", "content", MutationEventOp::ContentCompose))?;
    assert_no_frame(&event("repo", "content", MutationEventOp::ContentRetire))?;
    assert_no_frame(&event("repo", "content", MutationEventOp::RecordPublish))
}

// -- extract_handle tests --

#[test]
fn extract_handle_valid() {
    assert_eq!(
        extract_handle("handle:atproto:alice.example.com"),
        Some("alice.example.com")
    );
}

#[test]
fn extract_handle_empty_handle() {
    assert_eq!(extract_handle("handle:atproto:"), None);
}

#[test]
fn extract_handle_no_protocol() {
    assert_eq!(extract_handle("handle:"), None);
}

#[test]
fn extract_handle_not_a_handle() {
    assert_eq!(extract_handle("record/app.bsky.feed.post/abc"), None);
}

#[test]
fn extract_handle_multiple_colons() {
    assert_eq!(
        extract_handle("handle:dns:sub.example.com:extra"),
        Some("sub.example.com:extra")
    );
}

// -- op_to_action tests --

#[test]
fn op_to_action_exhaustive() {
    assert_eq!(op_to_action(MutationEventOp::TagSet), Some("create"));
    assert_eq!(op_to_action(MutationEventOp::TagDelete), Some("delete"));
    assert_eq!(op_to_action(MutationEventOp::EdgePut), Some("create"));
    assert_eq!(op_to_action(MutationEventOp::EdgeDelete), Some("delete"));
    assert_eq!(
        op_to_action(MutationEventOp::AssertionPublish),
        Some("create")
    );
    assert_eq!(
        op_to_action(MutationEventOp::RevocationPublish),
        Some("create")
    );
    assert_eq!(op_to_action(MutationEventOp::AnchorOrigin), Some("create"));
    assert_eq!(op_to_action(MutationEventOp::OperationPublish), None);
    assert_eq!(op_to_action(MutationEventOp::NamespaceUpdate), None);
    assert_eq!(op_to_action(MutationEventOp::SequenceUpdate), None);
    assert_eq!(op_to_action(MutationEventOp::MetadataUpdate), None);
    assert_eq!(op_to_action(MutationEventOp::ContentPublish), None);
    assert_eq!(op_to_action(MutationEventOp::ContentAlias), None);
    assert_eq!(op_to_action(MutationEventOp::ContentCompose), None);
    assert_eq!(op_to_action(MutationEventOp::ContentRetire), None);
    assert_eq!(op_to_action(MutationEventOp::RecordPublish), None);
}

// -- frame output tests --

#[test]
fn to_json_commit_contains_type_and_ops() -> TestResult {
    let json = json_frame(&event("repo", "record/a/b", MutationEventOp::TagSet), 42)?;
    assert!(json.contains("\"$type\":\"#commit\""), "{json}");
    assert!(json.contains("\"seq\":42"), "{json}");
    assert!(json.contains("\"action\":\"create\""), "{json}");
    assert!(json.contains("\"path\":\"record/a/b\""), "{json}");
    Ok(())
}

#[test]
fn to_json_handle_contains_did_and_handle() -> TestResult {
    let json = json_frame(
        &event(
            "_handles",
            "handle:atproto:alice.test",
            MutationEventOp::TagSet,
        ),
        1,
    )?;
    assert!(json.contains("\"$type\":\"#handle\""), "{json}");
    assert!(json.contains("\"handle\":\"alice.test\""), "{json}");
    Ok(())
}

#[test]
fn to_json_identity_contains_did() -> TestResult {
    let json = json_frame(&event("repo", "edge/x", MutationEventOp::EdgePut), 5)?;
    assert!(json.contains("\"$type\":\"#identity\""), "{json}");
    assert!(json.contains("\"did\":\"repo\""), "{json}");
    Ok(())
}

#[test]
fn to_json_tombstone() -> TestResult {
    let json = json_frame(&event("repo", "_tombstone", MutationEventOp::TagSet), 10)?;
    assert!(json.contains("\"$type\":\"#tombstone\""), "{json}");
    Ok(())
}

#[test]
fn to_cbor_produces_non_empty_bytes() -> TestResult {
    let bytes = cbor_frame(&event("repo", "record/a/b", MutationEventOp::TagSet), 1)?;
    assert!(!bytes.is_empty());
    Ok(())
}

#[test]
fn cbor_record_cid_is_tagged_binary_dag_cbor_cid() -> TestResult {
    let event = event("repo", "record/a/b", MutationEventOp::TagSet);
    let encoded = cbor_frame(&event, 1)?;
    let cid = kappa_module_atproto::cid::cid_for_cbor(b"record");
    let mut tagged_cid = vec![0xd8, 42, 0x58, 37, 0];
    tagged_cid.extend_from_slice(&cid);
    assert!(
        encoded
            .windows(tagged_cid.len())
            .any(|bytes| bytes == tagged_cid)
    );
    Ok(())
}

#[test]
fn malformed_record_label_is_rejected() {
    let mut event = event("repo", "record/a/b", MutationEventOp::TagSet);
    event.value = Some("sha256:abc".into());
    assert!(to_cbor(&event, 1).is_err());
}

#[test]
fn info_json_contains_name_and_message() {
    let json = info_json("TestInfo", "test message");
    assert!(json.contains("\"name\":\"TestInfo\""), "{json}");
    assert!(json.contains("\"message\":\"test message\""), "{json}");
}

#[test]
fn outdated_cursor_json_contains_name() {
    let json = outdated_cursor_json("too slow");
    assert!(json.contains("\"OutdatedCursor\""), "{json}");
    assert!(json.contains("\"too slow\""), "{json}");
}

#[test]
fn info_cbor_produces_non_empty() {
    assert!(!info_cbor("Test", "msg").is_empty());
}

#[test]
fn outdated_cursor_cbor_produces_non_empty() {
    assert!(!outdated_cursor_cbor("lag").is_empty());
}

#[test]
fn to_json_delete_action() -> TestResult {
    let json = json_frame(&event("repo", "record/a/b", MutationEventOp::TagDelete), 1)?;
    assert!(json.contains("\"action\":\"delete\""), "{json}");
    Ok(())
}

#[test]
fn to_json_null_cid_on_delete() -> TestResult {
    let mut e = event("repo", "record/a/b", MutationEventOp::TagDelete);
    e.value = None;
    let json = json_frame(&e, 1)?;
    assert!(json.contains("\"cid\":null"), "{json}");
    Ok(())
}
