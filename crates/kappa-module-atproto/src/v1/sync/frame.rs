//! AT Protocol firehose frame formatting.
//!
//! Shared infrastructure for encoding MutationEvent into AT Protocol
//! frame types (#commit, #handle, #identity, #tombstone, #info).
//! Used by the firehose WebSocket handler and any future consumer
//! that produces AT Protocol wire-format event frames.

use kappa_handler::{MutationEvent, MutationEventOp};

use crate::dag_cbor::{self, CommitFrame, CommitOp, FrameOp};

/// True for ledger mutations that are repository-internal bookkeeping.
///
/// An operation receipt (`OperationPublish`), a namespace lifecycle record
/// (`NamespaceUpdate`), a sequence advance (`SequenceUpdate`), a namespace
/// metadata write (`MetadataUpdate`), a content framing commitment
/// (`ContentPublish`), a digest alias binding (`ContentAlias`), a
/// content composition (`ContentCompose`), a retirement (`ContentRetire`)
/// and a record installation (`RecordPublish`) carry no record path, no
/// record CID and no account identity change, so the firehose contract
/// has no #commit or #identity content for them. The repository changes
/// they accompany reach subscribers through their own tag and identity
/// events.
///
/// Exhaustive on MutationEventOp: adding an operation without deciding
/// its firehose form is a compile error.
const fn is_bookkeeping(op: MutationEventOp) -> bool {
    match op {
        MutationEventOp::OperationPublish
        | MutationEventOp::NamespaceUpdate
        | MutationEventOp::SequenceUpdate
        | MutationEventOp::MetadataUpdate
        | MutationEventOp::ContentPublish
        | MutationEventOp::ContentAlias
        | MutationEventOp::ContentCompose
        | MutationEventOp::ContentRetire
        | MutationEventOp::RecordPublish => true,
        MutationEventOp::TagSet
        | MutationEventOp::TagDelete
        | MutationEventOp::EdgePut
        | MutationEventOp::EdgeDelete
        | MutationEventOp::AssertionPublish
        | MutationEventOp::RevocationPublish
        | MutationEventOp::AnchorOrigin => false,
    }
}

/// Classify a MutationEvent into an AT Protocol frame type, or `None` when
/// the event is bookkeeping that produces no frame.
///
/// Bookkeeping is decided first, so a metadata key or sequence name that
/// happens to look like a handle or tombstone tag never becomes a frame.
/// Then, by namespace/name before operation type:
/// - _handles namespace + handle: prefix: #handle
/// - _tombstone tag name: #tombstone
pub fn classify(event: &MutationEvent) -> Option<&'static str> {
    if is_bookkeeping(event.operation) {
        return None;
    }
    if event.namespace == "_handles" && event.name.starts_with("handle:") {
        return Some("#handle");
    }
    if event.name == "_tombstone" || event.name.starts_with("_tombstone/") {
        return Some("#tombstone");
    }
    match event.operation {
        MutationEventOp::TagSet | MutationEventOp::TagDelete => Some("#commit"),
        MutationEventOp::EdgePut
        | MutationEventOp::EdgeDelete
        | MutationEventOp::AssertionPublish
        | MutationEventOp::RevocationPublish
        | MutationEventOp::AnchorOrigin => Some("#identity"),
        MutationEventOp::OperationPublish
        | MutationEventOp::NamespaceUpdate
        | MutationEventOp::SequenceUpdate
        | MutationEventOp::MetadataUpdate
        | MutationEventOp::ContentPublish
        | MutationEventOp::ContentAlias
        | MutationEventOp::ContentCompose
        | MutationEventOp::ContentRetire
        | MutationEventOp::RecordPublish => None,
    }
}

/// Extract handle string from a tag name like "handle:atproto:alice.example.com".
pub fn extract_handle(tag_name: &str) -> Option<&str> {
    tag_name
        .strip_prefix("handle:")
        .and_then(|s| s.split_once(':'))
        .map(|(_, handle)| handle)
        .filter(|h| !h.is_empty())
}

/// Map MutationEventOp to AT Protocol commit operation action, or `None`
/// for bookkeeping operations, which have no commit action.
/// Exhaustive, no wildcard.
pub const fn op_to_action(op: MutationEventOp) -> Option<&'static str> {
    match op {
        MutationEventOp::TagSet
        | MutationEventOp::EdgePut
        | MutationEventOp::AssertionPublish
        | MutationEventOp::RevocationPublish
        | MutationEventOp::AnchorOrigin => Some("create"),
        MutationEventOp::TagDelete | MutationEventOp::EdgeDelete => Some("delete"),
        MutationEventOp::OperationPublish
        | MutationEventOp::NamespaceUpdate
        | MutationEventOp::SequenceUpdate
        | MutationEventOp::MetadataUpdate
        | MutationEventOp::ContentPublish
        | MutationEventOp::ContentAlias
        | MutationEventOp::ContentCompose
        | MutationEventOp::ContentRetire
        | MutationEventOp::RecordPublish => None,
    }
}

fn commit_action(op: MutationEventOp) -> Result<&'static str, kappa_handler::HandlerError> {
    op_to_action(op).ok_or_else(|| {
        kappa_handler::HandlerError::internal(format!(
            "{} mutation has no commit action",
            op.as_str()
        ))
    })
}

/// Encode a MutationEvent as a DAG-CBOR binary frame, or `None` when the
/// event produces no frame.
pub fn to_cbor(
    event: &MutationEvent,
    seq: u64,
) -> Result<Option<Vec<u8>>, kappa_handler::HandlerError> {
    let Some(frame_type) = classify(event) else {
        return Ok(None);
    };
    let header = dag_cbor::encode_header(FrameOp::Message, frame_type);
    let body = body_for(event, seq, frame_type)?;
    Ok(Some(dag_cbor::frame(header, body)))
}

/// Encode a MutationEvent as a JSON text frame, or `None` when the event
/// produces no frame.
pub fn to_json(
    event: &MutationEvent,
    seq: u64,
) -> Result<Option<String>, kappa_handler::HandlerError> {
    let Some(frame_type) = classify(event) else {
        return Ok(None);
    };
    let value = json_value_for(event, seq, frame_type)?;
    serde_json::to_string(&value)
        .map(Some)
        .map_err(|error| kappa_handler::HandlerError::internal(format!("frame JSON: {error}")))
}

/// Encode an #info frame as DAG-CBOR binary.
pub fn info_cbor(name: &str, message: &str) -> Vec<u8> {
    dag_cbor::frame(
        dag_cbor::encode_header(FrameOp::Message, "#info"),
        dag_cbor::encode_info_body(name, message),
    )
}

/// Encode an #info frame as JSON text.
pub fn info_json(name: &str, message: &str) -> String {
    serde_json::to_string(&serde_json::json!({
        "$type": "#info",
        "name": name,
        "message": message,
    }))
    .expect("info JSON serialization is infallible")
}

/// Encode an OutdatedCursor error frame as DAG-CBOR binary.
pub fn outdated_cursor_cbor(message: &str) -> Vec<u8> {
    dag_cbor::frame(
        dag_cbor::encode_header(FrameOp::Error, "#info"),
        dag_cbor::encode_info_body("OutdatedCursor", message),
    )
}

/// Encode an OutdatedCursor error frame as JSON text.
pub fn outdated_cursor_json(message: &str) -> String {
    serde_json::to_string(&serde_json::json!({
        "$type": "#info",
        "name": "OutdatedCursor",
        "message": message,
    }))
    .expect("outdated cursor JSON serialization is infallible")
}

// -- Internal helpers --------------------------------------------------------

fn body_for(
    event: &MutationEvent,
    seq: u64,
    frame_type: &str,
) -> Result<Vec<u8>, kappa_handler::HandlerError> {
    Ok(match frame_type {
        "#handle" => {
            let handle = extract_handle(&event.name).unwrap_or("");
            dag_cbor::encode_handle_body(seq, &event.namespace, handle)
        }
        "#identity" => dag_cbor::encode_identity_body(seq, &event.namespace),
        "#tombstone" => dag_cbor::encode_tombstone_body(seq, &event.namespace),
        _ => {
            let action = commit_action(event.operation)?;
            let cid = record_cid(event)?;
            let ops = [CommitOp {
                action,
                path: &event.name,
                cid: cid.as_ref().map(|cid| cid.as_slice()),
            }];
            dag_cbor::encode_commit_body(&CommitFrame {
                seq,
                repo: &event.namespace,
                commit_cid: &[],
                rev: "",
                since: None,
                blocks_car: &[],
                ops: &ops,
            })
        }
    })
}

fn record_cid(event: &MutationEvent) -> Result<Option<[u8; 36]>, kappa_handler::HandlerError> {
    event
        .value
        .as_deref()
        .map(|value| {
            let label = kappa_store::Kappa::parse(value)?;
            if label.axis() != kappa_store::Axis::Sha256 {
                return Err(kappa_handler::HandlerError::internal(
                    "ATProto record CID requires SHA-256",
                ));
            }
            let mut cid = [0u8; 36];
            cid[..4].copy_from_slice(&[1, 0x71, 0x12, 0x20]);
            cid[4..].copy_from_slice(label.digest_bytes());
            Ok(cid)
        })
        .transpose()
}

fn json_value_for(
    event: &MutationEvent,
    seq: u64,
    frame_type: &str,
) -> Result<serde_json::Value, kappa_handler::HandlerError> {
    Ok(match frame_type {
        "#handle" => {
            let handle = extract_handle(&event.name).unwrap_or("");
            serde_json::json!({
                "$type": "#handle",
                "seq": seq,
                "did": event.namespace,
                "handle": handle,
            })
        }
        "#identity" => serde_json::json!({
            "$type": "#identity",
            "seq": seq,
            "did": event.namespace,
        }),
        "#tombstone" => serde_json::json!({
            "$type": "#tombstone",
            "seq": seq,
            "did": event.namespace,
        }),
        _ => {
            let action = commit_action(event.operation)?;
            let cid_value: serde_json::Value = match record_cid(event)? {
                Some(cid) => serde_json::Value::String(crate::cid::cid_to_string(&cid)),
                None => serde_json::Value::Null,
            };
            serde_json::json!({
                "$type": "#commit",
                "seq": seq,
                "repo": event.namespace,
                "ops": [{
                    "action": action,
                    "path": event.name,
                    "cid": cid_value,
                }],
            })
        }
    })
}
