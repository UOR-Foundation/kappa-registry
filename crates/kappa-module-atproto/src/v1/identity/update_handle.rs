use std::sync::Arc;

use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{
    HandlerError, Outcome, WriteTarget, blocking, clock_now, execute, read_json_with_bytes, store,
    try_service,
};
use kappa_store::{
    Axis, ExecutionWrites, HandleRecord, StoreError, TagUpdate, VerifiedContent,
    default_handle_grace_ms, handle_update, succession_resolve,
};

use crate::protocol_id;
use crate::session::SessionStore;

/// Tag in `_handles` binding a handle to the content of its DID string.
pub fn did_tag(record: &HandleRecord) -> String {
    format!("handle_did:{}:{}", record.protocol.as_str(), record.handle)
}

/// `_handles` namespace metadata key holding the DID string for a handle.
pub fn did_meta_key(record: &HandleRecord) -> String {
    format!("_did:{}", did_tag(record))
}

/// Replace the anchor's handles in `record.protocol` with `record` and bind
/// the handle to `did`, all in one `_handles` execution.
///
/// Ownership is decided by `handle_update` in the execution's own view:
/// another anchor's attested handle, or its unattested handle within
/// `grace_ms` of its claim, conflicts. The DID binding is written only after
/// that decision, so a conflict writes nothing.
pub fn publish_handle<E: ExecutionWrites + ?Sized>(
    execution: &mut E,
    did: &str,
    record: &HandleRecord,
    grace_ms: i64,
) -> Result<(), StoreError> {
    handle_update(
        execution,
        &record.anchor,
        record,
        &record.protocol,
        grace_ms,
    )?;
    // The DID is protocol metadata, not substrate identity: the tag lets
    // resolveHandle find the DID content, the metadata carries the string.
    let did_content = VerifiedContent::compute(Axis::Sha256, did.as_bytes())?;
    let did_kappa = did_content.kappa().clone();
    execution.blob_put(&did_content)?;
    execution.tag_put(&did_tag(record), &TagUpdate::Set { kappa: did_kappa })?;
    execution.namespace_put_meta(&did_meta_key(record), did.as_bytes())
}

/// POST /xrpc/com.atproto.identity.updateHandle
///
/// Removes old atproto handles for the authenticated DID and creates
/// a new handle binding. Requires a valid session token. The session
/// DID is the external identifier. The session anchor (resolved
/// through the succession chain to get the current anchor) is the
/// internal store identifier.
///
/// After key rotation, the session carries the OLD anchor. The
/// handler resolves through the succession chain. If the old anchor
/// is watermarked with KeyCompromise, the session is rejected via
/// the watermark check in the auth layer; the handler does not
/// need to check watermarks here.
pub async fn update_handle(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let access_token = kappa_handler::extract_bearer_token(cx).ok_or_else(|| {
        HandlerError::protocol(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "missing access token",
        )
    })?;

    let session_store = try_service::<Arc<SessionStore>>(cx)
        .ok_or_else(|| HandlerError::internal("session store not configured"))?
        .clone();

    let now = clock_now(cx)?;

    let validated = blocking({
        let session_store = session_store.clone();
        let access_token = access_token.clone();
        move || session_store.validate_token(&access_token, now)
    })
    .await?;
    let (did, session_anchor) = validated.ok_or_else(|| {
        HandlerError::protocol(
            StatusCode::UNAUTHORIZED,
            "InvalidToken",
            "invalid or expired token",
        )
    })?;

    #[derive(serde::Deserialize)]
    struct UpdateHandleRequest {
        handle: String,
    }

    let (req, raw): (UpdateHandleRequest, _) = read_json_with_bytes(body, 64 * 1024).await?;

    if req.handle.is_empty() {
        return Err(HandlerError::protocol(
            StatusCode::BAD_REQUEST,
            "InvalidHandle",
            "missing required field: handle",
        ));
    }

    let s = store(cx);

    // Resolve the session anchor through the succession chain to get
    // the current anchor. If the user rotated keys, the session's
    // anchor is the old one. The succession chain gives the current.
    // The handles namespace is resolved in the same blocking call.
    let (current_anchor, handles) = blocking(move || {
        let anchor = succession_resolve(&*s, &session_anchor)?;
        let handles = s.namespace_resolve("_handles", None)?;
        Ok::<_, StoreError>((anchor, handles))
    })
    .await?;

    let record = HandleRecord {
        anchor: current_anchor,
        handle: req.handle,
        protocol: protocol_id().clone(),
        claimed_at_ms: now.as_i64(),
        attested_at_ms: None,
    };
    let committed = execute(cx, WriteTarget::existing(handles), &raw, move |execution| {
        // The session is read again inside the publishing execution and
        // recorded as its authorization dependency: a revocation that
        // lands before this publication refuses it.
        if execution.session_get(&access_token)?.is_none() {
            return Err(HandlerError::protocol(
                StatusCode::UNAUTHORIZED,
                "InvalidToken",
                "session revoked",
            ));
        }
        publish_handle(execution, &did, &record, default_handle_grace_ms())?;
        Ok(Outcome::Publish(()))
    })
    .await?;

    let mut response = kappa_handler::json_response(StatusCode::OK, &serde_json::json!({}))?;
    committed.annotate(&mut response);
    Ok(response)
}
