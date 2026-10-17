use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{
    HandlerError, Outcome, WriteTarget, blocking, caller_anchor, clock_now, execute, path_param,
    store,
};
use kappa_store::{
    HandleRecord, Kappa, ProtocolId, StoreError, default_handle_grace_ms, handle_claim,
};

#[derive(serde::Deserialize)]
struct ClaimRequest {
    handle: String,
    protocol: Option<String>,
    anchor: String,
}

fn handle_to_json(r: &HandleRecord) -> serde_json::Value {
    serde_json::json!({
        "anchor": r.anchor.to_string(),
        "handle": r.handle,
        "protocol": r.protocol,
        "claimed_at_ms": r.claimed_at_ms,
        "attested_at_ms": r.attested_at_ms,
    })
}

pub async fn claim(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (ClaimRequest, _) =
        kappa_handler::read_json_with_bytes(body, 64 * 1024).await?;
    let anchor = Kappa::parse(&req.anchor)?;

    let caller = caller_anchor(cx)
        .ok_or_else(|| HandlerError::unauthorized("handle claim requires authentication"))?;
    if caller != anchor {
        return Err(HandlerError::forbidden(
            "caller anchor does not match claim anchor",
        ));
    }

    let protocol = ProtocolId::new(req.protocol.as_deref().unwrap_or("atproto"))
        .map_err(|error| HandlerError::bad_request(error.to_string()))?;

    let now = clock_now(cx)?;

    let record = HandleRecord {
        anchor: anchor.clone(),
        handle: req.handle,
        protocol,
        claimed_at_ms: now.as_i64(),
        attested_at_ms: None,
    };

    let target = handles_target(cx).await?;
    let committed = execute(cx, target, &raw, move |execution| {
        handle_claim(execution, &record, default_handle_grace_ms())?;
        Ok(Outcome::Publish(()))
    })
    .await?;

    let mut response = kappa_handler::json_response(
        StatusCode::CREATED,
        &serde_json::json!({"anchor": anchor.to_string(), "attested_at_ms": null}),
    )?;
    committed.annotate(&mut response);
    Ok(response)
}

/// Handle records publish in the system `_handles` namespace epoch.
async fn handles_target(cx: &Cx) -> Result<WriteTarget, HandlerError> {
    let s = store(cx);
    let handles = blocking(move || s.namespace_resolve("_handles", None)).await?;
    Ok(WriteTarget::existing(handles))
}

pub async fn get(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let protocol = ProtocolId::new(&path_param(cx, "protocol")?)
        .map_err(|error| HandlerError::bad_request(error.to_string()))?;
    let handle = path_param(cx, "handle")?;
    let s = store(cx);

    let record = blocking(move || {
        let result = s.handle_get(protocol, &handle)?;
        Ok::<_, StoreError>(result)
    })
    .await?;

    kappa_handler::json_response(StatusCode::OK, &handle_to_json(&record))
}

pub async fn by_anchor(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let anchor_str = path_param(cx, "anchor")?;
    let anchor = Kappa::parse(&anchor_str)?;
    let page = kappa_handler::page_request_from(cx, 1000)?;
    let s = store(cx);

    let handles = blocking(move || {
        let result = s.handle_list_by_anchor(&anchor, &page)?;
        Ok::<_, StoreError>(result)
    })
    .await?;

    let records: Vec<serde_json::Value> = handles.items.iter().map(handle_to_json).collect();
    kappa_handler::json_response(
        StatusCode::OK,
        &serde_json::json!({"handles": records, "next_after": handles.next_after}),
    )
}

pub async fn delete(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let protocol = ProtocolId::new(&path_param(cx, "protocol")?)
        .map_err(|error| HandlerError::bad_request(error.to_string()))?;
    let handle = path_param(cx, "handle")?;

    let caller = caller_anchor(cx)
        .ok_or_else(|| HandlerError::unauthorized("handle delete requires authentication"))?;

    let target = handles_target(cx).await?;
    let committed = execute(cx, target, &[], move |execution| {
        // Ownership is checked in the execution's own view, under the
        // writer that publishes the deletion.
        let existing = execution
            .handle_get(&protocol, &handle)?
            .ok_or_else(|| HandlerError::not_found(format!("handle {protocol}:{handle}")))?;
        if existing.anchor != caller {
            return Err(HandlerError::forbidden(
                "only the handle owner can delete it",
            ));
        }
        execution.handle_delete(&protocol, &handle)?;
        Ok(Outcome::Publish(()))
    })
    .await?;

    let mut response = kappa_handler::empty_response(StatusCode::NO_CONTENT);
    committed.annotate(&mut response);
    Ok(response)
}
