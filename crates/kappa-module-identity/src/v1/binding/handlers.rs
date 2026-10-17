use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{
    HandlerError, Outcome, blocking, caller_anchor, clock_now, execute, path_param, store,
};
use kappa_store::identity::{BindingMethod, TrustLevel};
use kappa_store::{IdentityBinding, Kappa, StoreError};

#[derive(serde::Deserialize)]
struct BindingPutRequest {
    source: String,
    target: String,
    method: Option<String>,
    trust_level: Option<u8>,
    verified_at_ms: Option<i64>,
}

/// Bindings publish in the target anchor's namespace epoch, so only that
/// anchor, authenticated, may create or delete them.
fn require_target_caller(cx: &Cx, target: &Kappa, action: &str) -> Result<(), HandlerError> {
    let caller = caller_anchor(cx)
        .ok_or_else(|| HandlerError::unauthorized(format!("{action} requires authentication")))?;
    if caller != *target {
        return Err(HandlerError::forbidden(format!(
            "{action} is permitted only to the binding target anchor"
        )));
    }
    Ok(())
}

fn binding_to_json(b: &IdentityBinding) -> serde_json::Value {
    serde_json::json!({
        "source": b.source,
        "target": b.target.to_string(),
        "method": b.method.as_str(),
        "trust_level": b.trust_level.as_str(),
        "verified_at_ms": b.verified_at_ms,
    })
}

pub async fn put(cx: &Cx, body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (BindingPutRequest, _) =
        kappa_handler::read_json_with_bytes(body, 64 * 1024).await?;
    let target_kappa = Kappa::parse(&req.target)?;
    require_target_caller(cx, &target_kappa, "binding")?;
    let now = clock_now(cx)?;

    let verified_at_ms = req.verified_at_ms.unwrap_or_else(|| now.as_i64());
    let binding = IdentityBinding {
        source: req.source,
        target: target_kappa.clone(),
        method: BindingMethod::parse(req.method.as_deref().unwrap_or("self-asserted"))
            .ok_or_else(|| HandlerError::bad_request("invalid binding method"))?,
        trust_level: match req.trust_level.unwrap_or(1) {
            0 => TrustLevel::Unverified,
            1 => TrustLevel::Verified,
            2 => TrustLevel::ServerCustodial,
            3 => TrustLevel::SelfSovereign,
            _ => return Err(HandlerError::bad_request("invalid binding trust level")),
        },
        verified_at_ms: Some(verified_at_ms),
        metadata: None,
    };

    // A binding publishes in the target anchor's namespace epoch.
    let target = kappa_handler::anchor_write_target(cx, &target_kappa).await?;
    let committed = execute(cx, target, &raw, move |execution| {
        execution.binding_put(&binding)?;
        Ok(Outcome::Publish(()))
    })
    .await?;

    let mut response = kappa_handler::json_response(StatusCode::CREATED, &serde_json::json!({}))?;
    committed.annotate(&mut response);
    Ok(response)
}

pub async fn get(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let source = path_param(cx, "source")?;
    let s = store(cx);

    let bindings = blocking(move || {
        let result = s.binding_get(&source)?;
        Ok::<_, StoreError>(result)
    })
    .await?;

    let items: Vec<serde_json::Value> = bindings.iter().map(binding_to_json).collect();
    kappa_handler::json_response(StatusCode::OK, &serde_json::json!({"bindings": items}))
}

#[derive(serde::Deserialize)]
struct BindingDeleteRequest {
    source: String,
    target: String,
}

pub async fn delete(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (BindingDeleteRequest, _) =
        kappa_handler::read_json_with_bytes(body, 64 * 1024).await?;
    let target_kappa = Kappa::parse(&req.target)?;
    require_target_caller(cx, &target_kappa, "binding delete")?;

    let s = store(cx);
    let source = req.source;
    let target = kappa_handler::anchor_write_target(cx, &target_kappa).await?;

    let committed = execute(cx, target, &raw, move |execution| {
        // Read under the execution's writer: no binding can publish between
        // this check and the deletion. An absent binding publishes nothing.
        let bound = s
            .binding_get(&source)?
            .iter()
            .any(|binding| binding.target == target_kappa);
        if !bound {
            return Ok(Outcome::Discard(()));
        }
        execution.binding_delete(&source, &target_kappa)?;
        Ok(Outcome::Publish(()))
    })
    .await?;

    let mut response = kappa_handler::empty_response(StatusCode::NO_CONTENT);
    committed.annotate(&mut response);
    Ok(response)
}

pub async fn list_by_asserter(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let anchor_str = path_param(cx, "anchor")?;
    let anchor_kappa = Kappa::parse(&anchor_str)?;
    let page = kappa_handler::page_request_from(cx, 1000)?;
    let s = store(cx);

    let bindings = blocking(move || {
        let result = s.binding_list_by_target(&anchor_kappa, &page)?;
        Ok::<_, StoreError>(result)
    })
    .await?;

    let items: Vec<serde_json::Value> = bindings.items.iter().map(binding_to_json).collect();
    kappa_handler::json_response(
        StatusCode::OK,
        &serde_json::json!({"bindings": items, "next_after": bindings.next_after}),
    )
}
