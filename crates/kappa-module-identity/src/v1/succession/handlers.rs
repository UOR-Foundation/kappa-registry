use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{HandlerError, Outcome, blocking, clock_now, execute, path_param, store};
use kappa_store::{
    Kappa, Succession, SuccessionReason, VerifiedSuccession, succession_chain,
    succession_put_with_default_watermark, succession_resolve,
};

#[derive(serde::Deserialize)]
struct SuccessionRequest {
    old_anchor: String,
    new_anchor: String,
    old_algorithm: String,
    old_public_key: String,
    new_algorithm: String,
    new_public_key: String,
    reason: String,
    effective_at_ms: Option<i64>,
    old_signature: String,
    new_signature: String,
    /// Canonical dCBOR watermark including the old anchor's COSE signature.
    watermark: String,
    previd: Option<String>,
}

pub async fn put(cx: &Cx, body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (SuccessionRequest, _) =
        kappa_handler::read_json_with_bytes(body, 64 * 1024).await?;

    if req.reason.is_empty() {
        return Err(HandlerError::bad_request("missing required field: reason"));
    }

    let old_anchor = Kappa::parse(&req.old_anchor)?;
    let new_anchor = Kappa::parse(&req.new_anchor)?;
    let old_public_key = hex::decode(&req.old_public_key)
        .map_err(|e| HandlerError::bad_request(format!("invalid old_public_key hex: {e}")))?;
    let new_public_key = hex::decode(&req.new_public_key)
        .map_err(|e| HandlerError::bad_request(format!("invalid new_public_key hex: {e}")))?;
    let old_sig = hex::decode(&req.old_signature)
        .map_err(|e| HandlerError::bad_request(format!("invalid old_signature hex: {e}")))?;
    let new_sig = hex::decode(&req.new_signature)
        .map_err(|e| HandlerError::bad_request(format!("invalid new_signature hex: {e}")))?;
    let watermark_bytes = hex::decode(&req.watermark)
        .map_err(|e| HandlerError::bad_request(format!("invalid watermark hex: {e}")))?;
    let watermark: kappa_store::Watermark =
        kappa_store::canonical::from_canonical(&watermark_bytes)
            .map_err(|e| HandlerError::bad_request(format!("invalid canonical watermark: {e}")))?;

    let reason = match req.reason.as_str() {
        "key-compromise" => SuccessionReason::KeyCompromise,
        "administrative" => SuccessionReason::Administrative,
        "rotation" => SuccessionReason::Rotation,
        other => {
            return Err(HandlerError::bad_request(format!(
                "invalid reason: {other}, expected rotation|key-compromise|administrative"
            )));
        }
    };

    let previd = match &req.previd {
        Some(s) => Some(Kappa::parse(s)?),
        None => None,
    };

    let now = clock_now(cx)?;
    let effective_at_ms = req.effective_at_ms.unwrap_or_else(|| now.as_i64());

    let succession = Succession {
        old_anchor: old_anchor.clone(),
        new_anchor,
        reason,
        effective_at_ms,
        old_cose_signature: kappa_store::SignedPayload::from_cose_bytes(old_sig),
        new_cose_signature: kappa_store::SignedPayload::from_cose_bytes(new_sig),
        prev_identifier: previd,
        chain_anchor: None,
    };

    let verified = VerifiedSuccession::verify(
        succession,
        &req.old_algorithm,
        &old_public_key,
        &req.new_algorithm,
        &new_public_key,
    )?;

    // The succession record, its watermark, and the watermark edge publish
    // together in the old anchor's namespace epoch.
    let target = kappa_handler::anchor_write_target(cx, &old_anchor).await?;
    let committed = execute(cx, target, &raw, move |execution| {
        let kappa = succession_put_with_default_watermark(execution, &verified, &watermark)?;
        Ok(Outcome::Publish(kappa))
    })
    .await?;

    let mut response = kappa_handler::json_response(
        StatusCode::CREATED,
        &serde_json::json!({"kappa": committed.value.to_string()}),
    )?;
    committed.annotate(&mut response);
    Ok(response)
}

pub async fn resolve(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let anchor_str = path_param(cx, "anchor")?;
    let anchor = Kappa::parse(&anchor_str)?;
    let s = store(cx);

    let current = blocking(move || {
        let result = succession_resolve(&*s, &anchor)?;
        Ok::<_, kappa_store::StoreError>(result)
    })
    .await?;

    kappa_handler::json_response(
        StatusCode::OK,
        &serde_json::json!({"current": current.to_string()}),
    )
}

pub async fn chain(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let anchor_str = path_param(cx, "anchor")?;
    let anchor = Kappa::parse(&anchor_str)?;
    let s = store(cx);

    let chain_result = blocking(move || {
        let result = succession_chain(&*s, &anchor)?;
        Ok::<_, kappa_store::StoreError>(result)
    })
    .await?;

    let chain_strs: Vec<String> = chain_result.iter().map(|k| k.to_string()).collect();
    kappa_handler::json_response(StatusCode::OK, &serde_json::json!({"chain": chain_strs}))
}
