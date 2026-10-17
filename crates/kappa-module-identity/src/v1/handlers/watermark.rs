use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{HandlerError, Outcome, execute};
use kappa_store::{
    EdgeInput, EdgeRelation, Kappa, TagUpdate, VerifiedContent, Watermark, canonical_bytes,
};

#[derive(serde::Deserialize)]
struct WatermarkRequest {
    asserter: String,
    invalidate_before_ms: i64,
    reason: String,
    public_key: String,
    signature: String,
    set_at_ms: i64,
}

pub async fn handler(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (WatermarkRequest, _) =
        kappa_handler::read_json_with_bytes(body, 64 * 1024).await?;

    if req.reason.is_empty() {
        return Err(HandlerError::bad_request("missing required field: reason"));
    }

    let asserter_kappa = Kappa::parse(&req.asserter)?;

    let watermark = Watermark {
        asserter: asserter_kappa.clone(),
        invalidate_before_ms: req.invalidate_before_ms,
        reason: kappa_store::identity::WatermarkReason::parse(&req.reason)
            .ok_or_else(|| HandlerError::bad_request("invalid watermark reason"))?,
        set_at_ms: req.set_at_ms,
        cose_signature: kappa_store::SignedPayload::from_cose_bytes(
            hex::decode(&req.signature)
                .map_err(|e| HandlerError::bad_request(format!("invalid signature hex: {e}")))?,
        ),
    };
    let public_key = hex::decode(&req.public_key)
        .map_err(|e| HandlerError::bad_request(format!("invalid public_key hex: {e}")))?;
    kappa_crypto::signed_types::verify_watermark(&watermark, &public_key)
        .map_err(|e| HandlerError::bad_request(format!("watermark signature: {e}")))?;

    let content =
        VerifiedContent::compute(kappa_store::Axis::Sha256, &canonical_bytes(&watermark))?;

    // The signed record, its index entry, tag, and edge publish in one epoch
    // of the asserter's namespace.
    let target = kappa_handler::anchor_write_target(cx, &asserter_kappa).await?;
    let committed = execute(cx, target, &raw, move |execution| {
        let kappa = content.kappa().clone();
        execution.blob_put(&content)?;
        kappa_store::blob_meta_put_indexed(execution, &kappa, "object-type", "watermark")?;
        execution.watermark_put(&watermark)?;
        execution.tag_put(
            &format!("watermark/{kappa}"),
            &TagUpdate::Set {
                kappa: kappa.clone(),
            },
        )?;
        execution.edge_put(&EdgeInput {
            source: asserter_kappa.clone(),
            target: kappa.clone(),
            relation: EdgeRelation::Builtin(kappa_store::edge::BuiltinRelation::Assertion),
            created_at_ms: execution.now().as_i64(),
            asserter: asserter_kappa.clone(),
            metadata: Some(b"watermark".to_vec()),
        })?;
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
