use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{HandlerError, Outcome, execute};
use kappa_store::{Axis, Kappa, StoreError, TagUpdate, VerifiedContent};

#[derive(serde::Deserialize)]
struct AnchorRequest {
    algorithm: String,
    public_key: String,
    #[serde(default)]
    endpoint: Option<String>,
}

pub async fn handler(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (AnchorRequest, _) =
        kappa_handler::read_json_with_bytes(body, 64 * 1024).await?;

    let public_key_bytes = hex::decode(&req.public_key)
        .map_err(|e| HandlerError::bad_request(format!("invalid public_key hex: {e}")))?;

    let anchor = Kappa::from_key(&req.algorithm, &public_key_bytes)
        .map_err(|error| HandlerError::bad_request(error.to_string()))?;

    let spec = serde_json::json!({
        "anchor": anchor.to_string(),
        "algorithm": req.algorithm,
        "public_key": req.public_key,
        "endpoint": req.endpoint,
    });
    let spec_bytes = serde_json::to_vec(&spec)
        .map_err(|error| HandlerError::internal(format!("anchor spec encoding: {error}")))?;
    let spec_content =
        VerifiedContent::compute_owned(Axis::Sha256, spec_bytes).map_err(StoreError::from)?;

    // The spec record and the tag naming it publish in one epoch of the
    // anchor's namespace.
    let target = kappa_handler::anchor_write_target(cx, &anchor).await?;
    let committed = execute(cx, target, &raw, move |execution| {
        execution.blob_put(&spec_content)?;
        execution.tag_put(
            "anchor/spec",
            &TagUpdate::Set {
                kappa: spec_content.kappa().clone(),
            },
        )?;
        Ok(Outcome::Publish(()))
    })
    .await?;

    let mut response = kappa_handler::json_response(
        StatusCode::CREATED,
        &serde_json::json!({"anchor": anchor.to_string()}),
    )?;
    committed.annotate(&mut response);
    Ok(response)
}
