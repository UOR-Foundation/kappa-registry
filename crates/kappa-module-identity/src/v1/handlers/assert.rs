use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{HandlerError, Outcome, execute};
use kappa_store::{
    Axis, EdgeInput, EdgeRelation, IdentityAssertion, Kappa, VerifiedContent, canonical_bytes,
};

#[derive(serde::Deserialize)]
struct AssertRequest {
    algorithm: String,
    public_key: String,
    subject: String,
    facet: String,
    value: Option<String>,
    basis: Option<String>,
    valid_from_ms: Option<i64>,
    valid_until_ms: Option<i64>,
    signature: String,
}

pub async fn handler(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (AssertRequest, _) =
        kappa_handler::read_json_with_bytes(body, 64 * 1024).await?;

    let public_key_bytes = hex::decode(&req.public_key)
        .map_err(|e| HandlerError::bad_request(format!("invalid public_key hex: {e}")))?;
    let signature_bytes = hex::decode(&req.signature)
        .map_err(|e| HandlerError::bad_request(format!("invalid signature hex: {e}")))?;
    let value_bytes = match &req.value {
        Some(v) => hex::decode(v).unwrap_or_else(|_| v.as_bytes().to_vec()),
        None => Vec::new(),
    };

    let asserter_anchor = Kappa::from_key(&req.algorithm, &public_key_bytes)
        .map_err(|error| HandlerError::bad_request(error.to_string()))?;

    let assertion = IdentityAssertion {
        asserter: asserter_anchor.clone(),
        subject: req.subject.clone(),
        facet: req.facet,
        value: value_bytes,
        basis: req.basis.as_deref().unwrap_or("self-asserted").to_string(),
        valid_from_ms: req.valid_from_ms.unwrap_or(0),
        valid_until_ms: req.valid_until_ms,
        cose_signature: kappa_store::SignedPayload::from_cose_bytes(signature_bytes),
    };

    kappa_crypto::signed_types::verify_assertion(&assertion, &public_key_bytes)
        .map_err(|e| HandlerError::bad_request(format!("signature verification error: {e}")))?;

    let content = VerifiedContent::compute(Axis::Sha256, &canonical_bytes(&assertion))?;
    let subject_kappa = Kappa::compute(Axis::Sha256, req.subject.as_bytes())?;
    let directory_label = crate::directory::label(&assertion.subject, &assertion.facet);

    // The signed record, its asserter and subject index entries, tag, and
    // edge publish in one epoch of the asserter's namespace. `assertion_put`
    // writes the subject index that cross-namespace subject queries read.
    let target = kappa_handler::anchor_write_target(cx, &asserter_anchor).await?;
    let committed = execute(cx, target, &raw, move |execution| {
        let kappa = content.kappa().clone();
        execution.blob_put(&content)?;
        kappa_store::blob_meta_put_indexed(execution, &kappa, "object-type", "assertion")?;
        execution.assertion_put(&assertion)?;
        execution.tag_put(
            &format!("assertion/{kappa}"),
            &kappa_store::TagUpdate::Set {
                kappa: kappa.clone(),
            },
        )?;
        execution.edge_put(&EdgeInput {
            source: asserter_anchor.clone(),
            target: subject_kappa.clone(),
            relation: EdgeRelation::Builtin(kappa_store::edge::BuiltinRelation::Assertion),
            created_at_ms: execution.now().as_i64(),
            asserter: asserter_anchor.clone(),
            metadata: None,
        })?;
        Ok(Outcome::Publish(kappa))
    })
    .await?;

    // The directory indexes committed assertions, so it publishes after the
    // store commit. A failed publication leaves the assertion committed but
    // unindexed: the request fails so the client retries, which republishes
    // the identical assertion (a no-op) and indexes it; an unavailable
    // directory is recovered from its committed state before it serves
    // proofs again.
    let directory = crate::directory::directory(cx);
    let publisher = directory.clone();
    let request = kappa_transparency::Request {
        label: directory_label,
        value: Some(committed.value.clone()),
    };
    let published = kappa_handler::blocking(move || {
        publisher
            .publish(&[request])
            .map_err(crate::directory::directory_error)
    })
    .await;
    if let Err(error) = published {
        crate::directory::recover_in_background(directory);
        return Err(HandlerError::protocol(
            StatusCode::SERVICE_UNAVAILABLE,
            "DirectoryPublicationFailed",
            format!(
                "assertion {} committed but not indexed in the identity directory ({error}); retry",
                committed.value
            ),
        ));
    }

    let mut response = kappa_handler::json_response(
        StatusCode::CREATED,
        &serde_json::json!({"kappa": committed.value.to_string()}),
    )?;
    committed.annotate(&mut response);
    Ok(response)
}
