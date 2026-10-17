use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{HandlerError, Outcome, execute};
use kappa_store::{
    EdgeInput, EdgeRelation, Kappa, Revocation, RevocationReason, TagUpdate, VerifiedContent,
    canonical_bytes,
};

#[derive(serde::Deserialize)]
struct RevokeRequest {
    asserter: String,
    assertion_kappa: String,
    reason: Option<String>,
    signature: String,
    public_key: String,
    revoked_at_ms: i64,
}

pub async fn handler(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (RevokeRequest, _) =
        kappa_handler::read_json_with_bytes(body, 64 * 1024).await?;

    let asserter_kappa = Kappa::parse(&req.asserter)?;
    let assertion_kappa = Kappa::parse(&req.assertion_kappa)?;

    let reason = match req.reason.as_deref() {
        Some("key-compromise") => RevocationReason::KeyCompromise,
        Some("erroneous") => RevocationReason::Erroneous,
        Some("privilege-withdrawn") => RevocationReason::PrivilegeWithdrawn,
        Some("cessation-of-operation") => RevocationReason::CessationOfOperation,
        _ => RevocationReason::Superseded,
    };
    let signature = hex::decode(&req.signature)
        .map_err(|e| HandlerError::bad_request(format!("invalid signature hex: {e}")))?;

    let revocation = Revocation {
        asserter: asserter_kappa.clone(),
        assertion_kappa: assertion_kappa.clone(),
        reason,
        revoked_at_ms: req.revoked_at_ms,
        cose_signature: kappa_store::SignedPayload::from_cose_bytes(signature),
    };
    let public_key = hex::decode(&req.public_key)
        .map_err(|e| HandlerError::bad_request(format!("invalid public_key hex: {e}")))?;
    kappa_crypto::signed_types::verify_revocation(&revocation, &public_key)
        .map_err(|e| HandlerError::bad_request(format!("revocation signature: {e}")))?;

    let content =
        VerifiedContent::compute(kappa_store::Axis::Sha256, &canonical_bytes(&revocation))?;

    // The label the revoked assertion holds in the directory, resolved
    // before the revocation commits so a revocation of an unknown
    // assertion is refused rather than committed unindexed.
    let store = kappa_handler::store(cx);
    let revoked = assertion_kappa.clone();
    let revoked_label = kappa_handler::blocking(move || {
        store
            .assertion_get(&revoked)
            .map(|assertion| crate::directory::label(&assertion.subject, &assertion.facet))
    })
    .await?;

    // The signed record, its index entry, tag, and edge publish in one epoch
    // of the asserter's namespace.
    let target = kappa_handler::anchor_write_target(cx, &asserter_kappa).await?;
    let revoked_assertion = assertion_kappa.clone();
    let committed = execute(cx, target, &raw, move |execution| {
        let kappa = content.kappa().clone();
        execution.blob_put(&content)?;
        kappa_store::blob_meta_put_indexed(execution, &kappa, "object-type", "revocation")?;
        execution.revocation_put(&revocation)?;
        execution.tag_put(
            &format!("revocation/{kappa}"),
            &TagUpdate::Set {
                kappa: kappa.clone(),
            },
        )?;
        execution.edge_put(&EdgeInput {
            source: asserter_kappa.clone(),
            target: assertion_kappa.clone(),
            relation: EdgeRelation::Builtin(kappa_store::edge::BuiltinRelation::Revocation),
            created_at_ms: execution.now().as_i64(),
            asserter: asserter_kappa.clone(),
            metadata: None,
        })?;
        Ok(Outcome::Publish(kappa))
    })
    .await?;

    // The directory retracts the label only while it names the revoked
    // assertion; a later assertion that replaced it stays active. As for
    // assertions, a failed publication fails the request for a retry and
    // recovers the directory from its committed state.
    let directory = crate::directory::directory(cx);
    let retractor = directory.clone();
    let retracted = kappa_handler::blocking(move || {
        retractor
            .retract(&revoked_label, &revoked_assertion)
            .map_err(crate::directory::directory_error)
    })
    .await;
    if let Err(error) = retracted {
        crate::directory::recover_in_background(directory);
        return Err(HandlerError::protocol(
            StatusCode::SERVICE_UNAVAILABLE,
            "DirectoryPublicationFailed",
            format!(
                "revocation {} committed but not indexed in the identity directory ({error}); retry",
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
