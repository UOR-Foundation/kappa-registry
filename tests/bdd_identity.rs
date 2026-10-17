use super::{BddWorld, StatusCode};
use cucumber::{then, when};
use kappa_crypto::{Signer, ed25519::Ed25519Signer, signed_types};
use kappa_store::{
    Axis, IdentityAssertion, Kappa, Revocation, RevocationReason, SignedPayload, Watermark,
};

async fn post(
    w: &BddWorld,
    route: &str,
    body: &serde_json::Value,
    expected: StatusCode,
) -> serde_json::Value {
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("HTTP client")
        .post(format!(
            "{}{}",
            w.app.as_ref().expect("application").base_url,
            route
        ))
        .json(body)
        .send()
        .await
        .expect("identity HTTP request");
    let status = response.status();
    let bytes = response.bytes().await.expect("identity response");
    assert_eq!(status, expected, "{}", String::from_utf8_lossy(&bytes));
    serde_json::from_slice(&bytes).expect("identity JSON response")
}

#[when("I exercise signed identity admission through HTTP")]
async fn signed_admission(w: &mut BddWorld) -> Result<(), Box<dyn std::error::Error>> {
    let signer = Ed25519Signer::from_bytes(&[37; 32])?;
    let anchor = Kappa::from_key(signer.algorithm(), signer.public_key())?;
    let key = hex::encode(signer.public_key());
    post(
        w,
        "/identity/anchor",
        &serde_json::json!({
            "algorithm": signer.algorithm(), "public_key": key,
        }),
        StatusCode::CREATED,
    )
    .await;
    let assertion = signed_types::sign_assertion(
        IdentityAssertion {
            asserter: anchor.clone(),
            subject: "bdd-signed-subject".into(),
            facet: "name".into(),
            value: b"Alice".to_vec(),
            basis: "self-asserted".into(),
            valid_from_ms: 100,
            valid_until_ms: None,
            cose_signature: SignedPayload::empty(),
        },
        &signer,
    )?;
    let assertion_body = serde_json::json!({
        "algorithm": signer.algorithm(), "public_key": key, "subject": assertion.subject,
        "facet": assertion.facet, "value": hex::encode(&assertion.value), "basis": assertion.basis,
        "valid_from_ms": assertion.valid_from_ms, "signature": hex::encode(assertion.cose_signature.as_bytes()),
    });
    let mut tampered = assertion_body.clone();
    tampered["subject"] = "bdd-forged-subject".into();
    post(w, "/identity/assert", &tampered, StatusCode::BAD_REQUEST).await;
    tampered = assertion_body.clone();
    tampered["public_key"] = hex::encode(Ed25519Signer::from_bytes(&[38; 32])?.public_key()).into();
    post(w, "/identity/assert", &tampered, StatusCode::BAD_REQUEST).await;
    let accepted = post(w, "/identity/assert", &assertion_body, StatusCode::CREATED).await;
    let expected = Kappa::compute(Axis::Sha256, &kappa_store::canonical_bytes(&assertion))?;
    assert_eq!(accepted["kappa"], expected.to_string());
    super::get(w, "/identity/resolve/bdd-signed-subject").await;
    let resolved: serde_json::Value = serde_json::from_slice(&w.body).expect("resolution");
    assert_eq!(w.status, Some(StatusCode::OK));
    assert_eq!(
        resolved["valid"]
            .as_array()
            .expect("valid assertions")
            .len(),
        1
    );

    let revocation = signed_types::sign_revocation(
        Revocation {
            asserter: anchor.clone(),
            assertion_kappa: expected,
            reason: RevocationReason::Superseded,
            revoked_at_ms: 200,
            cose_signature: SignedPayload::empty(),
        },
        &signer,
    )?;
    let revocation_body = serde_json::json!({
        "asserter": anchor.to_string(), "assertion_kappa": revocation.assertion_kappa.to_string(),
        "reason": "superseded", "revoked_at_ms": 200, "public_key": key,
        "signature": hex::encode(revocation.cose_signature.as_bytes()),
    });
    let mut tampered = revocation_body.clone();
    tampered["revoked_at_ms"] = 201.into();
    post(w, "/identity/revoke", &tampered, StatusCode::BAD_REQUEST).await;
    tampered = revocation_body.clone();
    tampered["public_key"] = hex::encode(Ed25519Signer::from_bytes(&[38; 32])?.public_key()).into();
    post(w, "/identity/revoke", &tampered, StatusCode::BAD_REQUEST).await;
    tampered = revocation_body.clone();
    tampered["signature"] = hex::encode(assertion.cose_signature.as_bytes()).into();
    post(w, "/identity/revoke", &tampered, StatusCode::BAD_REQUEST).await;
    tampered = assertion_body.clone();
    tampered["signature"] = hex::encode(revocation.cose_signature.as_bytes()).into();
    post(w, "/identity/assert", &tampered, StatusCode::BAD_REQUEST).await;
    post(w, "/identity/revoke", &revocation_body, StatusCode::CREATED).await;

    let watermark = signed_types::sign_watermark(
        Watermark {
            asserter: anchor.clone(),
            invalidate_before_ms: 50,
            reason: kappa_store::identity::WatermarkReason::Policy,
            set_at_ms: 300,
            cose_signature: SignedPayload::empty(),
        },
        &signer,
    )?;
    let watermark_body = serde_json::json!({
        "asserter": anchor.to_string(), "invalidate_before_ms": 50, "reason": "policy",
        "set_at_ms": 300, "public_key": key, "signature": hex::encode(watermark.cose_signature.as_bytes()),
    });
    let mut tampered = watermark_body.clone();
    tampered["invalidate_before_ms"] = 500.into();
    post(w, "/identity/watermark", &tampered, StatusCode::BAD_REQUEST).await;
    tampered = watermark_body.clone();
    tampered["public_key"] = hex::encode(Ed25519Signer::from_bytes(&[38; 32])?.public_key()).into();
    post(w, "/identity/watermark", &tampered, StatusCode::BAD_REQUEST).await;
    tampered = watermark_body.clone();
    tampered["signature"] = hex::encode(revocation.cose_signature.as_bytes()).into();
    post(w, "/identity/watermark", &tampered, StatusCode::BAD_REQUEST).await;
    post(
        w,
        "/identity/watermark",
        &watermark_body,
        StatusCode::CREATED,
    )
    .await;
    for (subject, valid_from_ms) in [
        ("bdd-watermarked-subject", 25),
        ("bdd-retained-subject", 75),
    ] {
        let mut record = assertion.clone();
        record.subject = subject.into();
        record.valid_from_ms = valid_from_ms;
        let record = signed_types::sign_assertion(record, &signer)?;
        let body = serde_json::json!({
            "algorithm": signer.algorithm(), "public_key": key, "subject": record.subject,
            "facet": record.facet, "value": hex::encode(&record.value), "basis": record.basis,
            "valid_from_ms": record.valid_from_ms, "signature": hex::encode(record.cose_signature.as_bytes()),
        });
        post(w, "/identity/assert", &body, StatusCode::CREATED).await;
    }
    independent_resolution(w).await;
    Ok(())
}

async fn independent_resolution(w: &mut BddWorld) {
    super::get(w, "/identity/resolve/bdd-watermarked-subject").await;
    assert_eq!(w.status, Some(StatusCode::OK));
    let result: serde_json::Value = serde_json::from_slice(&w.body).expect("watermark resolution");
    assert!(result["valid"].as_array().expect("valid list").is_empty());
    assert_eq!(result["watermarked_count"], 1);
    assert_eq!(result["revoked_count"], 0);
    super::get(w, "/identity/resolve/bdd-retained-subject").await;
    assert_eq!(w.status, Some(StatusCode::OK));
    let result: serde_json::Value = serde_json::from_slice(&w.body).expect("retained resolution");
    let valid = result["valid"].as_array().expect("valid list");
    assert_eq!(valid.len(), 1);
    assert_eq!(valid[0]["subject"], "bdd-retained-subject");
    assert_eq!(valid[0]["valid_from_ms"], 75);
    assert_eq!(result["watermarked_count"], 0);
    assert_eq!(result["revoked_count"], 0);
}

#[then("signed identity resolution retains revocation and rejects forged subjects")]
async fn persisted_resolution(w: &mut BddWorld) {
    independent_resolution(w).await;
    super::get(w, "/identity/resolve/bdd-signed-subject").await;
    assert_eq!(w.status, Some(StatusCode::OK));
    let result: serde_json::Value = serde_json::from_slice(&w.body).expect("resolution JSON");
    assert!(result["valid"].as_array().expect("valid list").is_empty());
    assert_eq!(result["revoked_count"], 1);
    assert_eq!(result["watermarked_count"], 0);
    super::get(w, "/identity/resolve/bdd-forged-subject").await;
    assert_eq!(w.status, Some(StatusCode::OK));
    let result: serde_json::Value = serde_json::from_slice(&w.body).expect("resolution JSON");
    assert!(result["valid"].as_array().expect("valid list").is_empty());
    assert_eq!(result["revoked_count"], 0);
}
