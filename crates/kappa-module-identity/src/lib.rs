//! Identity HTTP protocol module for kappa-registry.
//!
//! Endpoints:
//!   GET  /identity/whoami        - node identity and trust position
//!   POST /identity/assert        - publish an identity assertion
//!   GET  /identity/resolve/{sub} - resolve assertions about a subject
//!   POST /identity/revoke        - revoke an assertion
//!   GET  /identity/absence/{sub}/{facet} - absence proof (requires AKD)

use std::borrow::Cow;
use std::sync::Arc;

use topcoat::context::{app_context, request_context, try_app_context, Cx};
use topcoat::router::error::{bad_request, not_found};
use topcoat::router::{
    to_bytes, Body, IntoResponse, Method, Path, RouteFn, RouteFuture, RouterBuilder, StatusCode,
};

use kappa_core::canonical;
use kappa_core::identity::assertion::IdentityAssertion;
use kappa_core::identity::node::NodeIdentity;
use kappa_core::identity::resolution;
use kappa_core::identity::revocation::{Revocation, RevocationReason};
use kappa_core::kappa::kappa_from_bytes;
use kappa_core::store::KappaStore;

fn store_err(e: kappa_core::StoreError) -> topcoat::Error {
    use kappa_core::StoreError;
    match &e {
        StoreError::NotFound(_) => not_found().into(),
        _ => bad_request(e.to_string()).into(),
    }
}

fn path_param<'a>(cx: &'a Cx, key: &str) -> &'a str {
    use topcoat::router::RawPathParams;
    let params: &RawPathParams = request_context(cx);
    params
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
        .unwrap_or("")
}

fn store(cx: &Cx) -> &Arc<dyn KappaStore> {
    app_context::<Arc<dyn KappaStore>>(cx)
}

async fn read_body(body: Body) -> topcoat::Result<topcoat::router::Bytes> {
    to_bytes(body, usize::MAX)
        .await
        .map_err(|e| bad_request(format!("failed to read body: {e}")).into())
}

// -- Whoami -----------------------------------------------------------------

fn whoami_handler(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        match try_app_context::<Arc<NodeIdentity>>(cx) {
            Some(identity) => {
                let id = identity.clone();
                let info = tokio::task::spawn_blocking(move || {
                    let anchor = id.anchor().as_str().to_string();
                    let algorithm = id.algorithm().to_string();
                    let position = id.position();
                    serde_json::json!({
                        "anchor": anchor,
                        "algorithm": algorithm,
                        "trust_position": position.as_str(),
                    })
                })
                .await
                .map_err(|e| bad_request(e.to_string()))?;
                (
                    StatusCode::OK,
                    [("content-type", "application/json".to_string())],
                    serde_json::to_string(&info).unwrap_or_else(|_| "{}".to_owned()),
                )
                    .into_response(cx)
            }
            None => {
                let body = serde_json::json!({
                    "error": "node identity not bootstrapped"
                });
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [("content-type", "application/json".to_string())],
                    serde_json::to_string(&body).unwrap_or_default(),
                )
                    .into_response(cx)
            }
        }
    })
}

// -- Assert -----------------------------------------------------------------

fn assert_handler(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let v: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| bad_request(format!("invalid JSON: {e}")))?;

        let algorithm = v["algorithm"]
            .as_str()
            .ok_or_else(|| bad_request("missing algorithm"))?;
        let public_key_hex = v["public_key"]
            .as_str()
            .ok_or_else(|| bad_request("missing public_key"))?;
        let public_key_bytes =
            hex::decode(public_key_hex).map_err(|_| bad_request("invalid public_key hex"))?;
        let subject = v["subject"]
            .as_str()
            .ok_or_else(|| bad_request("missing subject"))?
            .to_string();
        let facet = v["facet"]
            .as_str()
            .ok_or_else(|| bad_request("missing facet"))?
            .to_string();
        let value_b64 = v["value"].as_str().unwrap_or("");
        let value_bytes = hex::decode(value_b64).unwrap_or_else(|_| value_b64.as_bytes().to_vec());
        let basis = v["basis"].as_str().unwrap_or("self-asserted").to_string();
        let valid_from_ms = v["valid_from_ms"].as_u64().unwrap_or(0);
        let valid_until_ms = v["valid_until_ms"].as_u64();
        let signature_hex = v["signature"]
            .as_str()
            .ok_or_else(|| bad_request("missing signature"))?;
        let signature =
            hex::decode(signature_hex).map_err(|_| bad_request("invalid signature hex"))?;

        let mut assertion = IdentityAssertion {
            asserter: String::new(),
            subject: subject.clone(),
            facet,
            value: value_bytes,
            basis,
            valid_from_ms,
            valid_until_ms,
            signature,
        };

        let asserter_anchor = kappa_core::crypto::anchor::asserter_from_signature(
            algorithm,
            &public_key_bytes,
            &assertion.signable_bytes(),
            &assertion.signature,
        )
        .map_err(|e| bad_request(format!("signature verification failed: {}", e)))?;

        assertion.asserter = asserter_anchor.as_str().to_string();

        let s = store(cx).clone();
        let assertion_bytes = canonical::canonical_bytes(&assertion);
        let kappa = kappa_from_bytes(&assertion_bytes);
        let asserter_ns = assertion.asserter.clone();

        tokio::task::spawn_blocking({
            let s = s.clone();
            let k = kappa.clone();
            let ab = assertion_bytes;
            let ns = asserter_ns;
            move || {
                s.blob_put(&k, &ab)?;
                s.blob_put_meta(&k, "object-type", b"assertion")?;
                s.tag_set(&ns, &format!("assertion/{}", k), &k)?;
                Ok::<_, kappa_core::StoreError>(())
            }
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(store_err)?;

        let resp = serde_json::json!({"kappa": kappa});
        (
            StatusCode::CREATED,
            [("content-type", "application/json".to_string())],
            serde_json::to_string(&resp).unwrap_or_default(),
        )
            .into_response(cx)
    })
}

// -- Resolve ----------------------------------------------------------------

fn resolve_handler(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let subject = path_param(cx, "subject");
        let s = store(cx).clone();
        let sub = subject.to_string();

        let result = tokio::task::spawn_blocking(move || {
            let namespaces = s.namespace_list()?;
            let mut assertions = Vec::new();
            let mut revocations = Vec::new();

            for ns in &namespaces {
                let tags = s.tag_prefix(ns, "assertion/")?;
                for tag in &tags {
                    if let Ok(blob) = s.blob_get(&tag.kappa) {
                        if let Ok(a) = canonical::from_canonical::<IdentityAssertion>(&blob) {
                            if a.subject == sub {
                                assertions.push(a);
                            }
                        }
                    }
                }

                let rev_tags = s.tag_prefix(ns, "revocation/")?;
                for tag in &rev_tags {
                    if let Ok(blob) = s.blob_get(&tag.kappa) {
                        if let Ok(r) = canonical::from_canonical::<Revocation>(&blob) {
                            revocations.push(r);
                        }
                    }
                }
            }

            let result = resolution::resolve_all(&assertions, &revocations, &[]);
            Ok::<_, kappa_core::StoreError>(result)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(store_err)?;

        let valid: Vec<serde_json::Value> = result
            .valid
            .iter()
            .map(|a| {
                serde_json::json!({
                    "asserter": a.asserter,
                    "subject": a.subject,
                    "facet": a.facet,
                    "basis": a.basis,
                    "valid_from_ms": a.valid_from_ms,
                })
            })
            .collect();

        let resp = serde_json::json!({
            "subject": subject,
            "valid": valid,
            "revoked_count": result.revoked.len(),
            "watermarked_count": result.watermarked.len(),
        });

        (
            StatusCode::OK,
            [("content-type", "application/json".to_string())],
            serde_json::to_string(&resp).unwrap_or_default(),
        )
            .into_response(cx)
    })
}

// -- Revoke -----------------------------------------------------------------

fn revoke_handler(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let v: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| bad_request(format!("invalid JSON: {e}")))?;

        let asserter = v["asserter"]
            .as_str()
            .ok_or_else(|| bad_request("missing asserter"))?
            .to_string();
        let assertion_kappa = v["assertion_kappa"]
            .as_str()
            .ok_or_else(|| bad_request("missing assertion_kappa"))?
            .to_string();
        let reason_str = v["reason"].as_str().unwrap_or("superseded");
        let reason = match reason_str {
            "key-compromise" => RevocationReason::KeyCompromise,
            "erroneous" => RevocationReason::Erroneous,
            "privilege-withdrawn" => RevocationReason::PrivilegeWithdrawn,
            "cessation-of-operation" => RevocationReason::CessationOfOperation,
            _ => RevocationReason::Superseded,
        };
        let revoked_at_ms = v["revoked_at_ms"].as_u64().unwrap_or(0);
        let signature_hex = v["signature"].as_str().unwrap_or("");
        let signature = hex::decode(signature_hex).unwrap_or_default();

        let revocation = Revocation {
            asserter: asserter.clone(),
            assertion_kappa,
            reason,
            revoked_at_ms,
            signature,
        };

        let s = store(cx).clone();
        let rev_bytes = canonical::canonical_bytes(&revocation);
        let kappa = kappa_from_bytes(&rev_bytes);

        tokio::task::spawn_blocking({
            let s = s.clone();
            let k = kappa.clone();
            let rb = rev_bytes;
            let ns = asserter;
            move || {
                s.blob_put(&k, &rb)?;
                s.tag_set(&ns, &format!("revocation/{}", k), &k)?;
                Ok::<_, kappa_core::StoreError>(())
            }
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(store_err)?;

        let resp = serde_json::json!({"kappa": kappa});
        (
            StatusCode::CREATED,
            [("content-type", "application/json".to_string())],
            serde_json::to_string(&resp).unwrap_or_default(),
        )
            .into_response(cx)
    })
}

// -- Absence ----------------------------------------------------------------

fn absence_handler(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let subject = path_param(cx, "subject");
        let facet = path_param(cx, "facet");

        let resp = serde_json::json!({
            "subject": subject,
            "facet": facet,
            "proof_available": false,
            "reason": "AKD integration required for cryptographic absence proofs"
        });

        (
            StatusCode::OK,
            [("content-type", "application/json".to_string())],
            serde_json::to_string(&resp).unwrap_or_default(),
        )
            .into_response(cx)
    })
}

/// Register all identity HTTP routes on the router builder.
pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/identity/whoami")),
            whoami_handler,
        ))
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/identity/assert")),
            assert_handler,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/identity/resolve/{subject}")),
            resolve_handler,
        ))
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/identity/revoke")),
            revoke_handler,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/identity/absence/{subject}/{facet}")),
            absence_handler,
        ))
}
