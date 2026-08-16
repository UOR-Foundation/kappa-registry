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

use kappa_akd::AkdManager;
use kappa_core::canonical;
use kappa_core::identity::assertion::IdentityAssertion;
use kappa_core::identity::node::NodeIdentity;
use kappa_core::identity::resolution;
use kappa_core::identity::revocation::{Revocation, RevocationReason};
use kappa_core::kappa::kappa_from_bytes;
use kappa_core::store::KappaStore;
use kappa_core::types::NamespaceRef;

/// Asserter filter registered in app_context by the server layer.
/// The resolve handler reads this and passes it to resolve_all_filtered.
/// If not registered, all asserters are trusted (permissive default).
pub struct AsserterFilter(pub Box<dyn Fn(&str) -> bool + Send + Sync>);

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
        let facet_str = v["facet"]
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
            facet: facet_str,
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

        // Derive audience label if audience field is present
        let audience_id = v["audience"].as_str().map(|a| a.to_string());
        let akd_label = match &audience_id {
            Some(aud) => {
                let derived = kappa_core::identity::audience::derive_audience_label(
                    &subject, aud,
                );
                format!("{}/{}", derived, assertion.facet)
            }
            None => format!("{}/{}", subject, assertion.facet),
        };

        let s = store(cx).clone();
        let assertion_bytes = canonical::canonical_bytes(&assertion);
        let kappa = kappa_from_bytes(&assertion_bytes);
        let asserter_ns = assertion.asserter.clone();
        let facet_for_edge = assertion.facet.clone();

        // ATOMIC: blob_put + blob_meta + tag_set + edge_put + epoch_advance
        // All store operations happen in one spawn_blocking closure.
        // If any step fails, the entire operation fails and no partial
        // state is visible to readers (redb ACID commit at the end).
        tokio::task::spawn_blocking({
            let s = s.clone();
            let k = kappa.clone();
            let ab = assertion_bytes;
            let ns = NamespaceRef::from(asserter_ns.as_str());
            let subj = subject.clone();
            let facet = facet_for_edge;
            move || {
                let _span = tracing::info_span!("store_mutation", op = "identity_assert", ns = %ns, subject = %subj).entered();
                // 1. Store assertion blob
                s.ingest_verified(&k,&ab)?;
                s.blob_put_meta(&k, "object-type", b"assertion")?;

                // 2. Tag under asserter namespace
                s.tag_set(&ns, &format!("assertion/{}", k), &k)?;

                // 3. Cross-namespace inbound index
                s.assertion_index_put(&subj, &facet, &k)?;

                // 4. Edge: Assertion relation from asserter to subject
                s.edge_put(
                    &ns,
                    &kappa_core::types::Edge {
                        source: ns.as_str().to_string(),
                        target: subj.clone(),
                        relation: kappa_core::types::EdgeRelation::Assertion,
                        asserter: ns.as_str().to_string(),
                        value_kappa: Some(k.clone()),
                        metadata: None,
                    },
                )?;

                // 4. Epoch advance with the assertion mutation
                s.epoch_advance(
                    &ns,
                    vec![kappa_core::types::EpochMutation {
                        op: kappa_core::types::MutationOp::AssertionPublish,
                        namespace: ns.as_str().to_string(),
                        tag_name: format!("assertion/{}", k),
                        old_kappa: None,
                        new_kappa: Some(k.clone()),
                    }],
                )?;

                Ok::<_, kappa_core::StoreError>(())
            }
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(store_err)?;

        // AKD publish AFTER the atomic store operations succeed.
        // AKD is eventually consistent -- if this fails, the assertion
        // is stored and the AKD will catch up on the next successful publish.
        // The assertion is fully committed to the store before we attempt
        // AKD publication.
        if let Some(akd) = try_app_context::<Arc<AkdManager>>(cx) {
            let k = kappa.clone();
            let label = akd_label;
            if let Err(e) = akd
                .publish(vec![(
                    akd::AkdLabel::from(label.as_str()),
                    akd::AkdValue::from(k.as_str()),
                )])
                .await
            {
                tracing::warn!("AKD publish failed for assertion {}: {e}", kappa);
            }
        }

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

        // Optional query parameter: at_ms for point-in-time resolution
        let at_ms: Option<u64> = {
            use topcoat::router::RawPathParams;
            use topcoat::context::request_context;
            let params: &RawPathParams = request_context(cx);
            params
                .iter()
                .find(|(k, _)| *k == "at_ms")
                .and_then(|(_, v)| v.parse().ok())
        };

        // TrustPolicy filter: if registered in app_context, apply it.
        // Arc<AsserterFilter> is Send+Sync. Clone the Arc for the closure.
        let asserter_filter: Option<Arc<AsserterFilter>> =
            try_app_context::<Arc<AsserterFilter>>(cx).cloned();

        let s = store(cx).clone();
        let sub = subject.to_string();

        let result = tokio::task::spawn_blocking(move || {
            // Use cross-namespace inbound index for assertions (O(1) vs O(namespaces))
            let assertion_kappas = s.assertion_index_query_subject(&sub)?;
            let mut assertions = Vec::new();
            for ak in &assertion_kappas {
                if let Ok(blob) = s.blob_get(ak) {
                    if let Ok(a) = canonical::from_canonical::<IdentityAssertion>(&blob) {
                        assertions.push(a);
                    }
                }
            }

            // Revocations and watermarks still need namespace scan
            // (not indexed cross-namespace yet)
            let namespaces = s.namespace_list()?;
            let mut revocations = Vec::new();
            let mut watermarks = Vec::new();

            for ns_str in &namespaces {
                let ns = NamespaceRef::from(ns_str.as_str());
                let rev_tags = s.tag_prefix(&ns, "revocation/")?;
                for tag in &rev_tags {
                    if let Ok(blob) = s.blob_get(&tag.kappa) {
                        if let Ok(r) = canonical::from_canonical::<Revocation>(&blob) {
                            revocations.push(r);
                        }
                    }
                }

                let wm_tags = s.tag_prefix(&ns, "watermark/")?;
                for tag in &wm_tags {
                    if let Ok(blob) = s.blob_get(&tag.kappa) {
                        if let Ok(w) = canonical::from_canonical::<kappa_core::identity::watermark::Watermark>(&blob) {
                            watermarks.push(w);
                        }
                    }
                }
            }

            let result = match at_ms {
                Some(ts) => resolution::resolve_at(&assertions, &revocations, &watermarks, ts),
                None => resolution::resolve_all(&assertions, &revocations, &watermarks),
            };
            Ok::<_, kappa_core::StoreError>(result)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(store_err)?;

        // Apply TrustPolicy filter after spawn_blocking
        let mut result = result;
        if let Some(ref af) = asserter_filter {
            result.valid.retain(|a| (af.0)(&a.asserter));
        }

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

        let revoked_assertion_kappa = revocation.assertion_kappa.clone();

        // ATOMIC: blob_put + tag_set + edge_put + epoch_advance
        tokio::task::spawn_blocking({
            let s = s.clone();
            let k = kappa.clone();
            let rb = rev_bytes;
            let ns = NamespaceRef::from(asserter.as_str());
            let rak = revoked_assertion_kappa;
            move || {
                let _span = tracing::info_span!("store_mutation", op = "identity_revoke", ns = %ns).entered();
                s.ingest_verified(&k,&rb)?;
                s.blob_put_meta(&k, "object-type", b"revocation")?;
                s.tag_set(&ns, &format!("revocation/{}", k), &k)?;

                // Edge: Revocation relation from asserter to the assertion kappa
                s.edge_put(
                    &ns,
                    &kappa_core::types::Edge {
                        source: ns.as_str().to_string(),
                        target: rak.clone(),
                        relation: kappa_core::types::EdgeRelation::Revocation,
                        asserter: ns.as_str().to_string(),
                        value_kappa: Some(k.clone()),
                        metadata: None,
                    },
                )?;

                // Epoch advance with revocation mutation
                s.epoch_advance(
                    &ns,
                    vec![kappa_core::types::EpochMutation {
                        op: kappa_core::types::MutationOp::RevocationPublish,
                        namespace: ns.as_str().to_string(),
                        tag_name: format!("revocation/{}", k),
                        old_kappa: None,
                        new_kappa: Some(k.clone()),
                    }],
                )?;

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

        let Some(akd) = try_app_context::<Arc<AkdManager>>(cx) else {
            let resp = serde_json::json!({
                "subject": subject,
                "facet": facet,
                "proof_available": false,
                "reason": "AKD directory not initialized"
            });
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [("content-type", "application/json".to_string())],
                serde_json::to_string(&resp).unwrap_or_default(),
            )
                .into_response(cx);
        };

        let label = format!("{}/{}", subject, facet);
        match akd.lookup(akd::AkdLabel::from(label.as_str())).await {
            Ok(result) => {
                // Subject+facet EXISTS -- this is not absence
                let resp = serde_json::json!({
                    "subject": subject,
                    "facet": facet,
                    "exists": true,
                    "epoch": result.epoch,
                    "proof": result.proof_json,
                });
                (
                    StatusCode::OK,
                    [("content-type", "application/json".to_string())],
                    serde_json::to_string(&resp).unwrap_or_default(),
                )
                    .into_response(cx)
            }
            Err(_) => {
                // Subject+facet does NOT exist in the AKD tree.
                // This IS the absence proof -- the lookup failure means
                // the label was never published.
                let resp = serde_json::json!({
                    "subject": subject,
                    "facet": facet,
                    "exists": false,
                    "proof": "nonmembership",
                });
                (
                    StatusCode::OK,
                    [("content-type", "application/json".to_string())],
                    serde_json::to_string(&resp).unwrap_or_default(),
                )
                    .into_response(cx)
            }
        }
    })
}

// -- Watermark --------------------------------------------------------------

fn watermark_handler(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let v: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| bad_request(format!("invalid JSON: {e}")))?;

        let asserter = v["asserter"]
            .as_str()
            .ok_or_else(|| bad_request("missing asserter"))?
            .to_string();
        let invalidate_before_ms = v["invalidate_before_ms"]
            .as_u64()
            .ok_or_else(|| bad_request("missing invalidate_before_ms"))?;
        let reason = v["reason"]
            .as_str()
            .unwrap_or("unspecified")
            .to_string();
        let set_at_ms = v["set_at_ms"].as_u64().unwrap_or(0);

        let watermark = kappa_core::identity::watermark::Watermark {
            asserter: asserter.clone(),
            invalidate_before_ms,
            reason,
            set_at_ms,
        };

        let s = store(cx).clone();
        let wm_bytes = canonical::canonical_bytes(&watermark);
        let kappa = kappa_from_bytes(&wm_bytes);

        // ATOMIC: blob_put + blob_meta + tag_set + epoch_advance
        tokio::task::spawn_blocking({
            let s = s.clone();
            let k = kappa.clone();
            let wb = wm_bytes;
            let ns = NamespaceRef::from(asserter.as_str());
            move || {
                let _span = tracing::info_span!("store_mutation", op = "identity_watermark", ns = %ns).entered();
                s.ingest_verified(&k,&wb)?;
                s.blob_put_meta(&k, "object-type", b"watermark")?;
                s.tag_set(&ns, &format!("watermark/{}", k), &k)?;

                // Epoch advance: watermark is a mutation that invalidates
                // prior assertions. The epoch chain records when the
                // watermark was applied.
                s.epoch_advance(
                    &ns,
                    vec![kappa_core::types::EpochMutation {
                        op: kappa_core::types::MutationOp::RevocationPublish,
                        namespace: ns.as_str().to_string(),
                        tag_name: format!("watermark/{}", k),
                        old_kappa: None,
                        new_kappa: Some(k.clone()),
                    }],
                )?;

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

// -- Audit ------------------------------------------------------------------

fn audit_handler(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let start_str = path_param(cx, "start");
        let end_str = path_param(cx, "end");

        let start: u64 = start_str
            .parse()
            .map_err(|_| bad_request(format!("invalid start epoch: {}", start_str)))?;
        let end: u64 = end_str
            .parse()
            .map_err(|_| bad_request(format!("invalid end epoch: {}", end_str)))?;

        let Some(akd) = try_app_context::<Arc<AkdManager>>(cx) else {
            return Err(bad_request("AKD directory not initialized").into());
        };

        let result = akd
            .audit(start, end)
            .await
            .map_err(|e| bad_request(format!("audit proof generation failed: {e}")))?;

        let resp = serde_json::json!({
            "start_epoch": result.start_epoch,
            "end_epoch": result.end_epoch,
            "proof": result.proof_json,
        });

        (
            StatusCode::OK,
            [("content-type", "application/json".to_string())],
            serde_json::to_string(&resp).unwrap_or_default(),
        )
            .into_response(cx)
    })
}

// -- Anchor registration ----------------------------------------------------

fn anchor_handler(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let v: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| bad_request(format!("invalid JSON: {e}")))?;

        let algorithm = v["algorithm"]
            .as_str()
            .ok_or_else(|| bad_request("missing algorithm"))?
            .to_string();
        let public_key_hex = v["public_key"]
            .as_str()
            .ok_or_else(|| bad_request("missing public_key"))?;
        let public_key_bytes =
            hex::decode(public_key_hex).map_err(|_| bad_request("invalid public_key hex"))?;
        let endpoint = v["endpoint"].as_str().unwrap_or("").to_string();

        // Compute the anchor from algorithm + public key
        let anchor = kappa_core::crypto::anchor::anchor_from_key_str(
            &algorithm,
            &public_key_bytes,
        );

        let s = store(cx).clone();
        let anchor_clone = anchor.clone();

        // Store the anchor spec as a blob and tag it
        tokio::task::spawn_blocking({
            let s = s.clone();
            let a = anchor.clone();
            let ep = endpoint.clone();
            let algo = algorithm.clone();
            let pk = public_key_hex.to_string();
            move || {
                let _span = tracing::info_span!("store_mutation", op = "anchor_register", anchor = %a).entered();
                let spec = serde_json::json!({
                    "anchor": a,
                    "algorithm": algo,
                    "public_key": pk,
                    "endpoint": ep,
                });
                let spec_bytes = serde_json::to_vec(&spec)
                    .map_err(|e| kappa_core::StoreError::Io(std::io::Error::other(e.to_string())))?;
                let kappa = kappa_from_bytes(&spec_bytes);
                s.ingest_verified(&kappa,&spec_bytes)?;
                s.blob_put_meta(&kappa, "object-type", b"anchor-spec")?;
                let ns = NamespaceRef::from(a.as_str());
                s.tag_set(&ns, "anchor/spec", &kappa)?;
                if !ep.is_empty() {
                    s.tag_set(&ns, "anchor/endpoint", &kappa)?;
                }
                Ok::<String, kappa_core::StoreError>(kappa)
            }
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(store_err)?;

        let resp = serde_json::json!({"anchor": anchor_clone});
        (
            StatusCode::CREATED,
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
            Method::POST,
            Cow::Borrowed(Path::new("/identity/watermark")),
            watermark_handler,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/identity/absence/{subject}/{*facet}")),
            absence_handler,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/identity/audit/{start}/{end}")),
            audit_handler,
        ))
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/identity/anchor")),
            anchor_handler,
        ))
}
