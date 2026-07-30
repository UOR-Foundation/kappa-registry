//! OCI manifest handlers: PUT, GET, HEAD, DELETE, and tag list.
//!
//! Manifest PUT: digest ref -> verify + blob_put(digest). Tag ref ->
//! compute sha256 + blob_put + tag_set. Content-type and object-type
//! via blob_put_meta. No _ct/ tags. No _meta/ tags.

use std::sync::Arc;

use topcoat::context::{try_app_context, Cx};
use topcoat::router::error::bad_request;
use topcoat::router::{headers, Body, IntoResponse, Response, RouteFuture, StatusCode};

use kappa_core::kappa::{kappa_from_bytes, verify_kappa, KappaLabel};
use kappa_core::types::{Edge, EdgeRelation};

use crate::blob::DiskPressure;
use crate::{path_param, query_param, query_params_multi, read_body, store};

pub fn put_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let ns = path_param(cx, "ns");
        let reference = path_param(cx, "reference");
        let ct = headers(cx)
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/vnd.oci.image.manifest.v1+json");
        manifest_put(cx, ns, reference, ct, &bytes).await
    })
}

pub fn get_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let reference = path_param(cx, "reference");
        manifest_get(cx, ns, reference).await
    })
}

pub fn head_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let reference = path_param(cx, "reference");
        manifest_head(cx, ns, reference).await
    })
}

pub fn delete_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let reference = path_param(cx, "reference");
        manifest_delete(cx, ns, reference).await
    })
}

pub fn tag_list_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        tag_list(cx, ns).await
    })
}

/// Determine if a reference string is a valid digest.
/// Uses KappaLabel::parse for full validation: algorithm name, hex charset,
/// hex length, lowercase. Rejects timestamps, malformed digests, uppercase hex.
fn is_digest(reference: &str) -> bool {
    KappaLabel::parse(reference).is_ok()
}

/// Detect references that look like they were intended to be digests
/// but fail KappaLabel::parse validation. A reference with a known
/// algorithm prefix followed by a colon is a malformed digest, not a
/// tag name. Without this, "sha256:UPPERCASE" or "sha256:tooshort"
/// would silently become tag names instead of being rejected.
fn looks_like_bad_digest(reference: &str) -> bool {
    if let Some((algo, _)) = reference.split_once(':') {
        matches!(
            algo,
            "sha1" | "sha256" | "blake3" | "sha3-256" | "keccak256" | "sha512"
        )
    } else {
        false
    }
}

// -- PUT ----------------------------------------------------------------------

async fn manifest_put(
    cx: &Cx,
    ns: &str,
    reference: &str,
    content_type: &str,
    body: &[u8],
) -> topcoat::Result<Response> {
    let s = store(cx).clone();

    // Disk pressure check -- manifest PUT stores a blob
    if let Some(pressure) = try_app_context::<Arc<DiskPressure>>(cx) {
        if pressure.0.load(std::sync::atomic::Ordering::Relaxed) {
            return crate::oci_error(
                StatusCode::from_u16(507).unwrap(),
                "INSUFFICIENT_STORAGE",
                "disk pressure: insufficient space for write",
            );
        }
    }

    // Filter evaluation BEFORE storing
    if let Some(rejection) = crate::evaluate_filters(&s, ns, body).await? {
        return Ok(rejection);
    }

    // Schema validation BEFORE storing
    if let Some(rejection) = crate::validate_schemas(&s, ns, body).await? {
        return Ok(rejection);
    }

    // Determine kappa: digest ref -> verify, tag ref -> compute sha256
    let (kappa, is_tag) = if is_digest(reference) {
        // Digest reference: verify under client's axis
        let d = reference.to_string();
        let c = body.to_vec();
        let valid = tokio::task::spawn_blocking({
            let d = d.clone();
            move || verify_kappa(&d, &c)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(|e| bad_request(e.to_string()))?;

        if !valid {
            return crate::oci_error(
                StatusCode::BAD_REQUEST,
                "DIGEST_INVALID",
                &format!("computed digest does not match {}", reference),
            );
        }
        (reference.to_string(), false)
    } else {
        // Reject references that look like digests but fail validation.
        // A reference with a known algorithm prefix and colon is a malformed
        // digest, not a tag name. Without this check, "sha256:INVALID" would
        // be stored as a tag named "sha256:INVALID" instead of rejected.
        if looks_like_bad_digest(reference) {
            return crate::oci_error(
                StatusCode::BAD_REQUEST,
                "DIGEST_INVALID",
                &format!("invalid digest format: {}", reference),
            );
        }
        // Tag reference: compute sha256 (default axis)
        (kappa_from_bytes(body), true)
    };

    // Store blob at the computed/verified address
    let k = kappa.clone();
    let content = body.to_vec();
    tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.blob_put(&k, &content)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    // Store content-type metadata on the blob
    {
        let ct_bytes = content_type.as_bytes().to_vec();
        let k = kappa.clone();
        tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.blob_put_meta(&k, "content-type", &ct_bytes)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;
    }

    // Store object-type metadata on the blob (global + namespace-indexed)
    {
        let k = kappa.clone();
        let n = ns.to_string();
        tokio::task::spawn_blocking({
            let s = s.clone();
            move || {
                s.blob_put_meta(&k, "object-type", b"manifest")?;
                s.meta_set(&n, &k, "object-type", "manifest")
            }
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;
    }

    // Bind tag if reference is a tag name
    if is_tag {
        let n = ns.to_string();
        let r = reference.to_string();
        let k = kappa.clone();
        tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.tag_set(&n, &r, &k)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;
    }

    // Multi-tag bind via ?tag= query params (OCI tag parameter extension)
    let extra_tags = query_params_multi(cx, "tag");
    for extra_tag in &extra_tags {
        let n = ns.to_string();
        let k = kappa.clone();
        let t = extra_tag.clone();
        tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.tag_set(&n, &t, &k)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;
    }

    // Subject/referrer edge
    let subject_digest = parse_oci_subject(body);
    if let Some(ref subj) = subject_digest {
        let asserter = crate::registry_anchor(cx);
        let edge = Edge {
            source: kappa.clone(),
            target: subj.clone(),
            relation: EdgeRelation::RefersTo,
            asserter,
            value_kappa: None,
            metadata: None,
        };
        let n = ns.to_string();
        let _ = tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.edge_put(&n, &edge)
        })
        .await;
    }

    // Build response
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::CREATED;
    response
        .headers_mut()
        .insert("x-kappa-label", kappa.parse().unwrap());
    response
        .headers_mut()
        .insert("docker-content-digest", kappa.parse().unwrap());
    response.headers_mut().insert(
        "location",
        format!("/v2/{}/manifests/{}", ns, kappa).parse().unwrap(),
    );
    response
        .headers_mut()
        .insert("content-length", "0".parse().unwrap());
    if let Some(ref subj) = subject_digest {
        response
            .headers_mut()
            .insert("oci-subject", subj.parse().unwrap());
    }
    // OCI-Tag header: report tags bound via ?tag= query params
    if !extra_tags.is_empty() {
        let tag_value = extra_tags.join(", ");
        response
            .headers_mut()
            .insert("oci-tag", tag_value.parse().unwrap());
    }
    Ok(response)
}

// -- GET ----------------------------------------------------------------------

async fn manifest_get(cx: &Cx, ns: &str, reference: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();

    // Resolve reference: digest -> use directly, tag -> tag_get
    let kappa = if is_digest(reference) {
        reference.to_string()
    } else {
        let n = ns.to_string();
        let r = reference.to_string();
        tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.tag_get(&n, &r).map(|e| e.kappa)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?
    };

    // Get the manifest blob
    let k = kappa.clone();
    let content = tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.blob_get(&k)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    // Content-type from blob metadata
    let k = kappa.clone();
    let ct = tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.blob_get_meta(&k, "content-type")
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .ok()
    .and_then(|b| String::from_utf8(b).ok())
    .unwrap_or_else(|| "application/octet-stream".to_string());

    (
        StatusCode::OK,
        [
            ("content-type", ct),
            ("content-length", content.len().to_string()),
            ("x-kappa-label", kappa.clone()),
            ("docker-content-digest", kappa),
        ],
        content,
    )
        .into_response(cx)
}

// -- HEAD ---------------------------------------------------------------------

async fn manifest_head(cx: &Cx, ns: &str, reference: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();

    let kappa = if is_digest(reference) {
        reference.to_string()
    } else {
        let n = ns.to_string();
        let r = reference.to_string();
        tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.tag_get(&n, &r).map(|e| e.kappa)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?
    };

    // Use blob_get to get both size and content-type in one pass
    // (manifest blobs are small -- typically < 10 KiB)
    let k = kappa.clone();
    let content = tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.blob_get(&k)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    let k = kappa.clone();
    let ct = tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.blob_get_meta(&k, "content-type")
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .ok()
    .and_then(|b| String::from_utf8(b).ok())
    .unwrap_or_else(|| "application/octet-stream".to_string());

    (
        StatusCode::OK,
        [
            ("content-type", ct),
            ("content-length", content.len().to_string()),
            ("x-kappa-label", kappa.clone()),
            ("docker-content-digest", kappa),
        ],
    )
        .into_response(cx)
}

// -- DELETE -------------------------------------------------------------------

async fn manifest_delete(cx: &Cx, ns: &str, reference: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();

    if is_digest(reference) {
        // Delete by digest: find all tags pointing to this digest and delete them
        let n = ns.to_string();
        let digest = reference.to_string();
        let tags = tokio::task::spawn_blocking({
            let s = s.clone();
            let n = n.clone();
            let d = digest.clone();
            move || {
                let all_tags = s.tag_list(&n)?;
                Ok::<Vec<String>, kappa_core::StoreError>(
                    all_tags
                        .into_iter()
                        .filter(|t| t.kappa == d)
                        .map(|t| t.name)
                        .collect(),
                )
            }
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;

        for tag in &tags {
            let t = tag.clone();
            let n = ns.to_string();
            let _ = tokio::task::spawn_blocking({
                let s = s.clone();
                move || s.tag_delete(&n, &t)
            })
            .await;
        }

        let d = reference.to_string();
        tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.blob_delete(&d)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;

        return StatusCode::ACCEPTED.into_response(cx);
    }

    // Delete by tag name
    let n = ns.to_string();
    let tag = reference.to_string();
    tokio::task::spawn_blocking(move || s.tag_delete(&n, &tag))
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;

    StatusCode::ACCEPTED.into_response(cx)
}

// -- TAG LIST -----------------------------------------------------------------

async fn tag_list(cx: &Cx, ns: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let n = ns.to_string();

    let n_param: Option<usize> = query_param(cx, "n").and_then(|s| s.parse().ok());
    let last_param: Option<String> = query_param(cx, "last");
    let order_param: Option<String> = query_param(cx, "order");
    let after_param: Option<String> = query_param(cx, "after");
    let before_param: Option<String> = query_param(cx, "before");

    if n_param == Some(0) {
        let body = serde_json::json!({"name": ns, "tags": []});
        return (
            StatusCode::OK,
            [("content-type", "application/json".to_string())],
            serde_json::to_string(&body).unwrap_or_default(),
        )
            .into_response(cx);
    }

    let all_tags = tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.tag_list(&n)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    // Filter out internal tags (starting with _)
    let mut tag_names: Vec<&str> = all_tags
        .iter()
        .filter(|t| !t.name.starts_with('_'))
        .map(|t| t.name.as_str())
        .collect();

    // Apply timestamp range filters
    if let Some(ref after) = after_param {
        tag_names.retain(|t| *t > after.as_str());
    }
    if let Some(ref before) = before_param {
        tag_names.retain(|t| *t < before.as_str());
    }

    // Sort
    let descending = order_param.as_deref() == Some("desc");
    if descending {
        tag_names.sort_by(|a, b| b.cmp(a));
    } else {
        tag_names.sort();
    }

    // Pagination: skip past 'last'
    if let Some(ref last) = last_param {
        if let Some(pos) = tag_names.iter().position(|t| *t == last.as_str()) {
            tag_names = tag_names[pos + 1..].to_vec();
        }
    }

    // Apply limit
    let has_more = if let Some(limit) = n_param {
        if tag_names.len() > limit {
            tag_names.truncate(limit);
            true
        } else {
            false
        }
    } else {
        false
    };

    let body = serde_json::json!({"name": ns, "tags": tag_names});
    let json_body = serde_json::to_string(&body).unwrap_or_default();

    if has_more {
        if let Some(last_tag) = tag_names.last() {
            let link = format!("</v2/{}/tags/list?last={}>; rel=\"next\"", ns, last_tag);
            return (
                StatusCode::OK,
                [
                    ("content-type", "application/json".to_string()),
                    ("link", link),
                ],
                json_body,
            )
                .into_response(cx);
        }
    }

    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        json_body,
    )
        .into_response(cx)
}

// -- Helpers ------------------------------------------------------------------

fn parse_oci_subject(manifest_bytes: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(manifest_bytes).ok()?;
    v.get("subject")?.get("digest")?.as_str().map(String::from)
}
