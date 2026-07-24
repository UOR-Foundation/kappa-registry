use std::collections::HashMap;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::auth;
use crate::error::AppError;
use crate::kappa::KappaLabel;
use crate::store::{KappaStore, TagListOpts, TagUpdate};
use crate::AppState;

pub async fn manifest_put(
    state: &AppState,
    ns: &str,
    tag: &str,
    params: &HashMap<String, String>,
    body: &[u8],
) -> Result<Response, AppError> {
    auth::authorize(ns, "manifest.put")?;

    let content = body.to_vec();

    // Determine digest algorithm: if the reference is a valid digest, use its axis.
    // Otherwise default to sha256.
    let kappa = if let Ok(ref_label) = KappaLabel::parse(tag) {
        match crate::kappa::compute_kappa(ref_label.axis(), &content) {
            Ok(k) => k,
            Err(_) => KappaLabel::sha256(&content),
        }
    } else {
        KappaLabel::sha256(&content)
    };

    // Gate 1: admission filters
    let s = state.store.clone();
    let ns_owned = ns.to_string();
    let body_owned = content.clone();
    let filter_result = tokio::task::spawn_blocking({
        let s = s.clone();
        let n = ns_owned.clone();
        let b = body_owned.clone();
        move || s.filter_evaluate(&n, &b)
    })
    .await?;
    if let Err(reason) = filter_result {
        return Err(AppError::filter_rejected(&reason));
    }

    // Gate 2: schema validation (B30 - iterate all schemas for namespace)
    let s = state.store.clone();
    let ns_for_schema = ns.to_string();
    let body_for_schema = content.clone();
    let schemas = tokio::task::spawn_blocking({
        let s = s.clone();
        let n = ns_for_schema.clone();
        move || s.schema_list(&n)
    })
    .await??;
    for schema_record in &schemas {
        let s = state.store.clone();
        let n = ns_for_schema.clone();
        let sc = schema_record.scope.clone();
        let schema_result = tokio::task::spawn_blocking(move || s.schema_get(&n, &sc)).await??;
        if let Some((_schema_kappa, schema_bytes)) = schema_result {
            if let Ok(wrapper) = serde_json::from_slice::<serde_json::Value>(&schema_bytes) {
                let format = wrapper.get("format").and_then(|f| f.as_str()).unwrap_or("");
                if format == "json-schema" {
                    if let Some(validation) = wrapper.get("validation") {
                        if let Ok(instance) =
                            serde_json::from_slice::<serde_json::Value>(&body_for_schema)
                        {
                            if !jsonschema::is_valid(validation, &instance) {
                                return Err(AppError::schema_violation(
                                    "content does not match schema",
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // Gate 3: store blob
    let s = state.store.clone();
    let k = kappa.as_str().to_string();
    let c = content;
    tokio::task::spawn_blocking(move || s.put(&k, &c)).await??;

    // Gate 4: determine if reference is a digest or a tag.
    // A valid digest parses as a KappaLabel. An invalid digest uses a recognized
    // algorithm prefix (sha256, blake3, etc.) but fails full validation - reject
    // with 400. Anything else (including timestamps with colons) is a tag name.
    let ref_is_valid_digest = KappaLabel::parse(tag).is_ok();
    let ref_looks_like_bad_digest = !ref_is_valid_digest
        && tag
            .split_once(':')
            .map(|(algo, _)| {
                matches!(
                    algo,
                    "sha1" | "sha256" | "blake3" | "sha3-256" | "keccak256" | "sha512"
                )
            })
            .unwrap_or(false);

    if ref_looks_like_bad_digest {
        return Err(AppError::digest_invalid(tag, "invalid digest format"));
    }

    // When pushing by digest, verify the computed digest matches the reference
    if ref_is_valid_digest && kappa.as_str() != tag {
        return Err(AppError::digest_invalid(tag, kappa.as_str()));
    }

    if !ref_is_valid_digest {
        // Reference is a tag name - bind it
        let s = state.store.clone();
        let p = ns.to_string();
        let t = tag.to_string();
        let k = kappa.as_str().to_string();
        tokio::task::spawn_blocking(move || s.tag_set(&p, &t, &k)).await??;
    }

    // Bind additional tags from ?tag= query parameters
    for extra_tag in params.get("tag").into_iter() {
        let s = state.store.clone();
        let p = ns.to_string();
        let et = extra_tag.clone();
        let k = kappa.as_str().to_string();
        tokio::task::spawn_blocking(move || s.tag_set(&p, &et, &k)).await??;
    }

    // Store Content-Type metadata from the request or default to OCI manifest type
    let ct_value = params
        .get("_content_type")
        .cloned()
        .unwrap_or_else(|| "application/vnd.oci.image.manifest.v1+json".to_string());
    let s = state.store.clone();
    let k = kappa.as_str().to_string();
    let ct_bytes = ct_value.as_bytes().to_vec();
    tokio::task::spawn_blocking(move || s.put_meta(&k, "content-type", &ct_bytes)).await??;

    // Store object-type metadata
    let s = state.store.clone();
    let k = kappa.as_str().to_string();
    tokio::task::spawn_blocking(move || s.put_meta(&k, "object-type", b"manifest")).await??;

    // Detect subject field for OCI-Subject header
    let subject_digest: Option<String> = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("subject")
                .and_then(|s| s.get("digest"))
                .and_then(|d| d.as_str())
                .map(String::from)
        });

    // Create refers-to edge when subject is present
    if let Some(ref subj) = subject_digest {
        let edge_meta = vec![0xA0u8];
        let edge_canon = super::edge::edge_canonical_pub(
            kappa.as_str().as_bytes(),
            "refers-to",
            subj.as_bytes(),
            &edge_meta,
        );
        let axis = kappa.as_str().split(':').next().unwrap_or("sha256");
        if let Ok(edge_kappa) = crate::kappa::compute_kappa(axis, &edge_canon) {
            let s = state.store.clone();
            let ek = edge_kappa.as_str().to_string();
            let ec = edge_canon.clone();
            let _ = tokio::task::spawn_blocking({
                let s = s.clone();
                let ek = ek.clone();
                move || s.put(&ek, &ec)
            })
            .await;
            let s = state.store.clone();
            let src = kappa.as_str().to_string();
            let tgt = subj.clone();
            let n = ns.to_string();
            let _ = tokio::task::spawn_blocking(move || {
                s.edge_put(
                    &n,
                    &ek,
                    &src,
                    "refers-to",
                    &tgt,
                    &edge_canon,
                    serde_json::json!({}),
                )
            })
            .await;
        }
    }

    let mut resp = axum::http::Response::builder().status(StatusCode::CREATED);
    resp = resp.header("x-kappa-label", kappa.as_str());
    resp = resp.header("docker-content-digest", kappa.as_str());
    resp = resp.header(
        "location",
        crate::routes::segments::manifest_url(ns, kappa.as_str()),
    );
    resp = resp.header("content-length", "0");
    if let Some(ref subj) = subject_digest {
        resp = resp.header("oci-subject", subj.as_str());
    }
    Ok(resp
        .body(axum::body::Body::empty())
        .unwrap()
        .into_response())
}

pub async fn manifest_get(state: &AppState, ns: &str, version: &str) -> Result<Response, AppError> {
    auth::authorize(ns, "manifest.get")?;

    let kappa_str = if version.contains(':') {
        version.to_string()
    } else {
        let s = state.store.clone();
        let p = ns.to_string();
        let v = version.to_string();
        let result = tokio::task::spawn_blocking(move || s.tag_get(&p, &v)).await??;
        result.ok_or(AppError::TagUnknown)?
    };

    let s = state.store.clone();
    let k = kappa_str.clone();
    let content = tokio::task::spawn_blocking(move || s.get(&k)).await??;
    let content = content.ok_or(AppError::BlobUnknown)?;

    let s = state.store.clone();
    let k = kappa_str.clone();
    let ct = tokio::task::spawn_blocking(move || s.get_meta(&k, "content-type"))
        .await??
        .and_then(|v| String::from_utf8(v).ok())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    Ok((
        StatusCode::OK,
        [
            ("content-length", content.len().to_string()),
            ("x-kappa-label", kappa_str.clone()),
            ("docker-content-digest", kappa_str),
            ("content-type", ct),
        ],
        content,
    )
        .into_response())
}

pub async fn manifest_head(
    state: &AppState,
    ns: &str,
    version: &str,
) -> Result<Response, AppError> {
    auth::authorize(ns, "manifest.head")?;

    let kappa_str = if version.contains(':') {
        version.to_string()
    } else {
        let s = state.store.clone();
        let p = ns.to_string();
        let v = version.to_string();
        let result = tokio::task::spawn_blocking(move || s.tag_get(&p, &v)).await??;
        result.ok_or(AppError::TagUnknown)?
    };

    let s = state.store.clone();
    let k = kappa_str.clone();
    let content = tokio::task::spawn_blocking(move || s.get(&k)).await??;
    let content = content.ok_or(AppError::BlobUnknown)?;

    let s = state.store.clone();
    let k = kappa_str.clone();
    let ct = tokio::task::spawn_blocking(move || s.get_meta(&k, "content-type"))
        .await??
        .and_then(|v| String::from_utf8(v).ok())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    Ok((
        StatusCode::OK,
        [
            ("content-length", content.len().to_string()),
            ("x-kappa-label", kappa_str.clone()),
            ("docker-content-digest", kappa_str),
            ("content-type", ct),
        ],
    )
        .into_response())
}

pub async fn manifest_delete(state: &AppState, ns: &str, tag: &str) -> Result<Response, AppError> {
    auth::authorize(ns, "manifest.delete")?;

    // If the reference contains a colon, it is a digest - find and delete all
    // tags pointing to it, then remove the blob itself.
    if tag.contains(':') {
        let s = state.store.clone();
        let p = ns.to_string();
        let digest = tag.to_string();
        let tags = tokio::task::spawn_blocking({
            let s = s.clone();
            let p = p.clone();
            let d = digest.clone();
            move || s.tag_find_by_kappa(&p, &d)
        })
        .await??;
        for t in &tags {
            let s = state.store.clone();
            let p = ns.to_string();
            let t = t.clone();
            tokio::task::spawn_blocking(move || s.tag_delete(&p, &t)).await??;
        }
        let s = state.store.clone();
        tokio::task::spawn_blocking(move || s.remove(&digest)).await??;
        return Ok(StatusCode::ACCEPTED.into_response());
    }

    let s = state.store.clone();
    let p = ns.to_string();
    let t = tag.to_string();
    let deleted = tokio::task::spawn_blocking(move || s.tag_delete(&p, &t)).await??;
    if deleted {
        Ok(StatusCode::ACCEPTED.into_response())
    } else {
        Err(AppError::TagUnknown)
    }
}

pub async fn tag_list(
    state: &AppState,
    ns: &str,
    params: &HashMap<String, String>,
) -> Result<Response, AppError> {
    auth::authorize(ns, "tag.list")?;

    let opts = TagListOpts {
        n: params.get("n").and_then(|s| s.parse().ok()),
        last: params.get("last").cloned(),
        order: params.get("order").cloned(),
        after: params.get("after").cloned(),
        before: params.get("before").cloned(),
    };

    if opts.n == Some(0) {
        let body = serde_json::json!({"name": ns, "tags": []});
        return Ok((StatusCode::OK, Json(body)).into_response());
    }

    let s = state.store.clone();
    let p = ns.to_string();
    let page = tokio::task::spawn_blocking(move || s.tag_list(&p, &opts)).await??;

    let tag_names: Vec<&str> = page.tags.iter().map(|t| t.name.as_str()).collect();
    let body = serde_json::json!({"name": ns, "tags": tag_names});

    if page.has_more {
        if let Some(last_entry) = page.tags.last() {
            let link = crate::routes::segments::tag_list_link(ns, &last_entry.name);
            return Ok((StatusCode::OK, [("link", link)], Json(body)).into_response());
        }
    }

    Ok((StatusCode::OK, Json(body)).into_response())
}

pub async fn tag_get(
    state: &AppState,
    ns: &str,
    name: &str,
    raw: bool,
) -> Result<Response, AppError> {
    auth::authorize(ns, "tag.get")?;

    let s = state.store.clone();
    let p = ns.to_string();
    let n = name.to_string();
    let result = if raw {
        tokio::task::spawn_blocking(move || s.tag_get_raw(&p, &n)).await??
    } else {
        tokio::task::spawn_blocking(move || s.tag_get(&p, &n)).await??
    };
    let value = result.ok_or(AppError::TagUnknown)?;

    let body = if raw {
        serde_json::json!({"name": name, "value": value})
    } else {
        serde_json::json!({"name": name, "kappa": value})
    };
    Ok((
        StatusCode::OK,
        [
            ("x-kappa-label", value),
            ("content-type", "application/json".to_string()),
        ],
        Json(body),
    )
        .into_response())
}

pub async fn tag_put(
    state: &AppState,
    ns: &str,
    name: &str,
    kappa: &str,
    symref: Option<&str>,
    if_match: Option<&str>,
    if_none_match: Option<&str>,
) -> Result<Response, AppError> {
    auth::authorize(ns, "tag.put")?;

    // Symbolic ref creation: ?symref=target_name
    if let Some(target) = symref {
        let s = state.store.clone();
        let p = ns.to_string();
        let n = name.to_string();
        let t = target.to_string();
        tokio::task::spawn_blocking(move || s.tag_set_symbolic(&p, &n, &t)).await??;
        return Ok((
            StatusCode::CREATED,
            [
                ("x-kappa-label", format!("ref:{target}")),
                ("content-length", "0".to_string()),
            ],
        )
            .into_response());
    }

    // Content-before-tag: kappa must exist in store
    let s = state.store.clone();
    let k = kappa.to_string();
    let exists = tokio::task::spawn_blocking(move || s.exists(&k)).await??;
    if !exists {
        return Err(AppError::TagContentAbsent);
    }

    // CAS: If-Match
    if let Some(expected) = if_match {
        let s = state.store.clone();
        let p = ns.to_string();
        let n = name.to_string();
        let k = kappa.to_string();
        let exp = expected.to_string();
        let ok =
            tokio::task::spawn_blocking(move || s.tag_set_if(&p, &n, &k, Some(&exp))).await??;
        if ok {
            return Ok((
                StatusCode::OK,
                [
                    ("x-kappa-label", kappa.to_string()),
                    ("content-length", "0".to_string()),
                ],
            )
                .into_response());
        } else {
            return Err(AppError::Store(crate::store::StoreError::Conflict(
                "If-Match precondition failed".to_string(),
            )));
        }
    }

    // CAS: If-None-Match: *
    if if_none_match == Some("*") {
        let s = state.store.clone();
        let p = ns.to_string();
        let n = name.to_string();
        let k = kappa.to_string();
        let ok = tokio::task::spawn_blocking(move || s.tag_set_if(&p, &n, &k, None)).await??;
        if ok {
            return Ok((
                StatusCode::CREATED,
                [
                    ("x-kappa-label", kappa.to_string()),
                    ("content-length", "0".to_string()),
                ],
            )
                .into_response());
        } else {
            return Err(AppError::Store(crate::store::StoreError::Conflict(
                "tag already exists".to_string(),
            )));
        }
    }

    // Unconditional set
    let s = state.store.clone();
    let p = ns.to_string();
    let n = name.to_string();
    let current = tokio::task::spawn_blocking({
        let s = s.clone();
        let p = p.clone();
        let n = n.clone();
        move || s.tag_get(&p, &n)
    })
    .await??;

    let s2 = state.store.clone();
    let p2 = ns.to_string();
    let n2 = name.to_string();
    let k2 = kappa.to_string();
    tokio::task::spawn_blocking(move || s2.tag_set(&p2, &n2, &k2)).await??;

    let status = if current.is_some() {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((
        status,
        [
            ("x-kappa-label", kappa.to_string()),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response())
}

pub async fn tag_batch(state: &AppState, ns: &str, body: &[u8]) -> Result<Response, AppError> {
    auth::authorize(ns, "tag.batch")?;

    let v: serde_json::Value = serde_json::from_slice(body)?;
    let raw_updates = v["updates"]
        .as_array()
        .ok_or_else(|| AppError::NameInvalid("missing updates array".to_string()))?;

    let mut updates = Vec::with_capacity(raw_updates.len());
    for entry in raw_updates {
        let name = entry["name"]
            .as_str()
            .ok_or_else(|| AppError::NameInvalid("update missing name".to_string()))?;
        let new_kappa = entry["kappa"]
            .as_str()
            .ok_or_else(|| AppError::NameInvalid("update missing kappa".to_string()))?;
        let expected = if entry["expected"].is_null() {
            None
        } else {
            Some(entry["expected"].as_str().unwrap_or("").to_string())
        };
        updates.push(TagUpdate {
            name: name.to_string(),
            new_kappa: new_kappa.to_string(),
            expected,
        });
    }

    let s = state.store.clone();
    let n = ns.to_string();
    let result = tokio::task::spawn_blocking(move || s.tag_set_batch(&n, &updates)).await??;

    Ok((StatusCode::OK, Json(result)).into_response())
}
