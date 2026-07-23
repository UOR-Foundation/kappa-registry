use std::collections::HashMap;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::auth;
use crate::error::AppError;
use crate::kappa::KappaLabel;
use crate::store::{KappaStore, TagListOpts};
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
    let kappa = KappaLabel::sha256(&content);

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

    // Gate 3: content-before-tag - store blob first
    let s = state.store.clone();
    let k = kappa.as_str().to_string();
    let c = content;
    tokio::task::spawn_blocking(move || s.put(&k, &c)).await??;

    // Gate 4: bind the primary tag
    let s = state.store.clone();
    let p = ns.to_string();
    let t = tag.to_string();
    let k = kappa.as_str().to_string();
    tokio::task::spawn_blocking(move || s.tag_set(&p, &t, &k)).await??;

    // Gate 5: bind additional tags from ?tag= query parameters (B38)
    if let Some(extra_tag) = params.get("tag") {
        let s = state.store.clone();
        let p = ns.to_string();
        let et = extra_tag.clone();
        let k = kappa.as_str().to_string();
        tokio::task::spawn_blocking(move || s.tag_set(&p, &et, &k)).await??;
    }

    Ok((
        StatusCode::CREATED,
        [
            ("x-kappa-label", kappa.as_str().to_string()),
            ("docker-content-digest", kappa.as_str().to_string()),
            (
                "location",
                crate::routes::segments::manifest_url(ns, kappa.as_str()),
            ),
            ("content-length", "0".to_string()),
        ],
    )
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

    let body = serde_json::json!({"name": ns, "tags": page.tags});

    if page.has_more {
        if let Some(last_entry) = page.tags.last() {
            let link = crate::routes::segments::tag_list_link(ns, &last_entry.name);
            return Ok((StatusCode::OK, [("link", link)], Json(body)).into_response());
        }
    }

    Ok((StatusCode::OK, Json(body)).into_response())
}

pub async fn tag_get(state: &AppState, ns: &str, name: &str) -> Result<Response, AppError> {
    auth::authorize(ns, "tag.get")?;

    let s = state.store.clone();
    let p = ns.to_string();
    let n = name.to_string();
    let result = tokio::task::spawn_blocking(move || s.tag_get(&p, &n)).await??;
    let kappa = result.ok_or(AppError::TagUnknown)?;

    let body = serde_json::json!({"name": name, "kappa": kappa});
    Ok((
        StatusCode::OK,
        [
            ("x-kappa-label", kappa),
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
    if_match: Option<&str>,
    if_none_match: Option<&str>,
) -> Result<Response, AppError> {
    auth::authorize(ns, "tag.put")?;

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
