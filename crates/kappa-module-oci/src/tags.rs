//! Kappa tag operations: batch, prefix delete, CRUD, get/put by path.
//!
//! Three-argument tag_set. No content_type parameter. No _ct/ tags.
//! Symref resolves transparently -- the tag is a normal name-to-kappa
//! binding after creation.

use topcoat::context::Cx;
use topcoat::router::error::bad_request;
use topcoat::router::{headers, Body, IntoResponse, Response, RouteFuture, StatusCode};

use kappa_core::types::TagUpdate;

use crate::{path_param, query_param, read_body, store};

// -- Tag batch ----------------------------------------------------------------

pub fn tag_batch_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let ns = path_param(cx, "ns");
        tag_batch(cx, ns, &bytes).await
    })
}

async fn tag_batch(cx: &Cx, ns: &str, body: &[u8]) -> topcoat::Result<Response> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad_request(format!("invalid JSON: {e}")))?;
    let raw_updates = v["updates"]
        .as_array()
        .ok_or_else(|| bad_request("missing updates array"))?;

    let mut updates = Vec::with_capacity(raw_updates.len());
    for entry in raw_updates {
        let name = entry["name"]
            .as_str()
            .ok_or_else(|| bad_request("update missing name"))?;
        let new_kappa = entry["kappa"]
            .as_str()
            .ok_or_else(|| bad_request("update missing kappa"))?;
        let expected_version = if entry["expected_version"].is_null() {
            None
        } else {
            entry["expected_version"].as_u64()
        };
        updates.push(TagUpdate {
            name: name.to_string(),
            kappa: new_kappa.to_string(),
            expected_version,
        });
    }

    let s = store(cx).clone();
    let n = ns.to_string();
    tokio::task::spawn_blocking(move || s.tag_set_batch(&n, &updates))
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;

    (StatusCode::OK, [("content-length", "0")]).into_response(cx)
}

// -- Tag prefix delete --------------------------------------------------------

pub fn tag_delete_prefix_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let prefix = query_param(cx, "prefix").unwrap_or_default();
        if prefix.is_empty() {
            return Err(bad_request("missing prefix parameter").into());
        }
        tag_delete_prefix(cx, ns, &prefix).await
    })
}

async fn tag_delete_prefix(cx: &Cx, ns: &str, prefix: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let n = ns.to_string();
    let pfx = prefix.to_string();

    let matching = tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        move || s.tag_prefix(&n, &pfx)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    let count = matching.len();
    for tag in &matching {
        let t = tag.name.clone();
        let n = ns.to_string();
        let _ = tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.tag_delete(&n, &t)
        })
        .await;
    }

    let body = serde_json::json!({"deleted": count});
    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

// -- Tag CRUD -----------------------------------------------------------------

pub fn tag_crud_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let method = topcoat::router::method(cx);
        let ns = path_param(cx, "ns");
        match method.as_str() {
            "POST" => {
                let bytes = read_body(body).await?;
                tag_create(cx, ns, &bytes).await
            }
            "GET" => {
                let _ = body;
                let name = query_param(cx, "name").unwrap_or_default();
                if name.is_empty() {
                    return Err(bad_request("missing name parameter").into());
                }
                tag_get_by_query(cx, ns, &name).await
            }
            "DELETE" => {
                let _ = body;
                let name = query_param(cx, "name").unwrap_or_default();
                if name.is_empty() {
                    return Err(bad_request("missing name parameter").into());
                }
                tag_delete_by_query(cx, ns, &name).await
            }
            _ => Err(bad_request("method not allowed").into()),
        }
    })
}

async fn tag_create(cx: &Cx, ns: &str, body: &[u8]) -> topcoat::Result<Response> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad_request(format!("invalid JSON: {e}")))?;
    let name = v["name"].as_str().unwrap_or("");
    let kappa = v["kappa"].as_str().unwrap_or("");
    if name.is_empty() || kappa.is_empty() {
        return Err(bad_request("missing name or kappa in body").into());
    }

    let s = store(cx).clone();
    let n = ns.to_string();
    let k = kappa.to_string();

    // Content-before-tag: verify the blob exists
    let exists = tokio::task::spawn_blocking({
        let s = s.clone();
        let k = k.clone();
        move || s.blob_exists(&k)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    if !exists {
        return crate::oci_error(
            StatusCode::NOT_FOUND,
            "TAG_CONTENT_ABSENT",
            &format!("content {} does not exist", kappa),
        );
    }

    let nm = name.to_string();
    tokio::task::spawn_blocking(move || s.tag_set(&n, &nm, &k))
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;

    (StatusCode::CREATED, [("content-length", "0")]).into_response(cx)
}

async fn tag_get_by_query(cx: &Cx, ns: &str, name: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let n = ns.to_string();
    let nm = name.to_string();
    let entry = tokio::task::spawn_blocking(move || s.tag_get(&n, &nm))
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;

    let body = serde_json::json!({"name": name, "kappa": entry.kappa});
    (
        StatusCode::OK,
        [
            ("x-kappa-label", entry.kappa.clone()),
            ("content-type", "application/json".to_string()),
        ],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn tag_delete_by_query(cx: &Cx, ns: &str, name: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let n = ns.to_string();
    let nm = name.to_string();
    tokio::task::spawn_blocking(move || s.tag_delete(&n, &nm))
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;

    StatusCode::ACCEPTED.into_response(cx)
}

// -- Tag get by path param ----------------------------------------------------

pub fn tag_get_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let name = path_param(cx, "name");
        let raw = query_param(cx, "raw").as_deref() == Some("true");
        tag_get(cx, ns, name, raw).await
    })
}

async fn tag_get(cx: &Cx, ns: &str, name: &str, raw: bool) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let n = ns.to_string();
    let nm = name.to_string();

    let entry = tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.tag_get(&n, &nm)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    let value = &entry.kappa;
    let body = if raw {
        serde_json::json!({"name": name, "value": value})
    } else {
        serde_json::json!({"name": name, "kappa": value})
    };
    (
        StatusCode::OK,
        [
            ("x-kappa-label", value.clone()),
            ("content-type", "application/json".to_string()),
        ],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

// -- Tag put by path param ----------------------------------------------------

pub fn tag_put_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let name = path_param(cx, "name");
        let kappa = query_param(cx, "kappa").unwrap_or_default();
        let symref = query_param(cx, "symref");
        let if_match = headers(cx)
            .get("if-match")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let if_none_match = headers(cx)
            .get("if-none-match")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        tag_put(
            cx,
            ns,
            name,
            &kappa,
            symref.as_deref(),
            if_match.as_deref(),
            if_none_match.as_deref(),
        )
        .await
    })
}

async fn tag_put(
    cx: &Cx,
    ns: &str,
    name: &str,
    kappa: &str,
    symref: Option<&str>,
    if_match: Option<&str>,
    if_none_match: Option<&str>,
) -> topcoat::Result<Response> {
    let s = store(cx).clone();

    // Symref: resolve target tag's kappa and bind transparently
    if let Some(target) = symref {
        let n = ns.to_string();
        let nm = name.to_string();
        let t = target.to_string();
        let resolved_kappa = tokio::task::spawn_blocking({
            let s = s.clone();
            let n = n.clone();
            move || s.tag_get(&n, &t).map(|e| e.kappa)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;

        tokio::task::spawn_blocking({
            let s = s.clone();
            let n = n.clone();
            move || s.tag_set(&n, &nm, &resolved_kappa)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;

        return (
            StatusCode::CREATED,
            [
                ("x-kappa-label", format!("ref:{target}")),
                ("content-length", "0".to_string()),
            ],
        )
            .into_response(cx);
    }

    if kappa.is_empty() {
        return Err(bad_request("missing kappa parameter").into());
    }

    // Content-before-tag: verify the blob exists
    let k = kappa.to_string();
    let exists = tokio::task::spawn_blocking({
        let s = s.clone();
        let k = k.clone();
        move || s.blob_exists(&k)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    if !exists {
        return crate::oci_error(
            StatusCode::NOT_FOUND,
            "TAG_CONTENT_ABSENT",
            &format!("content {} does not exist", kappa),
        );
    }

    // If-Match: CAS by kappa-label comparison
    // (conformance test sends the current tag kappa as the If-Match value)
    if let Some(expected_kappa) = if_match {
        let n = ns.to_string();
        let nm = name.to_string();
        let k = kappa.to_string();
        let ek = expected_kappa.to_string();

        let result = tokio::task::spawn_blocking({
            let s = s.clone();
            move || match s.tag_get(&n, &nm) {
                Ok(entry) => {
                    if entry.kappa == ek {
                        s.tag_set(&n, &nm, &k)?;
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                }
                Err(_) => Ok(false),
            }
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;

        if result {
            return (
                StatusCode::OK,
                [
                    ("x-kappa-label", kappa.to_string()),
                    ("content-length", "0".to_string()),
                ],
            )
                .into_response(cx);
        } else {
            return (StatusCode::CONFLICT, "If-Match precondition failed").into_response(cx);
        }
    }

    // If-None-Match: * -- create-only (fail if tag exists)
    if if_none_match == Some("*") {
        let n = ns.to_string();
        let nm = name.to_string();
        let k = kappa.to_string();

        let updates = vec![TagUpdate {
            name: nm,
            kappa: k.clone(),
            expected_version: Some(0),
        }];
        let result = tokio::task::spawn_blocking({
            let s = s.clone();
            let n = n.clone();
            move || s.tag_set_batch(&n, &updates)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?;

        match result {
            Ok(()) => {
                return (
                    StatusCode::CREATED,
                    [
                        ("x-kappa-label", kappa.to_string()),
                        ("content-length", "0".to_string()),
                    ],
                )
                    .into_response(cx);
            }
            Err(_) => {
                return (StatusCode::CONFLICT, "tag already exists").into_response(cx);
            }
        }
    }

    // Unconditional set
    let n = ns.to_string();
    let nm = name.to_string();
    let k = kappa.to_string();

    let current_exists = tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        let nm = nm.clone();
        move || s.tag_get(&n, &nm).is_ok()
    })
    .await
    .unwrap_or(false);

    tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.tag_set(&n, &nm, &k)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    let status = if current_exists {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    (
        status,
        [
            ("x-kappa-label", kappa.to_string()),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response(cx)
}
