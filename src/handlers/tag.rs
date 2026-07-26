use std::sync::Arc;

use topcoat::context::{app_context, Cx};
use topcoat::router::error::{bad_request, not_found};
use topcoat::router::{headers, Body, IntoResponse, Response, RouteFuture, StatusCode};

use crate::auth::authorize;
use crate::kappa::KappaLabel;
use crate::ratelimit::OpClass;
use crate::store::fs::FsStore;
use crate::store::{KappaStore, TagListOpts, TagUpdate};

use super::path_param;

fn query_param(cx: &Cx, key: &str) -> Option<String> {
    let uri = topcoat::router::uri(cx);
    let query = uri.query()?;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(percent_decode(v));
            }
        }
    }
    None
}

fn query_params_multi(cx: &Cx, key: &str) -> Vec<String> {
    let uri = topcoat::router::uri(cx);
    let Some(query) = uri.query() else {
        return Vec::new();
    };
    query
        .split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            if k == key {
                Some(percent_decode(v))
            } else {
                None
            }
        })
        .collect()
}

pub fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next().and_then(hex_val);
            let lo = bytes.next().and_then(hex_val);
            if let (Some(h), Some(l)) = (hi, lo) {
                result.push((h << 4 | l) as char);
            } else {
                result.push('%');
            }
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn store(cx: &Cx) -> &Arc<FsStore> {
    app_context::<Arc<FsStore>>(cx)
}

pub fn manifest_put_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = super::read_body(body).await?;
        let ns = path_param(cx, "ns");
        let reference = path_param(cx, "reference");
        let ct = headers(cx)
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/vnd.oci.image.manifest.v1+json");
        manifest_put(cx, ns, reference, ct, &bytes).await
    })
}

pub fn manifest_get_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let reference = path_param(cx, "reference");
        manifest_get(cx, ns, reference).await
    })
}

pub fn manifest_head_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let reference = path_param(cx, "reference");
        manifest_head(cx, ns, reference).await
    })
}

pub fn manifest_delete_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
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
        let prefix = query_param(cx, "prefix");
        if let Some(ref pfx) = prefix {
            tag_list_prefix(cx, ns, pfx).await
        } else {
            tag_list(cx, ns).await
        }
    })
}

pub fn tag_batch_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = super::read_body(body).await?;
        let ns = path_param(cx, "ns");
        tag_batch(cx, ns, &bytes).await
    })
}

pub fn tag_delete_prefix_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let prefix = query_param(cx, "prefix").unwrap_or_default();
        if prefix.is_empty() {
            return Err(bad_request("missing prefix parameter").into());
        }
        let asserter = super::registry_anchor(cx);
        let s = store(cx).clone();
        let n = ns.to_string();
        let pfx = prefix;
        let count = tokio::task::spawn_blocking(move || {
            authorize(&*s, &n, OpClass::Admin, &asserter)?;
            s.tag_delete_prefix(&n, &pfx)
        })
        .await??;
        let body = serde_json::json!({"deleted": count});
        (
            StatusCode::OK,
            serde_json::to_string(&body).unwrap_or_default(),
        )
            .into_response(cx)
    })
}

pub fn tag_crud_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let method = topcoat::router::method(cx);
        let ns = path_param(cx, "ns");
        match method.as_str() {
            "POST" => {
                let bytes = super::read_body(body).await?;
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

pub fn tag_get_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let name = path_param(cx, "name");
        let raw = query_param(cx, "raw").as_deref() == Some("true");
        tag_get(cx, ns, name, raw).await
    })
}

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

async fn manifest_put(
    cx: &Cx,
    ns: &str,
    tag: &str,
    content_type: &str,
    body: &[u8],
) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    let content = body.to_vec();

    let kappa = if let Ok(ref_label) = KappaLabel::parse(tag) {
        match crate::kappa::compute_kappa(ref_label.axis(), &content) {
            Ok(k) => k,
            Err(_) => KappaLabel::sha256(&content),
        }
    } else {
        KappaLabel::sha256(&content)
    };

    // Gate 1: authorize + admission filters
    tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        let a = asserter.clone();
        let b = content.clone();
        move || {
            authorize(&*s, &n, OpClass::Write, &a)?;
            s.filter_evaluate(&n, &b).map_err(|reason| {
                crate::store::StoreError::Rejected(format!("filter rejected: {reason}"))
            })
        }
    })
    .await??;

    // Gate 2: schema validation
    let body_for_schema = content.clone();
    let schemas = tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        move || s.schema_list(&n)
    })
    .await??;
    for schema_record in &schemas {
        let sc = schema_record.scope.clone();
        let schema_result = tokio::task::spawn_blocking({
            let s = s.clone();
            let n = n.clone();
            move || s.schema_get(&n, &sc)
        })
        .await??;
        if let Some((_schema_kappa, schema_bytes)) = schema_result {
            if let Ok(wrapper) = serde_json::from_slice::<serde_json::Value>(&schema_bytes) {
                let format = wrapper.get("format").and_then(|f| f.as_str()).unwrap_or("");
                if format == "json-schema" {
                    if let Some(validation) = wrapper.get("validation") {
                        if let Ok(instance) =
                            serde_json::from_slice::<serde_json::Value>(&body_for_schema)
                        {
                            if !jsonschema::is_valid(validation, &instance) {
                                return Err(bad_request("content does not match schema").into());
                            }
                        }
                    }
                }
            }
        }
    }

    // Gate 3: store blob
    let k = kappa.as_str().to_string();
    let c = content;
    tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.put(&k, &c)
    })
    .await??;

    // Gate 4: digest vs tag
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
        return Err(bad_request(format!("digest invalid: {tag}, invalid digest format")).into());
    }

    if ref_is_valid_digest && kappa.as_str() != tag {
        return Err(bad_request(format!(
            "digest invalid: expected {tag}, got {}",
            kappa.as_str()
        ))
        .into());
    }

    if !ref_is_valid_digest {
        let t = tag.to_string();
        let k = kappa.as_str().to_string();
        tokio::task::spawn_blocking({
            let s = s.clone();
            let n = n.clone();
            move || s.tag_set(&n, &t, &k)
        })
        .await??;
    }

    for extra_tag in query_params_multi(cx, "tag") {
        let k = kappa.as_str().to_string();
        tokio::task::spawn_blocking({
            let s = s.clone();
            let n = n.clone();
            move || s.tag_set(&n, &extra_tag, &k)
        })
        .await??;
    }

    let ct_bytes = content_type.as_bytes().to_vec();
    let k = kappa.as_str().to_string();
    tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.put_meta(&k, "content-type", &ct_bytes)
    })
    .await??;

    let k = kappa.as_str().to_string();
    tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        move || s.meta_set(&n, &k, &[("object-type", "manifest")])
    })
    .await??;

    let subject_digest: Option<String> = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("subject")
                .and_then(|s| s.get("digest"))
                .and_then(|d| d.as_str())
                .map(String::from)
        });

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
            let ek = edge_kappa.as_str().to_string();
            let ec = edge_canon.clone();
            let _ = tokio::task::spawn_blocking({
                let s = s.clone();
                let ek = ek.clone();
                move || s.put(&ek, &ec)
            })
            .await;
            let a = asserter;
            let src = kappa.as_str().to_string();
            let tgt = subj.clone();
            let _ = tokio::task::spawn_blocking(move || {
                s.edge_put(
                    &n,
                    &a,
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

    let mut hdrs = vec![
        ("x-kappa-label", kappa.as_str().to_string()),
        ("docker-content-digest", kappa.as_str().to_string()),
        ("location", crate::urls::manifest_url(ns, kappa.as_str())),
        ("content-length", "0".to_string()),
    ];
    if let Some(ref subj) = subject_digest {
        hdrs.push(("oci-subject", subj.clone()));
    }

    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::CREATED;
    for (k, v) in &hdrs {
        response.headers_mut().insert(*k, v.parse().unwrap());
    }
    Ok(response)
}

async fn manifest_get(cx: &Cx, ns: &str, version: &str) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        let a = asserter;
        move || authorize(&*s, &n, OpClass::Read, &a)
    })
    .await??;

    let kappa_str = if version.contains(':') {
        version.to_string()
    } else {
        let v = version.to_string();
        let result = tokio::task::spawn_blocking({
            let s = s.clone();
            let n = n.clone();
            move || s.tag_get(&n, &v)
        })
        .await??;
        result.ok_or_else(not_found)?
    };

    let k = kappa_str.clone();
    let content = tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.get(&k)
    })
    .await??
    .ok_or_else(not_found)?;

    let k = kappa_str.clone();
    let ct = tokio::task::spawn_blocking(move || s.get_meta(&k, "content-type"))
        .await??
        .and_then(|v| String::from_utf8(v).ok())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    (
        StatusCode::OK,
        [
            ("content-length", content.len().to_string()),
            ("x-kappa-label", kappa_str.clone()),
            ("docker-content-digest", kappa_str),
            ("content-type", ct),
        ],
        content,
    )
        .into_response(cx)
}

async fn manifest_head(cx: &Cx, ns: &str, version: &str) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        let a = asserter;
        move || authorize(&*s, &n, OpClass::Read, &a)
    })
    .await??;

    let kappa_str = if version.contains(':') {
        version.to_string()
    } else {
        let v = version.to_string();
        let result = tokio::task::spawn_blocking({
            let s = s.clone();
            let n = n.clone();
            move || s.tag_get(&n, &v)
        })
        .await??;
        result.ok_or_else(not_found)?
    };

    let k = kappa_str.clone();
    let content = tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.get(&k)
    })
    .await??
    .ok_or_else(not_found)?;

    let k = kappa_str.clone();
    let ct = tokio::task::spawn_blocking(move || s.get_meta(&k, "content-type"))
        .await??
        .and_then(|v| String::from_utf8(v).ok())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    (
        StatusCode::OK,
        [
            ("content-length", content.len().to_string()),
            ("x-kappa-label", kappa_str.clone()),
            ("docker-content-digest", kappa_str),
            ("content-type", ct),
        ],
    )
        .into_response(cx)
}

async fn manifest_delete(cx: &Cx, ns: &str, tag: &str) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();

    if tag.contains(':') {
        let digest = tag.to_string();
        let tags = tokio::task::spawn_blocking({
            let s = s.clone();
            let n = n.clone();
            let d = digest.clone();
            let a = asserter;
            move || {
                authorize(&*s, &n, OpClass::Admin, &a)?;
                s.tag_find_by_kappa(&n, &d)
            }
        })
        .await??;
        for t in &tags {
            let t = t.clone();
            tokio::task::spawn_blocking({
                let s = s.clone();
                let n = n.clone();
                move || s.tag_delete(&n, &t)
            })
            .await??;
        }
        tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.remove(&digest)
        })
        .await??;
        return StatusCode::ACCEPTED.into_response(cx);
    }

    let t = tag.to_string();
    let deleted = tokio::task::spawn_blocking(move || {
        authorize(&*s, &n, OpClass::Admin, &asserter)?;
        s.tag_delete(&n, &t)
    })
    .await??;
    if deleted {
        StatusCode::ACCEPTED.into_response(cx)
    } else {
        Err(not_found().into())
    }
}

async fn tag_list(cx: &Cx, ns: &str) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let p = ns.to_string();

    let opts = TagListOpts {
        n: query_param(cx, "n").and_then(|s| s.parse().ok()),
        last: query_param(cx, "last"),
        order: query_param(cx, "order"),
        after: query_param(cx, "after"),
        before: query_param(cx, "before"),
    };

    if opts.n == Some(0) {
        tokio::task::spawn_blocking({
            let s = s.clone();
            let p = p.clone();
            let a = asserter;
            move || authorize(&*s, &p, OpClass::Read, &a)
        })
        .await??;
        let body = serde_json::json!({"name": ns, "tags": []});
        return (
            StatusCode::OK,
            serde_json::to_string(&body).unwrap_or_default(),
        )
            .into_response(cx);
    }

    let page = tokio::task::spawn_blocking(move || {
        authorize(&*s, &p, OpClass::Read, &asserter)?;
        s.tag_list(&p, &opts)
    })
    .await??;

    let tag_names: Vec<&str> = page.tags.iter().map(|t| t.name.as_str()).collect();
    let body = serde_json::json!({"name": ns, "tags": tag_names});
    let json_body = serde_json::to_string(&body).unwrap_or_default();

    if page.has_more {
        if let Some(last_entry) = page.tags.last() {
            let link = crate::urls::tag_list_link(ns, &last_entry.name);
            return (StatusCode::OK, [("link", link)], json_body).into_response(cx);
        }
    }

    (StatusCode::OK, json_body).into_response(cx)
}

async fn tag_list_prefix(cx: &Cx, ns: &str, prefix: &str) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    let pfx = prefix.to_string();
    let entries = tokio::task::spawn_blocking(move || {
        authorize(&*s, &n, OpClass::Read, &asserter)?;
        s.tag_list_prefix(&n, &pfx)
    })
    .await??;

    let names: Vec<&str> = entries.iter().map(|t| t.name.as_str()).collect();
    let body = serde_json::json!({"name": ns, "tags": names});
    (
        StatusCode::OK,
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn tag_get(cx: &Cx, ns: &str, name: &str, raw: bool) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let p = ns.to_string();
    let nm = name.to_string();
    let result = if raw {
        tokio::task::spawn_blocking(move || {
            authorize(&*s, &p, OpClass::Read, &asserter)?;
            s.tag_get_raw(&p, &nm)
        })
        .await??
    } else {
        tokio::task::spawn_blocking(move || {
            authorize(&*s, &p, OpClass::Read, &asserter)?;
            s.tag_get(&p, &nm)
        })
        .await??
    };
    let value = result.ok_or_else(not_found)?;

    let body = if raw {
        serde_json::json!({"name": name, "value": value})
    } else {
        serde_json::json!({"name": name, "kappa": value})
    };
    (
        StatusCode::OK,
        [
            ("x-kappa-label", value),
            ("content-type", "application/json".to_string()),
        ],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
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
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let p = ns.to_string();

    if let Some(target) = symref {
        let nm = name.to_string();
        let t = target.to_string();
        tokio::task::spawn_blocking({
            let s = s.clone();
            let p = p.clone();
            let a = asserter;
            move || {
                authorize(&*s, &p, OpClass::Write, &a)?;
                s.tag_set_symbolic(&p, &nm, &t)
            }
        })
        .await??;
        return (
            StatusCode::CREATED,
            [
                ("x-kappa-label", format!("ref:{target}")),
                ("content-length", "0".to_string()),
            ],
        )
            .into_response(cx);
    }

    let k = kappa.to_string();
    let exists = tokio::task::spawn_blocking({
        let s = s.clone();
        let p = p.clone();
        let a = asserter.clone();
        let k = k.clone();
        move || {
            authorize(&*s, &p, OpClass::Write, &a)?;
            s.exists(&k)
        }
    })
    .await??;
    if !exists {
        return Err(not_found().into());
    }

    // D-5: If-Match uses per-tag version CAS.
    if let Some(expected_str) = if_match {
        let expected_version: u64 = expected_str
            .parse()
            .map_err(|_| bad_request("If-Match must be a version number"))?;
        let nm = name.to_string();
        let k = kappa.to_string();
        let ok = tokio::task::spawn_blocking({
            let s = s.clone();
            let p = p.clone();
            move || s.tag_set_if(&p, &nm, &k, expected_version)
        })
        .await??;
        if ok {
            return (
                StatusCode::OK,
                [
                    ("x-kappa-label", kappa.to_string()),
                    ("content-length", "0".to_string()),
                ],
            )
                .into_response(cx);
        } else {
            return (StatusCode::CONFLICT, "If-Match version precondition failed")
                .into_response(cx);
        }
    }

    // D-5: If-None-Match: * uses version 0 (create-if-absent).
    if if_none_match == Some("*") {
        let nm = name.to_string();
        let k = kappa.to_string();
        let ok = tokio::task::spawn_blocking({
            let s = s.clone();
            let p = p.clone();
            move || s.tag_set_if(&p, &nm, &k, 0)
        })
        .await??;
        if ok {
            return (
                StatusCode::CREATED,
                [
                    ("x-kappa-label", kappa.to_string()),
                    ("content-length", "0".to_string()),
                ],
            )
                .into_response(cx);
        } else {
            return (StatusCode::CONFLICT, "tag already exists").into_response(cx);
        }
    }

    let nm = name.to_string();
    let current = tokio::task::spawn_blocking({
        let s = s.clone();
        let p = p.clone();
        let nm = nm.clone();
        move || s.tag_get(&p, &nm)
    })
    .await??;

    let k = kappa.to_string();
    tokio::task::spawn_blocking(move || s.tag_set(&p, &nm, &k)).await??;

    let status = if current.is_some() {
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
        // D-5: expected_version replaces expected value.
        // null = unconditional, 0 = create-if-absent, N = version CAS.
        let expected_version = if entry["expected_version"].is_null() {
            None
        } else {
            entry["expected_version"].as_u64()
        };
        updates.push(TagUpdate {
            name: name.to_string(),
            new_kappa: new_kappa.to_string(),
            expected_version,
        });
    }

    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    let result = tokio::task::spawn_blocking(move || {
        authorize(&*s, &n, OpClass::Write, &asserter)?;
        s.tag_set_batch(&n, &updates)
    })
    .await??;

    (
        StatusCode::OK,
        serde_json::to_string(&result).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn tag_create(cx: &Cx, ns: &str, body: &[u8]) -> topcoat::Result<Response> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad_request(format!("invalid JSON: {e}")))?;
    let name = v["name"].as_str().unwrap_or("");
    let kappa = v["kappa"].as_str().unwrap_or("");
    if name.is_empty() || kappa.is_empty() {
        return Err(bad_request("missing name or kappa in body").into());
    }

    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    let k = kappa.to_string();
    let exists = tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        let a = asserter;
        let k = k.clone();
        move || {
            authorize(&*s, &n, OpClass::Write, &a)?;
            s.exists(&k)
        }
    })
    .await??;
    if !exists {
        return Err(not_found().into());
    }

    let nm = name.to_string();
    tokio::task::spawn_blocking(move || s.tag_set(&n, &nm, &k)).await??;

    (StatusCode::CREATED, [("content-length", "0")]).into_response(cx)
}

async fn tag_get_by_query(cx: &Cx, ns: &str, name: &str) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    let nm = name.to_string();
    let result = tokio::task::spawn_blocking(move || {
        authorize(&*s, &n, OpClass::Read, &asserter)?;
        s.tag_get(&n, &nm)
    })
    .await??;
    let val = result.ok_or_else(not_found)?;
    let body = serde_json::json!({"name": name, "kappa": val});
    (
        StatusCode::OK,
        [("x-kappa-label", val)],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn tag_delete_by_query(cx: &Cx, ns: &str, name: &str) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    let nm = name.to_string();
    let deleted = tokio::task::spawn_blocking(move || {
        authorize(&*s, &n, OpClass::Admin, &asserter)?;
        s.tag_delete(&n, &nm)
    })
    .await??;
    if deleted {
        StatusCode::ACCEPTED.into_response(cx)
    } else {
        Err(not_found().into())
    }
}
