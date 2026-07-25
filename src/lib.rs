pub mod auth;
pub mod bundle;
pub mod config;
pub mod crypto;
pub mod delta;
pub mod error;
pub mod handlers;
pub mod kappa;
pub mod ratelimit;
pub mod routes;
pub mod store;
pub mod transaction;

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Json;
use axum::Router;
use tower_http::trace::TraceLayer;

use crate::handlers::upload::SessionStore;
use crate::ratelimit::TieredRateLimiter;
use crate::routes::Endpoint;
use crate::store::fs::FsStore;
use crate::store::KappaStore;
use crate::transaction::TransactionManager;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<FsStore>,
    pub sessions: Arc<SessionStore>,
    pub transactions: Arc<TransactionManager>,
    pub rate_limiter: Option<TieredRateLimiter>,
    pub signer: Option<Arc<dyn crate::crypto::RegistrySigner>>,
    pub max_blob_size: usize,
    pub upload_timeout_secs: u64,
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .fallback(any(dispatch))
        .layer(axum::extract::DefaultBodyLimit::max(state.max_blob_size))
        .layer(middleware::map_response(add_warning_header))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn add_warning_header(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert("warning", "299 - \"kappa-registry\"".parse().unwrap());
    response
}

async fn dispatch(
    method: Method,
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    body: Bytes,
) -> Response {
    let path = uri.path();
    let uri_str = uri.to_string();
    let method_str = method.as_str();
    let params = routes::query_params(&uri_str);
    let p = |key: &str| -> Option<&str> { routes::param_first(&params, key) };

    let endpoint = routes::parse(method_str, path);
    tracing::debug!(
        method = method_str,
        path = path,
        uri = uri_str.as_str(),
        endpoint = ?endpoint,
        "dispatch"
    );

    // Tiered rate limiting
    let mut rate_snapshot = None;
    if let Some(ref limiter) = state.rate_limiter {
        let ip = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').find_map(|s| s.trim().parse().ok()))
            .or_else(|| {
                headers
                    .get("x-real-ip")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse().ok())
            })
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let op_class = endpoint.op_class();
        match limiter.check(ip, op_class) {
            Ok(snap) => rate_snapshot = snap,
            Err(rejection) => return (*rejection).into_response(),
        }
    }

    let mut response = match endpoint {
        Endpoint::Version => handlers::blob::version_check().into_response(),
        Endpoint::Health => {
            let probe = path.strip_prefix("/v2/_health/").unwrap_or("live");
            match probe {
                "ready" => match tempfile::NamedTempFile::new_in(state.store.root()) {
                    Ok(_) => StatusCode::OK.into_response(),
                    Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                },
                _ => StatusCode::OK.into_response(),
            }
        }

        Endpoint::BlobPut { ns, kappa } => {
            handlers::blob::put(&state, ns, kappa, &params, &headers, &body)
                .await
                .into_response()
        }
        Endpoint::BlobGet { ns, kappa } => handlers::blob::get(&state, ns, kappa, &headers)
            .await
            .into_response(),
        Endpoint::BlobHead { ns, kappa } => handlers::blob::head(&state, ns, kappa)
            .await
            .into_response(),
        Endpoint::BlobDelete { ns, kappa } => handlers::blob::delete(&state, ns, kappa)
            .await
            .into_response(),
        Endpoint::BlobList { ns } => {
            let prefix = p("prefix").unwrap_or("");
            handlers::blob::list(&state, ns, prefix)
                .await
                .into_response()
        }
        Endpoint::MetaList { ns } => {
            // Compound query: ?filter=key1:val1&filter=key2:val2
            let filters: Vec<&str> = params
                .get("filter")
                .map(|v| v.iter().map(|s| s.as_str()).collect())
                .unwrap_or_default();
            if !filters.is_empty() {
                let parsed: Vec<(String, String)> = filters
                    .iter()
                    .filter_map(|f| {
                        let (k, v) = f.split_once(':')?;
                        Some((k.to_string(), v.to_string()))
                    })
                    .collect();
                if parsed.len() == 1 {
                    let s = state.store.clone();
                    let n = ns.to_string();
                    let k = parsed[0].0.clone();
                    let v = parsed[0].1.clone();
                    match tokio::task::spawn_blocking(move || s.meta_query(&n, &k, &v)).await {
                        Ok(Ok(kappas)) => {
                            (StatusCode::OK, Json(serde_json::json!({"kappas": kappas})))
                                .into_response()
                        }
                        Ok(Err(e)) => error::AppError::Store(e).into_response(),
                        Err(e) => error::AppError::internal(&e.to_string()).into_response(),
                    }
                } else {
                    let s = state.store.clone();
                    let n = ns.to_string();
                    match tokio::task::spawn_blocking(move || {
                        let refs: Vec<(&str, &str)> = parsed
                            .iter()
                            .map(|(k, v)| (k.as_str(), v.as_str()))
                            .collect();
                        s.meta_query_compound(&n, &refs)
                    })
                    .await
                    {
                        Ok(Ok(kappas)) => {
                            (StatusCode::OK, Json(serde_json::json!({"kappas": kappas})))
                                .into_response()
                        }
                        Ok(Err(e)) => error::AppError::Store(e).into_response(),
                        Err(e) => error::AppError::internal(&e.to_string()).into_response(),
                    }
                }
            } else {
                // Single key+value query (legacy path)
                let key = p("key").unwrap_or("");
                let value = p("value").unwrap_or("");
                if key.is_empty() {
                    handlers::blob::list_by_meta(&state, ns, key, value)
                        .await
                        .into_response()
                } else {
                    let s = state.store.clone();
                    let n = ns.to_string();
                    let k = key.to_string();
                    let v = value.to_string();
                    match tokio::task::spawn_blocking(move || {
                        if v.is_empty() {
                            s.meta_query_exists(&n, &k)
                        } else {
                            s.meta_query(&n, &k, &v)
                        }
                    })
                    .await
                    {
                        Ok(Ok(kappas)) => {
                            (StatusCode::OK, Json(serde_json::json!({"kappas": kappas})))
                                .into_response()
                        }
                        Ok(Err(e)) => error::AppError::Store(e).into_response(),
                        Err(e) => error::AppError::internal(&e.to_string()).into_response(),
                    }
                }
            }
        }

        Endpoint::UploadStart { ns } => {
            if let Some(digest) = p("digest") {
                if !body.is_empty() {
                    handlers::blob::put(&state, ns, digest, &params, &headers, &body)
                        .await
                        .into_response()
                } else {
                    let mount = p("mount");
                    handlers::upload::start(&state, ns, mount)
                        .await
                        .into_response()
                }
            } else {
                let mount = p("mount");
                handlers::upload::start(&state, ns, mount)
                    .await
                    .into_response()
            }
        }
        Endpoint::UploadChunk { id } => {
            let range_start = headers
                .get("content-range")
                .and_then(|v| v.to_str().ok())
                .and_then(handlers::upload::parse_range_start);
            handlers::upload::chunk(&state, id, range_start, &body)
                .await
                .into_response()
        }
        Endpoint::UploadStatus { id } => {
            handlers::upload::recovery(&state, id).await.into_response()
        }
        Endpoint::UploadComplete { id } => {
            let kappa = p("kappa").or_else(|| p("digest")).unwrap_or("");
            let range_start = headers
                .get("content-range")
                .and_then(|v| v.to_str().ok())
                .and_then(handlers::upload::parse_range_start);
            handlers::upload::complete(&state, id, kappa, range_start, &body)
                .await
                .into_response()
        }
        Endpoint::UploadCancel { id } => handlers::upload::cancel(&state, id).into_response(),

        Endpoint::ManifestPut { ns, tag } => {
            let mut manifest_params = params.clone();
            if let Some(ct) = headers.get("content-type").and_then(|v| v.to_str().ok()) {
                manifest_params
                    .entry("_content_type".to_string())
                    .or_default()
                    .push(ct.to_string());
            }
            handlers::tag::manifest_put(&state, ns, tag, &manifest_params, &body)
                .await
                .into_response()
        }
        Endpoint::ManifestHead { ns, version } => handlers::tag::manifest_head(&state, ns, version)
            .await
            .into_response(),
        Endpoint::ManifestGet { ns, version } => handlers::tag::manifest_get(&state, ns, version)
            .await
            .into_response(),
        Endpoint::ManifestDelete { ns, tag } => handlers::tag::manifest_delete(&state, ns, tag)
            .await
            .into_response(),
        Endpoint::TagDeletePrefix { ns } => {
            let prefix = p("prefix").unwrap_or("");
            if prefix.is_empty() {
                error::AppError::NameInvalid("missing prefix parameter".to_string()).into_response()
            } else {
                let s = state.store.clone();
                let n = ns.to_string();
                let pfx = prefix.to_string();
                match tokio::task::spawn_blocking(move || s.tag_delete_prefix(&n, &pfx)).await {
                    Ok(Ok(count)) => (StatusCode::OK, Json(serde_json::json!({"deleted": count})))
                        .into_response(),
                    Ok(Err(e)) => error::AppError::Store(e).into_response(),
                    Err(e) => error::AppError::internal(&e.to_string()).into_response(),
                }
            }
        }
        Endpoint::TagCreate { ns } => match method_str {
            "POST" => {
                let v: Result<serde_json::Value, _> = serde_json::from_slice(&body);
                match v {
                    Ok(v) => {
                        let name = v["name"].as_str().unwrap_or("");
                        let kappa = v["kappa"].as_str().unwrap_or("");
                        if name.is_empty() || kappa.is_empty() {
                            error::AppError::NameInvalid(
                                "missing name or kappa in body".to_string(),
                            )
                            .into_response()
                        } else {
                            let s = state.store.clone();
                            let n = ns.to_string();
                            let nm = name.to_string();
                            let k = kappa.to_string();
                            match tokio::task::spawn_blocking({
                                let s = s.clone();
                                let k = k.clone();
                                move || s.exists(&k)
                            })
                            .await
                            {
                                Ok(Ok(true)) => {}
                                _ => return error::AppError::TagContentAbsent.into_response(),
                            }
                            match tokio::task::spawn_blocking(move || s.tag_set(&n, &nm, &k)).await
                            {
                                Ok(Ok(())) => {
                                    (StatusCode::CREATED, [("content-length", "0".to_string())])
                                        .into_response()
                                }
                                Ok(Err(e)) => error::AppError::Store(e).into_response(),
                                Err(e) => error::AppError::internal(&e.to_string()).into_response(),
                            }
                        }
                    }
                    Err(e) => error::AppError::internal(&e.to_string()).into_response(),
                }
            }
            "GET" => match p("name") {
                Some(name) => {
                    let s = state.store.clone();
                    let n = ns.to_string();
                    let nm = name.to_string();
                    match tokio::task::spawn_blocking(move || s.tag_get(&n, &nm)).await {
                        Ok(Ok(Some(val))) => {
                            let body = serde_json::json!({"name": name, "kappa": val});
                            (StatusCode::OK, [("x-kappa-label", val)], Json(body)).into_response()
                        }
                        Ok(Ok(None)) => error::AppError::TagUnknown.into_response(),
                        Ok(Err(e)) => error::AppError::Store(e).into_response(),
                        Err(e) => error::AppError::internal(&e.to_string()).into_response(),
                    }
                }
                None => error::AppError::NameInvalid("missing name parameter".to_string())
                    .into_response(),
            },
            "DELETE" => match p("name") {
                Some(name) => {
                    let s = state.store.clone();
                    let n = ns.to_string();
                    let nm = name.to_string();
                    match tokio::task::spawn_blocking(move || s.tag_delete(&n, &nm)).await {
                        Ok(Ok(true)) => StatusCode::ACCEPTED.into_response(),
                        Ok(Ok(false)) => error::AppError::TagUnknown.into_response(),
                        Ok(Err(e)) => error::AppError::Store(e).into_response(),
                        Err(e) => error::AppError::internal(&e.to_string()).into_response(),
                    }
                }
                None => error::AppError::NameInvalid("missing name parameter".to_string())
                    .into_response(),
            },
            _ => error::AppError::NameInvalid("method not allowed".to_string()).into_response(),
        },
        Endpoint::TagBatch { ns } => handlers::tag::tag_batch(&state, ns, &body)
            .await
            .into_response(),
        Endpoint::TagList { ns } => {
            if let Some(prefix) = p("prefix") {
                let s = state.store.clone();
                let n = ns.to_string();
                let pfx = prefix.to_string();
                match tokio::task::spawn_blocking(move || s.tag_list_prefix(&n, &pfx)).await {
                    Ok(Ok(entries)) => {
                        let names: Vec<&str> = entries.iter().map(|t| t.name.as_str()).collect();
                        (
                            StatusCode::OK,
                            Json(serde_json::json!({"name": ns, "tags": names})),
                        )
                            .into_response()
                    }
                    Ok(Err(e)) => error::AppError::Store(e).into_response(),
                    Err(e) => error::AppError::internal(&e.to_string()).into_response(),
                }
            } else {
                handlers::tag::tag_list(&state, ns, &params)
                    .await
                    .into_response()
            }
        }
        Endpoint::TagGet { ns, name } => {
            let raw = p("raw") == Some("true");
            handlers::tag::tag_get(&state, ns, name, raw)
                .await
                .into_response()
        }
        Endpoint::TagPut { ns, name } => {
            let kappa = p("kappa").unwrap_or("");
            let symref = p("symref");
            let if_match = headers.get("if-match").and_then(|v| v.to_str().ok());
            let if_none_match = headers.get("if-none-match").and_then(|v| v.to_str().ok());
            handlers::tag::tag_put(&state, ns, name, kappa, symref, if_match, if_none_match)
                .await
                .into_response()
        }

        Endpoint::Referrers { ns, digest } => {
            handlers::referrers::list(&state, ns, digest, &params)
                .await
                .into_response()
        }

        Endpoint::EdgePut { ns } => handlers::edge::put(&state, ns, &body).await.into_response(),
        Endpoint::EdgeQuery { ns, node } => {
            let direction = p("direction").unwrap_or("outbound");
            let relation = p("relation");
            handlers::edge::query(&state, ns, node, direction, relation, &params)
                .await
                .into_response()
        }
        Endpoint::EdgeDelete { ns, kappa } => handlers::edge::delete(&state, ns, kappa)
            .await
            .into_response(),
        Endpoint::EdgeDiff { ns } => handlers::edge::diff(&state, ns, &body)
            .await
            .into_response(),

        Endpoint::Reconcile { ns } => handlers::reconcile::handle(&state, ns, &body)
            .await
            .into_response(),

        Endpoint::BundleCreate { ns } => handlers::bundle::create(&state, ns, &body)
            .await
            .into_response(),
        Endpoint::BundleIngest { ns } => handlers::bundle::ingest(&state, ns, &body)
            .await
            .into_response(),

        Endpoint::TransactionBegin { ns } => handlers::transaction::begin(&state, ns)
            .await
            .into_response(),
        Endpoint::TransactionPut { ns, id, kappa } => {
            handlers::transaction::put(&state, ns, id, kappa, &body)
                .await
                .into_response()
        }
        Endpoint::TransactionCommit { ns, id } => handlers::transaction::commit(&state, ns, id)
            .await
            .into_response(),
        Endpoint::TransactionAbort { ns, id } => handlers::transaction::abort(&state, ns, id)
            .await
            .into_response(),

        Endpoint::Compose { ns, op } => handlers::compose::compose(&state, ns, op, &body)
            .await
            .into_response(),
        Endpoint::Witness { ns, kappa } => handlers::compose::witness(&state, ns, kappa)
            .await
            .into_response(),

        Endpoint::SchemaPut { ns, scope } => handlers::schema::register(&state, ns, scope, &body)
            .await
            .into_response(),
        Endpoint::SchemaGet { ns, scope } => handlers::schema::get(&state, ns, scope)
            .await
            .into_response(),
        Endpoint::SchemaList { ns } => handlers::schema::list(&state, ns).await.into_response(),

        Endpoint::GcPin { ns } => handlers::gc::pin(&state, ns, &body).await.into_response(),
        Endpoint::GcUnpin { ns } => handlers::gc::unpin(&state, ns, &body).await.into_response(),
        Endpoint::GcSweep { ns } => handlers::gc::sweep(&state, ns).await.into_response(),
        Endpoint::GcStatus { ns } => handlers::gc::status(&state, ns).await.into_response(),

        Endpoint::FilterPut { ns, scope } => handlers::filter::register(&state, ns, scope, &body)
            .await
            .into_response(),
        Endpoint::FilterList { ns } => handlers::filter::list(&state, ns).await.into_response(),
        Endpoint::FilterDelete { ns, kappa } => handlers::filter::delete(&state, ns, kappa)
            .await
            .into_response(),

        Endpoint::SequenceNext { ns, name } => {
            let s = state.store.clone();
            let n = ns.to_string();
            let nm = name.to_string();
            match tokio::task::spawn_blocking(move || s.sequence_next(&n, &nm)).await {
                Ok(Ok(val)) => (
                    StatusCode::OK,
                    Json(serde_json::json!({"name": name, "value": val})),
                )
                    .into_response(),
                _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        }
        Endpoint::SequenceCurrent { ns, name } => {
            let s = state.store.clone();
            let n = ns.to_string();
            let nm = name.to_string();
            match tokio::task::spawn_blocking(move || s.sequence_current(&n, &nm)).await {
                Ok(Ok(val)) => (
                    StatusCode::OK,
                    Json(serde_json::json!({"name": name, "value": val})),
                )
                    .into_response(),
                _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        }
        Endpoint::CascadeDelete { ns } => {
            let v: Result<serde_json::Value, _> = serde_json::from_slice(&body);
            match v {
                Ok(v) => {
                    let prefix = v["prefix"].as_str().map(String::from);
                    let roots: Vec<String> = v["roots"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    let rels: Vec<String> = v["relations"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    let s = state.store.clone();
                    let n = ns.to_string();
                    match tokio::task::spawn_blocking(move || {
                        let rel_refs: Vec<&str> = rels.iter().map(|s| s.as_str()).collect();
                        if let Some(ref pfx) = prefix {
                            s.remove_reachable_from_prefix(&n, pfx, &rel_refs)
                        } else {
                            s.remove_reachable(&n, &roots, &rel_refs)
                        }
                    })
                    .await
                    {
                        Ok(Ok(report)) => (StatusCode::OK, Json(report)).into_response(),
                        Ok(Err(e)) => error::AppError::Store(e).into_response(),
                        Err(e) => error::AppError::internal(&e.to_string()).into_response(),
                    }
                }
                Err(e) => error::AppError::internal(&e.to_string()).into_response(),
            }
        }

        Endpoint::NamespaceRoot { ns } => {
            let s = state.store.clone();
            let ns_str = ns.to_string();
            match tokio::task::spawn_blocking(move || s.namespace_root(&ns_str)).await {
                Ok(Ok((root, count))) => {
                    let want_signed = p("signed") == Some("true");
                    if want_signed {
                        if let (Some(ref root_kappa), Some(ref signer)) = (&root, &state.signer) {
                            let timestamp = chrono::Utc::now().to_rfc3339();
                            let message = format!("{ns}\n{root_kappa}\n{timestamp}");
                            let sig = signer.sign(message.as_bytes()).unwrap_or_default();
                            let signed = crate::crypto::SignedRoot {
                                namespace: ns.to_string(),
                                root: root_kappa.clone(),
                                timestamp,
                                algorithm: signer.algorithm().to_string(),
                                public_key: signer.public_key_bytes(),
                                signature: sig,
                                attestation: None,
                            };
                            return (StatusCode::OK, Json(signed)).into_response();
                        }
                    }
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({"root": root, "count": count})),
                    )
                        .into_response()
                }
                _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        }
        Endpoint::NamespaceProof { ns, name } => {
            let s = state.store.clone();
            let ns_str = ns.to_string();
            let n = name.to_string();
            match tokio::task::spawn_blocking(move || s.namespace_proof(&ns_str, &n)).await {
                Ok(Ok(Some(proof))) => (StatusCode::OK, Json(proof)).into_response(),
                Ok(Ok(None)) => error::AppError::TagUnknown.into_response(),
                _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        }

        Endpoint::NotFound => {
            error::AppError::NameInvalid("unknown route".to_string()).into_response()
        }
    };

    if let Some(snap) = rate_snapshot {
        ratelimit::limiter::attach_headers(&mut response, &snap);
    }

    response
}
