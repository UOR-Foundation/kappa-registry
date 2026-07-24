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

    let endpoint = routes::parse(method_str, path);
    tracing::debug!(
        method = method_str,
        path = path,
        uri = uri_str.as_str(),
        params = ?params,
        endpoint = ?endpoint,
        "dispatch"
    );

    // Tiered rate limiting: check the appropriate bucket for this
    // endpoint's operation class and the client's IP.
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
        Endpoint::BlobGet { ns, kappa } => {
            handlers::blob::get(&state, ns, kappa).await.into_response()
        }
        Endpoint::BlobHead { ns, kappa } => handlers::blob::head(&state, ns, kappa)
            .await
            .into_response(),
        Endpoint::BlobDelete { ns, kappa } => handlers::blob::delete(&state, ns, kappa)
            .await
            .into_response(),
        Endpoint::BlobList { ns } => {
            let prefix = params.get("prefix").map(|s| s.as_str()).unwrap_or("");
            handlers::blob::list(&state, ns, prefix)
                .await
                .into_response()
        }
        Endpoint::MetaList { ns } => {
            let key = params.get("key").map(|s| s.as_str()).unwrap_or("");
            let value = params.get("value").map(|s| s.as_str()).unwrap_or("");
            handlers::blob::list_by_meta(&state, ns, key, value)
                .await
                .into_response()
        }

        Endpoint::UploadStart { ns } => {
            // Single-POST blob push: POST with ?digest= and a non-empty body
            if let Some(digest) = params.get("digest") {
                if !body.is_empty() {
                    handlers::blob::put(&state, ns, digest, &params, &headers, &body)
                        .await
                        .into_response()
                } else {
                    let mount = params.get("mount").map(|s| s.as_str());
                    handlers::upload::start(&state, ns, mount)
                        .await
                        .into_response()
                }
            } else {
                let mount = params.get("mount").map(|s| s.as_str());
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
            let kappa = params
                .get("kappa")
                .or_else(|| params.get("digest"))
                .map(|s| s.as_str())
                .unwrap_or("");
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
                manifest_params.insert("_content_type".to_string(), ct.to_string());
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
        Endpoint::TagBatch { ns } => handlers::tag::tag_batch(&state, ns, &body)
            .await
            .into_response(),
        Endpoint::TagList { ns } => handlers::tag::tag_list(&state, ns, &params)
            .await
            .into_response(),
        Endpoint::TagGet { ns, name } => {
            let raw = params.get("raw").map(|s| s == "true").unwrap_or(false);
            handlers::tag::tag_get(&state, ns, name, raw)
                .await
                .into_response()
        }
        Endpoint::TagPut { ns, name } => {
            let kappa = params.get("kappa").map(|s| s.as_str()).unwrap_or("");
            let symref = params.get("symref").map(|s| s.as_str());
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
            let direction = params
                .get("direction")
                .map(|s| s.as_str())
                .unwrap_or("outbound");
            let relation = params.get("relation").map(|s| s.as_str());
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

        Endpoint::NamespaceRoot { ns } => {
            let s = state.store.clone();
            let p = ns.to_string();
            match tokio::task::spawn_blocking(move || s.namespace_root(&p)).await {
                Ok(Ok((root, count))) => {
                    let want_signed = params.get("signed").map(|v| v == "true").unwrap_or(false);
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
                    let body = serde_json::json!({"root": root, "count": count});
                    (StatusCode::OK, Json(body)).into_response()
                }
                _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        }
        Endpoint::NamespaceProof { ns, name } => {
            let s = state.store.clone();
            let p = ns.to_string();
            let n = name.to_string();
            match tokio::task::spawn_blocking(move || s.namespace_proof(&p, &n)).await {
                Ok(Ok(Some(proof))) => (StatusCode::OK, Json(proof)).into_response(),
                Ok(Ok(None)) => crate::error::AppError::TagUnknown.into_response(),
                _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        }

        Endpoint::NotFound => {
            crate::error::AppError::NameInvalid("unknown route".to_string()).into_response()
        }
    };

    // Attach rate limit headers to successful responses.
    if let Some(snap) = rate_snapshot {
        ratelimit::limiter::attach_headers(&mut response, &snap);
    }

    response
}
