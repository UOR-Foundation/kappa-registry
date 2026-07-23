pub mod auth;
pub mod config;
pub mod error;
pub mod handlers;
pub mod kappa;
pub mod routes;
pub mod store;

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use tower_http::trace::TraceLayer;

use crate::handlers::upload::SessionStore;
use crate::routes::Endpoint;
use crate::store::fs::FsStore;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<FsStore>,
    pub sessions: Arc<SessionStore>,
    pub max_blob_size: usize,
    pub upload_timeout_secs: u64,
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .fallback(any(dispatch))
        .layer(middleware::map_response(add_warning_header))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub fn app_with_rate_limit(state: AppState, per_second: u64, burst: u32) -> Router {
    use tower_governor::governor::GovernorConfigBuilder;
    use tower_governor::key_extractor::GlobalKeyExtractor;
    use tower_governor::GovernorLayer;

    let governor_conf = GovernorConfigBuilder::default()
        .per_second(per_second)
        .burst_size(burst)
        .key_extractor(GlobalKeyExtractor)
        .finish()
        .unwrap();

    Router::new()
        .fallback(any(dispatch))
        .layer(middleware::map_response(add_warning_header))
        .layer(GovernorLayer::new(governor_conf))
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

    match routes::parse(method_str, path) {
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

        Endpoint::UploadStart { ns } => {
            let mount = params.get("mount").map(|s| s.as_str());
            handlers::upload::start(&state, ns, mount)
                .await
                .into_response()
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
            let kappa = params.get("kappa").map(|s| s.as_str()).unwrap_or("");
            handlers::upload::complete(&state, id, kappa, &body)
                .await
                .into_response()
        }
        Endpoint::UploadCancel { id } => handlers::upload::cancel(&state, id).into_response(),

        Endpoint::ManifestPut { ns, tag } => {
            handlers::tag::manifest_put(&state, ns, tag, &params, &body)
                .await
                .into_response()
        }
        Endpoint::ManifestGet { ns, version } => handlers::tag::manifest_get(&state, ns, version)
            .await
            .into_response(),
        Endpoint::ManifestDelete { ns, tag } => handlers::tag::manifest_delete(&state, ns, tag)
            .await
            .into_response(),
        Endpoint::TagList { ns } => handlers::tag::tag_list(&state, ns, &params)
            .await
            .into_response(),
        Endpoint::TagGet { ns, name } => handlers::tag::tag_get(&state, ns, name)
            .await
            .into_response(),
        Endpoint::TagPut { ns, name } => {
            let kappa = params.get("kappa").map(|s| s.as_str()).unwrap_or("");
            let if_match = headers.get("if-match").and_then(|v| v.to_str().ok());
            let if_none_match = headers.get("if-none-match").and_then(|v| v.to_str().ok());
            handlers::tag::tag_put(&state, ns, name, kappa, if_match, if_none_match)
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

        Endpoint::NotFound => {
            crate::error::AppError::NameInvalid("unknown route".to_string()).into_response()
        }
    }
}
