//! Cucumber integration runner for every public registry interface.
//!
//! Enforced scenarios must have implemented steps and pass. This keeps the
//! Gherkin suite honest as interfaces evolve.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use cucumber::{given, then, when, World};
use http_body_util::BodyExt;
use kappa_registry::handlers::upload::SessionStore;
use kappa_registry::store::fs::FsStore;
use kappa_registry::transaction::TransactionManager;
use kappa_registry::AppState;
use tempfile::TempDir;
use tower::util::ServiceExt;

#[derive(Default, cucumber::World)]
struct BddWorld {
    app: Option<Router>,
    data_dir: Option<TempDir>,
    status: Option<StatusCode>,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl std::fmt::Debug for BddWorld {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BddWorld")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("body_length", &self.body.len())
            .finish_non_exhaustive()
    }
}

fn fresh_app() -> (Router, TempDir) {
    let data_dir = TempDir::new().expect("create BDD store directory");
    let store = Arc::new(FsStore::new(data_dir.path().to_path_buf()).expect("create BDD store"));
    let transactions = Arc::new(TransactionManager::new(
        data_dir.path().to_path_buf(),
        64,
        64 * 1024 * 1024,
        256 * 1024 * 1024,
        3600,
    ));
    let state = AppState {
        store,
        sessions: Arc::new(SessionStore::new()),
        transactions,
        rate_limiter: None,
        signer: None,
        max_blob_size: 64 * 1024 * 1024,
        upload_timeout_secs: 3600,
    };
    (kappa_registry::app(state), data_dir)
}

async fn get(w: &mut BddWorld, uri: &str) {
    let app = w.app.as_ref().expect("scenario must create an app").clone();
    let request = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("build BDD request");
    let response = app.oneshot(request).await.expect("execute BDD request");
    w.status = Some(response.status());
    w.content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    w.body = response
        .into_body()
        .collect()
        .await
        .expect("read BDD response")
        .to_bytes()
        .to_vec();
}

#[given("a fresh registry application")]
fn fresh_registry(w: &mut BddWorld) {
    let (app, data_dir) = fresh_app();
    w.app = Some(app);
    w.data_dir = Some(data_dir);
}

#[when("I request the registry version")]
async fn request_version(w: &mut BddWorld) {
    get(w, "/v2/").await;
}

#[when("I request the OpenAPI document")]
async fn request_openapi(w: &mut BddWorld) {
    get(w, "/openapi.json").await;
}

#[when("I open the Scalar API reference")]
async fn open_scalar(w: &mut BddWorld) {
    get(w, "/docs").await;
}

#[when("I request the Scalar JavaScript asset")]
async fn request_scalar_asset(w: &mut BddWorld) {
    get(w, "/docs/scalar.js").await;
}

#[then("the response status is 200")]
fn response_is_successful(w: &mut BddWorld) {
    assert_eq!(w.status, Some(StatusCode::OK));
}

#[then("the response identifies the kappa distribution protocol")]
fn response_identifies_protocol(w: &mut BddWorld) {
    let body = String::from_utf8_lossy(&w.body);
    assert!(body.contains("kappa-distribution"), "response body: {body}");
}

#[then("the response is a valid OpenAPI document")]
fn response_is_openapi(w: &mut BddWorld) {
    let document: serde_json::Value =
        serde_json::from_slice(&w.body).expect("OpenAPI response must be JSON");
    assert_eq!(document["openapi"], "3.1.0");
    assert!(document["paths"].is_object());
    assert_eq!(w.content_type.as_deref(), Some("application/json"));
}

#[then("the document includes the Scalar documentation routes")]
fn document_includes_scalar_routes(w: &mut BddWorld) {
    let document: serde_json::Value = serde_json::from_slice(&w.body).unwrap();
    assert!(document["paths"]["/docs"]["get"].is_object());
    assert!(document["paths"]["/docs/scalar.js"]["get"].is_object());
}

#[then("the response is a Scalar HTML page")]
fn response_is_scalar_html(w: &mut BddWorld) {
    let body = String::from_utf8_lossy(&w.body);
    assert!(w
        .content_type
        .as_deref()
        .is_some_and(|value| value.starts_with("text/html")));
    assert!(body.contains("Scalar API Reference"));
    assert!(body.contains("/docs/scalar.js"));
    assert!(body.contains("/openapi.json"));
}

#[then("the response is a JavaScript asset")]
fn response_is_javascript(w: &mut BddWorld) {
    assert_eq!(w.content_type.as_deref(), Some("application/javascript"));
    assert!(w.body.len() > 1_000, "Scalar asset is unexpectedly small");
}

#[tokio::main]
async fn main() {
    BddWorld::cucumber()
        .fail_on_skipped_with(|feature, _rule, scenario| {
            feature
                .tags
                .iter()
                .chain(scenario.tags.iter())
                .any(|tag| tag.trim_start_matches('@') == "status:enforced")
        })
        .run_and_exit(concat!(env!("CARGO_MANIFEST_DIR"), "/features"))
        .await;
}
