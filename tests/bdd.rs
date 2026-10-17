//! Cucumber integration runner for every public registry interface.
//!
//! Enforced scenarios must have implemented steps and pass. This keeps the
//! Gherkin suite honest as interfaces evolve.

use std::net::SocketAddr;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use cucumber::{World, given, then, when};
use http::StatusCode;
use tempfile::TempDir;

#[path = "bdd_authority.rs"]
mod authority;
#[path = "bdd_identity.rs"]
mod identity;
#[path = "bdd_multipart.rs"]
mod multipart;

/// Server diagnostics outlive the scenario's store directory so a failed
/// run can be diagnosed from the log files alone.
const SERVER_LOG_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tmp/logs/bdd-server");

struct RegistryProcess {
    child: Child,
    base_url: String,
    /// Holds the file the server reports its bound address through.
    _ready_dir: TempDir,
}

impl Drop for RegistryProcess {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                self.child.kill().expect("stop BDD server");
                self.child.wait().expect("reap BDD server");
            }
            Err(error) => panic!("inspect BDD server process: {error}"),
        }
    }
}

#[derive(Default, cucumber::World)]
struct BddWorld {
    app: Option<RegistryProcess>,
    data_dir: Option<TempDir>,
    status: Option<StatusCode>,
    content_type: Option<String>,
    body: Vec<u8>,
    blob_identity: Option<String>,
    blob_content: Vec<u8>,
    /// Node authority anchors observed by the authority scenarios, in
    /// rotation order: the first is the startup authority.
    authorities: Vec<String>,
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

async fn fresh_app() -> (RegistryProcess, TempDir) {
    let data_dir = TempDir::new().expect("create BDD store directory");
    std::fs::write(data_dir.path().join("encryption.key"), [67; 32])
        .expect("provision test encryption key");
    let process = start_app(&data_dir).await;
    (process, data_dir)
}

/// Start the server binary on a kernel-assigned loopback port. The server
/// reports the address it bound through a ready file; no port is reserved
/// and released first, so no concurrent process can take it in between.
async fn start_app(data_dir: &TempDir) -> RegistryProcess {
    static STARTED: AtomicU64 = AtomicU64::new(0);
    std::fs::create_dir_all(SERVER_LOG_DIR).expect("create BDD server log directory");
    let started_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after the epoch")
        .as_millis();
    let started = STARTED.fetch_add(1, Ordering::Relaxed);
    let diagnostics = std::path::PathBuf::from(SERVER_LOG_DIR)
        .join(format!("{started_ms}-{}-{started}.log", std::process::id()));
    let ready_dir = TempDir::new().expect("create BDD ready file directory");
    let ready_file = ready_dir.path().join("listen");
    // The server's tracing subscriber writes to stdout; panics and startup
    // failures write to stderr. Both streams land in one log.
    let stdout = std::fs::File::create(&diagnostics).expect("create BDD server diagnostics");
    let stderr = stdout.try_clone().expect("share BDD server diagnostics");
    let mut child = Command::new(env!("CARGO_BIN_EXE_kappa-server"))
        .env_clear()
        .env("KAPPA_LISTEN_ADDR", "127.0.0.1:0")
        .env("KAPPA_READY_FILE", &ready_file)
        .env("KAPPA_STORE_ROOT", data_dir.path())
        .env(
            "KAPPA_ENCRYPTION_KEY_FILE",
            data_dir.path().join("encryption.key"),
        )
        .env("KAPPA_DISK_PRESSURE_THRESHOLD_MB", "0")
        .env(
            "KAPPA_AUTH_TOKENS",
            format!(
                "bdd-multipart={}",
                kappa_store::Kappa::sha256(b"bdd-multipart-owner")
            ),
        )
        // The root-token delegate: authorized for `_root` administration
        // only through the delegation the node publishes for it.
        .env(
            "KAPPA_ROOT_TOKEN",
            format!(
                "{}={}",
                authority::ROOT_TOKEN,
                kappa_store::Kappa::sha256(b"bdd-root-delegate")
            ),
        )
        .env("RUST_LOG", "info")
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .expect("start real BDD registry server");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let address = loop {
        if let Some(status) = child.try_wait().expect("inspect startup") {
            let log = std::fs::read_to_string(&diagnostics).expect("read startup diagnostics");
            panic!(
                "BDD server exited with {status} before reporting ready; {}:\n{log}",
                diagnostics.display()
            );
        }
        if let Ok(reported) = std::fs::read_to_string(&ready_file) {
            break reported
                .parse::<SocketAddr>()
                .unwrap_or_else(|error| panic!("ready file holds {reported:?}: {error}"));
        }
        if tokio::time::Instant::now() >= deadline {
            child.kill().expect("stop BDD server");
            child.wait().expect("reap BDD server");
            let log = std::fs::read_to_string(&diagnostics).expect("read startup diagnostics");
            panic!(
                "BDD server reported no address; {}:\n{log}",
                diagnostics.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let mut process = RegistryProcess {
        child,
        base_url: format!("http://{address}"),
        _ready_dir: ready_dir,
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .expect("BDD readiness client");
    loop {
        if let Some(status) = process.child.try_wait().expect("inspect startup") {
            let log = std::fs::read_to_string(&diagnostics).expect("read startup diagnostics");
            panic!(
                "BDD server exited with {status}; {}:\n{log}",
                diagnostics.display()
            );
        }
        if client
            .get(format!("{}/_status", process.base_url))
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            return process;
        }
        if tokio::time::Instant::now() >= deadline {
            let log = std::fs::read_to_string(&diagnostics).expect("read startup diagnostics");
            panic!(
                "BDD server readiness timeout; {}:\n{log}",
                diagnostics.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn get(w: &mut BddWorld, uri: &str) {
    let app = w.app.as_ref().expect("scenario must create an app");
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("BDD HTTP client")
        .get(format!("{}{uri}", app.base_url))
        .send()
        .await
        .expect("execute public BDD request");
    w.status = Some(response.status());
    w.content_type = response
        .headers()
        .get("content-type")
        .map(|value| value.to_str().expect("valid Content-Type header"))
        .map(str::to_owned);
    w.body = response.bytes().await.expect("read BDD response").to_vec();
}

#[given("a fresh registry application")]
async fn fresh_registry(w: &mut BddWorld) {
    let (app, data_dir) = fresh_app().await;
    w.app = Some(app);
    w.data_dir = Some(data_dir);
}

#[when("I request the registry version")]
async fn request_version(w: &mut BddWorld) {
    get(w, "/v2/").await;
}

#[when("I upload a verified multichunk blob through HTTP")]
async fn upload_blob(w: &mut BddWorld) {
    let content: Vec<_> = (0..196625).map(|i| (i % 251) as u8).collect();
    let identity = kappa_store::Kappa::sha256(&content).to_string();
    let app = w.app.as_ref().expect("application");
    let response = reqwest::Client::new()
        .put(format!(
            "{}/v2/bdd-publication/blobs/{identity}",
            app.base_url
        ))
        .header("content-type", "application/octet-stream")
        .body(content.clone())
        .send()
        .await
        .expect("HTTP upload");
    let status = response.status();
    let digest = response.headers().get("docker-content-digest").cloned();
    let body = response.text().await.expect("upload response body");
    assert_eq!(status, StatusCode::CREATED, "upload response: {body}");
    assert_eq!(
        digest
            .expect("published digest")
            .to_str()
            .expect("digest header"),
        identity
    );
    w.blob_identity = Some(identity);
    w.blob_content = content;
}

#[when("the registry process is killed and restarted with the same store")]
async fn restart_registry(w: &mut BddWorld) {
    drop(w.app.take());
    w.app = Some(start_app(w.data_dir.as_ref().expect("retained store")).await);
}

#[then("the published blob and its range are exact through HTTP")]
async fn published_blob_reads(w: &mut BddWorld) {
    let app = w.app.as_ref().expect("application");
    let identity = w.blob_identity.as_ref().expect("published identity");
    let url = format!("{}/v2/bdd-publication/blobs/{identity}", app.base_url);
    let client = reqwest::Client::new();
    let response = client.get(&url).send().await.expect("HTTP read");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.bytes().await.expect("blob bytes").as_ref(),
        w.blob_content
    );
    let response = client
        .get(&url)
        .header("range", "bytes=65529-65563")
        .send()
        .await
        .expect("HTTP range");
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response.bytes().await.expect("range bytes").as_ref(),
        &w.blob_content[65529..65564]
    );
}

#[when("I request the OpenAPI document")]
async fn request_openapi(w: &mut BddWorld) {
    get(w, "/openapi.json").await;
}

#[when("I subscribe with a malformed event cursor")]
async fn malformed_event_cursor(w: &mut BddWorld) {
    get(w, "/v2/_system/_events?since=invalid").await;
}

#[then("the event subscription rejects the cursor with status 400")]
fn cursor_rejected(w: &mut BddWorld) {
    assert_eq!(
        w.status,
        Some(StatusCode::BAD_REQUEST),
        "event response: {}",
        String::from_utf8_lossy(&w.body)
    );
    assert!(!w.body.is_empty());
}

#[then("the document describes event resume and resynchronization")]
fn event_contract_documented(w: &mut BddWorld) {
    let document: serde_json::Value = serde_json::from_slice(&w.body).expect("OpenAPI JSON");
    let operation = &document["paths"]["/v2/{namespace}/_events"]["get"];
    assert!(operation["responses"]["200"]["content"]["text/event-stream"].is_object());
    let parameters = operation["parameters"]
        .as_array()
        .expect("event parameters");
    for name in ["since", "prefix", "Last-Event-ID"] {
        assert!(parameters.iter().any(|parameter| parameter["name"] == name));
    }
    assert!(
        operation["description"]
            .as_str()
            .expect("description")
            .contains("resync_required")
    );
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
    assert_eq!(
        w.status,
        Some(StatusCode::OK),
        "response: {}",
        String::from_utf8_lossy(&w.body)
    );
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
    assert!(
        w.content_type
            .as_deref()
            .is_some_and(|value| value.starts_with("text/html"))
    );
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
        .run_and_exit(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../features/suites"
        ))
        .await;
}
