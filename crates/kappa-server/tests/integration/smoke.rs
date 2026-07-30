//! Smoke tests: start kappa-server, hit every route category once.
//!
//! These are not exhaustive -- the external conformance suite is exhaustive.
//! These prove routing works and handlers respond before conformance runs.
//! test_multipart_namespace proves multi-segment namespace routing ({*ns}).

use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// RAII guard that kills and waits on the server child process when
/// dropped. Prevents zombie processes on test success, failure, or panic.
/// Also owns the TempDir so the store root is cleaned up after the child exits.
struct ServerGuard {
    child: Child,
    tmp: tempfile::TempDir,
}

impl ServerGuard {
    /// The store root path, for tests that need to inspect the filesystem.
    #[allow(dead_code)]
    fn store_root(&self) -> &std::path::Path {
        self.tmp.path()
    }
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn pick_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn start_server() -> (ServerGuard, String) {
    let port = pick_port();
    let tmp = tempfile::tempdir().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_kappa-server"))
        .env("KAPPA_LISTEN_ADDR", format!("127.0.0.1:{}", port))
        .env("KAPPA_STORE_ROOT", tmp.path().to_str().unwrap())
        .env("KAPPA_RATELIMIT_READ_PERIOD_MS", "0")
        .env("KAPPA_RATELIMIT_WRITE_PERIOD_MS", "0")
        .env("KAPPA_RATELIMIT_ADMIN_PERIOD_MS", "0")
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start kappa-server");

    let base = format!("http://127.0.0.1:{}", port);
    let guard = ServerGuard { child, tmp };

    // Poll readiness -- guard ensures cleanup on panic
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if client.get(format!("{}/_status", base)).send().is_ok() {
            return (guard, base);
        }
    }
    // guard drops here, kills child, cleans tmp
    panic!("kappa-server did not become ready within 5 seconds");
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

fn sha256_digest(content: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(content);
    format!("sha256:{}", hex::encode(hash))
}

#[test]
fn test_version_check() {
    let (guard, base) = start_server();
    let resp = client().get(format!("{}/v2/", base)).send().unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().unwrap();
    assert!(body.contains("kappa-distribution"), "body: {body}");
    drop(guard);
}

#[test]
fn test_status() {
    let (guard, base) = start_server();
    let resp = client().get(format!("{}/_status", base)).send().unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().unwrap(), "ok");
    drop(guard);
}

#[test]
fn test_health_ready() {
    let (guard, base) = start_server();
    let resp = client()
        .get(format!("{}/v2/_health/ready", base))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    drop(guard);
}

#[test]
fn test_blob_put_get() {
    let (guard, base) = start_server();
    let content = b"smoke test blob content";
    let digest = sha256_digest(content);
    let url = format!("{}/v2/test/blobs/{}", base, digest);

    let put_resp = client().put(&url).body(content.to_vec()).send().unwrap();
    assert_eq!(
        put_resp.status(),
        201,
        "PUT blob: {}",
        put_resp.text().unwrap_or_default()
    );

    let get_resp = client().get(&url).send().unwrap();
    assert_eq!(get_resp.status(), 200);
    assert_eq!(get_resp.bytes().unwrap().as_ref(), content);
    drop(guard);
}

#[test]
fn test_blob_head() {
    let (guard, base) = start_server();
    let content = b"head test content";
    let digest = sha256_digest(content);
    let url = format!("{}/v2/test/blobs/{}", base, digest);

    client().put(&url).body(content.to_vec()).send().unwrap();

    let head_resp = client().head(&url).send().unwrap();
    assert_eq!(head_resp.status(), 200);
    let cl = head_resp
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(cl, content.len().to_string());
    drop(guard);
}

#[test]
fn test_blob_not_found() {
    let (guard, base) = start_server();
    let url = format!("{}/v2/test/blobs/sha256:{}", base, "0".repeat(64));
    let resp = client().get(&url).send().unwrap();
    assert_eq!(resp.status(), 404);
    drop(guard);
}

#[test]
fn test_manifest_put_get() {
    let (guard, base) = start_server();
    let content =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#;

    let put_resp = client()
        .put(format!("{}/v2/test/manifests/latest", base))
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(content.to_vec())
        .send()
        .unwrap();
    assert_eq!(
        put_resp.status(),
        201,
        "PUT manifest: {}",
        put_resp.text().unwrap_or_default()
    );

    let get_resp = client()
        .get(format!("{}/v2/test/manifests/latest", base))
        .send()
        .unwrap();
    assert_eq!(get_resp.status(), 200);
    drop(guard);
}

#[test]
fn test_tag_list() {
    let (guard, base) = start_server();
    let content = br#"{"schemaVersion":2}"#;
    client()
        .put(format!("{}/v2/test/manifests/v1", base))
        .body(content.to_vec())
        .send()
        .unwrap();

    let resp = client()
        .get(format!("{}/v2/test/tags/list", base))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().unwrap();
    assert!(body["tags"].is_array());
    drop(guard);
}

#[test]
fn test_upload_start_cancel() {
    let (guard, base) = start_server();
    let start_resp = client()
        .post(format!("{}/v2/test/blobs/uploads/", base))
        .send()
        .unwrap();
    assert_eq!(
        start_resp.status(),
        202,
        "upload start: {}",
        start_resp.text().unwrap_or_default()
    );
    drop(guard);
}

#[test]
fn test_multipart_namespace() {
    let (guard, base) = start_server();
    let content = b"multipart namespace test";
    let digest = sha256_digest(content);

    let url = format!("{}/v2/org/repo/name/blobs/{}", base, digest);
    let resp = client().put(&url).body(content.to_vec()).send().unwrap();
    assert_eq!(
        resp.status(),
        201,
        "multipart namespace PUT failed: {}",
        resp.text().unwrap_or_default()
    );

    let get_resp = client().get(&url).send().unwrap();
    assert_eq!(get_resp.status(), 200);
    assert_eq!(get_resp.bytes().unwrap().as_ref(), content);
    drop(guard);
}

#[test]
fn test_edge_put_query() {
    let (guard, base) = start_server();
    let src_content = b"edge source blob";
    let tgt_content = b"edge target blob";
    let src_digest = sha256_digest(src_content);
    let tgt_digest = sha256_digest(tgt_content);

    client()
        .put(format!("{}/v2/test/blobs/{}", base, src_digest))
        .body(src_content.to_vec())
        .send()
        .unwrap();
    client()
        .put(format!("{}/v2/test/blobs/{}", base, tgt_digest))
        .body(tgt_content.to_vec())
        .send()
        .unwrap();

    let edge_body = serde_json::json!({
        "source": src_digest,
        "relation": "owns",
        "target": tgt_digest,
    });
    let put_resp = client()
        .put(format!("{}/v2/test/edges/", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&edge_body).unwrap())
        .send()
        .unwrap();
    assert_eq!(
        put_resp.status(),
        201,
        "edge PUT: {}",
        put_resp.text().unwrap_or_default()
    );

    let query_resp = client()
        .get(format!("{}/v2/test/edges/{}", base, src_digest))
        .send()
        .unwrap();
    assert_eq!(query_resp.status(), 200);
    let body: serde_json::Value = query_resp.json().unwrap();
    assert!(body["edges"].is_array());
    drop(guard);
}

#[test]
fn test_sequence_next() {
    let (guard, base) = start_server();
    let resp = client()
        .post(format!("{}/v2/test/_sequence/counter1/next", base))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().unwrap();
    assert_eq!(body["value"], 1);
    drop(guard);
}

#[test]
fn test_namespace_root() {
    let (guard, base) = start_server();
    let resp = client()
        .get(format!("{}/v2/test/_root", base))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    drop(guard);
}

#[test]
fn test_filter_register() {
    let (guard, base) = start_server();
    let resp = client()
        .put(format!("{}/v2/test/filters/test_scope", base))
        .body(b"deny:forbidden".to_vec())
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        201,
        "filter register: {}",
        resp.text().unwrap_or_default()
    );
    drop(guard);
}

#[test]
fn test_schema_register() {
    let (guard, base) = start_server();
    let schema = serde_json::json!({
        "format": "json-schema",
        "scope": "test",
        "validation": {"type": "object"},
    });
    let resp = client()
        .put(format!("{}/v2/test/schemas/test_scope", base))
        .body(serde_json::to_string(&schema).unwrap())
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        201,
        "schema register: {}",
        resp.text().unwrap_or_default()
    );
    drop(guard);
}

#[test]
fn test_gc_sweep() {
    let (guard, base) = start_server();
    let resp = client()
        .post(format!("{}/v2/test/gc/sweep", base))
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        202,
        "gc sweep: {}",
        resp.text().unwrap_or_default()
    );
    drop(guard);
}

#[test]
fn test_events_sse() {
    let (guard, base) = start_server();
    let resp = client()
        .get(format!("{}/v2/test/_events", base))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "text/event-stream"
    );
    drop(guard);
}

#[test]
fn test_compose_g2() {
    let (guard, base) = start_server();
    let a = b"operand-alpha";
    let b_content = b"operand-beta";
    let ka = sha256_digest(a);
    let kb = sha256_digest(b_content);
    client()
        .put(format!("{}/v2/test/blobs/{}", base, ka))
        .body(a.to_vec())
        .send()
        .unwrap();
    client()
        .put(format!("{}/v2/test/blobs/{}", base, kb))
        .body(b_content.to_vec())
        .send()
        .unwrap();

    let compose_body = serde_json::json!({"operands": [ka, kb]});
    let resp = client()
        .post(format!("{}/v2/test/compose/g2", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&compose_body).unwrap())
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "compose g2: {}",
        resp.text().unwrap_or_default()
    );
    drop(guard);
}

#[test]
fn test_bundle_create() {
    let (guard, base) = start_server();
    let content = b"bundle-test-blob";
    let k = sha256_digest(content);
    client()
        .put(format!("{}/v2/test/blobs/{}", base, k))
        .body(content.to_vec())
        .send()
        .unwrap();

    let bundle_body = serde_json::json!({"kappas": [k], "delta": false});
    let resp = client()
        .post(format!("{}/v2/test/_bundle/create", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&bundle_body).unwrap())
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "bundle create: {}",
        resp.text().unwrap_or_default()
    );
    drop(guard);
}

#[test]
fn test_cascade() {
    let (guard, base) = start_server();
    let content = b"cascade-test";
    let k = sha256_digest(content);
    client()
        .put(format!("{}/v2/test/blobs/{}", base, k))
        .body(content.to_vec())
        .send()
        .unwrap();

    let cascade_body = serde_json::json!({"roots": [k]});
    let resp = client()
        .post(format!("{}/v2/test/blobs/_cascade", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&cascade_body).unwrap())
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "cascade: {}",
        resp.text().unwrap_or_default()
    );
    drop(guard);
}

#[test]
fn test_reconcile() {
    let (guard, base) = start_server();
    let recon_body = serde_json::json!({
        "type": "fingerprint",
        "lower": "",
        "upper": "~",
        "fingerprint": "0".repeat(64),
    });
    let resp = client()
        .post(format!("{}/v2/test/_reconcile", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&recon_body).unwrap())
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "reconcile: {}",
        resp.text().unwrap_or_default()
    );
    drop(guard);
}

#[test]
fn test_transaction_lifecycle() {
    let (guard, base) = start_server();

    let begin_resp = client()
        .post(format!("{}/v2/test/_transaction/begin", base))
        .send()
        .unwrap();
    assert_eq!(
        begin_resp.status(),
        201,
        "txn begin: {}",
        begin_resp.text().unwrap_or_default()
    );
    drop(guard);
}

#[test]
fn test_openapi_json() {
    let (guard, base) = start_server();
    let resp = client()
        .get(format!("{}/openapi.json", base))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(ct.contains("application/json"), "content-type: {}", ct);
    let body: serde_json::Value = resp.json().unwrap();
    assert_eq!(body["openapi"], "3.1.0");
    assert!(body["paths"].as_object().unwrap().len() >= 50);
    drop(guard);
}

#[test]
fn test_docs_scalar() {
    let (guard, base) = start_server();
    let resp = client()
        .get(format!("{}/docs", base))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(ct.contains("text/html"), "content-type: {}", ct);
    let body = resp.text().unwrap();
    assert!(body.contains("api-reference"), "missing Scalar script tag");
    assert!(body.contains("openapi"), "missing OpenAPI spec in HTML");
    drop(guard);
}
