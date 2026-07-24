use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use kappa_registry::handlers::upload::SessionStore;
use kappa_registry::kappa::KappaLabel;
use kappa_registry::store::fs::FsStore;
use kappa_registry::transaction::TransactionManager;
use kappa_registry::AppState;

// Test blob fixtures - computed once, used everywhere.
pub struct TestBlob {
    pub name: &'static str,
    pub content: &'static [u8],
    pub sha256: String,
}

impl TestBlob {
    pub fn new(name: &'static str, content: &'static [u8]) -> Self {
        let sha256 = KappaLabel::sha256(content).as_str().to_string();
        TestBlob {
            name,
            content,
            sha256,
        }
    }

    pub fn blob_path(&self, ns: &str) -> String {
        format!("/v2/{ns}/blobs/{}", self.sha256)
    }
}

pub fn test_blobs() -> Vec<TestBlob> {
    vec![
        TestBlob::new("empty", b""),
        TestBlob::new("hello", b"hello"),
        TestBlob::new("config", br#"{"type":"config"}"#),
        TestBlob::new("unknown_fields", br#"{"known":"v","_xyzzy":"preserve"}"#),
        TestBlob::new("no_content_type", b"no-ct-blob-content"),
        TestBlob::new("json_ct", br#"{"ct_test":true}"#),
    ]
}

pub fn blob<'a>(blobs: &'a [TestBlob], name: &str) -> &'a TestBlob {
    blobs.iter().find(|b| b.name == name).unwrap()
}

// URI builders - no hardcoded paths in test files.
pub fn version_uri() -> &'static str {
    "/v2/"
}

pub fn health_uri(probe: &str) -> String {
    format!("/v2/_health/{probe}")
}

pub fn blob_uri(ns: &str, kappa: &str) -> String {
    format!("/v2/{ns}/blobs/{kappa}")
}

pub fn upload_start_uri(ns: &str) -> String {
    format!("/v2/{ns}/blobs/uploads/")
}

pub fn upload_start_mount_uri(ns: &str, kappa: &str) -> String {
    format!("/v2/{ns}/blobs/uploads/?mount={kappa}")
}

pub fn manifest_uri(ns: &str, version: &str) -> String {
    format!("/v2/{ns}/manifests/{version}")
}

pub fn tag_list_uri(ns: &str) -> String {
    format!("/v2/{ns}/tags/list")
}

pub fn tag_list_uri_params(ns: &str, params: &str) -> String {
    format!("/v2/{ns}/tags/list?{params}")
}

pub fn tag_uri(ns: &str, name: &str) -> String {
    format!("/v2/{ns}/tags/{name}")
}

pub fn tag_put_uri(ns: &str, name: &str, kappa: &str) -> String {
    format!("/v2/{ns}/tags/{name}?kappa={kappa}")
}

pub fn edge_put_uri(ns: &str) -> String {
    format!("/v2/{ns}/edges/")
}

pub fn edge_query_uri(ns: &str, node: &str, direction: &str, relation: Option<&str>) -> String {
    let mut uri = format!("/v2/{ns}/edges/{node}?direction={direction}");
    if let Some(r) = relation {
        uri.push_str(&format!("&relation={r}"));
    }
    uri
}

pub fn edge_delete_uri(ns: &str, edge_kappa: &str) -> String {
    format!("/v2/{ns}/edges/{edge_kappa}")
}

pub fn compose_uri(ns: &str, op: &str) -> String {
    format!("/v2/{ns}/compose/{op}")
}

pub fn witness_uri(ns: &str, kappa: &str) -> String {
    format!("/v2/{ns}/witnesses/{kappa}")
}

pub fn schema_uri(ns: &str, scope: &str) -> String {
    format!("/v2/{ns}/schemas/{scope}")
}

pub fn schema_list_uri(ns: &str) -> String {
    format!("/v2/{ns}/schemas/")
}

pub fn gc_pin_uri(ns: &str) -> String {
    format!("/v2/{ns}/gc/pin")
}

pub fn gc_unpin_uri(ns: &str) -> String {
    format!("/v2/{ns}/gc/unpin")
}

pub fn gc_sweep_uri(ns: &str) -> String {
    format!("/v2/{ns}/gc/sweep")
}

pub fn gc_status_uri(ns: &str) -> String {
    format!("/v2/{ns}/gc/status")
}

pub fn filter_put_uri(ns: &str, scope: &str) -> String {
    format!("/v2/{ns}/filters/{scope}")
}

pub fn filter_list_uri(ns: &str) -> String {
    format!("/v2/{ns}/filters/")
}

pub fn filter_delete_uri(ns: &str, kappa: &str) -> String {
    format!("/v2/{ns}/filters/{kappa}")
}

pub fn edge_diff_uri(ns: &str) -> String {
    format!("/v2/{ns}/edges/_diff")
}

pub fn reconcile_uri(ns: &str) -> String {
    format!("/v2/{ns}/_reconcile")
}

pub fn tag_symref_uri(ns: &str, name: &str, target: &str) -> String {
    format!("/v2/{ns}/tags/{name}?symref={target}")
}

pub fn tag_raw_uri(ns: &str, name: &str) -> String {
    format!("/v2/{ns}/tags/{name}?raw=true")
}

pub fn tag_batch_uri(ns: &str) -> String {
    format!("/v2/{ns}/tags/_batch")
}

pub fn meta_list_uri(ns: &str, key: &str, value: &str) -> String {
    format!("/v2/{ns}/blobs/_meta?key={key}&value={value}")
}

pub fn namespace_root_uri(ns: &str) -> String {
    format!("/v2/{ns}/_root")
}

pub fn namespace_proof_uri(ns: &str, name: &str) -> String {
    format!("/v2/{ns}/_root/proof/{name}")
}

pub fn bundle_create_uri(ns: &str) -> String {
    format!("/v2/{ns}/_bundle/create")
}

pub fn bundle_ingest_uri(ns: &str) -> String {
    format!("/v2/{ns}/_bundle/ingest")
}

pub fn transaction_begin_uri(ns: &str) -> String {
    format!("/v2/{ns}/_transaction/begin")
}

pub fn transaction_put_uri(ns: &str, id: &str, kappa: &str) -> String {
    format!("/v2/{ns}/_transaction/{id}/{kappa}")
}

pub fn transaction_commit_uri(ns: &str, id: &str) -> String {
    format!("/v2/{ns}/_transaction/{id}/commit")
}

pub fn transaction_abort_uri(ns: &str, id: &str) -> String {
    format!("/v2/{ns}/_transaction/{id}")
}

// Absent kappa - a valid format that was never stored.
pub fn absent_kappa() -> String {
    format!("sha256:{}", "0".repeat(64))
}

// Test server that starts on an ephemeral port with a temp data dir.
// Field drop order is reverse declaration. _handle must be declared before
// _shutdown so _shutdown drops first (sends signal to the server), then
// _handle drops (joins the now-exiting thread). Reversing this deadlocks.
pub struct TestServer {
    pub addr: String,
    pub _data_dir: tempfile::TempDir,
    _handle: Option<std::thread::JoinHandle<()>>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl TestServer {
    pub fn start() -> Self {
        let data_dir = tempfile::TempDir::new().unwrap();
        let store = Arc::new(FsStore::new(data_dir.path().to_path_buf()).unwrap());
        let transactions = Arc::new(TransactionManager::new(
            data_dir.path().to_path_buf(),
            64,                // max concurrent
            64 * 1024 * 1024,  // max bytes per txn (same as max_blob_size)
            256 * 1024 * 1024, // max global staging bytes
            3600,              // timeout secs
        ));

        let signer: Option<Arc<dyn kappa_registry::crypto::RegistrySigner>> = {
            let ks = kappa_registry::crypto::keystore::KeyStore::new(data_dir.path());
            ks.ok()
                .and_then(|k| k.load_or_generate("ed25519").ok())
                .map(|s| Arc::from(s) as Arc<dyn kappa_registry::crypto::RegistrySigner>)
        };

        let state = AppState {
            store,
            sessions: Arc::new(SessionStore::new()),
            transactions,
            rate_limiter: None,
            signer,
            max_blob_size: 64 * 1024 * 1024,
            upload_timeout_secs: 3600,
        };

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel::<String>();

        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap().to_string();
                addr_tx.send(addr).unwrap();
                let app = kappa_registry::app(state);
                axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        rx.await.ok();
                    })
                    .await
                    .unwrap();
            });
        });

        let addr = addr_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        for _ in 0..50 {
            if TcpStream::connect(&addr).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        TestServer {
            addr,
            _data_dir: data_dir,
            _shutdown: tx,
            _handle: Some(handle),
        }
    }

    pub fn start_with_rate_limit(period_ms: u64, burst: u32) -> Self {
        use kappa_registry::ratelimit::{ClassConfig, RateLimitConfig, TieredRateLimiter};

        let data_dir = tempfile::TempDir::new().unwrap();
        let store = Arc::new(FsStore::new(data_dir.path().to_path_buf()).unwrap());
        let transactions = Arc::new(TransactionManager::new(
            data_dir.path().to_path_buf(),
            64,
            64 * 1024 * 1024,
            256 * 1024 * 1024,
            3600,
        ));

        // Apply the same config to all classes for integration test simplicity.
        let rl_config = RateLimitConfig {
            read: ClassConfig { period_ms, burst },
            write: ClassConfig { period_ms, burst },
            admin: ClassConfig { period_ms, burst },
        };

        let state = AppState {
            store,
            sessions: Arc::new(SessionStore::new()),
            transactions,
            rate_limiter: Some(TieredRateLimiter::new(&rl_config)),
            signer: None,
            max_blob_size: 64 * 1024 * 1024,
            upload_timeout_secs: 3600,
        };

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel::<String>();

        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap().to_string();
                addr_tx.send(addr).unwrap();
                let app = kappa_registry::app(state);
                axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        rx.await.ok();
                    })
                    .await
                    .unwrap();
            });
        });

        let addr = addr_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        for _ in 0..50 {
            if TcpStream::connect(&addr).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        TestServer {
            addr,
            _data_dir: data_dir,
            _shutdown: tx,
            _handle: Some(handle),
        }
    }
}

// Raw HTTP client - no reqwest needed for integration tests.
pub fn request(
    addr: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\n");
    for (k, v) in headers {
        req.push_str(k);
        req.push_str(": ");
        req.push_str(v);
        req.push_str("\r\n");
    }
    req.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    stream.write_all(req.as_bytes()).unwrap();
    if !body.is_empty() {
        stream.write_all(body).unwrap();
    }
    stream.flush().unwrap();
    let mut resp = Vec::new();
    let _ = stream.read_to_end(&mut resp);
    let split = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(resp.len());
    let head = String::from_utf8_lossy(&resp[..split]).to_string();
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    let hdrs: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string()))
        .collect();
    let body_bytes = if split + 4 <= resp.len() {
        resp[split + 4..].to_vec()
    } else {
        Vec::new()
    };
    (status, hdrs, body_bytes)
}

pub fn header<'a>(hdrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    hdrs.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

// Push a blob and assert success. Returns the kappa string.
pub fn push_blob(addr: &str, ns: &str, content: &[u8]) -> String {
    let kappa = KappaLabel::sha256(content).as_str().to_string();
    let path = blob_uri(ns, &kappa);
    let (status, _, _) = request(addr, "PUT", &path, &[], content);
    assert!(
        status == 201 || status == 200,
        "push_blob failed with {status} for {kappa}"
    );
    kappa
}

// Push a blob with explicit kappa (for multi-label or pre-computed).
pub fn push_blob_with_kappa(addr: &str, ns: &str, kappa: &str, content: &[u8]) -> u16 {
    let path = blob_uri(ns, kappa);
    let (status, _, _) = request(addr, "PUT", &path, &[], content);
    status
}

// JSON field extraction from response bodies.
pub fn json_str(body: &[u8], key: &str) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let pat = format!("\"{key}\"");
    let after = &text[text.find(&pat)? + pat.len()..];
    let after = &after[after.find(':')? + 1..];
    let after = &after[after.find('"')? + 1..];
    Some(after[..after.find('"')?].to_string())
}
