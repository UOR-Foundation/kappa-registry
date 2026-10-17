//! Shared test infrastructure for kappa-server integration tests.
//!
//! Each integration test file includes `mod helpers; use helpers::*;`
//! Each `[[test]]` binary compiles this module independently. Functions
//! used only by other test binaries appear unused in any single binary.
//!
//! Design informed by:
//! - redb/tests/integration_tests.rs:31-37 (create_tempfile defined once)
//! - distribution-spec/conformance/run.go:45-81 (runner with all shared state)
//! - topcoat-router/src/router.rs:558-610 (shared test helpers)

use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// RAII guard that kills and waits on the server child process when dropped.
/// Prevents zombie processes on test success, failure, or panic.
///
/// For restart tests (persistence.rs): the TempDir is NOT owned by this guard.
/// The test function owns the TempDir so it outlives multiple server instances.
///
/// For single-server tests: use start_server() which creates its own TempDir
/// and returns it alongside the guard.
pub struct ServerGuard {
    pub child: Child,
    /// The port the server bound and reported, never one reserved and
    /// released ahead of it: parallel tests cannot reach each other's
    /// servers.
    pub port: u16,
    store_root: PathBuf,
    _ready_dir: tempfile::TempDir,
}

impl ServerGuard {
    pub fn store_root(&self) -> &Path {
        &self.store_root
    }

    pub fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn https_base(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Explicit SIGKILL for crash simulation.
    /// On Unix: libc::kill(pid, SIGKILL).
    /// On non-Unix: Child::kill() (TerminateProcess).
    /// Blocks until the process is confirmed dead.
    pub fn kill_9(&mut self) {
        #[cfg(unix)]
        {
            unsafe {
                libc::kill(self.child.id() as i32, libc::SIGKILL);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        // Graceful shutdown: SIGTERM lets the server drain in-flight
        // requests and flush its store, so committed epochs are durable
        // without requiring fsync in test configuration.
        #[cfg(unix)]
        {
            // SAFETY: the child pid is valid because we own the Child.
            unsafe {
                libc::kill(self.child.id() as i32, libc::SIGTERM);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.kill();
        }
        // Bounded wait: if the server does not exit within 5 seconds
        // after SIGTERM, force-kill it so the test suite does not hang.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() >= deadline => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(_) => return,
            }
        }
    }
}

/// Server diagnostics outlive each test's store directory so a failed run
/// can be diagnosed from the log files alone.
const SERVER_LOG_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tmp/logs/it-server");

/// How long a server gets to start, or to refuse to.
const STARTUP_LIMIT: Duration = Duration::from_secs(10);

/// Log file receiving one server process's stdout (tracing) and stderr
/// (panics, startup failures). Named after the test thread and the
/// process's start order within this test binary.
fn server_log() -> (PathBuf, std::fs::File, std::fs::File) {
    static STARTED: AtomicU64 = AtomicU64::new(0);
    std::fs::create_dir_all(SERVER_LOG_DIR).expect("create it server log directory");
    let test = std::thread::current()
        .name()
        .unwrap_or("unnamed")
        .replace("::", "-");
    let started = STARTED.fetch_add(1, Ordering::Relaxed);
    let path =
        PathBuf::from(SERVER_LOG_DIR).join(format!("{test}-{}-{started}.log", std::process::id()));
    let stdout = std::fs::File::create(&path).expect("create it server log");
    let stderr = stdout.try_clone().expect("share it server log");
    (path, stdout, stderr)
}

/// A spawned server process, not yet known to be serving.
struct Spawned {
    child: Child,
    log_path: PathBuf,
    ready_dir: tempfile::TempDir,
}

impl Spawned {
    fn ready_file(&self) -> PathBuf {
        self.ready_dir.path().join("listen")
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log_path).expect("read it server log")
    }
}

/// Spawn a server on a kernel-assigned loopback port. It reports the port
/// it bound through a ready file, so no port is reserved and released
/// first, and no parallel test can take it in between.
fn spawn_server(store_root: &Path, extra_env: &[(&str, &str)]) -> Spawned {
    let ready_dir = tempfile::tempdir().expect("ready file directory");
    // Not under store_root: some tests (store_root_created_if_nonexistent)
    // pass a path that does not yet exist.
    let (log_path, stdout, stderr) = server_log();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kappa-server"));
    cmd.env("KAPPA_LISTEN_ADDR", "127.0.0.1:0")
        .env("KAPPA_READY_FILE", ready_dir.path().join("listen"))
        .env("KAPPA_STORE_ROOT", store_root)
        .env("KAPPA_RATELIMIT_READ_PERIOD_MS", "0")
        .env("KAPPA_RATELIMIT_WRITE_PERIOD_MS", "0")
        .env("KAPPA_RATELIMIT_ADMIN_PERIOD_MS", "0")
        .env("RUST_LOG", "info")
        .stdout(stdout)
        .stderr(stderr);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let child = cmd.spawn().expect("failed to start kappa-server");
    Spawned {
        child,
        log_path,
        ready_dir,
    }
}

/// Wait for the server's reported address, then for `/_status` at that
/// address over `client` and `scheme`.
fn await_ready(
    mut spawned: Spawned,
    store_root: &Path,
    client: &reqwest::blocking::Client,
    scheme: &str,
) -> ServerGuard {
    let deadline = Instant::now() + STARTUP_LIMIT;
    let ready_file = spawned.ready_file();
    let port = loop {
        if let Some(status) = spawned.child.try_wait().expect("inspect server process") {
            panic!(
                "kappa-server exited with {status} before reporting ready; {}:\n{}",
                spawned.log_path.display(),
                spawned.log()
            );
        }
        if let Ok(reported) = std::fs::read_to_string(&ready_file) {
            let bound: std::net::SocketAddr = reported
                .parse()
                .unwrap_or_else(|e| panic!("ready file holds {reported:?}: {e}"));
            break bound.port();
        }
        assert!(
            Instant::now() < deadline,
            "kappa-server reported no address within {STARTUP_LIMIT:?}; {}:\n{}",
            spawned.log_path.display(),
            spawned.log()
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let guard = ServerGuard {
        child: spawned.child,
        port,
        store_root: store_root.to_path_buf(),
        _ready_dir: spawned.ready_dir,
    };
    let status_url = format!("{scheme}://127.0.0.1:{port}/_status");
    while Instant::now() < deadline {
        if client
            .get(&status_url)
            .send()
            .is_ok_and(|response| response.status().is_success())
        {
            return guard;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let log = std::fs::read_to_string(&spawned.log_path).expect("read it server log");
    panic!(
        "kappa-server bound port {port} but {status_url} never succeeded; {}:\n{log}",
        spawned.log_path.display()
    );
}

/// Start a server at a specific store root.
/// Used by restart tests where the TempDir outlives the server.
/// The caller owns the TempDir.
pub fn start_server_at(store_root: &Path) -> ServerGuard {
    start_server_at_with_env(store_root, &[])
}

/// Start a server at a specific store root with extra env vars.
pub fn start_server_at_with_env(store_root: &Path, extra_env: &[(&str, &str)]) -> ServerGuard {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("readiness client");
    await_ready(
        spawn_server(store_root, extra_env),
        store_root,
        &client,
        "http",
    )
}

/// Start a server with a fresh TempDir and optional extra env vars.
/// Returns the guard, base URL, and TempDir (caller must hold TempDir).
pub fn start_server_with_env(
    extra_env: &[(&str, &str)],
) -> (ServerGuard, String, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let guard = start_server_at_with_env(tmp.path(), extra_env);
    let base = guard.base();
    (guard, base, tmp)
}

/// Start a server with defaults. Returns guard, base URL, and TempDir.
pub fn start_server() -> (ServerGuard, String, tempfile::TempDir) {
    start_server_with_env(&[])
}

/// Start a server that must refuse to start: it exits, unsuccessfully,
/// without ever reporting a bound address. Returns its exit status.
pub fn assert_refuses_to_start(store_root: &Path, extra_env: &[(&str, &str)]) -> ExitStatus {
    let mut spawned = spawn_server(store_root, extra_env);
    let deadline = Instant::now() + STARTUP_LIMIT;
    loop {
        assert!(
            !spawned.ready_file().exists(),
            "kappa-server started when it must refuse; {}:\n{}",
            spawned.log_path.display(),
            spawned.log()
        );
        if let Some(status) = spawned.child.try_wait().expect("inspect server process") {
            assert!(
                !status.success(),
                "kappa-server refused with a successful exit"
            );
            return status;
        }
        if Instant::now() >= deadline {
            spawned.child.kill().expect("stop kappa-server");
            spawned.child.wait().expect("reap kappa-server");
            panic!(
                "kappa-server neither started nor exited within {STARTUP_LIMIT:?}; {}:\n{}",
                spawned.log_path.display(),
                spawned.log()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Start a TLS-enabled server. Readiness is probed over HTTPS with
/// danger_accept_invalid_certs (self-signed test certs).
pub fn start_server_tls(store_root: &Path, extra_env: &[(&str, &str)]) -> ServerGuard {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
        .expect("TLS readiness client");
    await_ready(
        spawn_server(store_root, extra_env),
        store_root,
        &client,
        "https",
    )
}

pub fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

pub fn sha256_digest(content: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(content);
    format!("sha256:{}", hex::encode(hash))
}

pub fn sha512_digest(content: &[u8]) -> String {
    use sha2::{Digest, Sha512};
    let hash = Sha512::digest(content);
    format!("sha512:{}", hex::encode(hash))
}

pub fn sha3_256_digest(content: &[u8]) -> String {
    use sha3::{Digest, Sha3_256};
    let hash = Sha3_256::digest(content);
    format!("sha3-256:{}", hex::encode(hash))
}

pub fn keccak256_digest(content: &[u8]) -> String {
    use sha3::{Digest, Keccak256};
    let hash = Keccak256::digest(content);
    format!("keccak256:{}", hex::encode(hash))
}

pub fn blake3_digest(content: &[u8]) -> String {
    let hash = blake3::hash(content);
    format!("blake3:{}", hash.to_hex())
}

pub fn resolve_location(base: &str, location: &str) -> String {
    if location.starts_with('/') {
        format!("{}{}", base, location)
    } else {
        location.to_string()
    }
}

/// Create a namespace explicitly via the namespace create endpoint.
/// Idempotent: 201 on first call, 409 on subsequent calls (both are success).
/// Every test that needs a namespace calls this. No test assumes side-effect
/// creation from push operations.
pub fn create_namespace(c: &reqwest::blocking::Client, base: &str, ns: &str) {
    let resp = c
        .post(format!("{}/v2/{}/_namespace/create", base, ns))
        .send()
        .unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 201 || status == 409,
        "create namespace '{}': expected 201 or 409, got {}",
        ns,
        status
    );
}

/// Push a blob via monolithic PUT and return the status code.
/// Creates the namespace first if it doesn't exist.
pub fn push_blob(c: &reqwest::blocking::Client, base: &str, ns: &str, content: &[u8]) -> u16 {
    create_namespace(c, base, ns);
    let digest = sha256_digest(content);
    let resp = c
        .put(format!("{}/v2/{}/blobs/{}", base, ns, digest))
        .body(content.to_vec())
        .send()
        .unwrap();
    resp.status().as_u16()
}

/// Push a manifest with a tag and return the status code.
/// Creates the namespace first if it doesn't exist.
pub fn push_manifest(
    c: &reqwest::blocking::Client,
    base: &str,
    ns: &str,
    tag: &str,
    content: &[u8],
) -> u16 {
    create_namespace(c, base, ns);
    let resp = c
        .put(format!("{}/v2/{}/manifests/{}", base, ns, tag))
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(content.to_vec())
        .send()
        .unwrap();
    resp.status().as_u16()
}

/// Push an edge and return the status code.
pub fn push_edge(
    c: &reqwest::blocking::Client,
    base: &str,
    ns: &str,
    source: &str,
    relation: &str,
    target: &str,
) -> u16 {
    let body = serde_json::json!({
        "source": source,
        "relation": relation,
        "target": target,
    });
    let resp = c
        .put(format!("{}/v2/{}/edges/", base, ns))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .unwrap();
    resp.status().as_u16()
}

/// Start a chunked upload, return the upload URL.
pub fn start_upload(c: &reqwest::blocking::Client, base: &str, ns: &str) -> String {
    let resp = c
        .post(format!("{}/v2/{}/blobs/uploads/", base, ns))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 202, "upload start failed: {}", resp.status());
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    resolve_location(base, loc)
}

/// Send a chunk via PATCH and return the new upload URL.
pub fn send_chunk(
    c: &reqwest::blocking::Client,
    base: &str,
    upload_url: &str,
    offset: usize,
    data: &[u8],
) -> String {
    let end = offset + data.len() - 1;
    let resp = c
        .patch(upload_url)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Range", format!("{}-{}", offset, end))
        .body(data.to_vec())
        .send()
        .unwrap();
    if resp.status() != 202 {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        panic!(
            "chunk PATCH failed: {} -- body: {} -- url: {} -- offset: {} -- data_len: {}",
            status,
            body,
            upload_url,
            offset,
            data.len()
        );
    }
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    resolve_location(base, loc)
}

/// Verify an HTTP response body is a valid OCI error envelope with the expected code.
/// OCI error format: {"errors": [{"code": "CODE", "message": "..."}]}
pub fn assert_oci_error(body: &str, expected_code: &str) {
    let parsed: serde_json::Value = serde_json::from_str(body)
        .unwrap_or_else(|_| panic!("response body is not valid JSON: {}", body));
    let errors = parsed["errors"]
        .as_array()
        .unwrap_or_else(|| panic!("response missing 'errors' array: {}", body));
    assert!(!errors.is_empty(), "errors array is empty: {}", body);
    let code = errors[0]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("error missing 'code' field: {}", body));
    assert_eq!(
        code, expected_code,
        "expected error code '{}', got '{}' in: {}",
        expected_code, code, body
    );
}

/// Build a signed identity assertion JSON body for POST /identity/assert.
///
/// Generates an ed25519 key, builds the IdentityAssertion naming the
/// key's anchor as asserter, and signs it as COSE_Sign1 over the record's
/// signable bytes, the form the server verifies.
pub fn signed_assertion(
    subject: &str,
    facet: &str,
    value: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(signed_assertion_with_key(subject, facet, value, None)?.0)
}

/// Build a signed assertion, optionally reusing an existing key.
/// Returns (json_body, secret_key_bytes) so the key can sign further
/// assertions from the same asserter.
pub fn signed_assertion_with_key(
    subject: &str,
    facet: &str,
    value: &str,
    existing_key: Option<&[u8; 32]>,
) -> Result<(serde_json::Value, [u8; 32]), Box<dyn std::error::Error>> {
    use kappa_crypto::Signer;
    use kappa_crypto::ed25519::Ed25519Signer;
    use kappa_store::identity::IdentityAssertion;

    let secret_bytes: [u8; 32] = match existing_key {
        Some(k) => *k,
        None => {
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes).expect("assertion key entropy");
            bytes
        }
    };
    let signer = Ed25519Signer::from_bytes(&secret_bytes)?;
    let asserter = kappa_store::Kappa::from_key(signer.algorithm(), signer.public_key())?;
    let value_bytes = hex::decode(value).unwrap_or_else(|_| value.as_bytes().to_vec());

    let assertion = kappa_crypto::signed_types::sign_assertion(
        IdentityAssertion {
            asserter,
            subject: subject.to_owned(),
            facet: facet.to_owned(),
            value: value_bytes.clone(),
            basis: "self-asserted".to_owned(),
            valid_from_ms: 0,
            valid_until_ms: None,
            cose_signature: kappa_store::SignedPayload::empty(),
        },
        &signer,
    )?;

    let body = serde_json::json!({
        "algorithm": signer.algorithm(),
        "public_key": hex::encode(signer.public_key()),
        "subject": subject,
        "facet": facet,
        "value": hex::encode(&value_bytes),
        "basis": "self-asserted",
        "valid_from_ms": 0,
        "signature": hex::encode(assertion.cose_signature.as_bytes()),
    });

    Ok((body, secret_bytes))
}

/// Build a signed revocation JSON body for POST /identity/revoke, by the
/// asserter whose secret key is `secret_bytes`, of the assertion `kappa`.
pub fn signed_revocation(
    kappa: &str,
    secret_bytes: &[u8; 32],
    revoked_at_ms: i64,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use kappa_crypto::Signer;
    use kappa_crypto::ed25519::Ed25519Signer;
    use kappa_store::identity::{Revocation, RevocationReason};

    let signer = Ed25519Signer::from_bytes(secret_bytes)?;
    let asserter = kappa_store::Kappa::from_key(signer.algorithm(), signer.public_key())?;
    let revocation = kappa_crypto::signed_types::sign_revocation(
        Revocation {
            assertion_kappa: kappa_store::Kappa::parse(kappa)?,
            asserter: asserter.clone(),
            reason: RevocationReason::Superseded,
            revoked_at_ms,
            cose_signature: kappa_store::SignedPayload::empty(),
        },
        &signer,
    )?;
    Ok(serde_json::json!({
        "asserter": asserter.to_string(),
        "assertion_kappa": kappa,
        "reason": "superseded",
        "revoked_at_ms": revoked_at_ms,
        "public_key": hex::encode(signer.public_key()),
        "signature": hex::encode(revocation.cose_signature.as_bytes()),
    }))
}

/// Read server RSS in KB via /proc/{pid}/status. Linux only.
#[cfg(target_os = "linux")]
pub fn server_rss_kb(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            return line.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}

/// Recursively list all files under a directory.
#[cfg(unix)]
pub fn walkdir_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut result = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                result.extend(walkdir_files(&path));
            } else if path.is_file() {
                result.push(path);
            }
        }
    }
    result
}
