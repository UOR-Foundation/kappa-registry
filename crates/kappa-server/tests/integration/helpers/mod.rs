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

#![allow(dead_code)]

use std::process::{Child, Command, Stdio};
use std::time::Duration;

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
    pub port: u16,
    store_root: std::path::PathBuf,
}

impl ServerGuard {
    pub fn store_root(&self) -> &std::path::Path {
        &self.store_root
    }

    pub fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
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
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn pick_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Start a server at a specific store root and port.
/// Used by restart tests where the TempDir outlives the server.
/// The caller owns the TempDir.
pub fn start_server_at(store_root: &std::path::Path, port: u16) -> ServerGuard {
    start_server_at_with_env(store_root, port, &[])
}

/// Start a server at a specific store root and port with extra env vars.
pub fn start_server_at_with_env(
    store_root: &std::path::Path,
    port: u16,
    extra_env: &[(&str, &str)],
) -> ServerGuard {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kappa-server"));
    cmd.env("KAPPA_LISTEN_ADDR", format!("127.0.0.1:{}", port))
        .env("KAPPA_STORE_ROOT", store_root.to_str().unwrap())
        .env("KAPPA_RATELIMIT_READ_PERIOD_MS", "0")
        .env("KAPPA_RATELIMIT_WRITE_PERIOD_MS", "0")
        .env("KAPPA_RATELIMIT_ADMIN_PERIOD_MS", "0")
        .env("RUST_LOG", "error")
        .stdout(Stdio::null());
    // Write stderr to a temp file for diagnostics on startup failure.
    // Cannot use store_root because some tests (store_root_created_if_nonexistent)
    // pass a path that does not yet exist.
    let stderr_path = std::env::temp_dir().join(format!("kappa-server-{}.stderr", port));
    let stderr_file = std::fs::File::create(&stderr_path)
        .expect("failed to create stderr log");
    cmd.stderr(stderr_file);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let child = cmd.spawn().expect("failed to start kappa-server");

    let base = format!("http://127.0.0.1:{}", port);
    let guard = ServerGuard {
        child,
        port,
        store_root: store_root.to_path_buf(),
    };

    let c = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if c.get(format!("{}/_status", base)).send().is_ok() {
            return guard;
        }
    }
    let stderr_content = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    panic!(
        "kappa-server did not become ready within 5 seconds\nserver stderr:\n{}",
        stderr_content
    );
}

/// Start a server with a fresh TempDir and optional extra env vars.
/// Returns the guard, base URL, and TempDir (caller must hold TempDir).
pub fn start_server_with_env(
    extra_env: &[(&str, &str)],
) -> (ServerGuard, String, tempfile::TempDir) {
    let port = pick_port();
    let tmp = tempfile::tempdir().unwrap();
    let guard = start_server_at_with_env(tmp.path(), port, extra_env);
    let base = guard.base();
    (guard, base, tmp)
}

/// Start a server with defaults. Returns guard, base URL, and TempDir.
pub fn start_server() -> (ServerGuard, String, tempfile::TempDir) {
    start_server_with_env(&[])
}

/// Start a server and expect it to NOT become ready (for negative tests).
/// Returns a guard that will kill the process on drop even if the test panics.
pub fn start_server_expect_failure(store_root: &std::path::Path, port: u16) -> ServerGuard {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kappa-server"));
    cmd.env("KAPPA_LISTEN_ADDR", format!("127.0.0.1:{}", port))
        .env("KAPPA_STORE_ROOT", store_root.to_str().unwrap())
        .env("KAPPA_RATELIMIT_READ_PERIOD_MS", "0")
        .env("KAPPA_RATELIMIT_WRITE_PERIOD_MS", "0")
        .env("KAPPA_RATELIMIT_ADMIN_PERIOD_MS", "0")
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = cmd.spawn().expect("failed to start kappa-server");
    ServerGuard {
        child,
        port,
        store_root: store_root.to_path_buf(),
    }
}

/// Start a TLS-enabled server. Polls readiness via HTTPS with
/// danger_accept_invalid_certs (self-signed test certs).
pub fn start_server_tls(
    store_root: &std::path::Path,
    port: u16,
    extra_env: &[(&str, &str)],
) -> ServerGuard {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kappa-server"));
    cmd.env("KAPPA_LISTEN_ADDR", format!("127.0.0.1:{}", port))
        .env("KAPPA_STORE_ROOT", store_root.to_str().unwrap())
        .env("KAPPA_RATELIMIT_READ_PERIOD_MS", "0")
        .env("KAPPA_RATELIMIT_WRITE_PERIOD_MS", "0")
        .env("KAPPA_RATELIMIT_ADMIN_PERIOD_MS", "0")
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let child = cmd.spawn().expect("failed to start kappa-server");
    let guard = ServerGuard {
        child,
        port,
        store_root: store_root.to_path_buf(),
    };

    let c = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let base = format!("https://127.0.0.1:{}", port);
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if c.get(format!("{}/_status", base)).send().is_ok() {
            return guard;
        }
    }
    panic!("TLS kappa-server did not become ready within 5 seconds");
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
        ns, status
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
            status, body, upload_url, offset, data.len()
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

/// Build a properly signed identity assertion JSON body.
///
/// Generates an ed25519 keypair, constructs the IdentityAssertion with
/// the same structure the server's assert_handler uses, computes
/// signable_bytes via kappa_core, signs it, and returns the full JSON
/// body ready for POST /identity/assert.
pub fn signed_assertion(subject: &str, facet: &str, value: &str) -> serde_json::Value {
    signed_assertion_with_key(subject, facet, value, None).0
}

/// Build a signed assertion, optionally reusing an existing keypair.
/// Returns (json_body, signing_key_bytes) so the key can be reused
/// for multiple assertions from the same asserter.
pub fn signed_assertion_with_key(
    subject: &str,
    facet: &str,
    value: &str,
    existing_key: Option<&[u8; 32]>,
) -> (serde_json::Value, [u8; 32]) {
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use kappa_core::identity::assertion::IdentityAssertion;

    let secret_bytes: [u8; 32] = match existing_key {
        Some(k) => *k,
        None => {
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes).unwrap();
            bytes
        }
    };
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key: VerifyingKey = (&signing_key).into();
    let public_key_bytes = verifying_key.to_bytes();

    let value_bytes = hex::decode(value).unwrap_or_else(|_| value.as_bytes().to_vec());

    // Build the assertion with asserter="" -- the server fills this AFTER
    // signature verification via asserter_from_signature. The signable_bytes
    // method produces canonical dCBOR of fields 0-6 (excluding signature).
    let assertion = IdentityAssertion {
        asserter: String::new(),
        subject: subject.to_owned(),
        facet: facet.to_owned(),
        value: value_bytes.clone(),
        basis: "self-asserted".to_owned(),
        valid_from_ms: 0,
        valid_until_ms: None,
        signature: vec![], // placeholder, replaced below
    };

    let signable = assertion.signable_bytes();
    let signature = signing_key.sign(&signable);

    let body = serde_json::json!({
        "algorithm": "ed25519",
        "public_key": hex::encode(public_key_bytes),
        "subject": subject,
        "facet": facet,
        "value": hex::encode(&value_bytes),
        "basis": "self-asserted",
        "valid_from_ms": 0,
        "signature": hex::encode(signature.to_bytes()),
    });

    (body, secret_bytes)
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
