//! Shared test infrastructure for kappa-server integration tests.
//!
//! Each integration test file includes `mod helpers; use helpers::*;`
//! Not every file uses every helper, so all items are `#[allow(dead_code)]`.
//!
//! One ServerGuard. One start_server(). One client(). One sha256_digest().
//! Every integration test file uses: mod helpers; use helpers::*;
//!
//! Design informed by:
//! - redb/tests/integration_tests.rs:31-37 (create_tempfile defined once)
//! - distribution-spec/conformance/run.go:45-81 (runner with all shared state)
//! - topcoat-router/src/router.rs:558-610 (shared test helpers)

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
        .stdout(Stdio::null())
        .stderr(Stdio::null());
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
    panic!("kappa-server did not become ready within 5 seconds");
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

/// Push a blob via monolithic PUT and return the status code.
pub fn push_blob(c: &reqwest::blocking::Client, base: &str, ns: &str, content: &[u8]) -> u16 {
    let digest = sha256_digest(content);
    let resp = c
        .put(format!("{}/v2/{}/blobs/{}", base, ns, digest))
        .body(content.to_vec())
        .send()
        .unwrap();
    resp.status().as_u16()
}

/// Push a manifest with a tag and return the status code.
pub fn push_manifest(
    c: &reqwest::blocking::Client,
    base: &str,
    ns: &str,
    tag: &str,
    content: &[u8],
) -> u16 {
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
    assert_eq!(resp.status(), 202, "chunk PATCH failed: {}", resp.status());
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
