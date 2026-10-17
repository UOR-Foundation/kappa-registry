//! TLS tests: prove the server serves HTTPS, rejects plain HTTP to TLS port,
//! and exits on invalid cert/key paths.
//!
//! The server wraps each accepted TcpStream with tokio_rustls::TlsAcceptor
//! through a TlsListener implementing topcoat's Listener trait, served by
//! topcoat::serve::internal_serve.
//!
//! Certificates are generated in-process with rcgen, so the tests depend on
//! no external program.

use super::helpers::*;

use std::time::Duration;

/// Generate a self-signed certificate and key using rcgen (pure Rust).
/// Returns (cert_pem, key_pem) written to files in the given directory.
fn generate_self_signed_cert(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let cert_path = dir.join("test.crt");
    let key_path = dir.join("test.key");

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();

    (cert_path, key_path)
}

/// Client for a self-signed test server.
fn tls_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// Start a TLS server with a fresh self-signed certificate. The returned
/// directories hold the certificate and the store for the guard's life.
fn start_tls() -> (ServerGuard, tempfile::TempDir, tempfile::TempDir) {
    let cert_tmp = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = generate_self_signed_cert(cert_tmp.path());
    let store_tmp = tempfile::tempdir().unwrap();
    let guard = start_server_tls(
        store_tmp.path(),
        &[
            ("KAPPA_TLS_CERT", cert_path.to_str().unwrap()),
            ("KAPPA_TLS_KEY", key_path.to_str().unwrap()),
        ],
    );
    (guard, cert_tmp, store_tmp)
}

// =============================================================================
// Core TLS tests
// =============================================================================

#[test]
fn tls_serves_https() {
    let (guard, _cert, _store) = start_tls();

    let resp = tls_client()
        .get(format!("{}/_status", guard.https_base()))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "HTTPS /_status should return 200");
    drop(guard);
}

#[test]
fn tls_rejects_plain_http() {
    let (guard, _cert, _store) = start_tls();

    // Plain HTTP to TLS port should fail
    let plain = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let result = plain.get(format!("{}/_status", guard.base())).send();
    assert!(result.is_err(), "plain HTTP to TLS port should fail");
    drop(guard);
}

#[test]
fn tls_invalid_cert_path_exits() {
    let tmp = tempfile::tempdir().unwrap();

    assert_refuses_to_start(
        &tmp.path().join("data"),
        &[
            ("KAPPA_TLS_CERT", "/nonexistent/path/cert.pem"),
            ("KAPPA_TLS_KEY", "/nonexistent/path/key.pem"),
        ],
    );
}

#[test]
fn tls_invalid_key_path_exits() {
    let cert_tmp = tempfile::tempdir().unwrap();
    let (cert_path, _) = generate_self_signed_cert(cert_tmp.path());
    let store_tmp = tempfile::tempdir().unwrap();

    assert_refuses_to_start(
        store_tmp.path(),
        &[
            ("KAPPA_TLS_CERT", cert_path.to_str().unwrap()),
            ("KAPPA_TLS_KEY", "/nonexistent/path/key.pem"),
        ],
    );
}

// =============================================================================
// TLS blob operations
// =============================================================================

#[test]
fn tls_blob_put_get_over_https() {
    let (guard, _cert, _store) = start_tls();
    let c = tls_client();

    let content = b"tls blob content test";
    let digest = sha256_digest(content);
    let url = format!("{}/v2/tls-test/blobs/{}", guard.https_base(), digest);

    let put = c.put(&url).body(content.to_vec()).send().unwrap();
    assert_eq!(put.status(), 201, "HTTPS blob PUT failed");

    let get = c.get(&url).send().unwrap();
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().unwrap().as_ref(), content);
    drop(guard);
}
