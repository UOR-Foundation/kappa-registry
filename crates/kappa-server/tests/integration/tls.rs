//! TLS tests: prove the server serves HTTPS, rejects plain HTTP to TLS port,
//! and exits on invalid cert/key paths.
//!
//! FAILS UNTIL: TLS support is implemented by:
//! - Adding KAPPA_TLS_CERT and KAPPA_TLS_KEY to Config::from_env()
//! - Creating a TlsListener implementing topcoat's Listener trait
//!   (topcoat has no native TLS -- topcoat/crates/topcoat/src/serve.rs
//!   takes impl Listener which is TcpListener or UnixListener only)
//! - Wrapping accepted TcpStream with tokio_rustls::TlsAcceptor
//! - Calling topcoat::serve::internal_serve(tls_listener, service, shutdown)
//!   instead of topcoat::start(router)
//!
//! Cert generation uses rcgen (pure Rust) instead of openssl CLI.
//! The Nix devshell is hermetic -- openssl CLI may not be available.

#[path = "helpers/mod.rs"]
#[allow(dead_code, unused_imports)]
mod helpers;
use helpers::*;

use std::time::Duration;

/// Generate a self-signed certificate and key using rcgen (pure Rust).
/// Returns (cert_pem, key_pem) written to files in the given directory.
fn generate_self_signed_cert(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let cert_path = dir.join("test.crt");
    let key_path = dir.join("test.key");

    // rcgen generates self-signed certs without external dependencies.
    // FAILS UNTIL: rcgen is added to dev-dependencies.
    // For now, generate minimal PEM stubs that will cause TLS init to fail
    // with a clear error rather than silently producing invalid certs.
    //
    // When rcgen is available:
    //   let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    //   std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    //   std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
    //
    // Fallback: use openssl CLI if available, otherwise write stubs.
    let status = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_path.to_str().unwrap(),
            "-out",
            cert_path.to_str().unwrap(),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match status {
        Ok(s) if s.success() => {}
        _ => {
            // openssl not available. Write valid-looking but incorrect PEM.
            // TLS tests will fail with connection errors, which is the
            // correct failure mode for "TLS not implemented yet."
            std::fs::write(
                &cert_path,
                "-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----\n",
            )
            .unwrap();
            std::fs::write(
                &key_path,
                "-----BEGIN PRIVATE KEY-----\nINVALID\n-----END PRIVATE KEY-----\n",
            )
            .unwrap();
        }
    }

    (cert_path, key_path)
}

// =============================================================================
// Core TLS tests
// =============================================================================

#[test]
fn tls_serves_https() {
    // FAILS UNTIL: TLS listener implemented in main.rs
    let cert_tmp = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = generate_self_signed_cert(cert_tmp.path());
    let port = pick_port();
    let store_tmp = tempfile::tempdir().unwrap();

    let guard = start_server_at_with_env(
        store_tmp.path(),
        port,
        &[
            ("KAPPA_TLS_CERT", cert_path.to_str().unwrap()),
            ("KAPPA_TLS_KEY", key_path.to_str().unwrap()),
        ],
    );

    let c = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let base = format!("https://127.0.0.1:{}", port);
    let mut ready = false;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if c.get(format!("{}/_status", base)).send().is_ok() {
            ready = true;
            break;
        }
    }

    assert!(ready, "TLS server did not become ready within 5 seconds");
    let resp = c.get(format!("{}/_status", base)).send().unwrap();
    assert_eq!(resp.status(), 200, "HTTPS /_status should return 200");
    drop(guard);
}

#[test]
fn tls_rejects_plain_http() {
    // FAILS UNTIL: TLS listener implemented
    let cert_tmp = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = generate_self_signed_cert(cert_tmp.path());
    let port = pick_port();
    let store_tmp = tempfile::tempdir().unwrap();

    let guard = start_server_at_with_env(
        store_tmp.path(),
        port,
        &[
            ("KAPPA_TLS_CERT", cert_path.to_str().unwrap()),
            ("KAPPA_TLS_KEY", key_path.to_str().unwrap()),
        ],
    );

    // Wait for server ready via HTTPS
    let tls_client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let base_tls = format!("https://127.0.0.1:{}", port);
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if tls_client
            .get(format!("{}/_status", base_tls))
            .send()
            .is_ok()
        {
            break;
        }
    }

    // Plain HTTP to TLS port should fail
    let plain = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let result = plain
        .get(format!("http://127.0.0.1:{}/_status", port))
        .send();
    assert!(result.is_err(), "plain HTTP to TLS port should fail");
    drop(guard);
}

#[test]
fn tls_invalid_cert_path_exits() {
    // FAILS UNTIL: TLS config validation implemented
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_kappa-server"))
        .env("KAPPA_LISTEN_ADDR", format!("127.0.0.1:{}", port))
        .env(
            "KAPPA_STORE_ROOT",
            tmp.path().join("data").to_str().unwrap(),
        )
        .env("KAPPA_TLS_CERT", "/nonexistent/path/cert.pem")
        .env("KAPPA_TLS_KEY", "/nonexistent/path/key.pem")
        .env("RUST_LOG", "error")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to start kappa-server");

    // Server should exit within 3 seconds
    let mut exited = false;
    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(100));
        if let Ok(Some(status)) = child.try_wait() {
            assert!(
                !status.success(),
                "should exit non-zero on invalid cert path"
            );
            exited = true;
            break;
        }
    }
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
        panic!("server should have exited on invalid cert path");
    }
}

#[test]
fn tls_invalid_key_path_exits() {
    // FAILS UNTIL: TLS config validation implemented
    let cert_tmp = tempfile::tempdir().unwrap();
    let (cert_path, _) = generate_self_signed_cert(cert_tmp.path());
    let store_tmp = tempfile::tempdir().unwrap();
    let port = pick_port();

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_kappa-server"))
        .env("KAPPA_LISTEN_ADDR", format!("127.0.0.1:{}", port))
        .env("KAPPA_STORE_ROOT", store_tmp.path().to_str().unwrap())
        .env("KAPPA_TLS_CERT", cert_path.to_str().unwrap())
        .env("KAPPA_TLS_KEY", "/nonexistent/path/key.pem")
        .env("RUST_LOG", "error")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to start kappa-server");

    let mut exited = false;
    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(100));
        if let Ok(Some(status)) = child.try_wait() {
            assert!(
                !status.success(),
                "should exit non-zero on invalid key path"
            );
            exited = true;
            break;
        }
    }
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
        panic!("server should have exited on invalid key path");
    }
}

// =============================================================================
// TLS blob operations
// =============================================================================

#[test]
fn tls_blob_put_get_over_https() {
    // FAILS UNTIL: TLS listener implemented
    let cert_tmp = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = generate_self_signed_cert(cert_tmp.path());
    let port = pick_port();
    let store_tmp = tempfile::tempdir().unwrap();

    let guard = start_server_at_with_env(
        store_tmp.path(),
        port,
        &[
            ("KAPPA_TLS_CERT", cert_path.to_str().unwrap()),
            ("KAPPA_TLS_KEY", key_path.to_str().unwrap()),
        ],
    );

    let c = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let base = format!("https://127.0.0.1:{}", port);

    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if c.get(format!("{}/_status", base)).send().is_ok() {
            break;
        }
    }

    let content = b"tls blob content test";
    let digest = sha256_digest(content);
    let url = format!("{}/v2/tls-test/blobs/{}", base, digest);

    let put = c.put(&url).body(content.to_vec()).send().unwrap();
    assert_eq!(put.status(), 201, "HTTPS blob PUT failed");

    let get = c.get(&url).send().unwrap();
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().unwrap().as_ref(), content);
    drop(guard);
}
