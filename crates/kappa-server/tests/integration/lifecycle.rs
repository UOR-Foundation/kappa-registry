//! Server lifecycle tests: startup, shutdown, epoch chain integrity,
//! upload session timeout, store root creation.

#[path = "helpers/mod.rs"]
#[allow(dead_code, unused_imports)]
mod helpers;
use helpers::*;

use std::time::Duration;

// =============================================================================
// GAP 26: Store root directory creation
// =============================================================================

#[test]
fn store_root_created_if_nonexistent() {
    let tmp = tempfile::tempdir().unwrap();
    let store_root = tmp.path().join("deeply").join("nested").join("store");
    assert!(!store_root.exists(), "store root should not exist yet");

    let port = pick_port();
    let guard = start_server_at(&store_root, port);

    // Server should have created the directory
    assert!(
        store_root.exists(),
        "server should create store root directory"
    );
    let c = client();
    let resp = c.get(format!("{}/_status", guard.base())).send().unwrap();
    assert_eq!(resp.status(), 200);
    drop(guard);
}

// =============================================================================
// GAP 27: SIGTERM graceful shutdown
// =============================================================================

#[test]
#[cfg(unix)]
fn sigterm_graceful_shutdown() {
    let (mut guard, base, _tmp) = start_server();
    let c = client();

    // Verify server is running
    let resp = c.get(format!("{}/_status", base)).send().unwrap();
    assert_eq!(resp.status(), 200);

    // Send SIGTERM (graceful shutdown)
    unsafe {
        libc::kill(guard.child.id() as i32, libc::SIGTERM);
    }

    // Server should exit cleanly within 5 seconds
    let mut exited = false;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if let Ok(Some(_status)) = guard.child.try_wait() {
            exited = true;
            break;
        }
    }
    assert!(exited, "server should exit within 5 seconds of SIGTERM");

    // Port should be released
    let listener = std::net::TcpListener::bind(format!("127.0.0.1:{}", guard.port));
    assert!(
        listener.is_ok(),
        "port should be released after graceful shutdown"
    );
}

// =============================================================================
// GAP 13: Epoch chain integrity after multiple operations
// =============================================================================

#[test]
fn epoch_chain_has_valid_root_after_mutations() {
    let (guard, base, _tmp) = start_server();
    let c = client();

    // Create multiple tags to advance epochs
    for i in 0..5 {
        let content = format!(r#"{{"schemaVersion":2,"i":{}}}"#, i);
        push_manifest(
            &c,
            &base,
            "epoch-chain-test",
            &format!("tag-{}", i),
            content.as_bytes(),
        );
    }

    // Epoch root should exist and be accessible
    let resp = c
        .get(format!("{}/v2/epoch-chain-test/_root", base))
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "epoch root should be accessible after mutations"
    );
    let body: serde_json::Value = resp.json().unwrap();
    // The response should contain a root hash or kappa
    let body_str = serde_json::to_string(&body).unwrap();
    assert!(
        body_str.len() > 10,
        "epoch root response should contain data: {}",
        body_str
    );
    drop(guard);
}

// =============================================================================
// GAP 10: Upload session timeout/eviction
// CLAUDE.md: main.rs spawns periodic cleanup every 60s calling evict_expired
// =============================================================================

#[test]
fn upload_session_expires_after_timeout() {
    // Start server with a short upload timeout
    let (guard, base, _tmp) = start_server_with_env(&[("KAPPA_UPLOAD_TIMEOUT", "2")]);
    let c = client();

    // Start an upload
    let upload_url = start_upload(&c, &base, "timeout-test");

    // Send one chunk
    let upload_url = send_chunk(&c, &base, &upload_url, 0, b"chunk-before-timeout");

    // Wait for the session to expire (timeout + cleanup interval)
    // The cleanup runs every 60s in production, but the session itself
    // is marked expired after KAPPA_UPLOAD_TIMEOUT seconds.
    // Accessing an expired session should return 404.
    std::thread::sleep(Duration::from_secs(3));

    // Try to send another chunk -- session should be expired
    let resp = c
        .patch(&upload_url)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Range", "20-39")
        .body(b"chunk-after-timeout".to_vec())
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "expired upload session should return 404, got {}",
        resp.status()
    );
    drop(guard);
}

// =============================================================================
// GAP 20: Transaction lifecycle (begin/commit/abort)
// Smoke test only tests begin. This tests the full lifecycle.
// =============================================================================

#[test]
fn transaction_begin_put_commit() {
    let (guard, base, _tmp) = start_server();
    let c = client();

    // Begin transaction
    let resp = c
        .post(format!("{}/v2/txn-ns/_transaction/begin", base))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 201, "txn begin should return 201");
    let body: serde_json::Value = resp.json().unwrap();
    let txn_id = body["id"].as_str().expect("transaction should have an id");

    // Stage a blob in the transaction
    let content = b"transactional-blob";
    let digest = sha256_digest(content);
    let resp = c
        .put(format!(
            "{}/v2/txn-ns/_transaction/{}/{}",
            base, txn_id, digest
        ))
        .body(content.to_vec())
        .send()
        .unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 200 || status == 201,
        "txn put should succeed, got {}",
        status
    );

    // Commit
    let resp = c
        .post(format!("{}/v2/txn-ns/_transaction/{}/commit", base, txn_id))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "txn commit should return 200");

    // Blob should be accessible after commit
    let resp = c
        .get(format!("{}/v2/txn-ns/blobs/{}", base, digest))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "blob should be accessible after commit");
    drop(guard);
}

#[test]
fn transaction_abort_rolls_back() {
    let (guard, base, _tmp) = start_server();
    let c = client();

    // Begin transaction
    let resp = c
        .post(format!("{}/v2/txn-ns/_transaction/begin", base))
        .send()
        .unwrap();
    let body: serde_json::Value = resp.json().unwrap();
    let txn_id = body["id"].as_str().expect("transaction should have an id");

    // Stage a blob
    let content = b"aborted-blob";
    let digest = sha256_digest(content);
    c.put(format!(
        "{}/v2/txn-ns/_transaction/{}/{}",
        base, txn_id, digest
    ))
    .body(content.to_vec())
    .send()
    .unwrap();

    // Abort
    let resp = c
        .delete(format!("{}/v2/txn-ns/_transaction/{}", base, txn_id))
        .send()
        .unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 200 || status == 204,
        "txn abort should succeed, got {}",
        status
    );

    // Blob should NOT be accessible after abort
    let resp = c
        .get(format!("{}/v2/txn-ns/blobs/{}", base, digest))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 404, "blob should not exist after abort");
    drop(guard);
}
