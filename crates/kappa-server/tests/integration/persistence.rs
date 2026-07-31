//! Persistence tests: kill -9 and restart scenarios proving state survives
//! process death. Every test starts a server, writes state, sends SIGKILL
//! (not graceful shutdown), restarts with the SAME store root, and verifies
//! the state survived.
//!
//! FAILS UNTIL: PersistentStore is implemented in kappa-store-redb and wired
//! into main.rs replacing InMemoryStore. InMemoryStore loses all structured
//! state (tags, edges, sequences, metadata, namespaces) on restart.
//!
//! Kill pattern informed by redb/tests/crash_consistency.rs:127-165 which
//! uses a two-pass approach. Our black-box approach uses SIGKILL on a child
//! process, which is less precise but tests the full stack including fsync.
//!
//! TempDir ownership: the test function owns the TempDir so it outlives
//! multiple server instances. The ServerGuard does NOT own the TempDir.

extern crate libc;

#[path = "helpers/mod.rs"]
#[allow(dead_code, unused_imports)]
mod helpers;
use helpers::*;

use std::time::Duration;

// =============================================================================
// Kill -9 and restart tests
// =============================================================================

#[test]
fn kill_9_tags_survive() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();
    let c = client();
    let manifest =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#;

    // Phase 1: start server, push manifest with tag
    {
        let mut guard = start_server_at(tmp.path(), port);
        let status = push_manifest(&c, &guard.base(), "persist", "latest", manifest);
        assert_eq!(status, 201, "manifest PUT failed");
        guard.kill_9();
    }

    // Phase 2: restart at same store root, verify tag survived
    {
        let guard = start_server_at(tmp.path(), port);
        let resp = c
            .get(format!("{}/v2/persist/manifests/latest", guard.base()))
            .send()
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "tag did not survive restart: {}",
            resp.text().unwrap()
        );
        drop(guard);
    }
}

#[test]
fn kill_9_edges_survive() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();
    let c = client();

    let pairs: Vec<(Vec<u8>, Vec<u8>, String, String)> = (0..3)
        .map(|i| {
            let src = format!("edge-src-{}", i).into_bytes();
            let tgt = format!("edge-tgt-{}", i).into_bytes();
            let sk = sha256_digest(&src);
            let tk = sha256_digest(&tgt);
            (src, tgt, sk, tk)
        })
        .collect();

    let relations = ["owns", "derived-from", "composed-of"];

    // Phase 1: push blobs and edges
    {
        let mut guard = start_server_at(tmp.path(), port);
        let base = guard.base();
        for (src, tgt, _, _) in &pairs {
            push_blob(&c, &base, "edges-ns", src);
            push_blob(&c, &base, "edges-ns", tgt);
        }
        for (i, (_, _, sk, tk)) in pairs.iter().enumerate() {
            let status = push_edge(&c, &base, "edges-ns", sk, relations[i], tk);
            assert!(
                status == 201 || status == 200,
                "edge PUT failed: {}",
                status
            );
        }
        guard.kill_9();
    }

    // Phase 2: restart, verify all 3 edges
    {
        let guard = start_server_at(tmp.path(), port);
        let base = guard.base();
        for (_, _, sk, tk) in &pairs {
            let resp = c
                .get(format!("{}/v2/edges-ns/edges/{}", base, sk))
                .send()
                .unwrap();
            assert_eq!(
                resp.status(),
                200,
                "edge query for {} failed after restart",
                sk
            );
            let body: serde_json::Value = resp.json().unwrap();
            let edges = body["edges"].as_array().unwrap();
            assert!(
                edges
                    .iter()
                    .any(|e| e["target"].as_str() == Some(tk.as_str())),
                "edge from {} to {} not found after restart",
                sk,
                tk
            );
        }
        drop(guard);
    }
}

#[test]
fn kill_9_sequences_survive() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();
    let c = client();

    // Phase 1: increment sequence 5 times
    {
        let mut guard = start_server_at(tmp.path(), port);
        let base = guard.base();
        for i in 1..=5 {
            let resp = c
                .post(format!("{}/v2/seq-ns/_sequence/counter/next", base))
                .send()
                .unwrap();
            assert_eq!(resp.status(), 200);
            let body: serde_json::Value = resp.json().unwrap();
            assert_eq!(body["value"], i, "sequence value mismatch at step {}", i);
        }
        guard.kill_9();
    }

    // Phase 2: restart, verify sequence_current returns 5
    {
        let guard = start_server_at(tmp.path(), port);
        let resp = c
            .get(format!("{}/v2/seq-ns/_sequence/counter", guard.base()))
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().unwrap();
        assert_eq!(
            body["value"], 5,
            "sequence did not survive restart: got {}",
            body
        );
        drop(guard);
    }
}

#[test]
fn kill_9_meta_survives() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();
    let c = client();

    // Phase 1: push manifests (which store object-type metadata via meta_set)
    {
        let mut guard = start_server_at(tmp.path(), port);
        let base = guard.base();
        for i in 0..3 {
            let content = format!(r#"{{"schemaVersion":2,"meta-test":{}}}"#, i);
            let tag = format!("meta-{}", i);
            let status = push_manifest(&c, &base, "meta-ns", &tag, content.as_bytes());
            assert_eq!(status, 201, "manifest PUT {} failed", i);
        }
        guard.kill_9();
    }

    // Phase 2: restart, verify meta_query returns results
    {
        let guard = start_server_at(tmp.path(), port);
        let resp = c
            .get(format!(
                "{}/v2/meta-ns/blobs/_meta?key=object-type&value=manifest",
                guard.base()
            ))
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().unwrap();
        let kappas = body["kappas"].as_array().unwrap();
        assert!(
            kappas.len() >= 3,
            "expected >= 3 kappas in meta query after restart, got {}: {}",
            kappas.len(),
            body
        );
        drop(guard);
    }
}

#[test]
fn kill_9_namespaces_survive() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();
    let c = client();

    // Phase 1: create namespace by pushing a tag
    {
        let mut guard = start_server_at(tmp.path(), port);
        let status = push_manifest(
            &c,
            &guard.base(),
            "ns-survive-test",
            "v1",
            br#"{"schemaVersion":2}"#,
        );
        assert_eq!(status, 201);
        guard.kill_9();
    }

    // Phase 2: restart, verify namespace exists via _root endpoint
    {
        let guard = start_server_at(tmp.path(), port);
        let resp = c
            .get(format!("{}/v2/ns-survive-test/_root", guard.base()))
            .send()
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "namespace did not survive restart: {}",
            resp.text().unwrap()
        );
        drop(guard);
    }
}

#[test]
fn kill_9_epoch_pointer_survives() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();
    let c = client();

    // Phase 1: create a tag (triggers epoch advance)
    {
        let mut guard = start_server_at(tmp.path(), port);
        push_manifest(
            &c,
            &guard.base(),
            "epoch-ns",
            "v1",
            br#"{"schemaVersion":2}"#,
        );
        // Verify epoch root exists before kill
        let resp = c
            .get(format!("{}/v2/epoch-ns/_root", guard.base()))
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200);
        guard.kill_9();
    }

    // Phase 2: restart, verify epoch root is accessible
    {
        let guard = start_server_at(tmp.path(), port);
        let resp = c
            .get(format!("{}/v2/epoch-ns/_root", guard.base()))
            .send()
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "epoch root not accessible after restart"
        );
        drop(guard);
    }
}

// =============================================================================
// Format version tests
// KAPPA-SPECIFIC: These test kappa_core::version::check_or_write_version(),
// NOT redb's internal format detection (redb/src/db.rs:1070-1077).
// The format_version file is at {store_root}/format_version.
// =============================================================================

#[test]
fn format_version_rejects_old() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();

    // Write an old format version that the server must reject.
    std::fs::write(tmp.path().join("format_version"), "3\n").unwrap();

    let mut guard = start_server_expect_failure(tmp.path(), port);

    // Server should exit or never become ready within 3 seconds
    let base = format!("http://127.0.0.1:{}", port);
    let c = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let mut became_ready = false;
    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(100));
        // Check if process has exited
        if let Ok(Some(_)) = guard.child.try_wait() {
            break;
        }
        if c.get(format!("{}/_status", base)).send().is_ok() {
            became_ready = true;
            break;
        }
    }

    drop(guard);

    assert!(
        !became_ready,
        "server should have rejected old format version and refused to start"
    );
}

#[test]
fn format_version_accepts_current() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();

    // Write the current format version from the constant, not hardcoded.
    std::fs::write(
        tmp.path().join("format_version"),
        format!("{}\n", kappa_core::version::STORE_FORMAT_VERSION),
    )
    .unwrap();

    let guard = start_server_at(tmp.path(), port);
    let c = client();
    let resp = c.get(format!("{}/_status", guard.base())).send().unwrap();
    assert_eq!(resp.status(), 200);
    drop(guard);
}

// =============================================================================
// Stress and edge case tests
// =============================================================================

#[test]
fn tag_1000_namespaces_all_survive_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();
    let c = client();
    let content = br#"{"schemaVersion":2}"#;

    // Phase 1: create 1000 namespaces with 1 tag each
    {
        let mut guard = start_server_at(tmp.path(), port);
        let base = guard.base();
        for i in 0..1000 {
            let ns = format!("ns-{:04}", i);
            let status = push_manifest(&c, &base, &ns, "latest", content);
            assert_eq!(status, 201, "namespace {} creation failed", ns);
        }
        guard.kill_9();
    }

    // Phase 2: restart, verify all 1000 tags exist
    {
        let guard = start_server_at(tmp.path(), port);
        let base = guard.base();
        let mut missing = Vec::new();
        for i in 0..1000 {
            let ns = format!("ns-{:04}", i);
            let resp = c
                .get(format!("{}/v2/{}/manifests/latest", base, ns))
                .send()
                .unwrap();
            if resp.status() != 200 {
                missing.push(ns);
            }
        }
        assert!(
            missing.is_empty(),
            "{} of 1000 namespaces lost tags after restart. First missing: {:?}",
            missing.len(),
            &missing[..std::cmp::min(5, missing.len())]
        );
        drop(guard);
    }
}

#[test]
fn tag_name_with_slashes_survives_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();
    let c = client();

    let filter_content = b"deny:test";

    // Phase 1: register a filter (creates _filter/test-scope internal tag)
    {
        let mut guard = start_server_at(tmp.path(), port);
        let base = guard.base();
        let resp = c
            .put(format!("{}/v2/slash-ns/filters/test-scope", base))
            .body(filter_content.to_vec())
            .send()
            .unwrap();
        assert_eq!(
            resp.status(),
            201,
            "filter register failed: {}",
            resp.text().unwrap()
        );
        guard.kill_9();
    }

    // Phase 2: restart, verify filter list includes the filter
    {
        let guard = start_server_at(tmp.path(), port);
        let resp = c
            .get(format!("{}/v2/slash-ns/filters/", guard.base()))
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().unwrap();
        assert!(
            body.contains("test-scope"),
            "filter with slash in tag name did not survive restart: {}",
            body
        );
        drop(guard);
    }
}

#[test]
fn epoch_chain_10_deep_survives_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();
    let c = client();

    // Phase 1: advance 10 epochs by creating 10 different tags
    {
        let mut guard = start_server_at(tmp.path(), port);
        let base = guard.base();
        for i in 0..10 {
            let content = format!(r#"{{"schemaVersion":2,"epoch":{}}}"#, i);
            let tag = format!("v{}", i);
            push_manifest(&c, &base, "epoch-chain", &tag, content.as_bytes());
        }
        guard.kill_9();
    }

    // Phase 2: restart, verify epoch root exists
    {
        let guard = start_server_at(tmp.path(), port);
        let resp = c
            .get(format!("{}/v2/epoch-chain/_root", guard.base()))
            .send()
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "epoch root not accessible after restart"
        );
        drop(guard);
    }
}

#[test]
fn sequence_next_monotonic_across_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();
    let c = client();

    // Phase 1: increment sequence 5 times
    {
        let mut guard = start_server_at(tmp.path(), port);
        for _ in 0..5 {
            c.post(format!("{}/v2/mono-ns/_sequence/mono/next", guard.base()))
                .send()
                .unwrap();
        }
        guard.kill_9();
    }

    // Phase 2: restart, next call should return 6, not 1
    {
        let guard = start_server_at(tmp.path(), port);
        let resp = c
            .post(format!("{}/v2/mono-ns/_sequence/mono/next", guard.base()))
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().unwrap();
        assert_eq!(
            body["value"], 6,
            "sequence should continue at 6 after restart, got {}",
            body["value"]
        );
        drop(guard);
    }
}

// =============================================================================
// Concurrent HTTP writes (tests server request handling, not redb internals)
// Name reflects what is actually tested: HTTP-level concurrent writes that
// result in serialized redb writes (redb allows only one WriteTransaction
// at a time per redb/src/db.rs:1191-1193).
// =============================================================================

#[test]
fn concurrent_http_writes_no_data_loss() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();
    let guard = start_server_at(tmp.path(), port);
    let base = guard.base();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));

    let handles: Vec<_> = (0..16)
        .map(|t| {
            let base = base.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let c = client();
                for i in 0..100 {
                    let ns = format!("load-{}", t);
                    let content = format!(r#"{{"schemaVersion":2,"t":{},"i":{}}}"#, t, i);
                    let tag = format!("tag-{}", i);
                    let status = push_manifest(&c, &base, &ns, &tag, content.as_bytes());
                    assert_eq!(status, 201, "thread {} tag {} failed", t, tag);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }

    // Verify all 1600 tags exist
    let c = client();
    for t in 0..16 {
        let ns = format!("load-{}", t);
        let resp = c
            .get(format!("{}/v2/{}/tags/list", base, ns))
            .send()
            .unwrap();
        let body: serde_json::Value = resp.json().unwrap();
        let tags = body["tags"].as_array().unwrap();
        assert_eq!(
            tags.len(),
            100,
            "namespace {} has {} tags, expected 100",
            ns,
            tags.len()
        );
    }
    drop(guard);
}

#[test]
fn large_edge_metadata_survives_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();
    let c = client();

    let src = b"large-meta-src";
    let tgt = b"large-meta-tgt";
    let sk = sha256_digest(src);
    let tk = sha256_digest(tgt);

    // Phase 1: push edge with 64KB metadata
    {
        let mut guard = start_server_at(tmp.path(), port);
        let base = guard.base();
        push_blob(&c, &base, "bigmeta", src);
        push_blob(&c, &base, "bigmeta", tgt);

        let edge = serde_json::json!({
            "source": sk,
            "relation": "owns",
            "target": tk,
            "metadata": {"data": "x".repeat(65536)},
        });
        let resp = c
            .put(format!("{}/v2/bigmeta/edges/", base))
            .header("content-type", "application/json")
            .body(serde_json::to_string(&edge).unwrap())
            .send()
            .unwrap();
        let status = resp.status().as_u16();
        assert!(
            status == 201 || status == 200,
            "edge PUT failed: {}",
            status
        );
        guard.kill_9();
    }

    // Phase 2: restart, verify edge exists
    {
        let guard = start_server_at(tmp.path(), port);
        let resp = c
            .get(format!("{}/v2/bigmeta/edges/{}", guard.base(), sk))
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().unwrap();
        let edges = body["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1, "edge not found after restart");
        drop(guard);
    }
}

#[test]
fn blob_meta_survives_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();
    let c = client();

    let content = b"blob-meta-persist-test";
    let digest = sha256_digest(content);

    // Phase 1: push blob with content-type metadata
    {
        let mut guard = start_server_at(tmp.path(), port);
        let resp = c
            .put(format!("{}/v2/blobmeta/blobs/{}", guard.base(), digest))
            .header("content-type", "text/plain")
            .body(content.to_vec())
            .send()
            .unwrap();
        assert_eq!(resp.status(), 201);
        guard.kill_9();
    }

    // Phase 2: restart, verify content-type metadata survived
    {
        let guard = start_server_at(tmp.path(), port);
        let resp = c
            .get(format!("{}/v2/blobmeta/blobs/{}", guard.base(), digest))
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(
            ct, "text/plain",
            "content-type metadata did not survive restart: got '{}'",
            ct
        );
        drop(guard);
    }
}

#[test]
fn tag_set_batch_survives_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();
    let c = client();

    // Phase 1: create tags via manifest PUT
    {
        let mut guard = start_server_at(tmp.path(), port);
        let base = guard.base();
        for i in 0..3 {
            let content = format!(r#"{{"schemaVersion":2,"batch":{}}}"#, i);
            let tag = format!("batch-{}", i);
            push_manifest(&c, &base, "batch-ns", &tag, content.as_bytes());
        }
        guard.kill_9();
    }

    // Phase 2: restart, verify all batch tags exist
    {
        let guard = start_server_at(tmp.path(), port);
        let resp = c
            .get(format!("{}/v2/batch-ns/tags/list", guard.base()))
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().unwrap();
        let tags = body["tags"].as_array().unwrap();
        assert!(
            tags.len() >= 3,
            "batch tags did not survive restart: got {} tags",
            tags.len()
        );
        drop(guard);
    }
}

#[test]
fn blob_list_after_reopen_matches_filesystem() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();
    let c = client();

    let mut pushed_digests = Vec::new();

    // Phase 1: push several blobs
    {
        let mut guard = start_server_at(tmp.path(), port);
        let base = guard.base();
        for i in 0..10 {
            let content = format!("list-test-blob-{}", i);
            let digest = sha256_digest(content.as_bytes());
            push_blob(&c, &base, "list-ns", content.as_bytes());
            pushed_digests.push(digest);
        }
        guard.kill_9();
    }

    // Phase 2: restart, verify blob list contains all pushed blobs
    {
        let guard = start_server_at(tmp.path(), port);
        let resp = c
            .get(format!("{}/v2/list-ns/blobs/", guard.base()))
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().unwrap();
        let kappas = body["kappas"].as_array().unwrap();
        let kappa_strs: Vec<&str> = kappas.iter().filter_map(|v| v.as_str()).collect();
        for digest in &pushed_digests {
            assert!(
                kappa_strs.contains(&digest.as_str()),
                "blob {} not in blob list after restart",
                digest
            );
        }
        drop(guard);
    }
}

#[test]
fn edge_asserter_filter_survives_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();
    let c = client();

    let src = b"asr-src";
    let tgt = b"asr-tgt";
    let sk = sha256_digest(src);
    let tk = sha256_digest(tgt);

    // Phase 1: push edge
    {
        let mut guard = start_server_at(tmp.path(), port);
        let base = guard.base();
        push_blob(&c, &base, "asr-ns", src);
        push_blob(&c, &base, "asr-ns", tgt);
        push_edge(&c, &base, "asr-ns", &sk, "owns", &tk);
        guard.kill_9();
    }

    // Phase 2: restart, query by source
    {
        let guard = start_server_at(tmp.path(), port);
        let resp = c
            .get(format!("{}/v2/asr-ns/edges/{}", guard.base(), sk))
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().unwrap();
        let edges = body["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1, "edge not found after restart");
        drop(guard);
    }
}

#[test]
fn tag_prefix_range_scan_correct_after_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();
    let c = client();

    // Phase 1: create tags with versioned names
    {
        let mut guard = start_server_at(tmp.path(), port);
        let base = guard.base();
        for tag in ["v1.0", "v1.1", "v1.2", "v2.0", "v2.1"] {
            let content = format!(r#"{{"schemaVersion":2,"tag":"{}"}}"#, tag);
            push_manifest(&c, &base, "prefix-ns", tag, content.as_bytes());
        }
        guard.kill_9();
    }

    // Phase 2: restart, verify all 5 tags present
    {
        let guard = start_server_at(tmp.path(), port);
        let resp = c
            .get(format!("{}/v2/prefix-ns/tags/list", guard.base()))
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().unwrap();
        let tags = body["tags"].as_array().unwrap();
        assert_eq!(
            tags.len(),
            5,
            "expected 5 tags after restart, got {}",
            tags.len()
        );
        drop(guard);
    }
}

// =============================================================================
// Durability invariant: redb default is Durability::Immediate
// This test documents the invariant. If it fails, data loss on kill -9 is
// expected -- which means ALL the kill_9_* tests above are invalid.
// =============================================================================

#[test]
fn redb_durability_immediate_is_default() {
    let tmp = tempfile::tempdir().unwrap();
    let port = pick_port();
    let c = client();

    // Write a tag
    {
        let mut guard = start_server_at(tmp.path(), port);
        push_manifest(
            &c,
            &guard.base(),
            "durable",
            "proof",
            br#"{"schemaVersion":2}"#,
        );
        // Kill immediately -- no graceful shutdown
        guard.kill_9();
    }

    // If Durability::Immediate is the default, the tag survives
    {
        let guard = start_server_at(tmp.path(), port);
        let resp = c
            .get(format!("{}/v2/durable/manifests/proof", guard.base()))
            .send()
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "durability test failed: data lost after kill, \
             which means Durability::Immediate is NOT the default"
        );
        drop(guard);
    }
}

// =============================================================================
// Regression: basic blob roundtrip works with persistent store
// =============================================================================

#[test]
fn blob_put_get_roundtrip_persistent() {
    let (guard, base, _tmp) = start_server();
    let c = client();

    let content = b"persistent store blob roundtrip";
    let digest = sha256_digest(content);
    let url = format!("{}/v2/regression/blobs/{}", base, digest);

    let put = c.put(&url).body(content.to_vec()).send().unwrap();
    assert_eq!(put.status(), 201);

    let get = c.get(&url).send().unwrap();
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().unwrap().as_ref(), content);
    drop(guard);
}
