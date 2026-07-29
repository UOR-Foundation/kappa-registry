//! Operational tests: concurrency, large blobs, rate limiting, quota enforcement,
//! GC under load. These prove the registry survives production workloads beyond
//! the OCI conformance suite's single-threaded sequential tests.

use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier};
use std::time::Duration;

struct ServerGuard {
    child: Child,
    tmp: tempfile::TempDir,
}

impl ServerGuard {
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

fn start_server_with_env(extra_env: &[(&str, &str)]) -> (ServerGuard, String) {
    let port = pick_port();
    let tmp = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kappa-server"));
    cmd.env("KAPPA_LISTEN_ADDR", format!("127.0.0.1:{}", port))
        .env("KAPPA_STORE_ROOT", tmp.path().to_str().unwrap())
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
    let guard = ServerGuard { child, tmp };

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
    panic!("kappa-server did not become ready within 5 seconds");
}

fn start_server() -> (ServerGuard, String) {
    start_server_with_env(&[])
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

fn sha256_digest(content: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(content);
    format!("sha256:{}", hex::encode(hash))
}

/// Resolve a Location header value against the server base URL.
/// Location may be absolute or relative (starting with /).
fn resolve_location(base: &str, location: &str) -> String {
    if location.starts_with('/') {
        format!("{}{}", base, location)
    } else {
        location.to_string()
    }
}

// =============================================================================
// 1. Concurrent writes from multiple clients
// =============================================================================

#[test]
fn concurrent_blob_writes_no_corruption() {
    let (guard, base) = start_server();
    let thread_count = 8;
    let blobs_per_thread = 10;
    let barrier = Arc::new(Barrier::new(thread_count));

    let handles: Vec<_> = (0..thread_count)
        .map(|t| {
            let base = base.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let c = client();
                for i in 0..blobs_per_thread {
                    let content = format!("thread-{}-blob-{}-{}", t, i, "x".repeat(256));
                    let content = content.as_bytes();
                    let digest = sha256_digest(content);
                    let url = format!("{}/v2/concurrent/blobs/{}", base, digest);

                    let put = c.put(&url).body(content.to_vec()).send().unwrap();
                    assert!(
                        put.status() == 201 || put.status() == 200,
                        "thread {} blob {} PUT failed: {}",
                        t,
                        i,
                        put.status()
                    );

                    let get = c.get(&url).send().unwrap();
                    assert_eq!(get.status(), 200, "thread {} blob {} GET failed", t, i);
                    assert_eq!(
                        get.bytes().unwrap().as_ref(),
                        content,
                        "thread {} blob {} content mismatch",
                        t,
                        i
                    );
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }
    drop(guard);
}

#[test]
fn concurrent_manifest_tag_writes() {
    let (guard, base) = start_server();
    let thread_count = 4;
    let barrier = Arc::new(Barrier::new(thread_count));

    let handles: Vec<_> = (0..thread_count)
        .map(|t| {
            let base = base.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let c = client();
                for i in 0..5 {
                    let manifest = serde_json::json!({
                        "schemaVersion": 2,
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "thread": t,
                        "iteration": i,
                    });
                    let body = serde_json::to_vec(&manifest).unwrap();
                    let tag = format!("thread-{}-iter-{}", t, i);
                    let put = c
                        .put(format!("{}/v2/concurrent-tags/manifests/{}", base, tag))
                        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
                        .body(body.clone())
                        .send()
                        .unwrap();
                    assert_eq!(put.status(), 201, "thread {} tag {} failed", t, tag);

                    let get = c
                        .get(format!("{}/v2/concurrent-tags/manifests/{}", base, tag))
                        .send()
                        .unwrap();
                    assert_eq!(get.status(), 200);
                    assert_eq!(get.bytes().unwrap().as_ref(), body.as_slice());
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }

    let resp = client()
        .get(format!("{}/v2/concurrent-tags/tags/list", base))
        .send()
        .unwrap();
    let body: serde_json::Value = resp.json().unwrap();
    let tags = body["tags"].as_array().unwrap();
    assert_eq!(tags.len(), thread_count * 5);
    drop(guard);
}

// =============================================================================
// 2. Large blob streaming
// =============================================================================

#[test]
fn large_blob_roundtrip_10mb() {
    let (guard, base) = start_server();
    let size = 10 * 1024 * 1024; // 10 MiB
    let content: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let digest = sha256_digest(&content);
    let url = format!("{}/v2/large/blobs/{}", base, digest);

    let put = client().put(&url).body(content.clone()).send().unwrap();
    assert_eq!(put.status(), 201, "large blob PUT failed");

    let get = client().get(&url).send().unwrap();
    assert_eq!(get.status(), 200);
    let returned = get.bytes().unwrap();
    assert_eq!(returned.len(), size, "large blob size mismatch");
    assert_eq!(
        returned.as_ref(),
        content.as_slice(),
        "large blob content mismatch"
    );

    // HEAD returns correct Content-Length
    let head = client().head(&url).send().unwrap();
    assert_eq!(head.status(), 200);
    let cl: usize = head
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(cl, size);

    // Range request on large blob
    let range_get = client()
        .get(&url)
        .header("Range", "bytes=1000000-1000999")
        .send()
        .unwrap();
    assert_eq!(range_get.status(), 206);
    let range_body = range_get.bytes().unwrap();
    assert_eq!(range_body.len(), 1000);
    assert_eq!(range_body.as_ref(), &content[1000000..1001000]);
    drop(guard);
}

// =============================================================================
// 3. Chunked upload with recovery
// =============================================================================

#[test]
fn chunked_upload_with_recovery() {
    let (guard, base) = start_server();
    let content: Vec<u8> = (0..8192).map(|i| (i % 199) as u8).collect();
    let digest = sha256_digest(&content);
    let c = client();

    // Start upload
    let start = c
        .post(format!("{}/v2/chunked/blobs/uploads/", base))
        .send()
        .unwrap();
    assert_eq!(start.status(), 202);
    let location = start.headers().get("location").unwrap().to_str().unwrap();
    let upload_url = resolve_location(&base, location);

    // Send first chunk (0-4095)
    let chunk1 = c
        .patch(&upload_url)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Range", "0-4095")
        .body(content[0..4096].to_vec())
        .send()
        .unwrap();
    assert_eq!(chunk1.status(), 202, "chunk1 failed: {}", chunk1.status());
    let loc2 = chunk1.headers().get("location").unwrap().to_str().unwrap();
    let upload_url2 = resolve_location(&base, loc2);

    // Recovery: GET the upload to check progress
    let recovery = c.get(&upload_url2).send().unwrap();
    assert_eq!(recovery.status(), 204);
    let range = recovery.headers().get("range").unwrap().to_str().unwrap();
    assert!(
        range.contains("4095"),
        "recovery range should show 4095 bytes received, got: {}",
        range
    );

    // Send second chunk (4096-8191) and complete
    let complete_url = format!("{}?digest={}", upload_url2, digest);
    let complete = c
        .put(&complete_url)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Range", "4096-8191")
        .body(content[4096..].to_vec())
        .send()
        .unwrap();
    assert_eq!(
        complete.status(),
        201,
        "complete failed: {}",
        complete.text().unwrap_or_default()
    );

    // Verify content
    let get = c
        .get(format!("{}/v2/chunked/blobs/{}", base, digest))
        .send()
        .unwrap();
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().unwrap().as_ref(), content.as_slice());
    drop(guard);
}

// =============================================================================
// 4. Rate limiting under load
// =============================================================================

#[test]
fn rate_limiting_rejects_excess_requests() {
    // Start server with tight rate limits: 2 requests per second, burst of 2
    let (guard, base) = start_server_with_env(&[
        ("KAPPA_RATELIMIT_READ_PERIOD_MS", "500"),
        ("KAPPA_RATELIMIT_READ_BURST", "2"),
        ("KAPPA_RATELIMIT_WRITE_PERIOD_MS", "500"),
        ("KAPPA_RATELIMIT_WRITE_BURST", "2"),
        ("KAPPA_RATELIMIT_ADMIN_PERIOD_MS", "500"),
        ("KAPPA_RATELIMIT_ADMIN_BURST", "2"),
    ]);

    let c = client();

    // Push a blob so we have something to read
    let content = b"rate limit test blob";
    let digest = sha256_digest(content);
    let url = format!("{}/v2/ratelimit/blobs/{}", base, digest);
    c.put(&url).body(content.to_vec()).send().unwrap();

    // Fire 10 rapid GET requests -- some should be rate limited (429)
    let mut ok_count = 0;
    let mut limited_count = 0;
    for _ in 0..10 {
        let resp = c.get(&url).send().unwrap();
        match resp.status().as_u16() {
            200 => ok_count += 1,
            429 => {
                limited_count += 1;
                // 429 responses should have rate limit headers
                assert!(
                    resp.headers().contains_key("x-ratelimit-limit")
                        || resp.headers().contains_key("retry-after"),
                    "429 response missing rate limit headers"
                );
            }
            s => panic!("unexpected status {}", s),
        }
    }
    assert!(ok_count > 0, "at least one request should succeed");
    assert!(
        limited_count > 0,
        "at least one request should be rate limited (got {} ok, {} limited)",
        ok_count,
        limited_count
    );
    drop(guard);
}

// =============================================================================
// 5. Quota enforcement (MaxBlobSize)
// =============================================================================

#[test]
fn max_blob_size_enforced() {
    // Start server with 1 KiB max blob size
    let (guard, base) = start_server_with_env(&[("KAPPA_MAX_BLOB_SIZE", "1024")]);
    let c = client();

    // Small blob should succeed
    let small = b"small blob under 1 KiB";
    let small_digest = sha256_digest(small);
    let resp = c
        .put(format!("{}/v2/quota/blobs/{}", base, small_digest))
        .body(small.to_vec())
        .send()
        .unwrap();
    assert_eq!(resp.status(), 201, "small blob should succeed");

    // Large blob should be rejected
    let large = vec![0x42u8; 2048];
    let large_digest = sha256_digest(&large);
    let resp = c
        .put(format!("{}/v2/quota/blobs/{}", base, large_digest))
        .body(large)
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        413,
        "large blob should be rejected with 413, got {}",
        resp.status()
    );
    drop(guard);
}

// =============================================================================
// 6. GC sweep under concurrent writes
// =============================================================================

#[test]
fn gc_sweep_does_not_delete_pinned_or_tagged_blobs() {
    let (guard, base) = start_server();
    let c = client();

    // Push a manifest and tag it -- the manifest blob itself is the protected object
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let put_resp = c
        .put(format!("{}/v2/gc-test/manifests/keep-me", base))
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(manifest_bytes.clone())
        .send()
        .unwrap();
    assert_eq!(put_resp.status(), 201);
    // The manifest's kappa is tagged -- GC protects it via the tag root set

    // Push an orphan blob (not referenced by any tag)
    let orphan = b"gc-orphan-blob-should-be-collected";
    let orphan_digest = sha256_digest(orphan);
    c.put(format!("{}/v2/gc-test/blobs/{}", base, orphan_digest))
        .body(orphan.to_vec())
        .send()
        .unwrap();

    // Run GC sweep
    let sweep = c
        .post(format!("{}/v2/gc-test/gc/sweep", base))
        .send()
        .unwrap();
    assert_eq!(sweep.status(), 202);
    let sweep_body: serde_json::Value = sweep.json().unwrap();
    assert!(
        sweep_body["objects_evicted"].as_u64().unwrap() > 0,
        "GC should have evicted at least the orphan blob"
    );

    // Tagged manifest blob should still exist
    let get = c
        .get(format!("{}/v2/gc-test/manifests/keep-me", base))
        .send()
        .unwrap();
    assert_eq!(get.status(), 200, "tagged manifest should survive GC");

    // Orphan blob should be gone
    let get_orphan = c
        .get(format!("{}/v2/gc-test/blobs/{}", base, orphan_digest))
        .send()
        .unwrap();
    assert_eq!(
        get_orphan.status(),
        404,
        "orphan blob should be collected by GC"
    );
    drop(guard);
}

// =============================================================================
// 7. Concurrent reads and writes (read-your-writes consistency)
// =============================================================================

#[test]
fn read_your_writes_under_concurrency() {
    let (guard, base) = start_server();
    let thread_count = 4;
    let barrier = Arc::new(Barrier::new(thread_count));

    let handles: Vec<_> = (0..thread_count)
        .map(|t| {
            let base = base.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let c = client();
                for i in 0..20 {
                    let content = format!("ryw-t{}-i{}-payload", t, i);
                    let content = content.as_bytes();
                    let digest = sha256_digest(content);
                    let ns = format!("ryw-{}", t);
                    let url = format!("{}/v2/{}/blobs/{}", base, ns, digest);

                    // Write
                    let put = c.put(&url).body(content.to_vec()).send().unwrap();
                    assert!(put.status() == 201 || put.status() == 200);

                    // Immediately read back -- must see own write
                    let get = c.get(&url).send().unwrap();
                    assert_eq!(
                        get.status(),
                        200,
                        "read-your-write failed: thread {} iter {}",
                        t,
                        i
                    );
                    assert_eq!(get.bytes().unwrap().as_ref(), content);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }
    drop(guard);
}

// =============================================================================
// 8. Blob delete then re-push (idempotent content addressing)
// =============================================================================

#[test]
fn delete_then_repush_same_content() {
    let (guard, base) = start_server();
    let c = client();
    let content = b"delete-then-repush";
    let digest = sha256_digest(content);
    let url = format!("{}/v2/repush/blobs/{}", base, digest);

    // Push
    let put1 = c.put(&url).body(content.to_vec()).send().unwrap();
    assert_eq!(put1.status(), 201);

    // Delete
    let del = c.delete(&url).send().unwrap();
    assert_eq!(del.status(), 202);

    // Verify gone
    let get1 = c.get(&url).send().unwrap();
    assert_eq!(get1.status(), 404);

    // Re-push same content
    let put2 = c.put(&url).body(content.to_vec()).send().unwrap();
    assert_eq!(put2.status(), 201, "re-push should create again");

    // Verify present
    let get2 = c.get(&url).send().unwrap();
    assert_eq!(get2.status(), 200);
    assert_eq!(get2.bytes().unwrap().as_ref(), content);
    drop(guard);
}

// =============================================================================
// 9. Store root filesystem verification
// =============================================================================

#[test]
fn blob_stored_at_correct_filesystem_path() {
    let (guard, base) = start_server();
    let c = client();
    let content = b"filesystem-path-test";
    let digest = sha256_digest(content);
    let url = format!("{}/v2/fscheck/blobs/{}", base, digest);

    c.put(&url).body(content.to_vec()).send().unwrap();

    // Verify the blob exists at blobs/{algo}/{shard1}/{shard2}/{hex}
    let hex = digest.strip_prefix("sha256:").unwrap();
    let blob_path = guard
        .store_root()
        .join("blobs")
        .join("sha256")
        .join(&hex[..2])
        .join(&hex[2..4])
        .join(hex);
    assert!(
        blob_path.exists(),
        "blob not found at expected path: {}",
        blob_path.display()
    );
    let stored = std::fs::read(&blob_path).unwrap();
    assert_eq!(stored, content, "stored content does not match");
    drop(guard);
}

#[test]
fn sha512_blob_stored_at_correct_filesystem_path() {
    let (guard, base) = start_server();
    let c = client();
    let content = b"sha512-filesystem-path-test";

    // Compute sha512 digest
    use sha2::{Digest, Sha512};
    let hash = Sha512::digest(content);
    let hex_str = hex::encode(hash);
    let digest = format!("sha512:{}", hex_str);

    let url = format!("{}/v2/fscheck512/blobs/{}", base, digest);
    let put = c.put(&url).body(content.to_vec()).send().unwrap();
    assert_eq!(
        put.status(),
        201,
        "sha512 blob PUT failed: {}",
        put.status()
    );

    // Verify filesystem path uses sha512 directory
    let blob_path = guard
        .store_root()
        .join("blobs")
        .join("sha512")
        .join(&hex_str[..2])
        .join(&hex_str[2..4])
        .join(&hex_str);
    assert!(
        blob_path.exists(),
        "sha512 blob not found at expected path: {}",
        blob_path.display()
    );
    let stored = std::fs::read(&blob_path).unwrap();
    assert_eq!(stored, content);
    drop(guard);
}
