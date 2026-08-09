//! Streaming upload tests: prove chunked uploads use disk staging instead of
//! memory buffering, incremental digest computation is correct across axes,
//! staging files are cleaned up properly, and adversarial inputs are rejected.
//!
//! FAILS UNTIL: Disk-backed SessionStore is implemented in upload.rs replacing
//! the current Vec<u8> in-memory buffering.
//!
//! Adversarial tests informed by:
//! - OCI conformance run.go:940-1010 (out-of-order chunks)
//! - OCI conformance run.go:1279-1311 (bad digest on chunked upload)
//! - OCI conformance run.go:637-649 (whitespace-appended digest mismatch)
//! - OCI conformance run.go:1244-1248 (empty blob)

extern crate blake3;

#[path = "helpers/mod.rs"]
#[allow(dead_code, unused_imports)]
mod helpers;
use helpers::*;

use std::time::Duration;

// =============================================================================
// Memory-bounded upload
// RSS measurement: takes baseline BEFORE upload, measures delta AFTER.
// Linux-only for /proc. Upload success verified on all platforms.
// =============================================================================

#[test]
fn chunked_upload_100mb_rss_bounded() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let size: usize = 100 * 1024 * 1024;
    let chunk_size: usize = 1024 * 1024;

    // Measure baseline RSS before upload
    #[cfg(target_os = "linux")]
    let baseline_rss_kb = read_rss_kb(guard.pid());

    // Generate and upload deterministic content
    let mut upload_url = start_upload(&c, &base, "stream-100m");
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    let mut offset: usize = 0;
    while offset < size {
        let end = std::cmp::min(offset + chunk_size, size);
        let chunk: Vec<u8> = (offset..end).map(|i| (i % 251) as u8).collect();
        hasher.update(&chunk);
        upload_url = send_chunk(&c, &base, &upload_url, offset, &chunk);
        offset = end;
    }
    let digest = format!("sha256:{}", hex::encode(hasher.finalize()));

    // Complete
    let complete_url = format!("{}?digest={}", upload_url, digest);
    let resp = c.put(&complete_url).send().unwrap();
    assert_eq!(
        resp.status(),
        201,
        "100MB upload complete failed: {}",
        resp.text().unwrap()
    );

    // Verify RSS growth is bounded (Linux only)
    #[cfg(target_os = "linux")]
    {
        if let (Some(before), Some(after)) = (baseline_rss_kb, read_rss_kb(guard.pid())) {
            let growth_mb = (after.saturating_sub(before)) / 1024;
            assert!(
                growth_mb < 80,
                "server RSS grew by {} MB during 100MB upload -- \
                 should grow < 80 MB if streaming to disk. \
                 Baseline: {} KB, After: {} KB",
                growth_mb,
                before,
                after
            );
        }
    }

    // Verify content retrievable (all platforms)
    let head = c
        .head(format!("{}/v2/stream-100m/blobs/{}", base, digest))
        .send()
        .unwrap();
    assert_eq!(head.status(), 200);
    let cl: usize = head
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(cl, size, "uploaded blob size mismatch");
    drop(guard);
}

#[cfg(target_os = "linux")]
fn read_rss_kb(pid: u32) -> Option<u64> {
    let path = format!("/proc/{}/status", pid);
    let status = std::fs::read_to_string(&path).ok()?;
    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            return parts.get(1).and_then(|s| s.parse().ok());
        }
    }
    None
}

// =============================================================================
// Staging file lifecycle
// =============================================================================

#[test]
fn chunked_upload_complete_cleans_staging() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content: Vec<u8> = (0..65536).map(|i| (i % 199) as u8).collect();
    let digest = sha256_digest(&content);

    let mut upload_url = start_upload(&c, &base, "staging-clean");
    upload_url = send_chunk(&c, &base, &upload_url, 0, &content);

    // Complete
    let complete_url = format!("{}?digest={}", upload_url, digest);
    let resp = c.put(&complete_url).send().unwrap();
    assert_eq!(
        resp.status(),
        201,
        "complete failed: {}",
        resp.text().unwrap()
    );

    // After complete: staging dir should be empty
    let staging_dir = guard.store_root().join("staging");
    if staging_dir.exists() {
        let remaining: Vec<_> = std::fs::read_dir(&staging_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            remaining.is_empty(),
            "staging directory should be empty after complete, found {} entries",
            remaining.len()
        );
    }

    // Blob should be retrievable via HTTP
    let get = c
        .get(format!("{}/v2/staging-clean/blobs/{}", base, digest))
        .send()
        .unwrap();
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().unwrap().as_ref(), content.as_slice());
    drop(guard);
}

#[test]
fn chunked_upload_cancel_cleans_staging() {
    let (guard, base, _tmp) = start_server();
    let c = client();

    let upload_url = start_upload(&c, &base, "cancel-clean");
    let upload_url = send_chunk(&c, &base, &upload_url, 0, b"some chunk data here");

    let resp = c.delete(&upload_url).send().unwrap();
    assert_eq!(resp.status(), 204, "cancel failed");

    let staging_dir = guard.store_root().join("staging");
    if staging_dir.exists() {
        let remaining: Vec<_> = std::fs::read_dir(&staging_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            remaining.is_empty(),
            "staging should be empty after cancel, found {} entries",
            remaining.len()
        );
    }
    drop(guard);
}

// =============================================================================
// Digest mismatch rejection
// Informed by OCI conformance run.go:1279-1311 (bad digest blob tests)
// =============================================================================

#[test]
fn chunked_upload_digest_mismatch_rejects() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content = b"real content for digest mismatch";
    let wrong_digest = format!("sha256:{}", "0".repeat(64));

    let upload_url = start_upload(&c, &base, "mismatch");
    let upload_url = send_chunk(&c, &base, &upload_url, 0, content);

    let complete_url = format!("{}?digest={}", upload_url, wrong_digest);
    let resp = c.put(&complete_url).body(Vec::<u8>::new()).send().unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 400 || status == 409,
        "expected 400 or 409 for digest mismatch, got {}",
        status
    );
    drop(guard);
}

#[test]
fn chunked_upload_corrupted_bytes_rejected() {
    // OCI conformance run.go:1281-1286: appends "oh no" to blob bytes
    let (guard, base, _tmp) = start_server();
    let c = client();

    let real_content = b"real content uncorrupted";
    let digest_of_real = sha256_digest(real_content);
    let corrupted = [real_content.as_slice(), b"oh no"].concat();

    let upload_url = start_upload(&c, &base, "corrupt");
    let upload_url = send_chunk(&c, &base, &upload_url, 0, &corrupted);

    // Complete with digest of the UNCORRUPTED content
    let complete_url = format!("{}?digest={}", upload_url, digest_of_real);
    let resp = c.put(&complete_url).send().unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 400 || status == 409,
        "corrupted bytes should cause digest mismatch, got {}",
        status
    );
    drop(guard);
}

#[test]
fn chunked_upload_whitespace_appended_rejected() {
    // OCI conformance run.go:637-649: appends "  " to make digest mismatch
    let (guard, base, _tmp) = start_server();
    let c = client();

    let original = br#"{"schemaVersion":2}"#;
    let digest_of_original = sha256_digest(original);
    let tampered = [original.as_slice(), b"  "].concat();

    let upload_url = start_upload(&c, &base, "whitespace");
    let upload_url = send_chunk(&c, &base, &upload_url, 0, &tampered);

    let complete_url = format!("{}?digest={}", upload_url, digest_of_original);
    let resp = c.put(&complete_url).send().unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 400 || status == 409,
        "whitespace-appended content should cause digest mismatch, got {}",
        status
    );
    drop(guard);
}

// =============================================================================
// Out-of-order chunks
// OCI conformance run.go:1000-1010
// =============================================================================

#[test]
fn chunked_upload_out_of_order_rejected() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let chunk_size: usize = 4096;
    let content: Vec<u8> = (0..(chunk_size * 3)).map(|i| (i % 199) as u8).collect();

    let upload_url = start_upload(&c, &base, "ooo");
    let upload_url = send_chunk(&c, &base, &upload_url, 0, &content[0..chunk_size]);

    // Skip chunk 2, send chunk 3 -- out of order
    let resp = c
        .patch(&upload_url)
        .header("Content-Type", "application/octet-stream")
        .header(
            "Content-Range",
            format!("{}-{}", chunk_size * 2, chunk_size * 3 - 1),
        )
        .body(content[chunk_size * 2..chunk_size * 3].to_vec())
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        416,
        "out-of-order chunk should return 416, got {}",
        resp.status()
    );
    drop(guard);
}

// =============================================================================
// Empty blob via chunked upload
// OCI conformance run.go:1246 "empty"
// =============================================================================

#[test]
fn chunked_upload_empty_blob() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let digest = sha256_digest(b"");

    let upload_url = start_upload(&c, &base, "empty-chunked");
    let complete_url = format!("{}?digest={}", upload_url, digest);
    let resp = c.put(&complete_url).send().unwrap();
    let status = resp.status().as_u16();
    let resp_body = resp.text().unwrap_or_default();
    assert!(
        status == 201 || status == 200,
        "empty blob via chunked upload should succeed, got {} body: {}",
        status, resp_body
    );

    let get = c
        .get(format!("{}/v2/empty-chunked/blobs/{}", base, digest))
        .send()
        .unwrap();
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().unwrap().len(), 0);
    drop(guard);
}

// =============================================================================
// Multi-axis digest support
// =============================================================================

#[test]
fn chunked_upload_sha512_axis() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content: Vec<u8> = (0..8192).map(|i| (i % 199) as u8).collect();
    let digest = sha512_digest(&content);

    let upload_url = start_upload(&c, &base, "sha512-up");
    let upload_url = send_chunk(&c, &base, &upload_url, 0, &content);
    let complete_url = format!("{}?digest={}", upload_url, digest);
    let resp = c.put(&complete_url).send().unwrap();
    assert_eq!(
        resp.status(),
        201,
        "sha512 upload failed: {}",
        resp.text().unwrap()
    );

    let get = c
        .get(format!("{}/v2/sha512-up/blobs/{}", base, digest))
        .send()
        .unwrap();
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().unwrap().as_ref(), content.as_slice());
    drop(guard);
}

#[test]
fn chunked_upload_blake3_axis() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content: Vec<u8> = (0..8192).map(|i| (i % 173) as u8).collect();
    let digest = blake3_digest(&content);

    let upload_url = start_upload(&c, &base, "blake3-up");
    let upload_url = send_chunk(&c, &base, &upload_url, 0, &content);
    let complete_url = format!("{}?digest={}", upload_url, digest);
    let resp = c.put(&complete_url).send().unwrap();
    assert_eq!(
        resp.status(),
        201,
        "blake3 upload failed: {}",
        resp.text().unwrap()
    );

    let get = c
        .get(format!("{}/v2/blake3-up/blobs/{}", base, digest))
        .send()
        .unwrap();
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().unwrap().as_ref(), content.as_slice());
    drop(guard);
}

#[test]
fn chunked_upload_sha3_256_axis() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content: Vec<u8> = (0..8192).map(|i| (i % 199) as u8).collect();
    let digest = sha3_256_digest(&content);

    let upload_url = start_upload(&c, &base, "sha3-256-up");
    let upload_url = send_chunk(&c, &base, &upload_url, 0, &content);
    let complete_url = format!("{}?digest={}", upload_url, digest);
    let resp = c.put(&complete_url).send().unwrap();
    assert_eq!(
        resp.status(),
        201,
        "sha3-256 upload failed: {}",
        resp.text().unwrap()
    );

    let get = c
        .get(format!("{}/v2/sha3-256-up/blobs/{}", base, digest))
        .send()
        .unwrap();
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().unwrap().as_ref(), content.as_slice());
    drop(guard);
}

#[test]
fn chunked_upload_keccak256_axis() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content: Vec<u8> = (0..8192).map(|i| (i % 173) as u8).collect();
    let digest = keccak256_digest(&content);

    let upload_url = start_upload(&c, &base, "keccak256-up");
    let upload_url = send_chunk(&c, &base, &upload_url, 0, &content);
    let complete_url = format!("{}?digest={}", upload_url, digest);
    let resp = c.put(&complete_url).send().unwrap();
    assert_eq!(
        resp.status(),
        201,
        "keccak256 upload failed: {}",
        resp.text().unwrap()
    );

    let get = c
        .get(format!("{}/v2/keccak256-up/blobs/{}", base, digest))
        .send()
        .unwrap();
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().unwrap().as_ref(), content.as_slice());
    drop(guard);
}

// =============================================================================
// Upload recovery
// =============================================================================

#[test]
fn chunked_upload_resume_after_partial() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let chunk_size: usize = 4096;
    let content: Vec<u8> = (0..(chunk_size * 5)).map(|i| (i % 199) as u8).collect();
    let digest = sha256_digest(&content);

    let mut upload_url = start_upload(&c, &base, "resume");
    for i in 0..3 {
        let start = i * chunk_size;
        upload_url = send_chunk(
            &c,
            &base,
            &upload_url,
            start,
            &content[start..start + chunk_size],
        );
    }

    // Recovery: GET the upload URL
    let recovery = c.get(&upload_url).send().unwrap();
    assert_eq!(recovery.status(), 204, "recovery GET failed");
    let range = recovery.headers().get("range").unwrap().to_str().unwrap();
    assert!(
        range.contains(&format!("{}", 3 * chunk_size - 1)),
        "recovery range should show {} bytes, got: {}",
        3 * chunk_size,
        range
    );
    let loc = recovery
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let mut url = resolve_location(&base, loc);

    // Resume remaining 2 chunks
    for i in 3..5 {
        let start = i * chunk_size;
        url = send_chunk(&c, &base, &url, start, &content[start..start + chunk_size]);
    }

    let complete_url = format!("{}?digest={}", url, digest);
    let resp = c.put(&complete_url).send().unwrap();
    assert_eq!(
        resp.status(),
        201,
        "resume complete failed: {}",
        resp.text().unwrap()
    );

    let get = c
        .get(format!("{}/v2/resume/blobs/{}", base, digest))
        .send()
        .unwrap();
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().unwrap().as_ref(), content.as_slice());
    drop(guard);
}

// =============================================================================
// Staging file permissions (unix only)
// =============================================================================

#[test]
fn staging_file_permissions_not_world_readable() {
    #[cfg(not(unix))]
    {
        eprintln!("skipping staging permissions test on non-unix");
        return;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let (guard, base, _tmp) = start_server();
        let c = client();

        let upload_url = start_upload(&c, &base, "perms");
        // Send chunk and immediately check staging
        let _upload_url = send_chunk(&c, &base, &upload_url, 0, b"permissions-test-chunk-data");

        let staging_dir = guard.store_root().join("staging");
        if staging_dir.exists() {
            for path in walkdir_files(&staging_dir) {
                let mode = std::fs::metadata(&path).unwrap().permissions().mode();
                let world_bits = mode & 0o007;
                assert_eq!(
                    world_bits, 0,
                    "staging file {:?} is world-accessible: mode {:o}",
                    path, mode
                );
            }
        }
        drop(guard);
    }
}

// =============================================================================
// Zero-length chunk -- server must not crash
// =============================================================================

#[test]
fn chunked_upload_zero_length_chunk_no_crash() {
    let (guard, base, _tmp) = start_server();
    let c = client();

    let upload_url = start_upload(&c, &base, "zerochunk");
    let resp = c
        .patch(&upload_url)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Range", "0-0")
        .body(Vec::<u8>::new())
        .send()
        .unwrap();
    // Must not crash (500). Any other status is acceptable behavior.
    assert_ne!(resp.status(), 500, "zero-length chunk should not cause 500");
    // Server should still be responsive
    let status = c.get(format!("{}/_status", base)).send().unwrap().status();
    assert_eq!(status, 200, "server unresponsive after zero-length chunk");
    drop(guard);
}

// =============================================================================
// Streaming download tests
// Blob GET responses stream from file in 64 KiB chunks. Memory usage is
// O(chunk_size), not O(blob_size).
// =============================================================================

#[test]
fn streaming_download_large_blob_rss_bounded() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let size: usize = 100 * 1024 * 1024; // 100 MB
    let chunk_size: usize = 1024 * 1024;

    // Upload 100MB via chunked upload
    let mut upload_url = start_upload(&c, &base, "dl-100m");
    let mut upload_hasher = sha2::Sha256::new();
    use sha2::Digest;
    let mut offset: usize = 0;
    while offset < size {
        let end = std::cmp::min(offset + chunk_size, size);
        let chunk: Vec<u8> = (offset..end).map(|i| (i % 251) as u8).collect();
        upload_hasher.update(&chunk);
        upload_url = send_chunk(&c, &base, &upload_url, offset, &chunk);
        offset = end;
    }
    let digest = format!("sha256:{}", hex::encode(upload_hasher.finalize()));
    let complete_url = format!("{}?digest={}", upload_url, digest);
    let resp = c.put(&complete_url).send().unwrap();
    assert_eq!(resp.status(), 201, "upload failed: {}", resp.text().unwrap());

    // Measure baseline RSS before download
    #[cfg(target_os = "linux")]
    let baseline_rss = server_rss_kb(guard.pid());

    // Download and verify via streaming read
    let dl_resp = c
        .get(format!("{}/v2/dl-100m/blobs/{}", base, digest))
        .send()
        .unwrap();
    assert_eq!(dl_resp.status(), 200);

    let cl: usize = dl_resp
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(cl, size, "Content-Length mismatch");

    // Read body as bytes, hash it
    let body = dl_resp.bytes().unwrap();
    let mut dl_hasher = sha2::Sha256::new();
    dl_hasher.update(&body);
    assert_eq!(body.len(), size, "downloaded size mismatch");

    let dl_digest = format!("sha256:{}", hex::encode(dl_hasher.finalize()));
    assert_eq!(dl_digest, digest, "downloaded content digest mismatch");

    // Verify RSS growth is bounded (Linux only)
    #[cfg(target_os = "linux")]
    {
        if let (Some(before), Some(after)) = (baseline_rss, server_rss_kb(guard.pid())) {
            let growth_mb = (after.saturating_sub(before)) / 1024;
            assert!(
                growth_mb < 120,
                "server RSS grew by {} MB during 100MB download -- \
                 should grow < 120 MB if streaming from file. \
                 Baseline: {} KB, After: {} KB",
                growth_mb,
                before,
                after
            );
        }
    }
    drop(guard);
}

#[test]
fn streaming_download_content_length_set() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let size: usize = 10 * 1024 * 1024; // 10 MB
    let content: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let digest = sha256_digest(&content);
    c.put(format!("{}/v2/dl-cl/blobs/{}", base, digest))
        .body(content)
        .send()
        .unwrap();

    let resp = c
        .get(format!("{}/v2/dl-cl/blobs/{}", base, digest))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cl: usize = resp
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(cl, size);
    let body = resp.bytes().unwrap();
    assert_eq!(body.len(), size);
    drop(guard);
}

#[test]
fn streaming_download_concurrent_pulls_bounded() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let size: usize = 50 * 1024 * 1024; // 50 MB

    // Upload 50MB blob
    let mut upload_url = start_upload(&c, &base, "dl-conc");
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    let chunk_size: usize = 1024 * 1024;
    let mut offset: usize = 0;
    while offset < size {
        let end = std::cmp::min(offset + chunk_size, size);
        let chunk: Vec<u8> = (offset..end).map(|i| (i % 251) as u8).collect();
        hasher.update(&chunk);
        upload_url = send_chunk(&c, &base, &upload_url, offset, &chunk);
        offset = end;
    }
    let digest = format!("sha256:{}", hex::encode(hasher.finalize()));
    let complete_url = format!("{}?digest={}", upload_url, digest);
    c.put(&complete_url).send().unwrap();

    #[cfg(target_os = "linux")]
    let baseline_rss = server_rss_kb(guard.pid());

    // 5 concurrent GETs
    let handles: Vec<_> = (0..5)
        .map(|_| {
            let url = format!("{}/v2/dl-conc/blobs/{}", base, digest);
            let expected_size = size;
            std::thread::spawn(move || {
                let c = reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(120))
                    .build()
                    .unwrap();
                let resp = c.get(&url).send().unwrap();
                assert_eq!(resp.status().as_u16(), 200);
                let body = resp.bytes().unwrap();
                assert_eq!(body.len(), expected_size);
                true
            })
        })
        .collect();

    for h in handles {
        assert!(h.join().unwrap(), "concurrent download failed");
    }

    #[cfg(target_os = "linux")]
    {
        if let (Some(before), Some(after)) = (baseline_rss, server_rss_kb(guard.pid())) {
            let growth_mb = (after.saturating_sub(before)) / 1024;
            assert!(
                growth_mb < 100,
                "server RSS grew by {} MB during 5 concurrent 50MB downloads -- \
                 should grow < 100 MB if streaming. \
                 Baseline: {} KB, After: {} KB",
                growth_mb,
                before,
                after
            );
        }
    }
    drop(guard);
}

#[test]
fn streaming_download_small_blob_unchanged() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content = b"small blob content for streaming test";
    let digest = sha256_digest(content);
    c.put(format!("{}/v2/dl-small/blobs/{}", base, digest))
        .body(content.to_vec())
        .send()
        .unwrap();

    let resp = c
        .get(format!("{}/v2/dl-small/blobs/{}", base, digest))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("docker-content-digest").unwrap().to_str().unwrap(),
        digest
    );
    assert_eq!(
        resp.headers().get("accept-ranges").unwrap().to_str().unwrap(),
        "bytes"
    );
    assert_eq!(resp.bytes().unwrap().as_ref(), content);
    drop(guard);
}

#[test]
fn streaming_download_manifest_streams() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    // 3MB manifest (under default 4MB max_api_body_bytes limit)
    let manifest_size = 3 * 1024 * 1024;
    let manifest: Vec<u8> = {
        let mut m = br#"{"schemaVersion":2,"config":{"digest":"sha256:aaaa","data":""#.to_vec();
        // Pad with spaces to reach target size
        let padding_needed = manifest_size - m.len() - 3; // 3 for closing '"}}'
        m.extend(std::iter::repeat(b' ').take(padding_needed));
        m.extend(br#""}}"#);
        m
    };
    let tag = "big-manifest";
    let status = push_manifest(&c, &base, "dl-manifest", tag, &manifest);
    assert!(status == 201, "manifest push failed: {}", status);

    let resp = c
        .get(format!("{}/v2/dl-manifest/manifests/{}", base, tag))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cl: usize = resp
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(cl, manifest.len());
    let body = resp.bytes().unwrap();
    assert_eq!(body.len(), manifest.len());
    drop(guard);
}

#[test]
fn streaming_download_head_no_body() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content = b"head test blob for streaming";
    let digest = sha256_digest(content);
    c.put(format!("{}/v2/dl-head/blobs/{}", base, digest))
        .body(content.to_vec())
        .send()
        .unwrap();

    let resp = c
        .head(format!("{}/v2/dl-head/blobs/{}", base, digest))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cl: usize = resp
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(cl, content.len());
    // HEAD body must be empty
    assert_eq!(resp.bytes().unwrap().len(), 0);
    drop(guard);
}
