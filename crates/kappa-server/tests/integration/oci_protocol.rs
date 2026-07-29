//! OCI protocol correctness tests covering gaps identified by adversarial
//! review against OCI distribution-spec conformance/run.go.
//!
//! These test behaviors the smoke and operational tests do not cover:
//! - Blob DELETE atomicity (run.go:1406-1431)
//! - Tag DELETE atomicity (run.go:1347-1376)
//! - Manifest PUT with bad digest (run.go:637-649, 1697-1710)
//! - Tag list pagination (run.go:1586-1632)
//! - Range requests (run.go:1102-1238)
//! - Content-type preservation
//! - Response headers (docker-content-digest, x-kappa-label, etc.)
//! - Warning header on every response
//! - HEAD returns same headers as GET minus body

#[path = "helpers/mod.rs"]
#[allow(dead_code, unused_imports)]
mod helpers;
use helpers::*;

// =============================================================================
// GAP 2: Blob DELETE atomicity
// OCI conformance run.go:1406-1431 (stateAPIBlobDeleteAtomic)
// =============================================================================

#[test]
fn blob_delete_then_head_returns_404() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content = b"delete-atomicity-test";
    let digest = sha256_digest(content);
    let url = format!("{}/v2/oci-del/blobs/{}", base, digest);

    c.put(&url).body(content.to_vec()).send().unwrap();
    let del = c.delete(&url).send().unwrap();
    assert_eq!(del.status(), 202, "DELETE should return 202");

    let head = c.head(&url).send().unwrap();
    assert_eq!(
        head.status(),
        404,
        "HEAD after DELETE should return 404, got {}",
        head.status()
    );
    drop(guard);
}

// =============================================================================
// GAP 3: Tag DELETE atomicity
// OCI conformance run.go:1347-1376 (stateAPITagDeleteAtomic)
// =============================================================================

#[test]
fn tag_delete_then_get_returns_404() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content = br#"{"schemaVersion":2}"#;

    push_manifest(&c, &base, "oci-tagdel", "removeme", content);
    let del = c
        .delete(format!("{}/v2/oci-tagdel/manifests/removeme", base))
        .send()
        .unwrap();
    assert_eq!(del.status(), 202, "tag DELETE should return 202");

    let get = c
        .get(format!("{}/v2/oci-tagdel/manifests/removeme", base))
        .send()
        .unwrap();
    assert_eq!(
        get.status(),
        404,
        "GET after tag DELETE should return 404, got {}",
        get.status()
    );
    drop(guard);
}

// =============================================================================
// GAP 4: Manifest PUT with bad digest
// OCI conformance run.go:1697-1710 ("sha256:baddigeststring")
// =============================================================================

#[test]
fn manifest_put_with_bad_digest_format_rejected() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content = br#"{"schemaVersion":2}"#;

    // Push manifest with malformed digest as the reference
    let resp = c
        .put(format!(
            "{}/v2/oci-baddig/manifests/sha256:baddigeststring",
            base
        ))
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(content.to_vec())
        .send()
        .unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 400 || status == 404,
        "manifest PUT with bad digest format should be rejected, got {}",
        status
    );
    drop(guard);
}

// =============================================================================
// GAP 5: Tag list pagination
// OCI conformance run.go:1586-1632
// =============================================================================

#[test]
fn tag_list_pagination_with_last_parameter() {
    let (guard, base, _tmp) = start_server();
    let c = client();

    // Create 5 tags
    for tag in ["alpha", "beta", "gamma", "delta", "epsilon"] {
        let content = format!(r#"{{"schemaVersion":2,"tag":"{}"}}"#, tag);
        push_manifest(&c, &base, "oci-page", tag, content.as_bytes());
    }

    // Full list
    let resp = c
        .get(format!("{}/v2/oci-page/tags/list", base))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().unwrap();
    let tags = body["tags"].as_array().unwrap();
    assert_eq!(tags.len(), 5, "should have 5 tags");

    // Paginated: last=delta should exclude alpha, beta, delta and include epsilon, gamma
    let resp = c
        .get(format!("{}/v2/oci-page/tags/list?last=delta", base))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().unwrap();
    let tags = body["tags"].as_array().unwrap();
    let tag_names: Vec<&str> = tags
        .iter()
        .filter_map(|t| {
            t.get("name")
                .and_then(|n| n.as_str())
                .or_else(|| t.as_str())
        })
        .collect();
    // Tags after "delta" lexicographically: epsilon, gamma
    assert!(
        !tag_names.contains(&"alpha"),
        "alpha should be excluded (before last)"
    );
    assert!(
        !tag_names.contains(&"beta"),
        "beta should be excluded (before last)"
    );
    assert!(
        !tag_names.contains(&"delta"),
        "delta should be excluded (is last)"
    );
    drop(guard);
}

// =============================================================================
// GAP 6: Range requests on blobs
// OCI conformance run.go:1102-1238
// =============================================================================

#[test]
fn blob_range_request_middle() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content: Vec<u8> = (0..2048u16).map(|i| (i % 256) as u8).collect();
    let digest = sha256_digest(&content);
    let url = format!("{}/v2/oci-range/blobs/{}", base, digest);
    c.put(&url).body(content.clone()).send().unwrap();

    // Range: bytes=500-1499
    let resp = c
        .get(&url)
        .header("Range", "bytes=500-1499")
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        206,
        "range request should return 206, got {}",
        resp.status()
    );
    let body = resp.bytes().unwrap();
    assert_eq!(body.len(), 1000, "range body should be 1000 bytes");
    assert_eq!(body.as_ref(), &content[500..1500]);
    drop(guard);
}

#[test]
fn blob_range_request_open_ended() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content: Vec<u8> = (0..2048u16).map(|i| (i % 256) as u8).collect();
    let digest = sha256_digest(&content);
    let url = format!("{}/v2/oci-range/blobs/{}", base, digest);
    c.put(&url).body(content.clone()).send().unwrap();

    // Range: bytes=500-
    let resp = c.get(&url).header("Range", "bytes=500-").send().unwrap();
    assert_eq!(resp.status(), 206);
    let body = resp.bytes().unwrap();
    assert_eq!(body.len(), 2048 - 500);
    assert_eq!(body.as_ref(), &content[500..]);
    drop(guard);
}

#[test]
fn blob_range_request_suffix() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content: Vec<u8> = (0..2048u16).map(|i| (i % 256) as u8).collect();
    let digest = sha256_digest(&content);
    let url = format!("{}/v2/oci-range/blobs/{}", base, digest);
    c.put(&url).body(content.clone()).send().unwrap();

    // Range: bytes=-500
    let resp = c.get(&url).header("Range", "bytes=-500").send().unwrap();
    assert_eq!(resp.status(), 206);
    let body = resp.bytes().unwrap();
    assert_eq!(body.len(), 500);
    assert_eq!(body.as_ref(), &content[2048 - 500..]);
    drop(guard);
}

#[test]
fn blob_range_request_inverted_returns_416() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content: Vec<u8> = (0..2048u16).map(|i| (i % 256) as u8).collect();
    let digest = sha256_digest(&content);
    let url = format!("{}/v2/oci-range/blobs/{}", base, digest);
    c.put(&url).body(content.clone()).send().unwrap();

    // Range: bytes=500-0 (inverted)
    let resp = c.get(&url).header("Range", "bytes=500-0").send().unwrap();
    assert_eq!(
        resp.status(),
        416,
        "inverted range should return 416, got {}",
        resp.status()
    );
    drop(guard);
}

#[test]
fn blob_range_request_past_end_returns_416() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content: Vec<u8> = (0..2048u16).map(|i| (i % 256) as u8).collect();
    let digest = sha256_digest(&content);
    let url = format!("{}/v2/oci-range/blobs/{}", base, digest);
    c.put(&url).body(content.clone()).send().unwrap();

    // Range: bytes=5000-10000 (entirely past end)
    let resp = c
        .get(&url)
        .header("Range", "bytes=5000-10000")
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        416,
        "range past end should return 416, got {}",
        resp.status()
    );
    drop(guard);
}

// =============================================================================
// GAP 16: Content-type preservation
// =============================================================================

#[test]
fn content_type_preserved_on_get() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content = b"content-type-test";
    let digest = sha256_digest(content);
    let url = format!("{}/v2/oci-ct/blobs/{}", base, digest);

    c.put(&url)
        .header("content-type", "application/json")
        .body(content.to_vec())
        .send()
        .unwrap();

    let resp = c.get(&url).send().unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(ct, "application/json", "content-type should be preserved");
    drop(guard);
}

#[test]
fn content_type_defaults_to_octet_stream() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content = b"no-content-type";
    let digest = sha256_digest(content);
    let url = format!("{}/v2/oci-ct/blobs/{}", base, digest);

    // PUT without Content-Type header
    c.put(&url).body(content.to_vec()).send().unwrap();

    let resp = c.get(&url).send().unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(
        ct, "application/octet-stream",
        "default content-type should be application/octet-stream"
    );
    drop(guard);
}

// =============================================================================
// GAP 17: Response headers (docker-content-digest, x-kappa-label, etc.)
// CLAUDE.md: every GET/HEAD response includes these headers
// =============================================================================

#[test]
fn blob_get_includes_required_headers() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content = b"header-test-blob";
    let digest = sha256_digest(content);
    let url = format!("{}/v2/oci-hdr/blobs/{}", base, digest);
    c.put(&url).body(content.to_vec()).send().unwrap();

    let resp = c.get(&url).send().unwrap();
    assert_eq!(resp.status(), 200);
    let headers = resp.headers();

    assert!(
        headers.get("docker-content-digest").is_some(),
        "missing docker-content-digest"
    );
    assert_eq!(
        headers
            .get("docker-content-digest")
            .unwrap()
            .to_str()
            .unwrap(),
        digest
    );

    assert!(
        headers.get("x-kappa-label").is_some(),
        "missing x-kappa-label"
    );
    assert_eq!(
        headers.get("x-kappa-label").unwrap().to_str().unwrap(),
        digest
    );

    assert!(
        headers.get("x-kappa-axis").is_some(),
        "missing x-kappa-axis"
    );
    assert_eq!(
        headers.get("x-kappa-axis").unwrap().to_str().unwrap(),
        "sha256"
    );

    assert!(
        headers.get("content-length").is_some(),
        "missing content-length"
    );
    assert!(
        headers.get("accept-ranges").is_some(),
        "missing accept-ranges"
    );
    assert_eq!(
        headers.get("accept-ranges").unwrap().to_str().unwrap(),
        "bytes"
    );
    drop(guard);
}

// =============================================================================
// GAP 22: Warning header on every response
// kappa-distribution spec section 6.1
// =============================================================================

#[test]
fn warning_header_on_blob_get() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content = b"warning-header-test";
    let digest = sha256_digest(content);
    let url = format!("{}/v2/oci-warn/blobs/{}", base, digest);
    c.put(&url).body(content.to_vec()).send().unwrap();

    let resp = c.get(&url).send().unwrap();
    let warning = resp.headers().get("warning");
    assert!(warning.is_some(), "missing Warning header on blob GET");
    let val = warning.unwrap().to_str().unwrap();
    assert!(
        val.contains("299"),
        "Warning header should contain 299: {}",
        val
    );
    assert!(
        val.contains("kappa-registry"),
        "Warning should contain kappa-registry: {}",
        val
    );
    drop(guard);
}

#[test]
fn warning_header_on_error_response() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let url = format!("{}/v2/oci-warn/blobs/sha256:{}", base, "0".repeat(64));

    let resp = c.get(&url).send().unwrap();
    assert_eq!(resp.status(), 404);
    let warning = resp.headers().get("warning");
    assert!(
        warning.is_some(),
        "missing Warning header on 404 error response"
    );
    drop(guard);
}

// =============================================================================
// GAP 29: HEAD returns same headers as GET minus body
// =============================================================================

#[test]
fn head_returns_same_headers_as_get() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content = b"head-parity-test";
    let digest = sha256_digest(content);
    let url = format!("{}/v2/oci-head/blobs/{}", base, digest);
    c.put(&url).body(content.to_vec()).send().unwrap();

    let get_resp = c.get(&url).send().unwrap();
    let head_resp = c.head(&url).send().unwrap();

    assert_eq!(get_resp.status(), head_resp.status());

    for header_name in [
        "content-type",
        "content-length",
        "docker-content-digest",
        "x-kappa-label",
        "x-kappa-axis",
        "accept-ranges",
    ] {
        let get_val = get_resp
            .headers()
            .get(header_name)
            .map(|v| v.to_str().unwrap().to_string());
        let head_val = head_resp
            .headers()
            .get(header_name)
            .map(|v| v.to_str().unwrap().to_string());
        assert_eq!(
            get_val, head_val,
            "header '{}' differs between GET and HEAD: GET={:?}, HEAD={:?}",
            header_name, get_val, head_val
        );
    }
    drop(guard);
}

// =============================================================================
// GAP 30: Sequence isolation across namespaces
// =============================================================================

#[test]
fn sequence_isolated_across_namespaces() {
    let (guard, base, _tmp) = start_server();
    let c = client();

    // Increment counter in namespace A
    let resp = c
        .post(format!("{}/v2/ns-a/_sequence/counter/next", base))
        .send()
        .unwrap();
    let body: serde_json::Value = resp.json().unwrap();
    assert_eq!(body["value"], 1);

    let resp = c
        .post(format!("{}/v2/ns-a/_sequence/counter/next", base))
        .send()
        .unwrap();
    let body: serde_json::Value = resp.json().unwrap();
    assert_eq!(body["value"], 2);

    // Counter in namespace B should start at 1, not 3
    let resp = c
        .post(format!("{}/v2/ns-b/_sequence/counter/next", base))
        .send()
        .unwrap();
    let body: serde_json::Value = resp.json().unwrap();
    assert_eq!(
        body["value"], 1,
        "namespace B counter should be independent of namespace A"
    );
    drop(guard);
}
