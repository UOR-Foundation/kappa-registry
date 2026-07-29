//! Security and correctness tests: GC sweep, schema validation, filter
//! rejection, malformed request handling.

#[path = "helpers/mod.rs"]
#[allow(dead_code, unused_imports)]
mod helpers;
use helpers::*;

// =============================================================================
// GAP 15: GC sweep correctness
// Operational test gc_sweep_does_not_delete_pinned_or_tagged_blobs tests
// basic GC behavior. This tests additional invariants.
// =============================================================================

#[test]
fn gc_sweep_preserves_tagged_blobs() {
    let (guard, base, _tmp) = start_server();
    let c = client();

    // Push a manifest and tag it
    let manifest = br#"{"schemaVersion":2,"gc":"tagged"}"#;
    push_manifest(&c, &base, "gc-sec", "keep-me", manifest);

    // Push an orphan blob (not referenced by any tag)
    let orphan = b"gc-orphan-security-test";
    let orphan_digest = sha256_digest(orphan);
    push_blob(&c, &base, "gc-sec", orphan);

    // Run GC
    let resp = c
        .post(format!("{}/v2/gc-sec/gc/sweep", base))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 202, "gc sweep should return 202");

    // Tagged manifest should survive
    let get = c
        .get(format!("{}/v2/gc-sec/manifests/keep-me", base))
        .send()
        .unwrap();
    assert_eq!(get.status(), 200, "tagged manifest should survive GC");

    // Orphan should be evicted
    let get = c
        .get(format!("{}/v2/gc-sec/blobs/{}", base, orphan_digest))
        .send()
        .unwrap();
    assert_eq!(
        get.status(),
        404,
        "orphan blob should be evicted by GC, got {}",
        get.status()
    );
    drop(guard);
}

// =============================================================================
// GAP 18: Schema validation before storage
// CLAUDE.md: "validate schema (BEFORE storing)"
// =============================================================================

#[test]
fn schema_validation_rejects_invalid_content() {
    let (guard, base, _tmp) = start_server();
    let c = client();

    // Register a JSON schema that requires "name" field
    let schema = serde_json::json!({
        "format": "json-schema",
        "scope": "strict",
        "validation": {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {"type": "string"}
            }
        }
    });
    let resp = c
        .put(format!("{}/v2/schema-ns/schemas/strict", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&schema).unwrap())
        .send()
        .unwrap();
    assert_eq!(resp.status(), 201, "schema register should succeed");

    // Push content that violates the schema (missing "name")
    let invalid = br#"{"value": "no name field"}"#;
    let resp = c
        .put(format!("{}/v2/schema-ns/manifests/test", base))
        .header("content-type", "application/json")
        .body(invalid.to_vec())
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        422,
        "schema-violating content should be rejected with 422, got {}",
        resp.status()
    );

    // Verify rejected content was NOT stored
    let invalid_digest = sha256_digest(invalid);
    let get = c
        .get(format!("{}/v2/schema-ns/blobs/{}", base, invalid_digest))
        .send()
        .unwrap();
    assert_eq!(get.status(), 404, "rejected content should NOT be stored");
    drop(guard);
}

// =============================================================================
// Filter rejection (already tested in smoke, but here we verify
// rejected content is NOT stored -- the invariant CLAUDE.md specifies)
// =============================================================================

#[test]
fn filter_rejected_content_not_stored() {
    let (guard, base, _tmp) = start_server();
    let c = client();

    // Register a filter that rejects content containing "forbidden"
    let resp = c
        .put(format!("{}/v2/filter-ns/filters/deny-forbidden", base))
        .body(b"deny:forbidden".to_vec())
        .send()
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Push content containing "forbidden"
    let bad = b"this has forbidden content";
    let resp = c
        .put(format!("{}/v2/filter-ns/manifests/bad", base))
        .header("content-type", "application/json")
        .body(bad.to_vec())
        .send()
        .unwrap();
    assert_eq!(resp.status(), 422, "filtered content should be rejected");

    // Verify rejected content was NOT stored
    let bad_digest = sha256_digest(bad);
    let get = c
        .get(format!("{}/v2/filter-ns/blobs/{}", base, bad_digest))
        .send()
        .unwrap();
    assert_eq!(
        get.status(),
        404,
        "filter-rejected content should NOT be stored"
    );
    drop(guard);
}

// =============================================================================
// GAP 28: Malformed request handling
// =============================================================================

#[test]
fn blob_put_empty_body_handled() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let digest = sha256_digest(b"");
    let url = format!("{}/v2/malform/blobs/{}", base, digest);

    // Empty body with the digest of empty bytes -- should succeed
    let resp = c.put(&url).body(Vec::<u8>::new()).send().unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 200 || status == 201,
        "empty blob PUT should succeed, got {}",
        status
    );
    drop(guard);
}

#[test]
fn manifest_put_invalid_json_rejected() {
    let (guard, base, _tmp) = start_server();
    let c = client();

    // Push invalid JSON as a manifest
    let resp = c
        .put(format!("{}/v2/malform/manifests/bad-json", base))
        .header("content-type", "application/json")
        .body(b"this is not json {{{".to_vec())
        .send()
        .unwrap();
    // Server should not crash (500). 201 is acceptable (stored as opaque bytes).
    // 400 is acceptable (rejected invalid manifest).
    assert_ne!(resp.status(), 500, "invalid JSON should not cause 500");
    drop(guard);
}

#[test]
fn path_traversal_rejected() {
    let (guard, base, _tmp) = start_server();
    let c = client();

    // Try namespace with path traversal
    let resp = c
        .get(format!("{}/v2/../../../etc/passwd/tags/list", base))
        .send()
        .unwrap();
    // Should not return 200 with sensitive data. 400 or 404 acceptable.
    assert_ne!(resp.status(), 200, "path traversal should not return 200");
    drop(guard);
}

#[test]
fn extremely_long_header_handled() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content = b"long-header-test";
    let digest = sha256_digest(content);

    // Send a request with an extremely long header value
    let long_value = "x".repeat(100_000);
    let resp = c
        .put(format!("{}/v2/malform/blobs/{}", base, digest))
        .header("X-Custom-Header", long_value)
        .body(content.to_vec())
        .send();

    // Should not crash. Connection error or 400/413 acceptable.
    if let Ok(r) = resp {
        assert_ne!(r.status(), 500, "long header should not cause 500");
    }
    // Err case (connection error) is acceptable -- no assertion needed
    drop(guard);
}

// =============================================================================
// GAP 24: Reserved namespace authorization
// auth.rs implements capability-edge auth on reserved namespaces
// =============================================================================

#[test]
fn reserved_namespace_requires_capability() {
    let (guard, base, _tmp) = start_server();
    let c = client();

    // Push to a reserved namespace prefix without capability edge
    // Reserved prefixes: kappa/protocols, kappa/runtimes, kappa/os,
    // kappa/identity, nix, sesame
    let content = b"unauthorized-push";
    let digest = sha256_digest(content);
    let resp = c
        .put(format!("{}/v2/kappa/protocols/test/blobs/{}", base, digest))
        .body(content.to_vec())
        .send()
        .unwrap();
    // Should be rejected (403 or 401)
    let status = resp.status().as_u16();
    assert!(
        status == 403 || status == 401,
        "push to reserved namespace without capability should be rejected, got {}",
        status
    );

    // Push to a non-reserved namespace should succeed
    let resp = c
        .put(format!("{}/v2/myorg/myrepo/blobs/{}", base, digest))
        .body(content.to_vec())
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        201,
        "push to non-reserved namespace should succeed"
    );
    drop(guard);
}
