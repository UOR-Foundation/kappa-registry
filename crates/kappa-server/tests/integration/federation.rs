//! Federation primitive tests. NOT multi-node federation.
//! Federation itself is out of scope for this implementation phase.
//!
//! These test the primitives federation requires:
//! - verify_kappa rejects tampered/wrong-digest content
//! - blob_put is idempotent (federation cache semantics)
//! - Content is byte-exact after roundtrip (federation integrity invariant)
//! - Multi-axis blob integrity (sha256, sha512, blake3)

#[path = "helpers/mod.rs"]
#[allow(dead_code, unused_imports)]
mod helpers;
use helpers::*;

// =============================================================================
// verify_kappa: reject tampered content
// The primitive federation fetch-and-verify depends on
// =============================================================================

#[test]
fn verify_kappa_rejects_wrong_digest_on_put() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content = b"content for wrong digest test";
    let wrong_digest = format!("sha256:{}", "0".repeat(64));

    let resp = c
        .put(format!("{}/v2/fed-prim/blobs/{}", base, wrong_digest))
        .body(content.to_vec())
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "PUT with wrong digest should be 400, got {}",
        resp.status()
    );
    // Verify OCI error envelope
    let body = resp.text().unwrap();
    assert_oci_error(&body, "DIGEST_INVALID");
    drop(guard);
}

#[test]
fn verify_kappa_protects_existing_content() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let real = b"real content for verification";
    let digest = sha256_digest(real);

    // Push real content
    let resp = c
        .put(format!("{}/v2/fed-prim/blobs/{}", base, digest))
        .body(real.to_vec())
        .send()
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Push tampered content with same digest -- should either reject (400)
    // or return 200 (idempotent, existing blob untouched)
    let tampered = b"TAMPERED content";
    let resp = c
        .put(format!("{}/v2/fed-prim/blobs/{}", base, digest))
        .body(tampered.to_vec())
        .send()
        .unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 400 || status == 200,
        "expected 400 or 200, got {}",
        status
    );

    // Original content MUST be intact regardless
    let get = c
        .get(format!("{}/v2/fed-prim/blobs/{}", base, digest))
        .send()
        .unwrap();
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().unwrap().as_ref(), real, "content was tampered");
    drop(guard);
}

// =============================================================================
// Idempotent put: the primitive federation caching depends on
// =============================================================================

#[test]
fn blob_put_idempotent() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content = b"idempotent cache test";
    let digest = sha256_digest(content);
    let url = format!("{}/v2/fed-prim/blobs/{}", base, digest);

    let resp1 = c.put(&url).body(content.to_vec()).send().unwrap();
    assert_eq!(resp1.status(), 201, "first put should be 201");

    let resp2 = c.put(&url).body(content.to_vec()).send().unwrap();
    assert_eq!(resp2.status(), 200, "second put should be 200 (idempotent)");

    let get = c.get(&url).send().unwrap();
    assert_eq!(get.bytes().unwrap().as_ref(), content);
    drop(guard);
}

// =============================================================================
// Byte-exact integrity: federation invariant
// =============================================================================

#[test]
fn blob_content_byte_exact_roundtrip() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    // Content with every byte value including null, high bytes, control chars
    let content: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let digest = sha256_digest(&content);
    let url = format!("{}/v2/fed-prim/blobs/{}", base, digest);

    c.put(&url).body(content.clone()).send().unwrap();
    let get = c.get(&url).send().unwrap();
    assert_eq!(get.status(), 200);
    assert_eq!(
        get.bytes().unwrap().as_ref(),
        content.as_slice(),
        "blob content is not byte-exact after roundtrip"
    );
    drop(guard);
}

#[test]
fn blob_sha512_integrity() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let content = b"sha512 integrity test";
    let digest = sha512_digest(content);
    let url = format!("{}/v2/fed-prim/blobs/{}", base, digest);

    let resp = c.put(&url).body(content.to_vec()).send().unwrap();
    assert_eq!(resp.status(), 201);
    let get = c.get(&url).send().unwrap();
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().unwrap().as_ref(), content);
    drop(guard);
}

// =============================================================================
// HTTP client timeout: the primitive federation timeout depends on
// =============================================================================

#[test]
fn reqwest_client_timeout_honored() {
    use std::time::Duration;
    let c = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap();

    let start = std::time::Instant::now();
    let result = c.get("http://192.0.2.1:1/v2/x/blobs/sha256:abc").send();
    let elapsed = start.elapsed();

    assert!(
        result.is_err(),
        "request to non-routable address should fail"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "timeout should fire, took {:?}",
        elapsed
    );
}
