//! Bearer token authentication tests.
//!
//! FAILS UNTIL: BearerAuth middleware is implemented in auth.rs and
//! KAPPA_AUTH_REQUIRED / KAPPA_AUTH_TOKENS env vars are added to
//! Config::from_env() in config.rs. The auth layer must be registered
//! in main.rs BEFORE the rate limiting layer (warning -> auth -> ratelimit
//! -> handler).
//!
//! Current auth.rs implements capability-edge authorization on reserved
//! namespaces, NOT bearer token auth. These tests will get 200 instead
//! of 401 until the bearer auth middleware exists.

#[path = "helpers/mod.rs"]
#[allow(dead_code, unused_imports)]
mod helpers;
use helpers::*;

/// Compute a real anchor from a deterministic Ed25519 seed.
/// Uses the same anchor derivation as NodeAnchor::from_key.
fn anchor_from_seed(seed: &[u8; 32]) -> String {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
    let public_key = signing_key.verifying_key().to_bytes();
    kappa_core::crypto::anchor::anchor_from_key_str("ed25519", &public_key)
}

fn authed_server() -> (ServerGuard, String, tempfile::TempDir) {
    let anchor1 = anchor_from_seed(&[1u8; 32]);
    let anchor2 = anchor_from_seed(&[2u8; 32]);
    let tokens = format!(
        "test-secret-token={},backup-token={}",
        anchor1, anchor2
    );
    start_server_with_env(&[
        ("KAPPA_AUTH_REQUIRED", "true"),
        ("KAPPA_AUTH_TOKENS", &tokens),
    ])
}

// =============================================================================
// Core auth tests
// =============================================================================

#[test]
fn auth_required_rejects_without_token() {
    // FAILS UNTIL: BearerAuth middleware implemented
    let (guard, base, _tmp) = authed_server();
    let c = client();
    let resp = c
        .get(format!("{}/v2/auth-ns/tags/list", base))
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "expected 401 without token, got {}",
        resp.status()
    );
    // Verify WWW-Authenticate header
    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .expect("401 must have WWW-Authenticate header")
        .to_str()
        .unwrap();
    assert!(
        www_auth.contains("Bearer"),
        "WWW-Authenticate should indicate Bearer: {}",
        www_auth
    );
    // Verify OCI error envelope
    let body = resp.text().unwrap();
    assert_oci_error(&body, "UNAUTHORIZED");
    drop(guard);
}

#[test]
fn auth_required_accepts_with_token() {
    // FAILS UNTIL: BearerAuth middleware implemented
    let (guard, base, _tmp) = authed_server();
    let c = client();
    let resp = c
        .get(format!("{}/v2/auth-ns/tags/list", base))
        .header("Authorization", "Bearer test-secret-token")
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "expected 200 with valid token, got {}",
        resp.status()
    );
    drop(guard);
}

#[test]
fn auth_required_rejects_wrong_token() {
    // FAILS UNTIL: BearerAuth middleware implemented
    let (guard, base, _tmp) = authed_server();
    let c = client();
    let resp = c
        .get(format!("{}/v2/auth-ns/tags/list", base))
        .header("Authorization", "Bearer completely-wrong-token")
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "expected 401 with wrong token, got {}",
        resp.status()
    );
    drop(guard);
}

#[test]
fn auth_exempt_status() {
    // FAILS UNTIL: BearerAuth middleware implemented (but _status is exempt)
    let (guard, base, _tmp) = authed_server();
    let c = client();
    let resp = c.get(format!("{}/_status", base)).send().unwrap();
    assert_eq!(resp.status(), 200, "/_status should be exempt from auth");
    drop(guard);
}

#[test]
fn auth_exempt_version() {
    let (guard, base, _tmp) = authed_server();
    let c = client();
    let resp = c.get(format!("{}/v2/", base)).send().unwrap();
    assert_eq!(resp.status(), 200, "/v2/ should be exempt from auth");
    drop(guard);
}

#[test]
fn auth_exempt_health() {
    let (guard, base, _tmp) = authed_server();
    let c = client();
    let resp = c.get(format!("{}/v2/_health/ready", base)).send().unwrap();
    assert_eq!(
        resp.status(),
        200,
        "/v2/_health/ready should be exempt from auth"
    );
    drop(guard);
}

#[test]
fn auth_not_required_allows_all() {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let resp = c
        .get(format!("{}/v2/noauth/tags/list", base))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "should allow all without auth_required");
    drop(guard);
}

// =============================================================================
// Extended auth tests
// =============================================================================

#[test]
fn auth_multiple_tokens_all_valid() {
    // FAILS UNTIL: BearerAuth middleware implemented
    let (guard, base, _tmp) = authed_server();
    let c = client();

    let resp1 = c
        .get(format!("{}/v2/multi/tags/list", base))
        .header("Authorization", "Bearer test-secret-token")
        .send()
        .unwrap();
    assert_eq!(resp1.status(), 200, "primary token should work");

    let resp2 = c
        .get(format!("{}/v2/multi/tags/list", base))
        .header("Authorization", "Bearer backup-token")
        .send()
        .unwrap();
    assert_eq!(resp2.status(), 200, "backup token should work");
    drop(guard);
}

#[test]
fn auth_bearer_case_sensitive() {
    // FAILS UNTIL: BearerAuth middleware implemented
    let (guard, base, _tmp) = authed_server();
    let c = client();
    let resp = c
        .get(format!("{}/v2/case/tags/list", base))
        .header("Authorization", "Bearer TEST-SECRET-TOKEN")
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "token comparison should be case-sensitive"
    );
    drop(guard);
}

#[test]
fn auth_does_not_leak_tokens_in_error_response() {
    // FAILS UNTIL: BearerAuth middleware implemented
    let (guard, base, _tmp) = authed_server();
    let c = client();
    let resp = c.get(format!("{}/v2/leak/tags/list", base)).send().unwrap();
    let body = resp.text().unwrap();
    assert!(
        !body.contains("test-secret-token"),
        "error response must not contain the token"
    );
    assert!(
        !body.contains("backup-token"),
        "error response must not contain any configured token"
    );
    drop(guard);
}

#[test]
fn auth_blob_put_requires_token() {
    // FAILS UNTIL: BearerAuth middleware implemented
    let (guard, base, _tmp) = authed_server();
    let c = client();
    let content = b"auth-blob-test";
    let digest = sha256_digest(content);

    // Without token -- should be 401
    let resp = c
        .put(format!("{}/v2/write-auth/blobs/{}", base, digest))
        .body(content.to_vec())
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "blob PUT without token should be rejected"
    );

    // With token -- should succeed
    let resp = c
        .put(format!("{}/v2/write-auth/blobs/{}", base, digest))
        .header("Authorization", "Bearer test-secret-token")
        .body(content.to_vec())
        .send()
        .unwrap();
    assert_eq!(resp.status(), 201, "blob PUT with token should succeed");
    drop(guard);
}

#[test]
fn auth_delete_requires_token() {
    // FAILS UNTIL: BearerAuth middleware implemented
    let (guard, base, _tmp) = authed_server();
    let c = client();
    let content = b"auth-delete-test";
    let digest = sha256_digest(content);

    // Push with token
    c.put(format!("{}/v2/del-auth/blobs/{}", base, digest))
        .header("Authorization", "Bearer test-secret-token")
        .body(content.to_vec())
        .send()
        .unwrap();

    // Delete without token
    let resp = c
        .delete(format!("{}/v2/del-auth/blobs/{}", base, digest))
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "blob DELETE without token should be rejected"
    );

    // Delete with token
    let resp = c
        .delete(format!("{}/v2/del-auth/blobs/{}", base, digest))
        .header("Authorization", "Bearer test-secret-token")
        .send()
        .unwrap();
    assert_eq!(resp.status(), 202, "blob DELETE with token should succeed");
    drop(guard);
}

#[test]
fn auth_layer_before_ratelimit() {
    // FAILS UNTIL: BearerAuth middleware implemented and layered before ratelimit
    //
    // Uses 60000ms period (60s) to avoid timing sensitivity from GCRA replenishment.
    // Governor replenishes tokens continuously. With a 1s period, tokens replenish
    // during the test. 60s ensures no replenishment during the test window.
    // Ref: tower-governor/src/tests.rs:108-165
    let (guard, base, _tmp) = start_server_with_env(&[
        ("KAPPA_AUTH_REQUIRED", "true"),
        ("KAPPA_AUTH_TOKENS", &format!("rate-test-token={}", anchor_from_seed(&[3u8; 32]))),
        ("KAPPA_RATELIMIT_READ_PERIOD_MS", "60000"),
        ("KAPPA_RATELIMIT_READ_BURST", "3"),
    ]);
    let c = client();

    // 5 unauthenticated requests -- all should be 401, NOT 429
    // If auth runs before ratelimit, no tokens are consumed.
    for i in 0..5 {
        let resp = c
            .get(format!("{}/v2/rl-auth/tags/list", base))
            .send()
            .unwrap();
        assert_eq!(
            resp.status(),
            401,
            "unauthed request {} should be 401 (not 429 -- auth before ratelimit)",
            i
        );
    }

    // 3 authenticated requests -- all should succeed (burst = 3)
    for i in 0..3 {
        let resp = c
            .get(format!("{}/v2/rl-auth/tags/list", base))
            .header("Authorization", "Bearer rate-test-token")
            .send()
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "authed request {} should succeed (burst not exhausted by unauthed)",
            i
        );
    }
    drop(guard);
}

#[test]
fn auth_token_from_file() {
    // FAILS UNTIL: @ prefix file loading is implemented in Config::from_env()
    // Convention: KAPPA_AUTH_TOKENS=@/path/to/file reads tokens from file, one per line.
    let file_tmp = tempfile::tempdir().unwrap();
    let token_file = file_tmp.path().join("tokens.txt");
    let file_contents = format!(
        "file-token-one={}\nfile-token-two={}\n",
        anchor_from_seed(&[4u8; 32]),
        anchor_from_seed(&[5u8; 32]),
    );
    std::fs::write(&token_file, file_contents).unwrap();

    let token_path = format!("@{}", token_file.to_str().unwrap());
    let (guard, base, _tmp) = start_server_with_env(&[
        ("KAPPA_AUTH_REQUIRED", "true"),
        ("KAPPA_AUTH_TOKENS", &token_path),
    ]);
    let c = client();

    let resp = c
        .get(format!("{}/v2/file-auth/tags/list", base))
        .header("Authorization", "Bearer file-token-one")
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "token from file should work");

    let resp = c
        .get(format!("{}/v2/file-auth/tags/list", base))
        .header("Authorization", "Bearer file-token-two")
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "second token from file should work");

    let resp = c
        .get(format!("{}/v2/file-auth/tags/list", base))
        .header("Authorization", "Bearer not-in-file")
        .send()
        .unwrap();
    assert_eq!(resp.status(), 401, "token not in file should be rejected");
    drop(guard);
}

#[test]
fn auth_empty_token_list_allows_all() {
    // SECURITY DECISION: auth_required=true with empty token list allows all.
    // Rationale: no tokens configured means authentication cannot be performed,
    // so the server operates in open mode. The alternative (deny all) would
    // brick a misconfigured server with no recovery path.
    // If this decision is wrong, change this test to expect 401.
    // FAILS UNTIL: BearerAuth middleware implemented
    let (guard, base, _tmp) =
        start_server_with_env(&[("KAPPA_AUTH_REQUIRED", "true"), ("KAPPA_AUTH_TOKENS", "")]);
    let c = client();
    let resp = c
        .get(format!("{}/v2/empty-auth/tags/list", base))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "empty token list should allow all");
    drop(guard);
}
