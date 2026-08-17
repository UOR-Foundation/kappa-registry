//! AKD audit proof tests.
//!
//! Identity assertions require ed25519 signatures. The signed_assertion
//! helper in helpers/mod.rs generates a keypair, builds the IdentityAssertion
//! with kappa_core, computes signable_bytes, signs with ed25519-dalek,
//! and returns the full JSON body for POST /identity/assert.
//!
//! AKD proof/audit endpoints are not yet implemented. Tests that depend
//! on them will fail until AkdManager wraps akd::Directory and the
//! proof/audit HTTP endpoints are wired.

#[path = "helpers/mod.rs"]
#[allow(dead_code, unused_imports)]
mod helpers;
use helpers::*;

// =============================================================================
// Identity whoami
// =============================================================================

#[test]
fn identity_whoami_returns_anchor() {
    let (guard, base, _tmp) = start_server();
    let c = client();

    let resp = c.get(format!("{}/identity/whoami", base)).send().unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().unwrap();
    assert!(
        body.get("anchor").is_some(),
        "whoami should return anchor: {}",
        body
    );
    assert!(
        body.get("algorithm").is_some(),
        "whoami should return algorithm: {}",
        body
    );
    drop(guard);
}

// =============================================================================
// Identity assertion and resolution
// =============================================================================

#[test]
fn identity_assert_returns_kappa() {
    let (guard, base, _tmp) = start_server();
    let c = client();

    let body = signed_assertion("sha256:bob", "name/legal", "Qm9i");
    let resp = c
        .post(format!("{}/identity/assert", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 200 || status == 201,
        "identity assert should succeed, got {}",
        status
    );
    let resp_body: serde_json::Value = resp.json().unwrap();
    assert!(
        resp_body.get("kappa").is_some(),
        "response should contain kappa: {}",
        resp_body
    );
    drop(guard);
}

#[test]
fn identity_resolve_returns_assertions() {
    let (guard, base, _tmp) = start_server();
    let c = client();

    let body = signed_assertion("sha256:alice", "name/legal", "QWxpY2U");
    c.post(format!("{}/identity/assert", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .unwrap();

    let resp = c
        .get(format!("{}/identity/resolve/sha256:alice", base))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "resolve should return 200");
    drop(guard);
}

// =============================================================================
// AKD proof generation
// =============================================================================

#[test]
fn identity_proof_after_assertion() {
    // FAILS UNTIL: AKD proof endpoint implemented
    let (guard, base, _tmp) = start_server();
    let c = client();

    let body = signed_assertion("sha256:charlie", "name/legal", "Q2hhcmxpZQ");
    let assert_resp = c
        .post(format!("{}/identity/assert", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .unwrap();
    let status = assert_resp.status().as_u16();
    assert!(
        status == 200 || status == 201,
        "assertion should succeed, got {}",
        status
    );

    let resp = c
        .get(format!(
            "{}/identity/resolve/sha256:charlie?proof=true",
            base
        ))
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "proof request should return 200, got {}",
        resp.status()
    );
    let resp_body: serde_json::Value = resp.json().unwrap();
    let body_str = serde_json::to_string(&resp_body).unwrap();
    assert!(
        body_str.len() > 20,
        "proof response should contain substantial data: {}",
        body_str
    );
    drop(guard);
}

// =============================================================================
// AKD audit proof
// =============================================================================

#[test]
fn identity_audit_between_epochs() {
    // FAILS UNTIL: AKD audit endpoint implemented at /identity/audit/{start}/{end}
    let (guard, base, _tmp) = start_server();
    let c = client();

    let body1 = signed_assertion("sha256:dave", "name/legal", "dGVzdA");
    c.post(format!("{}/identity/assert", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body1).unwrap())
        .send()
        .unwrap();

    let body2 = signed_assertion("sha256:eve", "name/legal", "dGVzdA");
    c.post(format!("{}/identity/assert", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body2).unwrap())
        .send()
        .unwrap();

    let resp = c
        .get(format!("{}/identity/audit/1/2", base))
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "audit should return 200, got {}",
        resp.status()
    );
    drop(guard);
}

// =============================================================================
// Absence proof
// =============================================================================

#[test]
fn identity_absence_proof_for_nonexistent() {
    // FAILS UNTIL: absence proof endpoint returns cryptographic proof
    let (guard, base, _tmp) = start_server();
    let c = client();

    let body = signed_assertion("sha256:exists", "name/legal", "dGVzdA");
    c.post(format!("{}/identity/assert", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .unwrap();

    let resp = c
        .get(format!(
            "{}/identity/absence/sha256:nonexistent/name/legal",
            base
        ))
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "absence proof should return 200, got {}",
        resp.status()
    );
    drop(guard);
}

// =============================================================================
// Multiple assertions for same subject
// =============================================================================

#[test]
fn identity_multiple_assertions_same_subject() {
    let (guard, base, _tmp) = start_server();
    let c = client();

    let (_, key_bytes) = signed_assertion_with_key("sha256:grace", "name/legal", "v1", None);
    for value in ["v1", "v2", "v3"] {
        let (body, _) =
            signed_assertion_with_key("sha256:grace", "name/legal", value, Some(&key_bytes));
        let resp = c
            .post(format!("{}/identity/assert", base))
            .header("content-type", "application/json")
            .body(serde_json::to_string(&body).unwrap())
            .send()
            .unwrap();
        let status = resp.status().as_u16();
        assert!(
            status == 200 || status == 201,
            "assertion should succeed, got {}",
            status
        );
    }

    let resp = c
        .get(format!("{}/identity/resolve/sha256:grace", base))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);
    drop(guard);
}

// =============================================================================
// Audit proof covering multiple epochs
// =============================================================================

#[test]
fn identity_audit_covers_5_epochs() {
    // FAILS UNTIL: AKD audit endpoint implemented
    let (guard, base, _tmp) = start_server();
    let c = client();

    for i in 0..5 {
        let body = signed_assertion(
            &format!("sha256:audit-{}", i),
            "name/legal",
            &format!("val-{}", i),
        );
        c.post(format!("{}/identity/assert", base))
            .header("content-type", "application/json")
            .body(serde_json::to_string(&body).unwrap())
            .send()
            .unwrap();
    }

    let resp = c
        .get(format!("{}/identity/audit/1/5", base))
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "audit 1-5 should return 200, got {}",
        resp.status()
    );
    drop(guard);
}
