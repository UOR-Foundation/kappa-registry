//! AKD audit proof tests.
//!
//! FAILS UNTIL: AkdManager is implemented in kappa-akd with Directory
//! lifecycle management, and identity module endpoints are wired to it.
//!
//! AKD pattern (from akd/src/tests/test_core_protocol.rs:84-108):
//! 1. Directory::new(storage, vrf, parallelism).await
//! 2. directory.publish(vec![(label, value)]).await  -- batch, creates epoch
//! 3. directory.lookup(label).await  -- generates proof AFTER publish
//! 4. client::lookup_verify(pk, hash, epoch, label, proof)  -- offline verify
//!
//! The assertion endpoint MUST trigger a publish internally (epoch advance)
//! before a proof can be generated. This is expensive per-assertion but
//! necessary for the HTTP API model. A batch endpoint would be more
//! efficient but is not specified in this phase.
//!
//! All identity endpoints use /identity/ prefix (no /v2/{ns}/ prefix)
//! for node-level identity operations.

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
    // FAILS UNTIL: POST /identity/assert endpoint implemented
    let (guard, base, _tmp) = start_server();
    let c = client();

    let assertion = serde_json::json!({
        "subject": "sha256:bob",
        "facet": "name/legal",
        "value": "Qm9i",
    });
    let resp = c
        .post(format!("{}/identity/assert", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&assertion).unwrap())
        .send()
        .unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 200 || status == 201,
        "identity assert should succeed, got {}",
        status
    );
    let body: serde_json::Value = resp.json().unwrap();
    assert!(
        body.get("kappa").is_some(),
        "response should contain kappa: {}",
        body
    );
    drop(guard);
}

#[test]
fn identity_resolve_returns_assertions() {
    // FAILS UNTIL: GET /identity/resolve/{subject} endpoint implemented
    let (guard, base, _tmp) = start_server();
    let c = client();

    // Assert first
    let assertion = serde_json::json!({
        "subject": "sha256:alice",
        "facet": "name/legal",
        "value": "QWxpY2U=",
    });
    c.post(format!("{}/identity/assert", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&assertion).unwrap())
        .send()
        .unwrap();

    // Resolve
    let resp = c
        .get(format!("{}/identity/resolve/sha256:alice", base))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "resolve should return 200");
    drop(guard);
}

// =============================================================================
// AKD proof generation
// Pattern: publish THEN lookup (per akd test_core_protocol.rs:84-108)
// The assertion endpoint triggers publish internally.
// =============================================================================

#[test]
fn identity_proof_after_assertion() {
    // FAILS UNTIL: AKD proof endpoint implemented
    // Pattern: assert (which triggers AKD publish), then request proof
    let (guard, base, _tmp) = start_server();
    let c = client();

    // Assert -- this must trigger AKD directory.publish() internally
    let assertion = serde_json::json!({
        "subject": "sha256:charlie",
        "facet": "name/legal",
        "value": "Q2hhcmxpZQ==",
    });
    let assert_resp = c
        .post(format!("{}/identity/assert", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&assertion).unwrap())
        .send()
        .unwrap();
    let status = assert_resp.status().as_u16();
    assert!(
        status == 200 || status == 201,
        "assertion should succeed, got {}",
        status
    );

    // Request lookup proof -- AKD requires the epoch to exist first
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
    let body: serde_json::Value = resp.json().unwrap();
    // The response should contain proof data (structure depends on implementation)
    let body_str = serde_json::to_string(&body).unwrap();
    assert!(
        body_str.len() > 20,
        "proof response should contain substantial data: {}",
        body_str
    );
    drop(guard);
}

// =============================================================================
// AKD audit proof
// Pattern: publish multiple epochs, then audit between them
// (per akd test_core_protocol.rs:509-678)
// =============================================================================

#[test]
fn identity_audit_between_epochs() {
    // FAILS UNTIL: AKD audit endpoint implemented
    // Each assertion triggers a publish, creating a new epoch.
    // After 2 assertions, we have epochs 1 and 2.
    let (guard, base, _tmp) = start_server();
    let c = client();

    // Assertion 1 -> epoch 1
    c.post(format!("{}/identity/assert", base))
        .header("content-type", "application/json")
        .body(r#"{"subject":"sha256:dave","facet":"name/legal","value":"dGVzdA=="}"#)
        .send()
        .unwrap();

    // Assertion 2 -> epoch 2
    c.post(format!("{}/identity/assert", base))
        .header("content-type", "application/json")
        .body(r#"{"subject":"sha256:eve","facet":"name/legal","value":"dGVzdA=="}"#)
        .send()
        .unwrap();

    // Audit proof from epoch 1 to epoch 2
    // The audit endpoint path uses /identity/audit/{start}/{end}
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
// AKD NonMembershipProof for a subject that was never published
// =============================================================================

#[test]
fn identity_absence_proof_for_nonexistent() {
    // FAILS UNTIL: absence proof endpoint implemented
    // Must have at least one published epoch for the AKD tree to exist
    let (guard, base, _tmp) = start_server();
    let c = client();

    // Publish something so the AKD tree is initialized
    c.post(format!("{}/identity/assert", base))
        .header("content-type", "application/json")
        .body(r#"{"subject":"sha256:exists","facet":"name/legal","value":"dGVzdA=="}"#)
        .send()
        .unwrap();

    // Request absence proof for a subject that was NOT published
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
    let body: serde_json::Value = resp.json().unwrap();
    assert!(
        body.get("proof").is_some(),
        "absence response should contain proof: {}",
        body
    );
    drop(guard);
}

// =============================================================================
// Multiple assertions for same subject
// =============================================================================

#[test]
fn identity_multiple_assertions_same_subject() {
    // FAILS UNTIL: identity module implemented
    let (guard, base, _tmp) = start_server();
    let c = client();

    for value in ["v1", "v2", "v3"] {
        let assertion = serde_json::json!({
            "subject": "sha256:grace",
            "facet": "name/legal",
            "value": value,
        });
        let resp = c
            .post(format!("{}/identity/assert", base))
            .header("content-type", "application/json")
            .body(serde_json::to_string(&assertion).unwrap())
            .send()
            .unwrap();
        let status = resp.status().as_u16();
        assert!(
            status == 200 || status == 201,
            "assertion should succeed, got {}",
            status
        );
    }

    // Resolve should return data for all assertions
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
        let assertion = serde_json::json!({
            "subject": format!("sha256:audit-{}", i),
            "facet": "name/legal",
            "value": format!("val-{}", i),
        });
        c.post(format!("{}/identity/assert", base))
            .header("content-type", "application/json")
            .body(serde_json::to_string(&assertion).unwrap())
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
