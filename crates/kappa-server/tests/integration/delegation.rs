//! Delegation authorization integration tests.
//!
//! Exercises the full chain: bearer token -> asserter anchor -> capability
//! edge -> delegation edge -> authorization decision. Uses real Ed25519
//! keypairs and real anchors computed via anchor_from_key_str.

#[path = "helpers/mod.rs"]
#[allow(dead_code, unused_imports)]
mod helpers;
use helpers::*;

/// Compute a real anchor from a deterministic Ed25519 seed.
fn anchor_from_seed(seed: &[u8; 32]) -> String {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
    let public_key = signing_key.verifying_key().to_bytes();
    kappa_core::crypto::anchor::anchor_from_key_str("ed25519", &public_key)
}

const OWNER_SEED: [u8; 32] = [10u8; 32];
const DELEGATE_SEED: [u8; 32] = [20u8; 32];
const OUTSIDER_SEED: [u8; 32] = [30u8; 32];
const MIDDLE_SEED: [u8; 32] = [40u8; 32];

fn owner_anchor() -> String { anchor_from_seed(&OWNER_SEED) }
fn delegate_anchor() -> String { anchor_from_seed(&DELEGATE_SEED) }
fn outsider_anchor() -> String { anchor_from_seed(&OUTSIDER_SEED) }
fn middle_anchor() -> String { anchor_from_seed(&MIDDLE_SEED) }

/// Start a server with auth enabled. Owner is the root token (gets _root
/// delegation from node). Delegate, outsider, middle are auth-only tokens
/// with no automatic authority.
fn delegation_server() -> (ServerGuard, String, tempfile::TempDir) {
    let root_token = format!("owner-token={}", owner_anchor());
    let tokens = format!(
        "delegate-token={},outsider-token={},middle-token={}",
        delegate_anchor(), outsider_anchor(), middle_anchor(),
    );
    start_server_with_env(&[
        ("KAPPA_AUTH_REQUIRED", "true"),
        ("KAPPA_ROOT_TOKEN", &root_token),
        ("KAPPA_AUTH_TOKENS", &tokens),
    ])
}

/// Create a Capability edge granting an asserter ops on a namespace.
fn create_capability(c: &reqwest::blocking::Client, base: &str, token: &str, ns: &str, asserter: &str, ops: &[&str]) {
    let ops_json: Vec<serde_json::Value> = ops.iter().map(|o| serde_json::json!(o)).collect();
    let body = serde_json::json!({
        "source": asserter,
        "relation": "capability",
        "target": ns,
        "metadata": {"ops": ops_json},
    });
    let resp = c
        .put(format!("{}/v2/{}/edges/", base, ns))
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {}", token))
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .unwrap();
    assert!(
        resp.status().is_success(),
        "create_capability failed: {} -- {}",
        resp.status(), resp.text().unwrap_or_default()
    );
}

/// Create a Delegation edge from source (delegator) to target (delegate).
/// Returns the edge kappa from the x-kappa-label response header.
fn create_delegation(
    c: &reqwest::blocking::Client,
    base: &str,
    token: &str,
    ns: &str,
    source: &str,
    target: &str,
    scope: &serde_json::Value,
) -> String {
    let body = serde_json::json!({
        "source": source,
        "relation": "delegation",
        "target": target,
        "metadata": scope,
    });
    let resp = c
        .put(format!("{}/v2/{}/edges/", base, ns))
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {}", token))
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .unwrap();
    assert!(
        resp.status().is_success(),
        "create_delegation failed: {} -- {}",
        resp.status(), resp.text().unwrap_or_default()
    );
    resp.headers()
        .get("x-kappa-label")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn delegation_grants_access() {
    let (_guard, base, _tmp) = delegation_server();
    let c = client();
    let ns = "nix/delegation-test";

    // Owner creates capability on reserved namespace
    create_capability(&c, &base, "owner-token", ns, &owner_anchor(), &["read", "write", "admin"]);

    // Owner delegates to delegate with read+write
    let scope = serde_json::json!({
        "namespaces": [ns],
        "operations": ["read", "write"],
        "delegation_depth": 0,
    });
    create_delegation(&c, &base, "owner-token", ns, &owner_anchor(), &delegate_anchor(), &scope);

    // Delegate can read
    let resp = c
        .get(format!("{}/v2/{}/tags/list", base, ns))
        .header("Authorization", "Bearer delegate-token")
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "delegate should be able to read via delegation");
}

#[test]
fn delegation_scope_limits_operations() {
    let (_guard, base, _tmp) = delegation_server();
    let c = client();
    let ns = "nix/deleg-ops-test";

    create_capability(&c, &base, "owner-token", ns, &owner_anchor(), &["read", "write", "admin"]);

    // Delegate only read
    let scope = serde_json::json!({
        "namespaces": [ns],
        "operations": ["read"],
        "delegation_depth": 0,
    });
    create_delegation(&c, &base, "owner-token", ns, &owner_anchor(), &delegate_anchor(), &scope);

    // Delegate can read
    let resp = c
        .get(format!("{}/v2/{}/tags/list", base, ns))
        .header("Authorization", "Bearer delegate-token")
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "delegate should read");

    // Delegate cannot write (no write in scope)
    let content = b"delegation-write-test";
    let digest = sha256_digest(content);
    let resp = c
        .put(format!("{}/v2/{}/blobs/{}", base, ns, digest))
        .header("Authorization", "Bearer delegate-token")
        .body(content.to_vec())
        .send()
        .unwrap();
    assert_eq!(resp.status(), 403, "delegate should NOT write with read-only delegation");
}

#[test]
fn delegation_scope_limits_namespaces() {
    let (_guard, base, _tmp) = delegation_server();
    let c = client();
    let ns_a = "nix/deleg-ns-a";
    let ns_b = "nix/deleg-ns-b";

    // Owner has capability on both namespaces
    create_capability(&c, &base, "owner-token", ns_a, &owner_anchor(), &["read", "write", "admin"]);
    create_capability(&c, &base, "owner-token", ns_b, &owner_anchor(), &["read", "write", "admin"]);

    // Delegate only on ns_a
    let scope = serde_json::json!({
        "namespaces": [ns_a],
        "operations": ["read", "write"],
        "delegation_depth": 0,
    });
    create_delegation(&c, &base, "owner-token", ns_a, &owner_anchor(), &delegate_anchor(), &scope);

    // Delegate can read ns_a
    let resp = c
        .get(format!("{}/v2/{}/tags/list", base, ns_a))
        .header("Authorization", "Bearer delegate-token")
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Delegate cannot read ns_b
    let resp = c
        .get(format!("{}/v2/{}/tags/list", base, ns_b))
        .header("Authorization", "Bearer delegate-token")
        .send()
        .unwrap();
    assert_eq!(resp.status(), 403, "delegate should NOT access ns_b");
}

#[test]
fn delegation_expired_rejected() {
    let (_guard, base, _tmp) = delegation_server();
    let c = client();
    let ns = "nix/deleg-expired";

    create_capability(&c, &base, "owner-token", ns, &owner_anchor(), &["read", "write", "admin"]);

    // Delegation expired in the past
    let scope = serde_json::json!({
        "namespaces": [ns],
        "operations": ["read"],
        "expires_at_ms": 1000,
        "delegation_depth": 0,
    });
    create_delegation(&c, &base, "owner-token", ns, &owner_anchor(), &delegate_anchor(), &scope);

    let resp = c
        .get(format!("{}/v2/{}/tags/list", base, ns))
        .header("Authorization", "Bearer delegate-token")
        .send()
        .unwrap();
    assert_eq!(resp.status(), 403, "expired delegation should be rejected");
}

#[test]
fn delegation_depth_0_cannot_redelegate() {
    let (_guard, base, _tmp) = delegation_server();
    let c = client();
    let ns = "nix/deleg-depth0";

    create_capability(&c, &base, "owner-token", ns, &owner_anchor(), &["read", "write", "admin"]);

    // Owner delegates to middle with depth=0
    let scope = serde_json::json!({
        "namespaces": [ns],
        "operations": ["read", "write"],
        "delegation_depth": 0,
    });
    create_delegation(&c, &base, "owner-token", ns, &owner_anchor(), &middle_anchor(), &scope);

    // Middle tries to delegate to outsider — rejected at creation time
    // because middle's delegation_depth=0 means it cannot re-delegate.
    let scope2 = serde_json::json!({
        "namespaces": [ns],
        "operations": ["read"],
        "delegation_depth": 0,
    });
    let resp = c
        .put(format!("{}/v2/{}/edges/", base, ns))
        .header("Authorization", "Bearer middle-token")
        .json(&serde_json::json!({
            "source": middle_anchor(),
            "target": outsider_anchor(),
            "relation": "delegation",
            "metadata": scope2,
        }))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 403, "depth=0 delegate should not be able to re-delegate");

    // Outsider should NOT have access (delegation was never created)
    let resp = c
        .get(format!("{}/v2/{}/tags/list", base, ns))
        .header("Authorization", "Bearer outsider-token")
        .send()
        .unwrap();
    assert_eq!(resp.status(), 403, "outsider should NOT access via depth-0 chain");
}

#[test]
fn delegation_depth_1_transitive() {
    let (_guard, base, _tmp) = delegation_server();
    let c = client();
    let ns = "nix/deleg-depth1";

    create_capability(&c, &base, "owner-token", ns, &owner_anchor(), &["read", "write", "admin"]);

    // Owner delegates to middle with depth=1
    let scope = serde_json::json!({
        "namespaces": [ns],
        "operations": ["read", "write"],
        "delegation_depth": 1,
    });
    create_delegation(&c, &base, "owner-token", ns, &owner_anchor(), &middle_anchor(), &scope);

    // Middle delegates to outsider with depth=0
    let scope2 = serde_json::json!({
        "namespaces": [ns],
        "operations": ["read"],
        "delegation_depth": 0,
    });
    create_delegation(&c, &base, "middle-token", ns, &middle_anchor(), &outsider_anchor(), &scope2);

    // Outsider should have access: outsider -> middle (depth=1 allows recursion) -> owner (capability)
    let resp = c
        .get(format!("{}/v2/{}/tags/list", base, ns))
        .header("Authorization", "Bearer outsider-token")
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "outsider should access via depth-1 transitive delegation");
}

#[test]
fn delegation_revoked_rejected() {
    let (_guard, base, _tmp) = delegation_server();
    let c = client();
    let ns = "nix/deleg-revoke";

    create_capability(&c, &base, "owner-token", ns, &owner_anchor(), &["read", "write", "admin"]);

    // Create delegation
    let scope = serde_json::json!({
        "namespaces": [ns],
        "operations": ["read"],
        "delegation_depth": 0,
    });
    let edge_kappa = create_delegation(&c, &base, "owner-token", ns, &owner_anchor(), &delegate_anchor(), &scope);

    // Verify it works
    let resp = c
        .get(format!("{}/v2/{}/tags/list", base, ns))
        .header("Authorization", "Bearer delegate-token")
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "delegate should access before revocation");

    // Revoke by deleting the delegation edge using its kappa
    let resp = c
        .delete(format!("{}/v2/{}/edges/{}", base, ns, edge_kappa))
        .header("Authorization", "Bearer owner-token")
        .send()
        .unwrap();
    assert!(resp.status().is_success(), "edge delete failed: {}", resp.status());

    // Verify delegation no longer works
    let resp = c
        .get(format!("{}/v2/{}/tags/list", base, ns))
        .header("Authorization", "Bearer delegate-token")
        .send()
        .unwrap();
    assert_eq!(resp.status(), 403, "delegate should NOT access after revocation");
}
