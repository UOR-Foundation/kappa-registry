//! Delegation authorization integration tests.
//!
//! Exercises the full chain: bearer token -> asserter anchor -> capability
//! edge -> signed delegation edge -> authorization decision. Uses real
//! Ed25519 keypairs; every delegation is a `DelegationScope` signed with the
//! delegator's key and verified by the server at admission.

use super::helpers::*;

use kappa_crypto::Signer;
use kappa_crypto::ed25519::Ed25519Signer;
use kappa_store::delegation::DelegationScope;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const OWNER_SEED: [u8; 32] = [10u8; 32];
const DELEGATE_SEED: [u8; 32] = [20u8; 32];
const OUTSIDER_SEED: [u8; 32] = [30u8; 32];
const MIDDLE_SEED: [u8; 32] = [40u8; 32];

fn anchor(seed: &[u8; 32]) -> Result<kappa_store::Kappa, Box<dyn std::error::Error>> {
    let signer = Ed25519Signer::from_bytes(seed)?;
    Ok(kappa_store::Kappa::from_key(
        signer.algorithm(),
        signer.public_key(),
    )?)
}

fn delegation_server()
-> Result<(ServerGuard, String, tempfile::TempDir), Box<dyn std::error::Error>> {
    let root_token = format!("owner-token={}", anchor(&OWNER_SEED)?);
    let tokens = format!(
        "delegate-token={},outsider-token={},middle-token={}",
        anchor(&DELEGATE_SEED)?,
        anchor(&OUTSIDER_SEED)?,
        anchor(&MIDDLE_SEED)?,
    );
    Ok(start_server_with_env(&[
        ("KAPPA_AUTH_REQUIRED", "true"),
        ("KAPPA_ROOT_TOKEN", &root_token),
        ("KAPPA_AUTH_TOKENS", &tokens),
    ]))
}

fn now_ms() -> i64 {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after the epoch");
    i64::try_from(elapsed.as_millis()).expect("Unix milliseconds fit i64")
}

fn create_capability(
    c: &reqwest::blocking::Client,
    base: &str,
    token: &str,
    ns: &str,
    holder: &kappa_store::Kappa,
    ops: &[&str],
) {
    let body = serde_json::json!({
        "source": holder.to_string(),
        "relation": "capability",
        "target": ns,
        "metadata": {"ops": ops},
    });
    let resp = c
        .put(format!("{}/v2/{}/edges/", base, ns))
        .header("Authorization", format!("Bearer {}", token))
        .json(&body)
        .send()
        .unwrap();
    let status = resp.status();
    let text = resp.text().unwrap();
    assert!(
        status.is_success(),
        "create_capability failed: {status} -- {text}"
    );
}

fn signed_scope(
    delegator_seed: &[u8; 32],
    delegate_seed: &[u8; 32],
    namespaces: &[&str],
    operations: &[&str],
    valid_until_ms: Option<i64>,
    max_depth: u32,
) -> Result<DelegationScope, Box<dyn std::error::Error>> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).unwrap();
    let scope = DelegationScope {
        delegator: anchor(delegator_seed)?,
        delegate: anchor(delegate_seed)?,
        scope: operations.iter().map(|op| op.to_string()).collect(),
        namespaces: Some(namespaces.iter().map(|ns| ns.to_string()).collect()),
        valid_from_ms: now_ms() - 1_000,
        valid_until_ms,
        max_depth,
        nonce: nonce.to_vec(),
        cose_signature: kappa_store::SignedPayload::empty(),
    };
    Ok(kappa_crypto::signed_types::sign_delegation(
        scope,
        &Ed25519Signer::from_bytes(delegator_seed)?,
    )?)
}

fn put_delegation(
    c: &reqwest::blocking::Client,
    base: &str,
    token: &str,
    ns: &str,
    delegator_seed: &[u8; 32],
    scope: &DelegationScope,
) -> Result<reqwest::blocking::Response, Box<dyn std::error::Error>> {
    let signer = Ed25519Signer::from_bytes(delegator_seed)?;
    Ok(c.put(format!("{}/v2/{}/edges/", base, ns))
        .header("Authorization", format!("Bearer {}", token))
        .json(&serde_json::json!({
            "source": scope.delegator.to_string(),
            "relation": "delegation",
            "target": scope.delegate.to_string(),
            "metadata": serde_json::to_value(scope)?,
            "algorithm": signer.algorithm(),
            "public_key": hex::encode(signer.public_key()),
        }))
        .send()?)
}

fn create_delegation(
    c: &reqwest::blocking::Client,
    base: &str,
    token: &str,
    ns: &str,
    delegator_seed: &[u8; 32],
    scope: &DelegationScope,
) -> Result<String, Box<dyn std::error::Error>> {
    let resp = put_delegation(c, base, token, ns, delegator_seed, scope)?;
    let status = resp.status();
    let label = resp
        .headers()
        .get("x-kappa-label")
        .map(|v| v.to_str().unwrap().to_string());
    let text = resp.text()?;
    assert!(
        status.is_success(),
        "create_delegation failed: {status} -- {text}"
    );
    Ok(label.expect("delegation edge label"))
}

fn tags_status(c: &reqwest::blocking::Client, base: &str, ns: &str, token: &str) -> u16 {
    c.get(format!("{}/v2/{}/tags/list", base, ns))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .unwrap()
        .status()
        .as_u16()
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn delegation_grants_access() -> TestResult {
    let (_guard, base, _tmp) = delegation_server()?;
    let c = client();
    let ns = "nix/delegation-test";

    create_capability(
        &c,
        &base,
        "owner-token",
        ns,
        &anchor(&OWNER_SEED)?,
        &["read", "write", "admin"],
    );

    let scope = signed_scope(
        &OWNER_SEED,
        &DELEGATE_SEED,
        &[ns],
        &["read", "write"],
        None,
        0,
    )?;
    create_delegation(&c, &base, "owner-token", ns, &OWNER_SEED, &scope)?;

    assert_eq!(
        tags_status(&c, &base, ns, "delegate-token"),
        200,
        "delegate should be able to read via delegation"
    );
    Ok(())
}

#[test]
fn delegation_scope_limits_operations() -> TestResult {
    let (_guard, base, _tmp) = delegation_server()?;
    let c = client();
    let ns = "nix/deleg-ops-test";

    create_capability(
        &c,
        &base,
        "owner-token",
        ns,
        &anchor(&OWNER_SEED)?,
        &["read", "write", "admin"],
    );

    let scope = signed_scope(&OWNER_SEED, &DELEGATE_SEED, &[ns], &["read"], None, 0)?;
    create_delegation(&c, &base, "owner-token", ns, &OWNER_SEED, &scope)?;

    assert_eq!(
        tags_status(&c, &base, ns, "delegate-token"),
        200,
        "delegate should read"
    );

    let content = b"delegation-write-test";
    let digest = sha256_digest(content);
    let resp = c
        .put(format!("{}/v2/{}/blobs/{}", base, ns, digest))
        .header("Authorization", "Bearer delegate-token")
        .body(content.to_vec())
        .send()?;
    assert_eq!(
        resp.status(),
        403,
        "delegate should NOT write with read-only delegation"
    );
    Ok(())
}

#[test]
fn delegation_scope_limits_namespaces() -> TestResult {
    let (_guard, base, _tmp) = delegation_server()?;
    let c = client();
    let ns_a = "nix/deleg-ns-a";
    let ns_b = "nix/deleg-ns-b";

    create_capability(
        &c,
        &base,
        "owner-token",
        ns_a,
        &anchor(&OWNER_SEED)?,
        &["read", "write", "admin"],
    );
    create_capability(
        &c,
        &base,
        "owner-token",
        ns_b,
        &anchor(&OWNER_SEED)?,
        &["read", "write", "admin"],
    );

    let scope = signed_scope(
        &OWNER_SEED,
        &DELEGATE_SEED,
        &[ns_a],
        &["read", "write"],
        None,
        0,
    )?;
    create_delegation(&c, &base, "owner-token", ns_a, &OWNER_SEED, &scope)?;

    assert_eq!(tags_status(&c, &base, ns_a, "delegate-token"), 200);
    assert_eq!(
        tags_status(&c, &base, ns_b, "delegate-token"),
        403,
        "delegate should NOT access ns_b"
    );
    Ok(())
}

#[test]
fn delegation_expired_rejected() -> TestResult {
    let (_guard, base, _tmp) = delegation_server()?;
    let c = client();
    let ns = "nix/deleg-expired";

    create_capability(
        &c,
        &base,
        "owner-token",
        ns,
        &anchor(&OWNER_SEED)?,
        &["read", "write", "admin"],
    );

    let expired = signed_scope(
        &OWNER_SEED,
        &DELEGATE_SEED,
        &[ns],
        &["read"],
        Some(now_ms() - 1),
        0,
    )?;
    let resp = put_delegation(&c, &base, "owner-token", ns, &OWNER_SEED, &expired)?;
    let status = resp.status();
    let text = resp.text()?;
    assert_eq!(status, 400, "expired delegation admitted: {text}");

    let expiring = signed_scope(
        &OWNER_SEED,
        &DELEGATE_SEED,
        &[ns],
        &["read"],
        Some(now_ms() + 1_500),
        0,
    )?;
    create_delegation(&c, &base, "owner-token", ns, &OWNER_SEED, &expiring)?;
    assert_eq!(
        tags_status(&c, &base, ns, "delegate-token"),
        200,
        "delegation should grant access before expiry"
    );
    std::thread::sleep(std::time::Duration::from_millis(2_000));
    assert_eq!(
        tags_status(&c, &base, ns, "delegate-token"),
        403,
        "expired delegation should be rejected"
    );
    Ok(())
}

#[test]
fn delegation_depth_0_cannot_redelegate() -> TestResult {
    let (_guard, base, _tmp) = delegation_server()?;
    let c = client();
    let ns = "nix/deleg-depth0";

    create_capability(
        &c,
        &base,
        "owner-token",
        ns,
        &anchor(&OWNER_SEED)?,
        &["read", "write", "admin"],
    );

    let scope = signed_scope(
        &OWNER_SEED,
        &MIDDLE_SEED,
        &[ns],
        &["read", "write"],
        None,
        0,
    )?;
    create_delegation(&c, &base, "owner-token", ns, &OWNER_SEED, &scope)?;

    let scope2 = signed_scope(&MIDDLE_SEED, &OUTSIDER_SEED, &[ns], &["read"], None, 0)?;
    let resp = put_delegation(&c, &base, "middle-token", ns, &MIDDLE_SEED, &scope2)?;
    let status = resp.status();
    let text = resp.text()?;
    assert_eq!(
        status, 403,
        "depth=0 delegate should not be able to re-delegate: {text}"
    );

    assert_eq!(
        tags_status(&c, &base, ns, "outsider-token"),
        403,
        "outsider should NOT access via depth-0 chain"
    );
    Ok(())
}

#[test]
fn delegation_depth_1_transitive() -> TestResult {
    let (_guard, base, _tmp) = delegation_server()?;
    let c = client();
    let ns = "nix/deleg-depth1";

    create_capability(
        &c,
        &base,
        "owner-token",
        ns,
        &anchor(&OWNER_SEED)?,
        &["read", "write", "admin"],
    );

    let scope = signed_scope(
        &OWNER_SEED,
        &MIDDLE_SEED,
        &[ns],
        &["read", "write"],
        None,
        1,
    )?;
    create_delegation(&c, &base, "owner-token", ns, &OWNER_SEED, &scope)?;

    let scope2 = signed_scope(&MIDDLE_SEED, &OUTSIDER_SEED, &[ns], &["read"], None, 0)?;
    create_delegation(&c, &base, "middle-token", ns, &MIDDLE_SEED, &scope2)?;

    assert_eq!(
        tags_status(&c, &base, ns, "outsider-token"),
        200,
        "outsider should access via depth-1 transitive delegation"
    );
    Ok(())
}

#[test]
fn delegation_revoked_rejected() -> TestResult {
    let (_guard, base, _tmp) = delegation_server()?;
    let c = client();
    let ns = "nix/deleg-revoke";

    create_capability(
        &c,
        &base,
        "owner-token",
        ns,
        &anchor(&OWNER_SEED)?,
        &["read", "write", "admin"],
    );

    let scope = signed_scope(&OWNER_SEED, &DELEGATE_SEED, &[ns], &["read"], None, 0)?;
    let edge_kappa = create_delegation(&c, &base, "owner-token", ns, &OWNER_SEED, &scope)?;

    assert_eq!(
        tags_status(&c, &base, ns, "delegate-token"),
        200,
        "delegate should access before revocation"
    );

    let resp = c
        .delete(format!("{}/v2/{}/edges/{}", base, ns, edge_kappa))
        .header("Authorization", "Bearer owner-token")
        .send()?;
    let status = resp.status();
    let text = resp.text()?;
    assert!(
        status.is_success(),
        "edge delete failed: {status} -- {text}"
    );

    assert_eq!(
        tags_status(&c, &base, ns, "delegate-token"),
        403,
        "delegate should NOT access after revocation"
    );
    Ok(())
}

#[test]
fn revoking_a_parent_delegation_cuts_off_its_children() -> TestResult {
    let (_guard, base, _tmp) = delegation_server()?;
    let c = client();
    let ns = "nix/deleg-chain-revoke";

    create_capability(
        &c,
        &base,
        "owner-token",
        ns,
        &anchor(&OWNER_SEED)?,
        &["read", "write", "admin"],
    );

    let parent = signed_scope(
        &OWNER_SEED,
        &MIDDLE_SEED,
        &[ns],
        &["read", "write"],
        None,
        1,
    )?;
    let parent_edge = create_delegation(&c, &base, "owner-token", ns, &OWNER_SEED, &parent)?;
    let child = signed_scope(&MIDDLE_SEED, &OUTSIDER_SEED, &[ns], &["read"], None, 0)?;
    create_delegation(&c, &base, "middle-token", ns, &MIDDLE_SEED, &child)?;
    assert_eq!(tags_status(&c, &base, ns, "outsider-token"), 200);

    let resp = c
        .delete(format!("{}/v2/{}/edges/{}", base, ns, parent_edge))
        .header("Authorization", "Bearer owner-token")
        .send()?;
    let status = resp.status();
    let text = resp.text()?;
    assert!(
        status.is_success(),
        "edge delete failed: {status} -- {text}"
    );

    assert_eq!(
        tags_status(&c, &base, ns, "outsider-token"),
        403,
        "a delegation whose grantor lost authority grants nothing"
    );
    Ok(())
}

#[test]
fn delegation_signed_by_another_key_is_rejected() -> TestResult {
    let (_guard, base, _tmp) = delegation_server()?;
    let c = client();
    let ns = "nix/deleg-forged";

    create_capability(
        &c,
        &base,
        "owner-token",
        ns,
        &anchor(&OWNER_SEED)?,
        &["read", "write", "admin"],
    );

    let mut forged = signed_scope(&OUTSIDER_SEED, &DELEGATE_SEED, &[ns], &["read"], None, 0)?;
    forged.delegator = anchor(&OWNER_SEED)?;
    let resp = put_delegation(&c, &base, "owner-token", ns, &OWNER_SEED, &forged)?;
    let status = resp.status();
    let text = resp.text()?;
    assert_eq!(status, 400, "forged delegation admitted: {text}");
    assert_eq!(tags_status(&c, &base, ns, "delegate-token"), 403);
    Ok(())
}
