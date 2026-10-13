//! Authority and identity-write security tests.
//!
//! Authority edges: a caller may only make its own capability and
//! delegation claims, and only a namespace owner or `_root` admin can
//! create a capability (a root of authority). Identity writes that speak
//! for an anchor (revoke, watermark) must be signed by that anchor's key,
//! and must take effect when they are.

#[path = "helpers/mod.rs"]
#[allow(unused_imports)]
mod helpers;
use helpers::*;

use ed25519_dalek::Signer;

fn anchor_from_seed(seed: &[u8; 32]) -> String {
    let sk = ed25519_dalek::SigningKey::from_bytes(seed);
    kappa_core::crypto::anchor::anchor_from_key_str("ed25519", &sk.verifying_key().to_bytes())
}

const OWNER_SEED: [u8; 32] = [10u8; 32];
const DELEGATE_SEED: [u8; 32] = [20u8; 32];
const OUTSIDER_SEED: [u8; 32] = [30u8; 32];
const MIDDLE_SEED: [u8; 32] = [40u8; 32];

fn owner() -> String {
    anchor_from_seed(&OWNER_SEED)
}
fn delegate() -> String {
    anchor_from_seed(&DELEGATE_SEED)
}
fn outsider() -> String {
    anchor_from_seed(&OUTSIDER_SEED)
}
fn middle() -> String {
    anchor_from_seed(&MIDDLE_SEED)
}

/// Auth-required server. Owner holds the root token; the rest authenticate
/// with no authority of their own.
fn server() -> (ServerGuard, String, tempfile::TempDir) {
    let root = format!("owner-token={}", owner());
    let toks = format!(
        "delegate-token={},outsider-token={},middle-token={}",
        delegate(),
        outsider(),
        middle(),
    );
    start_server_with_env(&[
        ("KAPPA_AUTH_REQUIRED", "true"),
        ("KAPPA_ROOT_TOKEN", &root),
        ("KAPPA_AUTH_TOKENS", &toks),
    ])
}

/// PUT an edge; returns (status, edge kappa).
fn put_edge(
    c: &reqwest::blocking::Client,
    base: &str,
    token: &str,
    ns: &str,
    body: serde_json::Value,
) -> (u16, String) {
    let r = c
        .put(format!("{}/v2/{}/edges/", base, ns))
        .header("content-type", "application/json")
        .header("Authorization", format!("Bearer {}", token))
        .body(body.to_string())
        .send()
        .unwrap();
    let status = r.status().as_u16();
    let kappa = r
        .headers()
        .get("x-kappa-label")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    (status, kappa)
}

fn read_status(c: &reqwest::blocking::Client, base: &str, token: &str, ns: &str) -> u16 {
    c.get(format!("{}/v2/{}/tags/list", base, ns))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .unwrap()
        .status()
        .as_u16()
}

/// Owner holds a full capability on `ns` and delegates `ops` to `delegate`
/// with no re-delegation. Returns the delegation edge kappa.
fn setup(c: &reqwest::blocking::Client, base: &str, ns: &str, ops: &[&str]) -> String {
    let (s, _) = put_edge(
        c,
        base,
        "owner-token",
        ns,
        serde_json::json!({
            "source": owner(), "relation": "capability", "target": ns,
            "metadata": {"ops": ["read", "write", "admin"]},
        }),
    );
    assert_eq!(s, 201, "owner capability");
    let (s, k) = put_edge(
        c,
        base,
        "owner-token",
        ns,
        serde_json::json!({
            "source": owner(), "relation": "delegation", "target": delegate(),
            "metadata": {"namespaces": [ns], "operations": ops, "delegation_depth": 0},
        }),
    );
    assert_eq!(s, 201, "owner -> delegate delegation");
    assert_eq!(
        read_status(c, base, "outsider-token", ns),
        403,
        "outsider starts with no access"
    );
    assert_eq!(
        read_status(c, base, "delegate-token", ns),
        200,
        "delegate can read"
    );
    k
}

// -- Authority edges ------------------------------------------------------------

#[test]
fn delegation_cannot_be_forged_in_anothers_name() {
    // A depth-0 delegate writes a delegation that claims to come from the
    // owner, granting the outsider admin.
    let (_g, base, _t) = server();
    let c = client();
    let ns = "nix/authority-forge";
    setup(&c, &base, ns, &["read", "write"]);

    let (s, _) = put_edge(
        &c,
        &base,
        "delegate-token",
        ns,
        serde_json::json!({
            "source": owner(), "relation": "delegation", "target": outsider(),
            "metadata": {"namespaces": [ns], "operations": ["read", "write", "admin"], "delegation_depth": 0},
        }),
    );
    assert_eq!(
        s, 403,
        "edge whose source is not the caller must be rejected"
    );
    assert_eq!(
        read_status(&c, &base, "outsider-token", ns),
        403,
        "outsider gains nothing"
    );
}

#[test]
fn delegate_cannot_mint_capability() {
    // A delegate grants itself a capability, then the owner revokes the
    // delegation. The capability must not have been created, so access ends.
    let (_g, base, _t) = server();
    let c = client();
    let ns = "nix/authority-mint";
    let delegation = setup(&c, &base, ns, &["read", "write"]);

    let (s, _) = put_edge(
        &c,
        &base,
        "delegate-token",
        ns,
        serde_json::json!({
            "source": delegate(), "relation": "capability", "target": ns,
            "metadata": {"ops": ["read", "write", "admin"]},
        }),
    );
    assert_eq!(
        s, 403,
        "only the owner or a _root admin can create a capability"
    );

    let del = c
        .delete(format!("{}/v2/{}/edges/{}", base, ns, delegation))
        .header("Authorization", "Bearer owner-token")
        .send()
        .unwrap()
        .status()
        .as_u16();
    assert!(del < 300, "owner revokes the delegation: {del}");
    assert_eq!(
        read_status(&c, &base, "delegate-token", ns),
        403,
        "revocation ends access"
    );
}

#[test]
fn admin_delegate_cannot_mint_capability() {
    // Even a delegated admin cannot turn revocable access into a capability.
    let (_g, base, _t) = server();
    let c = client();
    let ns = "nix/authority-admin";
    setup(&c, &base, ns, &["read", "write", "admin"]);

    let (s, _) = put_edge(
        &c,
        &base,
        "delegate-token",
        ns,
        serde_json::json!({
            "source": delegate(), "relation": "capability", "target": ns,
            "metadata": {"ops": ["read", "write", "admin"]},
        }),
    );
    assert_eq!(s, 403);
}

#[test]
fn redelegation_from_self_still_works() {
    // Legitimate path: owner gives middle depth 1; middle delegates from
    // itself to the outsider.
    let (_g, base, _t) = server();
    let c = client();
    let ns = "nix/authority-chain";
    let (s, _) = put_edge(
        &c,
        &base,
        "owner-token",
        ns,
        serde_json::json!({
            "source": owner(), "relation": "capability", "target": ns,
            "metadata": {"ops": ["read", "write", "admin"]},
        }),
    );
    assert_eq!(s, 201);
    let (s, _) = put_edge(
        &c,
        &base,
        "owner-token",
        ns,
        serde_json::json!({
            "source": owner(), "relation": "delegation", "target": middle(),
            "metadata": {"namespaces": [ns], "operations": ["read", "write"], "delegation_depth": 1},
        }),
    );
    assert_eq!(s, 201);
    let (s, _) = put_edge(
        &c,
        &base,
        "middle-token",
        ns,
        serde_json::json!({
            "source": middle(), "relation": "delegation", "target": outsider(),
            "metadata": {"namespaces": [ns], "operations": ["read"], "delegation_depth": 0},
        }),
    );
    assert_eq!(s, 201, "a delegate re-delegates in its own name");
    assert_eq!(read_status(&c, &base, "outsider-token", ns), 200);
}

// -- Identity writes --------------------------------------------------------------

const SUBJECT: &str = "did:example:alice";

/// Publish a signed assertion from `key`; returns (assertion kappa, asserter anchor).
fn publish_assertion(
    c: &reqwest::blocking::Client,
    base: &str,
    key: &ed25519_dalek::SigningKey,
) -> (String, String) {
    let a = kappa_core::identity::assertion::IdentityAssertion {
        asserter: String::new(),
        subject: SUBJECT.into(),
        facet: "email".into(),
        value: vec![],
        basis: "self-asserted".into(),
        valid_from_ms: 1000,
        valid_until_ms: None,
        signature: vec![],
    };
    let r = c
        .post(format!("{}/identity/assert", base))
        .header("Authorization", "Bearer outsider-token")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "algorithm": "ed25519",
                "public_key": hex::encode(key.verifying_key().to_bytes()),
                "subject": SUBJECT, "facet": "email", "value": "", "valid_from_ms": 1000,
                "signature": hex::encode(key.sign(&a.signable_bytes()).to_bytes()),
            })
            .to_string(),
        )
        .send()
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        201,
        "signed assertion: {}",
        r.text().unwrap_or_default()
    );
    let kappa = r.json::<serde_json::Value>().unwrap()["kappa"]
        .as_str()
        .unwrap()
        .to_string();
    let asserter =
        kappa_core::crypto::anchor::anchor_from_key_str("ed25519", &key.verifying_key().to_bytes());
    (kappa, asserter)
}

fn resolve(c: &reqwest::blocking::Client, base: &str) -> serde_json::Value {
    c.get(format!("{}/identity/resolve/{}", base, SUBJECT))
        .header("Authorization", "Bearer outsider-token")
        .send()
        .unwrap()
        .json()
        .unwrap()
}

fn valid_count(c: &reqwest::blocking::Client, base: &str) -> usize {
    resolve(c, base)["valid"].as_array().unwrap().len()
}

fn post(c: &reqwest::blocking::Client, base: &str, path: &str, body: serde_json::Value) -> u16 {
    c.post(format!("{}{}", base, path))
        .header("Authorization", "Bearer middle-token")
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .unwrap()
        .status()
        .as_u16()
}

fn signed_revocation(key: &ed25519_dalek::SigningKey, assertion_kappa: &str) -> serde_json::Value {
    let r = kappa_core::identity::revocation::Revocation {
        asserter: String::new(),
        assertion_kappa: assertion_kappa.to_string(),
        reason: kappa_core::identity::revocation::RevocationReason::KeyCompromise,
        revoked_at_ms: 2000,
        signature: vec![],
    };
    serde_json::json!({
        "algorithm": "ed25519",
        "public_key": hex::encode(key.verifying_key().to_bytes()),
        "assertion_kappa": assertion_kappa, "reason": "key-compromise", "revoked_at_ms": 2000,
        "signature": hex::encode(key.sign(&r.signable_bytes()).to_bytes()),
    })
}

#[test]
fn unsigned_revocation_rejected() {
    let (_g, base, _t) = server();
    let c = client();
    let victim = ed25519_dalek::SigningKey::from_bytes(&[50u8; 32]);
    let (kappa, victim_anchor) = publish_assertion(&c, &base, &victim);

    let s = post(
        &c,
        &base,
        "/identity/revoke",
        serde_json::json!({
            "asserter": victim_anchor, "assertion_kappa": kappa, "reason": "key-compromise", "signature": "",
        }),
    );
    assert_eq!(s, 400);
    assert_eq!(valid_count(&c, &base), 1, "assertion stays valid");
}

#[test]
fn revocation_signed_by_another_key_does_not_void() {
    // The attacker signs with its own key. Claiming the victim's anchor is
    // rejected; a revocation in its own name cannot touch the assertion.
    let (_g, base, _t) = server();
    let c = client();
    let victim = ed25519_dalek::SigningKey::from_bytes(&[50u8; 32]);
    let attacker = ed25519_dalek::SigningKey::from_bytes(&[51u8; 32]);
    let (kappa, victim_anchor) = publish_assertion(&c, &base, &victim);

    let mut forged = signed_revocation(&attacker, &kappa);
    forged["asserter"] = serde_json::json!(victim_anchor);
    assert_eq!(
        post(&c, &base, "/identity/revoke", forged),
        400,
        "stated asserter must match the key"
    );

    assert_eq!(
        post(
            &c,
            &base,
            "/identity/revoke",
            signed_revocation(&attacker, &kappa)
        ),
        201
    );
    assert_eq!(
        valid_count(&c, &base),
        1,
        "another key's revocation does not void the assertion"
    );
}

#[test]
fn signed_revocation_takes_effect() {
    let (_g, base, _t) = server();
    let c = client();
    let key = ed25519_dalek::SigningKey::from_bytes(&[50u8; 32]);
    let (kappa, _) = publish_assertion(&c, &base, &key);
    assert_eq!(valid_count(&c, &base), 1);

    assert_eq!(
        post(
            &c,
            &base,
            "/identity/revoke",
            signed_revocation(&key, &kappa)
        ),
        201
    );
    let after = resolve(&c, &base);
    assert_eq!(
        after["valid"].as_array().unwrap().len(),
        0,
        "revoked assertion is no longer valid"
    );
    assert_eq!(after["revoked_count"], 1);
}

#[test]
fn watermark_requires_asserter_signature_and_takes_effect() {
    let (_g, base, _t) = server();
    let c = client();
    let key = ed25519_dalek::SigningKey::from_bytes(&[50u8; 32]);
    let (_, asserter) = publish_assertion(&c, &base, &key);

    // Unsigned watermark naming the asserter: rejected, nothing voided.
    let s = post(
        &c,
        &base,
        "/identity/watermark",
        serde_json::json!({
            "asserter": asserter, "invalidate_before_ms": 5000, "reason": "forged",
        }),
    );
    assert_eq!(s, 400);
    assert_eq!(valid_count(&c, &base), 1);

    // Signed by the asserter: every earlier assertion is voided.
    let w = kappa_core::identity::watermark::Watermark {
        asserter: String::new(),
        invalidate_before_ms: 5000,
        reason: "key compromise".into(),
        set_at_ms: 6000,
    };
    let s = post(
        &c,
        &base,
        "/identity/watermark",
        serde_json::json!({
            "algorithm": "ed25519",
            "public_key": hex::encode(key.verifying_key().to_bytes()),
            "invalidate_before_ms": 5000, "reason": "key compromise", "set_at_ms": 6000,
            "signature": hex::encode(key.sign(&kappa_core::canonical::canonical_bytes(&w)).to_bytes()),
        }),
    );
    assert_eq!(s, 201);
    let after = resolve(&c, &base);
    assert_eq!(after["valid"].as_array().unwrap().len(), 0);
    assert_eq!(after["watermarked_count"], 1);
}
