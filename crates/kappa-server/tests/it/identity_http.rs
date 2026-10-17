//! Integration tests for identity binding and succession HTTP endpoints.
//!
//! Bindings publish in the target anchor's namespace, so only that anchor,
//! authenticated by bearer token, may create or delete them. Successions
//! carry COSE signatures by both the old and the new key and the old
//! anchor's signed watermark.

use super::helpers::*;

use kappa_crypto::Signer;
use kappa_crypto::ed25519::Ed25519Signer;
use kappa_crypto::testing::Impostor;
use kappa_store::identity::{Succession, SuccessionReason};

const ALICE: [u8; 32] = [51; 32];
const BOB: [u8; 32] = [52; 32];

fn anchor(seed: &[u8; 32]) -> kappa_store::Kappa {
    let signer = Ed25519Signer::from_bytes(seed).expect("Ed25519 accepts any 32-byte seed");
    kappa_store::Kappa::from_key(signer.algorithm(), signer.public_key())
        .expect("ed25519 anchor framing fits u16")
}

/// Server where `alice-token` authenticates ALICE and `bob-token` BOB.
/// Authentication is optional, so anonymous requests reach the handlers.
fn identity_server() -> (ServerGuard, String, tempfile::TempDir) {
    let tokens = format!("alice-token={},bob-token={}", anchor(&ALICE), anchor(&BOB));
    start_server_with_env(&[("KAPPA_AUTH_TOKENS", &tokens)])
}

fn put_binding(
    c: &reqwest::blocking::Client,
    base: &str,
    token: Option<&str>,
    body: &serde_json::Value,
) -> reqwest::blocking::Response {
    let request = c.post(format!("{base}/identity/binding")).json(body);
    match token {
        Some(token) => request.bearer_auth(token),
        None => request,
    }
    .send()
    .expect("binding request")
}

fn bindings(c: &reqwest::blocking::Client, url: &str) -> Vec<serde_json::Value> {
    let resp = c.get(url).send().expect("binding list request");
    let status = resp.status();
    let text = resp.text().expect("binding list body");
    assert_eq!(status, 200, "binding list failed: {text}");
    let json: serde_json::Value = serde_json::from_str(&text).expect("binding list JSON");
    json["bindings"].as_array().expect("bindings array").clone()
}

// -- Binding tests ------------------------------------------------------------

#[test]
fn binding_put_get_roundtrip() {
    let (_guard, base, _tmp) = identity_server();
    let c = client();
    let target = anchor(&ALICE).to_string();

    let resp = put_binding(
        &c,
        &base,
        Some("alice-token"),
        &serde_json::json!({
            "source": "user@example.com",
            "target": target,
            "method": "key-challenge",
            "trust_level": 2,
            "verified_at_ms": 1000,
        }),
    );
    let status = resp.status();
    let text = resp.text().expect("binding response");
    assert_eq!(status, 201, "binding PUT failed: {text}");

    let found = bindings(&c, &format!("{base}/identity/binding/user@example.com"));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0]["source"], "user@example.com");
    assert_eq!(found[0]["target"], target);
    assert_eq!(found[0]["method"], "key-challenge");
    assert_eq!(found[0]["trust_level"], "server-custodial");
    assert_eq!(found[0]["verified_at_ms"], 1000);
}

#[test]
fn binding_requires_the_authenticated_target_anchor() {
    let (_guard, base, _tmp) = identity_server();
    let c = client();
    let body = serde_json::json!({
        "source": "claimed@example.com",
        "target": anchor(&ALICE).to_string(),
    });

    let anonymous = put_binding(&c, &base, None, &body);
    let status = anonymous.status();
    let text = anonymous.text().expect("binding response");
    assert_eq!(status, 401, "anonymous binding admitted: {text}");

    let other = put_binding(&c, &base, Some("bob-token"), &body);
    let status = other.status();
    let text = other.text().expect("binding response");
    assert_eq!(status, 403, "binding by another anchor admitted: {text}");

    assert!(bindings(&c, &format!("{base}/identity/binding/claimed@example.com")).is_empty());
}

#[test]
fn binding_delete_removes() {
    let (_guard, base, _tmp) = identity_server();
    let c = client();
    let body = serde_json::json!({
        "source": "delete-test@example.com",
        "target": anchor(&ALICE).to_string(),
    });
    let resp = put_binding(&c, &base, Some("alice-token"), &body);
    let status = resp.status();
    let text = resp.text().expect("binding response");
    assert_eq!(status, 201, "binding PUT failed: {text}");

    let resp = c
        .delete(format!("{base}/identity/binding"))
        .bearer_auth("alice-token")
        .json(&body)
        .send()
        .expect("binding delete request");
    let status = resp.status();
    let text = resp.text().expect("binding delete response");
    assert_eq!(status, 204, "binding DELETE failed: {text}");

    let found = bindings(
        &c,
        &format!("{base}/identity/binding/delete-test@example.com"),
    );
    assert!(
        found.is_empty(),
        "expected empty after delete, got {found:?}"
    );
}

#[test]
fn binding_list_by_asserter() {
    let (_guard, base, _tmp) = identity_server();
    let c = client();
    let target = anchor(&ALICE).to_string();
    for i in 0..3 {
        let resp = put_binding(
            &c,
            &base,
            Some("alice-token"),
            &serde_json::json!({
                "source": format!("id-{i}@example.com"),
                "target": target,
                "method": "self-asserted",
            }),
        );
        let status = resp.status();
        let text = resp.text().expect("binding response");
        assert_eq!(status, 201, "binding {i} PUT failed: {text}");
    }

    let found = bindings(&c, &format!("{base}/identity/binding/asserter/{target}"));
    assert_eq!(found.len(), 3, "expected 3 bindings, got {found:?}");
}

#[test]
fn binding_duplicate_idempotent() {
    let (_guard, base, _tmp) = identity_server();
    let c = client();
    let body = serde_json::json!({
        "source": "dup@example.com",
        "target": anchor(&ALICE).to_string(),
        "verified_at_ms": 7,
    });
    for attempt in 0..2 {
        let resp = put_binding(&c, &base, Some("alice-token"), &body);
        let status = resp.status();
        let text = resp.text().expect("binding response");
        assert_eq!(status, 201, "binding attempt {attempt} failed: {text}");
    }

    let found = bindings(&c, &format!("{base}/identity/binding/dup@example.com"));
    assert_eq!(
        found.len(),
        1,
        "duplicate should be idempotent, got {found:?}"
    );
}

// -- Succession tests ---------------------------------------------------------

fn seed(index: u8) -> [u8; 32] {
    [index; 32]
}

/// A succession from `old` to `new`, signed by both keys, with the old
/// anchor's watermark signed by `watermark_signer`.
fn succession_body(
    old: &[u8; 32],
    new: &[u8; 32],
    effective_at_ms: i64,
    watermark_signer: &dyn Signer,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let (old_signer, new_signer) = (
        Ed25519Signer::from_bytes(old)?,
        Ed25519Signer::from_bytes(new)?,
    );
    let record = kappa_crypto::signed_types::sign_succession(
        Succession {
            old_anchor: anchor(old),
            new_anchor: anchor(new),
            reason: SuccessionReason::Rotation,
            effective_at_ms,
            chain_anchor: None,
            prev_identifier: None,
            old_cose_signature: kappa_store::SignedPayload::empty(),
            new_cose_signature: kappa_store::SignedPayload::empty(),
        },
        &old_signer,
        &new_signer,
    )?;
    let watermark = kappa_store::default_watermark_for_succession(
        &record,
        kappa_store::clock::ClockMs::from_raw(effective_at_ms),
        watermark_signer,
    )?;
    let body = serde_json::json!({
        "old_anchor": record.old_anchor.to_string(),
        "new_anchor": record.new_anchor.to_string(),
        "old_algorithm": old_signer.algorithm(),
        "old_public_key": hex::encode(old_signer.public_key()),
        "new_algorithm": new_signer.algorithm(),
        "new_public_key": hex::encode(new_signer.public_key()),
        "reason": "rotation",
        "effective_at_ms": effective_at_ms,
        "old_signature": hex::encode(record.old_cose_signature.as_bytes()),
        "new_signature": hex::encode(record.new_cose_signature.as_bytes()),
        "watermark": hex::encode(kappa_store::canonical::canonical_bytes(&watermark)),
    });
    Ok(body)
}

fn post_succession(
    c: &reqwest::blocking::Client,
    base: &str,
    body: &serde_json::Value,
) -> (reqwest::StatusCode, String) {
    let resp = c
        .post(format!("{base}/identity/succession"))
        .json(body)
        .send()
        .expect("succession request");
    let status = resp.status();
    (status, resp.text().expect("succession response"))
}

fn resolve_current(c: &reqwest::blocking::Client, base: &str, from: &[u8; 32]) -> String {
    let resp = c
        .get(format!("{base}/identity/succession/{}", anchor(from)))
        .send()
        .expect("succession resolve request");
    let status = resp.status();
    let text = resp.text().expect("succession resolve response");
    assert_eq!(status, 200, "succession resolve failed: {text}");
    let json: serde_json::Value = serde_json::from_str(&text).expect("resolve JSON");
    json["current"].as_str().expect("current anchor").to_owned()
}

#[test]
fn succession_put_resolve() -> Result<(), Box<dyn std::error::Error>> {
    let (_guard, base, _tmp) = start_server();
    let c = client();
    let (old, new) = (seed(61), seed(62));

    let body = succession_body(&old, &new, 5000, &Ed25519Signer::from_bytes(&old)?)?;
    let (status, text) = post_succession(&c, &base, &body);
    assert_eq!(status, 201, "succession PUT failed: {text}");
    assert_eq!(resolve_current(&c, &base, &old), anchor(&new).to_string());
    Ok(())
}

#[test]
fn succession_chain_3_deep() -> Result<(), Box<dyn std::error::Error>> {
    let (_guard, base, _tmp) = start_server();
    let c = client();
    let (a, b, cc) = (seed(71), seed(72), seed(73));

    let body = succession_body(&a, &b, 1000, &Ed25519Signer::from_bytes(&a)?)?;
    let (status, text) = post_succession(&c, &base, &body);
    assert_eq!(status, 201, "A -> B failed: {text}");
    let body = succession_body(&b, &cc, 2000, &Ed25519Signer::from_bytes(&b)?)?;
    let (status, text) = post_succession(&c, &base, &body);
    assert_eq!(status, 201, "B -> C failed: {text}");

    assert_eq!(resolve_current(&c, &base, &a), anchor(&cc).to_string());

    let resp = c
        .get(format!("{base}/identity/succession/{}/chain", anchor(&a)))
        .send()
        .expect("succession chain request");
    let status = resp.status();
    let text = resp.text().expect("succession chain response");
    assert_eq!(status, 200, "succession chain failed: {text}");
    let json: serde_json::Value = serde_json::from_str(&text).expect("chain JSON");
    let chain: Vec<&str> = json["chain"]
        .as_array()
        .expect("chain array")
        .iter()
        .map(|link| link.as_str().expect("chain anchor"))
        .collect();
    assert_eq!(
        chain,
        [
            anchor(&a).to_string(),
            anchor(&b).to_string(),
            anchor(&cc).to_string()
        ]
    );
    Ok(())
}

#[test]
fn succession_self_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let (_guard, base, _tmp) = start_server();
    let c = client();
    let same = seed(81);
    let body = succession_body(&same, &same, 1000, &Ed25519Signer::from_bytes(&same)?)?;
    let (status, text) = post_succession(&c, &base, &body);
    assert_eq!(status, 400, "self-succession admitted: {text}");
    Ok(())
}

#[test]
fn succession_watermark_signed_by_another_key_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let (_guard, base, _tmp) = start_server();
    let c = client();
    let (old, new, outsider) = (seed(91), seed(92), seed(93));

    let forger = Impostor {
        claimed: Ed25519Signer::from_bytes(&old)?,
        actual: Ed25519Signer::from_bytes(&outsider)?,
    };
    let (status, text) = post_succession(&c, &base, &succession_body(&old, &new, 1000, &forger)?);
    assert_eq!(status, 400, "forged watermark admitted: {text}");
    assert!(
        text.contains("watermark verification"),
        "forged watermark rejected for the wrong reason: {text}"
    );
    assert_eq!(resolve_current(&c, &base, &old), anchor(&old).to_string());

    let genuine = succession_body(&old, &new, 1000, &Ed25519Signer::from_bytes(&old)?)?;
    let (status, text) = post_succession(&c, &base, &genuine);
    assert_eq!(
        status, 201,
        "genuine succession after the forgery failed: {text}"
    );
    assert_eq!(resolve_current(&c, &base, &old), anchor(&new).to_string());
    Ok(())
}

#[test]
fn unsigned_succession_rejected() {
    let (_guard, base, _tmp) = start_server();
    let c = client();
    let (status, text) = post_succession(
        &c,
        &base,
        &serde_json::json!({
            "old_anchor": anchor(&seed(95)).to_string(),
            "new_anchor": anchor(&seed(96)).to_string(),
            "reason": "rotation",
            "effective_at_ms": 5000,
        }),
    );
    assert_eq!(status, 400, "unsigned succession admitted: {text}");
}
