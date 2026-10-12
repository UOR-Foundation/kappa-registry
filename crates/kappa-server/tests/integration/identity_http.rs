//! Integration tests for identity binding and succession HTTP endpoints.

mod helpers;
#[allow(unused_imports)]
use helpers::*;

fn client() -> reqwest::blocking::Client {
    helpers::client()
}

// -- Binding tests ------------------------------------------------------------

#[test]
fn binding_put_get_roundtrip() -> Result<(), String> {
    let (_guard, base, _tmp) = start_server();
    let c = client();

    let body = serde_json::json!({
        "source": "user@example.com",
        "target": "sha256:aaaa",
        "method": "email-verification",
        "trust_level": 2,
        "verified_at_ms": 1000,
    });
    let resp = c
        .post(format!("{}/identity/binding", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .map_err(|e| e.to_string())?;
    assert_eq!(resp.status(), 201, "binding PUT failed: {}", resp.status());

    let resp = c
        .get(format!("{}/identity/binding/user@example.com", base))
        .send()
        .map_err(|e| e.to_string())?;
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
    let bindings = json["bindings"].as_array().unwrap();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0]["source"], "user@example.com");
    assert_eq!(bindings[0]["target"], "sha256:aaaa");
    assert_eq!(bindings[0]["method"], "email-verification");
    assert_eq!(bindings[0]["trust_level"], 2);
    assert_eq!(bindings[0]["verified_at_ms"], 1000);
    Ok(())
}

#[test]
fn binding_delete_removes() -> Result<(), String> {
    let (_guard, base, _tmp) = start_server();
    let c = client();

    // Create
    let body = serde_json::json!({
        "source": "delete-test@example.com",
        "target": "sha256:bbbb",
    });
    let resp = c
        .post(format!("{}/identity/binding", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .map_err(|e| e.to_string())?;
    assert_eq!(resp.status(), 201);

    // Delete
    let del_body = serde_json::json!({
        "source": "delete-test@example.com",
        "target": "sha256:bbbb",
    });
    let resp = c
        .delete(format!("{}/identity/binding", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&del_body).unwrap())
        .send()
        .map_err(|e| e.to_string())?;
    assert_eq!(resp.status(), 204);

    // Verify empty
    let resp = c
        .get(format!("{}/identity/binding/delete-test@example.com", base))
        .send()
        .map_err(|e| e.to_string())?;
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
    let bindings = json["bindings"].as_array().unwrap();
    assert!(
        bindings.is_empty(),
        "expected empty after delete, got {:?}",
        bindings
    );
    Ok(())
}

#[test]
fn binding_list_by_asserter() -> Result<(), String> {
    let (_guard, base, _tmp) = start_server();
    let c = client();

    let asserter = "sha256:asserter-anchor";
    for i in 0..3 {
        let body = serde_json::json!({
            "source": format!("id-{}@example.com", i),
            "target": asserter,
            "method": "self-asserted",
        });
        let resp = c
            .post(format!("{}/identity/binding", base))
            .header("content-type", "application/json")
            .body(serde_json::to_string(&body).unwrap())
            .send()
            .map_err(|e| e.to_string())?;
        assert_eq!(resp.status(), 201);
    }

    let resp = c
        .get(format!("{}/identity/binding/asserter/{}", base, asserter))
        .send()
        .map_err(|e| e.to_string())?;
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
    let bindings = json["bindings"].as_array().unwrap();
    assert_eq!(
        bindings.len(),
        3,
        "expected 3 bindings, got {}",
        bindings.len()
    );
    Ok(())
}

#[test]
fn binding_duplicate_idempotent() -> Result<(), String> {
    let (_guard, base, _tmp) = start_server();
    let c = client();

    let body = serde_json::json!({
        "source": "dup@example.com",
        "target": "sha256:cccc",
    });
    for _ in 0..2 {
        let resp = c
            .post(format!("{}/identity/binding", base))
            .header("content-type", "application/json")
            .body(serde_json::to_string(&body).unwrap())
            .send()
            .map_err(|e| e.to_string())?;
        assert_eq!(resp.status(), 201);
    }

    let resp = c
        .get(format!("{}/identity/binding/dup@example.com", base))
        .send()
        .map_err(|e| e.to_string())?;
    let json: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
    let bindings = json["bindings"].as_array().unwrap();
    assert_eq!(
        bindings.len(),
        1,
        "duplicate should be idempotent, got {}",
        bindings.len()
    );
    Ok(())
}

// -- Succession tests ---------------------------------------------------------
//
// A succession must be signed by both keys: the old anchor approves, the
// new anchor accepts. Anchors here are real Ed25519 anchors.

fn key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn anchor(k: &ed25519_dalek::SigningKey) -> String {
    kappa_core::crypto::anchor::anchor_from_key_str("ed25519", &k.verifying_key().to_bytes())
}

/// POST a succession from `old` to `new`, signed by `old_signer` and `new_signer`.
fn post_succession(
    c: &reqwest::blocking::Client,
    base: &str,
    old: &ed25519_dalek::SigningKey,
    new: &ed25519_dalek::SigningKey,
    old_signer: &ed25519_dalek::SigningKey,
    new_signer: &ed25519_dalek::SigningKey,
    reason: &str,
) -> Result<reqwest::blocking::Response, String> {
    use ed25519_dalek::Signer;
    let succession = kappa_core::identity::succession::IdentitySuccession {
        old_anchor: anchor(old),
        new_anchor: anchor(new),
        reason: reason.to_string(),
        effective_at_ms: 5000,
        old_signature: Vec::new(),
        new_signature: Vec::new(),
    };
    let message = succession.signable_bytes();
    let body = serde_json::json!({
        "old_anchor": succession.old_anchor,
        "new_anchor": succession.new_anchor,
        "reason": reason,
        "effective_at_ms": 5000,
        "algorithm": "ed25519",
        "old_public_key": hex::encode(old_signer.verifying_key().to_bytes()),
        "new_public_key": hex::encode(new_signer.verifying_key().to_bytes()),
        "old_signature": hex::encode(old_signer.sign(&message).to_bytes()),
        "new_signature": hex::encode(new_signer.sign(&message).to_bytes()),
    });
    c.post(format!("{}/identity/succession", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .map_err(|e| e.to_string())
}

#[test]
fn succession_put_resolve() -> Result<(), String> {
    let (_guard, base, _tmp) = start_server();
    let c = client();
    let (old, new) = (key(1), key(2));

    let resp = post_succession(&c, &base, &old, &new, &old, &new, "rotation")?;
    assert_eq!(
        resp.status(),
        201,
        "succession PUT failed: {}",
        resp.text().unwrap_or_default()
    );

    let resp = c
        .get(format!("{}/identity/succession/{}", base, anchor(&old)))
        .send()
        .map_err(|e| e.to_string())?;
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
    assert_eq!(json["current"], anchor(&new));
    Ok(())
}

#[test]
fn succession_chain_3_deep() -> Result<(), String> {
    let (_guard, base, _tmp) = start_server();
    let c = client();
    let (a, b, cc) = (key(1), key(2), key(3));

    // A -> B, B -> C
    let resp = post_succession(&c, &base, &a, &b, &a, &b, "rotation")?;
    assert_eq!(resp.status(), 201);
    let resp = post_succession(&c, &base, &b, &cc, &b, &cc, "upgrade")?;
    assert_eq!(resp.status(), 201);

    // Resolve A -> C
    let resp = c
        .get(format!("{}/identity/succession/{}", base, anchor(&a)))
        .send()
        .map_err(|e| e.to_string())?;
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
    assert_eq!(json["current"], anchor(&cc));

    // Chain from A = [A, B, C]
    let resp = c
        .get(format!("{}/identity/succession/{}/chain", base, anchor(&a)))
        .send()
        .map_err(|e| e.to_string())?;
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
    let chain = json["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 3, "expected 3-element chain, got {:?}", chain);
    assert_eq!(chain[0], anchor(&a));
    assert_eq!(chain[1], anchor(&b));
    assert_eq!(chain[2], anchor(&cc));
    Ok(())
}

#[test]
fn succession_self_rejected() -> Result<(), String> {
    let (_guard, base, _tmp) = start_server();
    let c = client();
    let same = key(1);

    let resp = post_succession(&c, &base, &same, &same, &same, &same, "rotation")?;
    assert_eq!(resp.status(), 400, "self-succession should be rejected");
    Ok(())
}

#[test]
fn succession_unsigned_rejected() -> Result<(), String> {
    let (_guard, base, _tmp) = start_server();
    let c = client();

    let body = serde_json::json!({
        "old_anchor": anchor(&key(1)),
        "new_anchor": anchor(&key(2)),
        "reason": "rotation",
    });
    let resp = c
        .post(format!("{}/identity/succession", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .map_err(|e| e.to_string())?;
    assert_eq!(resp.status(), 400, "unsigned succession must be rejected");
    Ok(())
}

#[test]
fn succession_without_old_key_rejected() -> Result<(), String> {
    // An attacker claims a victim's anchor by signing both sides itself.
    let (_guard, base, _tmp) = start_server();
    let c = client();
    let (victim, attacker) = (key(1), key(9));

    let resp = post_succession(
        &c,
        &base,
        &victim,
        &attacker,
        &attacker,
        &attacker,
        "compromise",
    )?;
    assert_eq!(
        resp.status(),
        400,
        "succession not signed by the old key must be rejected"
    );

    let resp = c
        .get(format!("{}/identity/succession/{}", base, anchor(&victim)))
        .send()
        .map_err(|e| e.to_string())?;
    let json: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
    assert_ne!(
        json["current"],
        anchor(&attacker),
        "victim anchor must not resolve to the attacker"
    );
    Ok(())
}
