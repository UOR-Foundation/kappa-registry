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
    assert!(bindings.is_empty(), "expected empty after delete, got {:?}", bindings);
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
    assert_eq!(bindings.len(), 3, "expected 3 bindings, got {}", bindings.len());
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
    assert_eq!(bindings.len(), 1, "duplicate should be idempotent, got {}", bindings.len());
    Ok(())
}

// -- Succession tests ---------------------------------------------------------

#[test]
fn succession_put_resolve() -> Result<(), String> {
    let (_guard, base, _tmp) = start_server();
    let c = client();

    let body = serde_json::json!({
        "old_anchor": "sha256:old-key",
        "new_anchor": "sha256:new-key",
        "reason": "rotation",
        "effective_at_ms": 5000,
    });
    let resp = c
        .post(format!("{}/identity/succession", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .map_err(|e| e.to_string())?;
    assert_eq!(resp.status(), 201, "succession PUT failed: {}", resp.text().unwrap_or_default());

    let resp = c
        .get(format!("{}/identity/succession/sha256:old-key", base))
        .send()
        .map_err(|e| e.to_string())?;
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
    assert_eq!(json["current"], "sha256:new-key");
    Ok(())
}

#[test]
fn succession_chain_3_deep() -> Result<(), String> {
    let (_guard, base, _tmp) = start_server();
    let c = client();

    // A -> B
    let body = serde_json::json!({
        "old_anchor": "sha256:anchor-a",
        "new_anchor": "sha256:anchor-b",
        "reason": "rotation",
    });
    c.post(format!("{}/identity/succession", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .map_err(|e| e.to_string())?;

    // B -> C
    let body = serde_json::json!({
        "old_anchor": "sha256:anchor-b",
        "new_anchor": "sha256:anchor-c",
        "reason": "upgrade",
    });
    c.post(format!("{}/identity/succession", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .map_err(|e| e.to_string())?;

    // Resolve A -> C
    let resp = c
        .get(format!("{}/identity/succession/sha256:anchor-a", base))
        .send()
        .map_err(|e| e.to_string())?;
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
    assert_eq!(json["current"], "sha256:anchor-c");

    // Chain from A = [A, B, C]
    let resp = c
        .get(format!("{}/identity/succession/sha256:anchor-a/chain", base))
        .send()
        .map_err(|e| e.to_string())?;
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
    let chain = json["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 3, "expected 3-element chain, got {:?}", chain);
    assert_eq!(chain[0], "sha256:anchor-a");
    assert_eq!(chain[1], "sha256:anchor-b");
    assert_eq!(chain[2], "sha256:anchor-c");
    Ok(())
}

#[test]
fn succession_self_rejected() -> Result<(), String> {
    let (_guard, base, _tmp) = start_server();
    let c = client();

    let body = serde_json::json!({
        "old_anchor": "sha256:same",
        "new_anchor": "sha256:same",
        "reason": "rotation",
    });
    let resp = c
        .post(format!("{}/identity/succession", base))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .map_err(|e| e.to_string())?;
    assert_eq!(resp.status(), 400, "self-succession should be rejected");
    Ok(())
}
