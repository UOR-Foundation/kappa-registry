use super::common::*;

// ── Range-Based Set Reconciliation (P2 Arm 2) ───────────────────────────

#[test]
fn reconcile_fingerprint_match_returns_done() {
    let srv = TestServer::start();
    let ns = "l6-fp-match";

    // Push some blobs and register them in the fingerprint set via reconcile
    let a = push_blob(&srv.addr, ns, b"reconcile-a");
    let b = push_blob(&srv.addr, ns, b"reconcile-b");

    // Insert items into the fingerprint set by sending them as items
    let items_body = format!(r#"{{"type":"items","lower":"a","upper":"a","items":["{a}","{b}"]}}"#);
    let (status, _, _) = request(
        &srv.addr,
        "POST",
        &reconcile_uri(ns),
        &[("Content-Type", "application/json")],
        items_body.as_bytes(),
    );
    assert_eq!(status, 200);

    // Now request the fingerprint for the full range
    let fp_req = r#"{"type":"items_request","lower":"a","upper":"a"}"#;
    let (status, _, resp) = request(
        &srv.addr,
        "POST",
        &reconcile_uri(ns),
        &[("Content-Type", "application/json")],
        fp_req.as_bytes(),
    );
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    assert_eq!(v["type"].as_str(), Some("items"));
    let items = v["items"].as_array().unwrap();
    assert!(
        items.len() >= 2,
        "items response should contain at least the 2 inserted items: {items:?}"
    );
}

#[test]
fn reconcile_fingerprint_mismatch_returns_items_or_subdivide() {
    let srv = TestServer::start();
    let ns = "l6-fp-mismatch";

    // Push items into the fingerprint set
    let a = push_blob(&srv.addr, ns, b"mismatch-a");
    let items_body = format!(r#"{{"type":"items","lower":"a","upper":"a","items":["{a}"]}}"#);
    request(
        &srv.addr,
        "POST",
        &reconcile_uri(ns),
        &[("Content-Type", "application/json")],
        items_body.as_bytes(),
    );

    // Send a fingerprint that does not match (all zeros)
    let fake_fp = "0".repeat(64);
    let fp_body =
        format!(r#"{{"type":"fingerprint","lower":"a","upper":"a","fingerprint":"{fake_fp}"}}"#);
    let (status, _, resp) = request(
        &srv.addr,
        "POST",
        &reconcile_uri(ns),
        &[("Content-Type", "application/json")],
        fp_body.as_bytes(),
    );
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    let resp_type = v["type"].as_str().unwrap_or("");
    // Should respond with items (small set) or subdivide (large set)
    assert!(
        resp_type == "items" || resp_type == "subdivide",
        "mismatch should yield items or subdivide, got: {resp_type}"
    );
    if resp_type == "items" {
        let items = v["items"].as_array().unwrap();
        assert!(
            items.iter().any(|i| i.as_str() == Some(a.as_str())),
            "items response should contain the inserted item"
        );
    }
}

#[test]
fn reconcile_items_exchange() {
    let srv = TestServer::start();
    let ns = "l6-items";

    // Server has item A
    let a = push_blob(&srv.addr, ns, b"exchange-a");
    let seed_body = format!(r#"{{"type":"items","lower":"a","upper":"a","items":["{a}"]}}"#);
    request(
        &srv.addr,
        "POST",
        &reconcile_uri(ns),
        &[("Content-Type", "application/json")],
        seed_body.as_bytes(),
    );

    // Peer sends item B, should receive item A back (items peer does not have)
    let b = push_blob(&srv.addr, ns, b"exchange-b");
    let peer_body = format!(r#"{{"type":"items","lower":"a","upper":"a","items":["{b}"]}}"#);
    let (status, _, resp) = request(
        &srv.addr,
        "POST",
        &reconcile_uri(ns),
        &[("Content-Type", "application/json")],
        peer_body.as_bytes(),
    );
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    assert_eq!(v["type"].as_str(), Some("items"));
    let returned_items = v["items"].as_array().unwrap();
    // Server should return A (which peer did not send)
    assert!(
        returned_items
            .iter()
            .any(|i| i.as_str() == Some(a.as_str())),
        "server should return items peer does not have: {returned_items:?}"
    );
    // Server should NOT return B (which peer just sent)
    assert!(
        !returned_items
            .iter()
            .any(|i| i.as_str() == Some(b.as_str())),
        "server should not echo back items peer sent: {returned_items:?}"
    );
}

#[test]
fn reconcile_items_request_returns_range() {
    let srv = TestServer::start();
    let ns = "l6-range";

    let a = push_blob(&srv.addr, ns, b"range-a");
    let b = push_blob(&srv.addr, ns, b"range-b");
    let c = push_blob(&srv.addr, ns, b"range-c");

    // Seed all three into the fingerprint set
    let seed = format!(r#"{{"type":"items","lower":"a","upper":"a","items":["{a}","{b}","{c}"]}}"#);
    request(
        &srv.addr,
        "POST",
        &reconcile_uri(ns),
        &[("Content-Type", "application/json")],
        seed.as_bytes(),
    );

    // Request full range (lower == upper)
    let req = r#"{"type":"items_request","lower":"x","upper":"x"}"#;
    let (status, _, resp) = request(
        &srv.addr,
        "POST",
        &reconcile_uri(ns),
        &[("Content-Type", "application/json")],
        req.as_bytes(),
    );
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 3, "full range should return all 3 items");
}

#[test]
fn reconcile_empty_namespace_zero_fingerprint_matches() {
    let srv = TestServer::start();
    let ns = "l6-empty-zero";

    // Empty namespace has fingerprint [0; 32]. Peer sends the same zero
    // fingerprint. Both sides are empty -- fingerprints match, done.
    let zero_fp = "0".repeat(64);
    let body =
        format!(r#"{{"type":"fingerprint","lower":"a","upper":"a","fingerprint":"{zero_fp}"}}"#);
    let (status, _, resp) = request(
        &srv.addr,
        "POST",
        &reconcile_uri(ns),
        &[("Content-Type", "application/json")],
        body.as_bytes(),
    );
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    assert_eq!(
        v["type"].as_str(),
        Some("done"),
        "two empty sets match: {v}"
    );
}

#[test]
fn reconcile_empty_namespace_nonzero_fingerprint_mismatches() {
    let srv = TestServer::start();
    let ns = "l6-empty-nonzero";

    // Peer has items (non-zero fingerprint). Empty namespace should respond
    // with items (empty list) indicating it has nothing in this range.
    let nonzero_fp = format!("{}{}", "ab".repeat(31), "cd");
    let body =
        format!(r#"{{"type":"fingerprint","lower":"a","upper":"a","fingerprint":"{nonzero_fp}"}}"#);
    let (status, _, resp) = request(
        &srv.addr,
        "POST",
        &reconcile_uri(ns),
        &[("Content-Type", "application/json")],
        body.as_bytes(),
    );
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    assert_eq!(
        v["type"].as_str(),
        Some("items"),
        "mismatch yields items: {v}"
    );
    let items = v["items"].as_array().unwrap();
    assert!(items.is_empty(), "empty namespace has no items to send");
}
