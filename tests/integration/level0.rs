use super::common::*;

// ── Node Identity Bootstrap (KNI-001 Invariants) ───────────────────

#[test]
fn whoami_returns_valid_json() {
    let srv = TestServer::start();
    let (status, hdrs, body) = request(&srv.addr, "GET", "/v2/test/_identity/whoami", &[], b"");
    assert_eq!(status, 200);
    assert_eq!(header(&hdrs, "content-type"), Some("application/json"));
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["anchor"].as_str().unwrap().starts_with("sha256:"));
    assert_eq!(v["algorithm"].as_str(), Some("ed25519"));
    assert_eq!(v["trust_position"].as_str(), Some("unprobed"));
    assert!(v["epoch"].is_number());
    assert!(v["self_assertions"].is_object());
}

#[test]
fn whoami_self_assertions_present() {
    let srv = TestServer::start();
    let (_, _, body) = request(&srv.addr, "GET", "/v2/test/_identity/whoami", &[], b"");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let sa = &v["self_assertions"];
    assert!(
        sa["node/anchor"].as_str().unwrap().starts_with("sha256:"),
        "node/anchor self-assertion present"
    );
    assert_eq!(
        sa["node/algorithm"].as_str(),
        Some("ed25519"),
        "node/algorithm self-assertion present"
    );
    assert!(
        sa["node/version"].as_str().is_some(),
        "node/version self-assertion present"
    );
    assert_eq!(
        sa["trust/position"].as_str(),
        Some("unprobed"),
        "trust/position self-assertion present"
    );
}

#[test]
fn whoami_anchor_matches_self_assertion() {
    let srv = TestServer::start();
    let (_, _, body) = request(&srv.addr, "GET", "/v2/test/_identity/whoami", &[], b"");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let anchor = v["anchor"].as_str().unwrap();
    let sa_anchor = v["self_assertions"]["node/anchor"].as_str().unwrap();
    assert_eq!(anchor, sa_anchor, "whoami anchor matches self-assertion");
}

#[test]
fn whoami_anchor_is_deterministic() {
    let srv = TestServer::start();
    let (_, _, b1) = request(&srv.addr, "GET", "/v2/a/_identity/whoami", &[], b"");
    let (_, _, b2) = request(&srv.addr, "GET", "/v2/b/_identity/whoami", &[], b"");
    let v1: serde_json::Value = serde_json::from_slice(&b1).unwrap();
    let v2: serde_json::Value = serde_json::from_slice(&b2).unwrap();
    assert_eq!(
        v1["anchor"], v2["anchor"],
        "anchor is the same regardless of namespace in the URL"
    );
}

#[test]
fn capability_edges_written_for_reserved_namespaces() {
    let srv = TestServer::start();
    // Get the node's anchor
    let (_, _, body) = request(&srv.addr, "GET", "/v2/test/_identity/whoami", &[], b"");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let anchor = v["anchor"].as_str().unwrap();

    // Query capability edges on a reserved namespace
    // The bootstrap writes capability edges from anchor to anchor on each reserved ns.
    // kappa/protocols is reserved -- query outbound capability edges from anchor.
    let edge_uri = format!(
        "/v2/kappa%2Fprotocols/edges/{}?direction=outbound&relation=capability",
        urlenc(anchor)
    );
    let (status, _, edge_body) = request(&srv.addr, "GET", &edge_uri, &[], b"");
    assert_eq!(status, 200);
    let ev: serde_json::Value = serde_json::from_slice(&edge_body).unwrap();
    let edges = ev["edges"].as_array().unwrap();
    assert!(
        !edges.is_empty(),
        "capability edge exists on kappa/protocols for node anchor"
    );

    // Verify the edge metadata contains admin ops
    let meta = &edges[0]["metadata"];
    let ops = meta["ops"].as_array().unwrap();
    let op_strs: Vec<&str> = ops.iter().filter_map(|v| v.as_str()).collect();
    assert!(op_strs.contains(&"read"));
    assert!(op_strs.contains(&"write"));
    assert!(op_strs.contains(&"admin"));
}

#[test]
fn self_assertions_stored_as_tags() {
    let srv = TestServer::start();
    let (_, _, body) = request(&srv.addr, "GET", "/v2/test/_identity/whoami", &[], b"");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let anchor = v["anchor"].as_str().unwrap();

    // The node's self-assertions are stored as tags in its own namespace.
    // tag_get on anchor namespace for node/anchor should return the anchor value.
    let tag_uri = format!("/v2/{}/tags/node%2Fanchor", urlenc(anchor));
    let (status, _, tag_body) = request(&srv.addr, "GET", &tag_uri, &[], b"");
    assert_eq!(status, 200, "node/anchor tag exists in node namespace");
    let tv: serde_json::Value = serde_json::from_slice(&tag_body).unwrap();
    assert_eq!(
        tv["kappa"].as_str().unwrap(),
        anchor,
        "node/anchor tag value is the anchor itself"
    );
}

#[test]
fn version_in_self_assertions_matches_crate() {
    let srv = TestServer::start();
    let (_, _, body) = request(&srv.addr, "GET", "/v2/test/_identity/whoami", &[], b"");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let version = v["self_assertions"]["node/version"].as_str().unwrap();
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
}

/// URL-encode a string for use in path segments (colons in kappa labels).
fn urlenc(s: &str) -> String {
    s.replace(':', "%3A")
}
