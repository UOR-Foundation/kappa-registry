use super::common::*;

#[test]
fn namespace_root_changes_on_tag_mutation() {
    let srv = TestServer::start();
    let ns = "l7-root";
    let content = br#"{"root":"test"}"#;
    request(&srv.addr, "PUT", &manifest_uri(ns, "v1"), &[], content);

    let (status, _, body) = request(&srv.addr, "GET", &namespace_root_uri(ns), &[], b"");
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let root1 = v["root"].as_str().unwrap().to_string();
    assert!(root1.starts_with("sha256:"), "root is a kappa-label");
    assert_eq!(v["count"].as_u64(), Some(1));

    // Add another tag -- root should change
    request(&srv.addr, "PUT", &manifest_uri(ns, "v2"), &[], b"more");
    let (_, _, body2) = request(&srv.addr, "GET", &namespace_root_uri(ns), &[], b"");
    let v2: serde_json::Value = serde_json::from_slice(&body2).unwrap();
    let root2 = v2["root"].as_str().unwrap().to_string();
    assert_ne!(root1, root2, "root changed after tag mutation");
    assert_eq!(v2["count"].as_u64(), Some(2));
}

#[test]
fn namespace_root_empty_namespace() {
    let srv = TestServer::start();
    let ns = "l7-root-empty";
    let (status, _, body) = request(&srv.addr, "GET", &namespace_root_uri(ns), &[], b"");
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["root"].is_null(), "empty namespace has null root");
    assert_eq!(v["count"].as_u64(), Some(0));
}

#[test]
fn namespace_proof_for_existing_tag() {
    let srv = TestServer::start();
    let ns = "l7-proof";
    let content = br#"{"proof":"test"}"#;
    request(&srv.addr, "PUT", &manifest_uri(ns, "tagged"), &[], content);

    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &namespace_proof_uri(ns, "tagged"),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["tag"].as_str(), Some("tagged"));
    assert_eq!(v["proof_format"].as_str(), Some("leaf_list"));
    assert!(v["root"].as_str().unwrap().starts_with("sha256:"));
    assert!(!v["leaves"].as_array().unwrap().is_empty());
}

#[test]
fn namespace_proof_absent_tag_returns_404() {
    let srv = TestServer::start();
    let ns = "l7-proof-absent";
    let (status, _, _) = request(
        &srv.addr,
        "GET",
        &namespace_proof_uri(ns, "nonexistent"),
        &[],
        b"",
    );
    assert_eq!(status, 404);
}
