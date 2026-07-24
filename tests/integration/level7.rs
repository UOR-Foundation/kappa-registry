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

#[test]
fn namespace_root_deterministic() {
    let srv = TestServer::start();
    let ns = "l7-root-det";

    // Create tags v1 then v2
    request(&srv.addr, "PUT", &manifest_uri(ns, "v1"), &[], b"det-a");
    request(&srv.addr, "PUT", &manifest_uri(ns, "v2"), &[], b"det-b");
    let (_, _, body) = request(&srv.addr, "GET", &namespace_root_uri(ns), &[], b"");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let root1 = v["root"].as_str().unwrap().to_string();

    // Delete both, recreate in reverse order
    request(&srv.addr, "DELETE", &manifest_uri(ns, "v1"), &[], b"");
    request(&srv.addr, "DELETE", &manifest_uri(ns, "v2"), &[], b"");
    request(&srv.addr, "PUT", &manifest_uri(ns, "v2"), &[], b"det-b");
    request(&srv.addr, "PUT", &manifest_uri(ns, "v1"), &[], b"det-a");
    let (_, _, body2) = request(&srv.addr, "GET", &namespace_root_uri(ns), &[], b"");
    let v2: serde_json::Value = serde_json::from_slice(&body2).unwrap();
    let root2 = v2["root"].as_str().unwrap().to_string();

    assert_eq!(
        root1, root2,
        "root is deterministic regardless of insertion order"
    );
}

#[test]
fn namespace_root_updates_on_batch() {
    let srv = TestServer::start();
    let ns = "l7-root-batch";
    let ka = push_blob(&srv.addr, ns, b"batch-root-a");

    // Create tag, read root
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "first"),
        &[],
        b"batch-first",
    );
    let (_, _, body) = request(&srv.addr, "GET", &namespace_root_uri(ns), &[], b"");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let root1 = v["root"].as_str().unwrap().to_string();

    // Batch add second tag
    let batch_body =
        format!(r#"{{"updates":[{{"name":"second","kappa":"{ka}","expected":null}}]}}"#);
    request(
        &srv.addr,
        "POST",
        &tag_batch_uri(ns),
        &[("Content-Type", "application/json")],
        batch_body.as_bytes(),
    );

    let (_, _, body2) = request(&srv.addr, "GET", &namespace_root_uri(ns), &[], b"");
    let v2: serde_json::Value = serde_json::from_slice(&body2).unwrap();
    let root2 = v2["root"].as_str().unwrap().to_string();
    assert_ne!(root1, root2, "root changed after batch tag update");
}

#[test]
fn namespace_root_updates_on_symref() {
    let srv = TestServer::start();
    let ns = "l7-root-sym";

    // Create tag "main", read root
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "main"),
        &[],
        b"sym-content",
    );
    let (_, _, body) = request(&srv.addr, "GET", &namespace_root_uri(ns), &[], b"");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let root1 = v["root"].as_str().unwrap().to_string();

    // Create symref HEAD -> main
    request(
        &srv.addr,
        "PUT",
        &tag_symref_uri(ns, "HEAD", "main"),
        &[],
        b"",
    );
    let (_, _, body2) = request(&srv.addr, "GET", &namespace_root_uri(ns), &[], b"");
    let v2: serde_json::Value = serde_json::from_slice(&body2).unwrap();
    let root2 = v2["root"].as_str().unwrap().to_string();
    assert_ne!(root1, root2, "root changed after symref creation");
}

#[test]
fn namespace_proof_client_side_verification() {
    use sha2::{Digest, Sha256};

    let srv = TestServer::start();
    let ns = "l7-proof-verify";

    request(&srv.addr, "PUT", &manifest_uri(ns, "alpha"), &[], b"pv-a");
    request(&srv.addr, "PUT", &manifest_uri(ns, "bravo"), &[], b"pv-b");
    request(&srv.addr, "PUT", &manifest_uri(ns, "charlie"), &[], b"pv-c");

    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &namespace_proof_uri(ns, "bravo"),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let server_root = v["root"].as_str().unwrap();
    let leaves = v["leaves"].as_array().unwrap();

    // Recompute root from leaves
    let mut root_hasher = Sha256::new();
    for leaf in leaves {
        let arr = leaf.as_array().unwrap();
        let name = arr[0].as_str().unwrap();
        let value = arr[1].as_str().unwrap();
        let leaf_hash = Sha256::digest(format!("{name}={value}").as_bytes());
        root_hasher.update(leaf_hash);
    }
    let root_hash = root_hasher.finalize();
    let recomputed = format!(
        "sha256:{}",
        root_hash
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );

    assert_eq!(
        recomputed, server_root,
        "client-side root verification matches server"
    );
}

/// Batch CAS rollback: if any update in the batch fails CAS validation,
/// no updates are applied. The namespace is always the endpoint namespace.
#[test]
fn batch_cas_rollback_on_failure() {
    let srv = TestServer::start();
    let ns = "l7-batch-rollback";
    let ka = push_blob(&srv.addr, ns, b"batch-rollback-a");
    let kb = push_blob(&srv.addr, ns, b"batch-rollback-b");

    // Pre-create ref-b so create-if-absent on ref-b will fail
    request(&srv.addr, "PUT", &tag_put_uri(ns, "ref-b", &kb), &[], b"");

    // Batch: create ref-a (should succeed alone) +
    //        create ref-b (fails, already exists)
    let batch_body = format!(
        r#"{{"updates":[
            {{"name":"ref-a","kappa":"{ka}","expected":null}},
            {{"name":"ref-b","kappa":"{kb}","expected":null}}
        ]}}"#
    );
    let (status, _, body) = request(
        &srv.addr,
        "POST",
        &tag_batch_uri(ns),
        &[("Content-Type", "application/json")],
        batch_body.as_bytes(),
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("failed"), "batch should fail: {text}");

    // Verify ref-a was NOT created (full rollback)
    let (status, _, _) = request(&srv.addr, "GET", &tag_uri(ns, "ref-a"), &[], b"");
    assert_eq!(status, 404, "ref-a should not exist after rollback");
}

#[test]
fn namespace_root_signed() {
    let srv = TestServer::start();
    let ns = "l7-signed";
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "sig-tag"),
        &[],
        b"signed-content",
    );

    let uri = format!("/v2/{ns}/_root?signed=true");
    let (status, _, body) = request(&srv.addr, "GET", &uri, &[], b"");
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["root"].as_str().unwrap().starts_with("sha256:"));
    assert!(v["algorithm"].as_str().is_some(), "algorithm present");
    assert!(v["public_key"].as_str().is_some(), "public_key present");
    assert!(v["signature"].as_str().is_some(), "signature present");
    assert!(
        !v["signature"].as_str().unwrap().is_empty(),
        "signature is non-empty"
    );
    assert!(v["timestamp"].as_str().is_some(), "timestamp present");
    assert_eq!(v["namespace"].as_str(), Some(ns));
}
