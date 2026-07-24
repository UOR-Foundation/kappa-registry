use super::common::*;

// ── Edge Diff (P2 Arm 1) ────────────────────────────────────────────────

#[test]
fn edge_diff_returns_want_minus_have() {
    let srv = TestServer::start();
    let ns = "l3-diff";

    // Create a chain: A -> B -> C -> D
    let a = push_blob(&srv.addr, ns, b"diff-node-a");
    let b = push_blob(&srv.addr, ns, b"diff-node-b");
    let c = push_blob(&srv.addr, ns, b"diff-node-c");
    let d = push_blob(&srv.addr, ns, b"diff-node-d");

    // Create edges: A owns B, B owns C, C owns D
    for (src, tgt) in [(&a, &b), (&b, &c), (&c, &d)] {
        let body =
            format!(r#"{{"source":"{src}","relation":"owns","target":"{tgt}","metadata":{{}}}}"#);
        request(
            &srv.addr,
            "PUT",
            &edge_put_uri(ns),
            &[("Content-Type", "application/json")],
            body.as_bytes(),
        );
    }

    // Diff: want everything from A, have everything from C.
    // Should return A, B, and their edge kappas (but not C, D, or C->D edge).
    let diff_body = format!(r#"{{"have":["{c}"],"want":["{a}"],"relations":["owns"]}}"#);
    let (status, _, resp) = request(
        &srv.addr,
        "POST",
        &edge_diff_uri(ns),
        &[("Content-Type", "application/json")],
        diff_body.as_bytes(),
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&resp);
    // A and B should be in the diff (reachable from want but not from have)
    assert!(text.contains(&a), "diff should contain A: {text}");
    assert!(text.contains(&b), "diff should contain B: {text}");
    // C and D should NOT be in the diff (reachable from have)
    assert!(!text.contains(&d), "diff should not contain D: {text}");
}

#[test]
fn edge_diff_empty_have_returns_full_want() {
    let srv = TestServer::start();
    let ns = "l3-diff-empty";
    let a = push_blob(&srv.addr, ns, b"diff-empty-a");
    let b = push_blob(&srv.addr, ns, b"diff-empty-b");

    let edge_body =
        format!(r#"{{"source":"{a}","relation":"owns","target":"{b}","metadata":{{}}}}"#);
    request(
        &srv.addr,
        "PUT",
        &edge_put_uri(ns),
        &[("Content-Type", "application/json")],
        edge_body.as_bytes(),
    );

    let diff_body = format!(r#"{{"have":[],"want":["{a}"],"relations":["owns"]}}"#);
    let (status, _, resp) = request(
        &srv.addr,
        "POST",
        &edge_diff_uri(ns),
        &[("Content-Type", "application/json")],
        diff_body.as_bytes(),
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&resp);
    assert!(text.contains(&a), "diff contains A: {text}");
    assert!(text.contains(&b), "diff contains B: {text}");
}

#[test]
fn edge_diff_identical_have_want_returns_empty() {
    let srv = TestServer::start();
    let ns = "l3-diff-same";
    let a = push_blob(&srv.addr, ns, b"diff-same-a");

    let diff_body = format!(r#"{{"have":["{a}"],"want":["{a}"],"relations":["owns"]}}"#);
    let (status, _, resp) = request(
        &srv.addr,
        "POST",
        &edge_diff_uri(ns),
        &[("Content-Type", "application/json")],
        diff_body.as_bytes(),
    );
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    let diff = v["diff"].as_array().unwrap();
    assert!(diff.is_empty(), "identical have/want yields empty diff");
}

// ── Edge CRUD ────────────────────────────────────────────────────────────

#[test]
fn edge_create_query_delete() {
    let srv = TestServer::start();
    let ns = "l3-edges";
    let source_k = push_blob(&srv.addr, ns, b"source blob");
    let target_k = push_blob(&srv.addr, ns, b"target blob");

    let edge_body = format!(
        r#"{{"source":"{source_k}","relation":"derives-from","target":"{target_k}","metadata":{{}}}}"#
    );

    // PUT edge
    let (status, hdrs, _) = request(
        &srv.addr,
        "PUT",
        &edge_put_uri(ns),
        &[("Content-Type", "application/json")],
        edge_body.as_bytes(),
    );
    assert_eq!(status, 201);
    let edge_kappa = header(&hdrs, "x-kappa-label").unwrap().to_string();
    assert!(edge_kappa.starts_with("sha256:"));

    // Idempotent re-create
    let (status, _, _) = request(
        &srv.addr,
        "PUT",
        &edge_put_uri(ns),
        &[("Content-Type", "application/json")],
        edge_body.as_bytes(),
    );
    assert_eq!(status, 200);

    // Query outbound from source
    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &edge_query_uri(ns, &source_k, "outbound", Some("derives-from")),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains(&target_k), "outbound has target: {text}");

    // Query inbound to target
    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &edge_query_uri(ns, &target_k, "inbound", Some("derives-from")),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains(&source_k), "inbound has source: {text}");

    // Relation filter - wrong relation returns empty
    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &edge_query_uri(ns, &source_k, "outbound", Some("owns")),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(!text.contains(&target_k), "wrong relation is empty: {text}");

    // DELETE edge
    let (status, _, _) = request(
        &srv.addr,
        "DELETE",
        &edge_delete_uri(ns, &edge_kappa),
        &[],
        b"",
    );
    assert_eq!(status, 202);

    // Query after delete - edge gone
    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &edge_query_uri(ns, &source_k, "outbound", Some("derives-from")),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(!text.contains(&edge_kappa), "deleted edge gone: {text}");
}

#[test]
fn edge_source_must_exist() {
    let srv = TestServer::start();
    let ns = "l3-src";
    let target_k = push_blob(&srv.addr, ns, b"target exists");
    let body = format!(
        r#"{{"source":"{}","relation":"owns","target":"{target_k}","metadata":{{}}}}"#,
        absent_kappa()
    );
    let (status, _, resp) = request(
        &srv.addr,
        "PUT",
        &edge_put_uri(ns),
        &[("Content-Type", "application/json")],
        body.as_bytes(),
    );
    assert_eq!(status, 409);
    let text = String::from_utf8_lossy(&resp);
    assert!(text.contains("EDGE_SOURCE_ABSENT"), "body: {text}");
}

#[test]
fn edge_absent_target_tolerated() {
    let srv = TestServer::start();
    let ns = "l3-tgt";
    let source_k = push_blob(&srv.addr, ns, b"source exists");
    let body = format!(
        r#"{{"source":"{source_k}","relation":"owns","target":"{}","metadata":{{}}}}"#,
        absent_kappa()
    );
    let (status, _, _) = request(
        &srv.addr,
        "PUT",
        &edge_put_uri(ns),
        &[("Content-Type", "application/json")],
        body.as_bytes(),
    );
    assert!(
        status == 201 || status == 200,
        "absent target accepted: {status}"
    );
}

#[test]
fn edge_kappa_inherits_source_axis() {
    let srv = TestServer::start();
    let ns = "l3-axis";
    let source_k = push_blob(&srv.addr, ns, b"axis source");
    let target_k = push_blob(&srv.addr, ns, b"axis target");
    let body = format!(
        r#"{{"source":"{source_k}","relation":"owns","target":"{target_k}","metadata":{{}}}}"#
    );
    let (_, hdrs, _) = request(
        &srv.addr,
        "PUT",
        &edge_put_uri(ns),
        &[("Content-Type", "application/json")],
        body.as_bytes(),
    );
    let edge_k = header(&hdrs, "x-kappa-label").unwrap();
    let source_axis = source_k.split(':').next().unwrap();
    assert!(
        edge_k.starts_with(&format!("{source_axis}:")),
        "edge kappa {edge_k} should start with source axis {source_axis}"
    );
}

#[test]
fn edge_blob_retrievable() {
    let srv = TestServer::start();
    let ns = "l3-blob";
    let source_k = push_blob(&srv.addr, ns, b"edge blob src");
    let target_k = push_blob(&srv.addr, ns, b"edge blob tgt");
    let body = format!(
        r#"{{"source":"{source_k}","relation":"derives-from","target":"{target_k}","metadata":{{}}}}"#
    );
    let (_, hdrs, _) = request(
        &srv.addr,
        "PUT",
        &edge_put_uri(ns),
        &[("Content-Type", "application/json")],
        body.as_bytes(),
    );
    let edge_k = header(&hdrs, "x-kappa-label").unwrap();
    let (status, _, edge_body) = request(&srv.addr, "GET", &blob_uri(ns, edge_k), &[], b"");
    assert_eq!(status, 200, "edge blob retrievable as a blob");
    assert!(!edge_body.is_empty(), "edge blob has content");
}

#[test]
fn edge_namespace_isolation() {
    let srv = TestServer::start();
    let ns_a = "l3-iso-a";
    let ns_b = "l3-iso-b";
    let src = push_blob(&srv.addr, ns_a, b"isolation-src");
    let tgt = push_blob(&srv.addr, ns_a, b"isolation-tgt");

    let edge_body =
        format!(r#"{{"source":"{src}","relation":"owns","target":"{tgt}","metadata":{{}}}}"#);
    let (status, _, _) = request(
        &srv.addr,
        "PUT",
        &edge_put_uri(ns_a),
        &[("Content-Type", "application/json")],
        edge_body.as_bytes(),
    );
    assert_eq!(status, 201);

    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &edge_query_uri(ns_b, &src, "outbound", Some("owns")),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(
        !text.contains(&tgt),
        "namespace B should not see namespace A edges: {text}"
    );
}
