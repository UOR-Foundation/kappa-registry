use super::common::*;

#[test]
fn gc_pin_unpin_sweep_status() {
    let srv = TestServer::start();
    let ns = "l5-gc";
    let kappa = push_blob(&srv.addr, ns, b"pinned content");

    // Pin
    let pin_body = format!(r#"{{"kappa":"{kappa}","ttl":0,"controller":""}}"#);
    let (status, hdrs, _) = request(
        &srv.addr,
        "POST",
        &gc_pin_uri(ns),
        &[("Content-Type", "application/json")],
        pin_body.as_bytes(),
    );
    assert_eq!(status, 201);
    let pin_kappa = header(&hdrs, "x-kappa-label").unwrap().to_string();

    // Unpin
    let unpin_body = format!(r#"{{"pin_kappa":"{pin_kappa}"}}"#);
    let (status, _, _) = request(
        &srv.addr,
        "POST",
        &gc_unpin_uri(ns),
        &[("Content-Type", "application/json")],
        unpin_body.as_bytes(),
    );
    assert_eq!(status, 200);

    // Sweep
    let (status, _, body) = request(&srv.addr, "POST", &gc_sweep_uri(ns), &[], b"");
    assert_eq!(status, 202);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("sweep_id"), "sweep response: {text}");

    // Wait briefly for async sweep
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Status
    let (status, _, body) = request(&srv.addr, "GET", &gc_status_uri(ns), &[], b"");
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("last_sweep"), "status has last_sweep: {text}");
}

#[test]
fn finalizer_blocks_unpin() {
    let srv = TestServer::start();
    let ns = "l5-fin";
    let kappa = push_blob(&srv.addr, ns, b"finalized content");

    let pin_body = format!(r#"{{"kappa":"{kappa}","ttl":0,"controller":"test-ctrl"}}"#);
    let (status, hdrs, _) = request(
        &srv.addr,
        "POST",
        &gc_pin_uri(ns),
        &[("Content-Type", "application/json")],
        pin_body.as_bytes(),
    );
    assert_eq!(status, 201);
    let pin_kappa = header(&hdrs, "x-kappa-label").unwrap().to_string();

    // Unpin without release - blocked
    let unpin_body = format!(r#"{{"pin_kappa":"{pin_kappa}"}}"#);
    let (status, _, body) = request(
        &srv.addr,
        "POST",
        &gc_unpin_uri(ns),
        &[("Content-Type", "application/json")],
        unpin_body.as_bytes(),
    );
    assert_eq!(status, 409);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("FINALIZER_OUTSTANDING"), "body: {text}");

    // Unpin with release - succeeds
    let release_body = format!(r#"{{"pin_kappa":"{pin_kappa}","release":"true"}}"#);
    let (status, _, _) = request(
        &srv.addr,
        "POST",
        &gc_unpin_uri(ns),
        &[("Content-Type", "application/json")],
        release_body.as_bytes(),
    );
    assert_eq!(status, 200);
}

#[test]
fn filter_register_list_evaluate_remove() {
    let srv = TestServer::start();
    let ns = "l5-filter";

    // Register filter
    let (status, hdrs, _) = request(
        &srv.addr,
        "PUT",
        &filter_put_uri(ns, "test-scope"),
        &[("Content-Type", "application/json")],
        b"deny:FORBIDDEN",
    );
    assert_eq!(status, 201);
    let fk = header(&hdrs, "x-kappa-label").unwrap().to_string();

    // List filters
    let (status, _, body) = request(&srv.addr, "GET", &filter_list_uri(ns), &[], b"");
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("test-scope"), "filter in list: {text}");

    // PUT blob matching deny rule - rejected
    let denied_content = b"this has FORBIDDEN in it";
    let denied_kappa = kappa_registry::kappa::KappaLabel::sha256(denied_content)
        .as_str()
        .to_string();
    let (status, _, body) = request(
        &srv.addr,
        "PUT",
        &blob_uri(ns, &denied_kappa),
        &[],
        denied_content,
    );
    assert_eq!(status, 422);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("FILTER_REJECTED"), "body: {text}");

    // PUT clean blob - accepted
    let clean_content = b"perfectly fine content";
    let clean_kappa = kappa_registry::kappa::KappaLabel::sha256(clean_content)
        .as_str()
        .to_string();
    let (status, _, _) = request(
        &srv.addr,
        "PUT",
        &blob_uri(ns, &clean_kappa),
        &[],
        clean_content,
    );
    assert_eq!(status, 201);

    // Remove filter
    let (status, _, _) = request(&srv.addr, "DELETE", &filter_delete_uri(ns, &fk), &[], b"");
    assert_eq!(status, 202);

    // Previously denied content now accepted
    let (status, _, _) = request(
        &srv.addr,
        "PUT",
        &blob_uri(ns, &denied_kappa),
        &[],
        denied_content,
    );
    assert_eq!(status, 201, "accepted after filter removal");
}

#[test]
fn gc_reachability_pinned_and_owned_survive() {
    let srv = TestServer::start();
    let ns = "l5-reach";
    let root_k = push_blob(&srv.addr, ns, b"gc root");
    let owned_k = push_blob(&srv.addr, ns, b"gc owned");
    let orphan_k = push_blob(&srv.addr, ns, b"gc orphan");

    // Create owns edge: root -> owned
    let edge_body = format!(
        r#"{{"source":"{root_k}","relation":"owns","target":"{owned_k}","metadata":{{}}}}"#
    );
    request(
        &srv.addr,
        "PUT",
        &edge_put_uri(ns),
        &[("Content-Type", "application/json")],
        edge_body.as_bytes(),
    );

    // Pin root
    let pin_body = format!(r#"{{"kappa":"{root_k}","ttl":0,"controller":""}}"#);
    request(
        &srv.addr,
        "POST",
        &gc_pin_uri(ns),
        &[("Content-Type", "application/json")],
        pin_body.as_bytes(),
    );

    // Sweep
    request(&srv.addr, "POST", &gc_sweep_uri(ns), &[], b"");
    std::thread::sleep(std::time::Duration::from_millis(300));

    // Pinned root survives
    let (status, _, _) = request(&srv.addr, "GET", &blob_uri(ns, &root_k), &[], b"");
    assert_eq!(status, 200, "pinned root survives sweep");

    // Owned blob survives (reachable via owns)
    let (status, _, _) = request(&srv.addr, "GET", &blob_uri(ns, &owned_k), &[], b"");
    assert_eq!(status, 200, "owned blob survives sweep");

    // Orphan evicted
    let (status, _, _) = request(&srv.addr, "GET", &blob_uri(ns, &orphan_k), &[], b"");
    assert_eq!(status, 404, "orphan evicted by sweep");
}

#[test]
fn gc_tag_as_root() {
    let srv = TestServer::start();
    let ns = "l5-tag-root";
    let content = b"tagged content survives";

    // Bind tag (no pin)
    request(&srv.addr, "PUT", &manifest_uri(ns, "keep-me"), &[], content);
    let tagged_k = kappa_registry::kappa::KappaLabel::sha256(content)
        .as_str()
        .to_string();

    // Push an untagged orphan
    let orphan_k = push_blob(&srv.addr, ns, b"orphan no tag no pin");

    // Sweep
    request(&srv.addr, "POST", &gc_sweep_uri(ns), &[], b"");
    std::thread::sleep(std::time::Duration::from_millis(300));

    // Tagged blob survives
    let (status, _, _) = request(&srv.addr, "GET", &blob_uri(ns, &tagged_k), &[], b"");
    assert_eq!(status, 200, "tagged blob survives sweep");

    // Orphan evicted
    let (status, _, _) = request(&srv.addr, "GET", &blob_uri(ns, &orphan_k), &[], b"");
    assert_eq!(status, 404, "untagged orphan evicted");
}
