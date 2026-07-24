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

    // Poll for sweep completion (redb edge operations may take longer under load)
    let mut sweep_done = false;
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let (s, _, b) = request(&srv.addr, "GET", &gc_status_uri(ns), &[], b"");
        if s == 200 {
            let t = String::from_utf8_lossy(&b);
            if t.contains("last_sweep") {
                sweep_done = true;
                break;
            }
        }
    }
    assert!(sweep_done, "sweep did not complete within 5 seconds");
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

    // Sweep and poll for completion
    request(&srv.addr, "POST", &gc_sweep_uri(ns), &[], b"");
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let (s, _, b) = request(&srv.addr, "GET", &gc_status_uri(ns), &[], b"");
        if s == 200 && String::from_utf8_lossy(&b).contains("last_sweep") {
            break;
        }
    }

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

    // Sweep and poll for completion
    request(&srv.addr, "POST", &gc_sweep_uri(ns), &[], b"");
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let (s, _, b) = request(&srv.addr, "GET", &gc_status_uri(ns), &[], b"");
        if s == 200 && String::from_utf8_lossy(&b).contains("last_sweep") {
            break;
        }
    }

    // Tagged blob survives
    let (status, _, _) = request(&srv.addr, "GET", &blob_uri(ns, &tagged_k), &[], b"");
    assert_eq!(status, 200, "tagged blob survives sweep");

    // Orphan evicted
    let (status, _, _) = request(&srv.addr, "GET", &blob_uri(ns, &orphan_k), &[], b"");
    assert_eq!(status, 404, "untagged orphan evicted");
}

#[test]
fn type_metadata_manifest() {
    let srv = TestServer::start();
    let ns = "l5-meta-manifest";
    let content = br#"{"type":"test-manifest"}"#;
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "meta-test"),
        &[],
        content,
    );
    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &meta_list_uri(ns, "object-type", "manifest"),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("sha256:"),
        "manifest in metadata list: {text}"
    );
}

#[test]
fn type_metadata_composition() {
    let srv = TestServer::start();
    let ns = "l5-meta-compose";
    let ka = push_blob(&srv.addr, ns, b"meta-compose-a");
    let kb = push_blob(&srv.addr, ns, b"meta-compose-b");
    let compose_body = format!(r#"{{"operands":["{ka}","{kb}"]}}"#);
    request(
        &srv.addr,
        "POST",
        &compose_uri(ns, "g2"),
        &[("Content-Type", "application/json")],
        compose_body.as_bytes(),
    );
    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &meta_list_uri(ns, "object-type", "composition"),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("sha256:"),
        "composition in metadata list: {text}"
    );

    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &meta_list_uri(ns, "object-type", "witness"),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("sha256:"), "witness in metadata list: {text}");
}

#[test]
fn type_metadata_edge() {
    let srv = TestServer::start();
    let ns = "l5-meta-edge";
    let src = push_blob(&srv.addr, ns, b"meta-edge-src");
    let tgt = push_blob(&srv.addr, ns, b"meta-edge-tgt");
    let edge_body =
        format!(r#"{{"source":"{src}","relation":"owns","target":"{tgt}","metadata":{{}}}}"#);
    request(
        &srv.addr,
        "PUT",
        &edge_put_uri(ns),
        &[("Content-Type", "application/json")],
        edge_body.as_bytes(),
    );
    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &meta_list_uri(ns, "object-type", "edge"),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("sha256:"), "edge in metadata list: {text}");
}

#[test]
fn rate_limit_triggers_429() {
    // burst=3: first 3 read requests succeed, 4th returns 429.
    // Use /v2/ns/tags/list (Read class) -- /v2/ is Exempt.
    let srv = TestServer::start_with_rate_limit(500, 3);
    let path = "/v2/rl-test/tags/list";
    for i in 1..=3 {
        let (s, _, _) = request(&srv.addr, "GET", path, &[], b"");
        assert_eq!(s, 200, "request {i} succeeds within burst");
    }
    let (s4, hdrs, _) = request(&srv.addr, "GET", path, &[], b"");
    assert_eq!(s4, 429, "request beyond burst returns 429");
    assert!(
        header(&hdrs, "retry-after").is_some(),
        "429 includes retry-after"
    );
    assert_eq!(
        header(&hdrs, "x-ratelimit-remaining"),
        Some("0"),
        "remaining is 0 when rate limited"
    );
    // Version check is exempt -- still works while read bucket is drained
    let (sv, _, _) = request(&srv.addr, "GET", "/v2/", &[], b"");
    assert_eq!(sv, 200, "exempt endpoint unaffected by read limit");
}

#[test]
fn rate_limit_headers_present() {
    let srv = TestServer::start_with_rate_limit(500, 5);
    let path = "/v2/rl-test/tags/list";
    let (status, hdrs, _) = request(&srv.addr, "GET", path, &[], b"");
    assert_eq!(status, 200);
    let limit = header(&hdrs, "x-ratelimit-limit");
    let remaining = header(&hdrs, "x-ratelimit-remaining");
    assert_eq!(limit, Some("5"), "x-ratelimit-limit matches burst size");
    assert_eq!(
        remaining,
        Some("4"),
        "remaining is burst - 1 after first request"
    );
}

#[test]
fn rate_limit_recovers_after_wait() {
    // period_ms=100, burst=2: drain in 2 requests, refill 1 per 100ms
    let srv = TestServer::start_with_rate_limit(100, 2);
    let path = "/v2/rl-test/tags/list";
    let (s1, _, _) = request(&srv.addr, "GET", path, &[], b"");
    assert_eq!(s1, 200);
    let (s2, _, _) = request(&srv.addr, "GET", path, &[], b"");
    assert_eq!(s2, 200);
    let (s3, hdrs, _) = request(&srv.addr, "GET", path, &[], b"");
    assert_eq!(s3, 429, "burst exhausted");
    // Read retry-after to know when to retry
    let wait = header(&hdrs, "retry-after")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    // Wait for refill: at least the retry-after value + margin
    std::thread::sleep(std::time::Duration::from_millis((wait * 1000) + 200));
    let (s4, hdrs4, _) = request(&srv.addr, "GET", path, &[], b"");
    assert_eq!(s4, 200, "request succeeds after refill");
    assert!(
        header(&hdrs4, "x-ratelimit-remaining").is_some(),
        "recovered response has remaining header"
    );
}

#[test]
fn type_metadata_pin() {
    let srv = TestServer::start();
    let ns = "l5-meta-pin";
    let kappa = push_blob(&srv.addr, ns, b"pinnable content");
    let pin_body = format!(r#"{{"kappa":"{kappa}","ttl":0,"controller":""}}"#);
    request(
        &srv.addr,
        "POST",
        &gc_pin_uri(ns),
        &[("Content-Type", "application/json")],
        pin_body.as_bytes(),
    );
    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &meta_list_uri(ns, "object-type", "pin"),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("sha256:"), "pin in metadata list: {text}");
}

#[test]
fn type_metadata_filter() {
    let srv = TestServer::start();
    let ns = "l5-meta-filter";
    request(
        &srv.addr,
        "PUT",
        &filter_put_uri(ns, "meta-scope"),
        &[("Content-Type", "application/json")],
        b"deny:BLOCKED",
    );
    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &meta_list_uri(ns, "object-type", "filter"),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("sha256:"), "filter in metadata list: {text}");
}

#[test]
fn type_metadata_schema() {
    let srv = TestServer::start();
    let ns = "l5-meta-schema";
    let schema = br#"{"scope":"meta","format":"json-schema","validation":{"type":"object"}}"#;
    request(
        &srv.addr,
        "PUT",
        &schema_uri(ns, "meta-scope"),
        &[("Content-Type", "application/json")],
        schema,
    );
    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &meta_list_uri(ns, "object-type", "schema"),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("sha256:"), "schema in metadata list: {text}");
}
