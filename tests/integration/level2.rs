use super::common::*;

#[test]
fn tag_bind_resolve_delete() {
    let srv = TestServer::start();
    let ns = "l2-tags";
    let content = br#"{"type":"manifest"}"#;

    // PUT manifest binds tag
    let (status, hdrs, _) = request(&srv.addr, "PUT", &manifest_uri(ns, "v1.0"), &[], content);
    assert_eq!(status, 201);
    let kappa = header(&hdrs, "x-kappa-label").unwrap().to_string();
    assert!(kappa.starts_with("sha256:"));

    // GET manifest resolves tag
    let (status, hdrs, body) = request(&srv.addr, "GET", &manifest_uri(ns, "v1.0"), &[], b"");
    assert_eq!(status, 200);
    assert_eq!(body, content);
    assert_eq!(header(&hdrs, "x-kappa-label"), Some(kappa.as_str()));

    // GET absent tag
    let (status, _, _) = request(&srv.addr, "GET", &manifest_uri(ns, "nonexistent"), &[], b"");
    assert_eq!(status, 404);

    // DELETE tag
    let (status, _, _) = request(&srv.addr, "DELETE", &manifest_uri(ns, "v1.0"), &[], b"");
    assert_eq!(status, 202);

    // GET after delete
    let (status, _, _) = request(&srv.addr, "GET", &manifest_uri(ns, "v1.0"), &[], b"");
    assert_eq!(status, 404);

    // Content survives tag deletion
    let (status, _, _) = request(&srv.addr, "GET", &blob_uri(ns, &kappa), &[], b"");
    assert_eq!(status, 200, "content survives tag deletion");
}

#[test]
fn tag_list_ordered() {
    let srv = TestServer::start();
    let ns = "l2-list";
    for tag in ["charlie", "alpha", "bravo"] {
        let content = format!("content-{tag}");
        request(
            &srv.addr,
            "PUT",
            &manifest_uri(ns, tag),
            &[],
            content.as_bytes(),
        );
    }
    let (status, _, body) = request(&srv.addr, "GET", &tag_list_uri(ns), &[], b"");
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    let alpha_pos = text.find("alpha").unwrap();
    let bravo_pos = text.find("bravo").unwrap();
    let charlie_pos = text.find("charlie").unwrap();
    assert!(
        alpha_pos < bravo_pos && bravo_pos < charlie_pos,
        "ASCIIbetical order"
    );
}

#[test]
fn tag_list_pagination() {
    let srv = TestServer::start();
    let ns = "l2-page";
    for tag in ["a", "b", "c", "d"] {
        let content = format!("page-{tag}");
        request(
            &srv.addr,
            "PUT",
            &manifest_uri(ns, tag),
            &[],
            content.as_bytes(),
        );
    }

    // n=2 returns 2 tags + Link
    let (status, hdrs, body) = request(&srv.addr, "GET", &tag_list_uri_params(ns, "n=2"), &[], b"");
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("\"a\"") || text.contains("\"name\":\"a\""));
    assert!(header(&hdrs, "link").is_some(), "more pages need Link");

    // n=0 returns empty, no Link
    let (status, hdrs, body) = request(&srv.addr, "GET", &tag_list_uri_params(ns, "n=0"), &[], b"");
    assert_eq!(status, 200);
    assert!(header(&hdrs, "link").is_none(), "n=0 has no Link");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("\"tags\":[]"), "n=0 empty tags: {text}");
}

#[test]
fn direct_tag_bind_and_resolve() {
    let srv = TestServer::start();
    let ns = "l2-direct";
    let kappa = push_blob(&srv.addr, ns, b"direct tag content");

    // PUT /tags/{name}?kappa={k} (A12)
    let (status, hdrs, _) = request(
        &srv.addr,
        "PUT",
        &tag_put_uri(ns, "direct-tag", &kappa),
        &[],
        b"",
    );
    assert_eq!(status, 201);
    assert_eq!(header(&hdrs, "x-kappa-label"), Some(kappa.as_str()));

    // GET /tags/{name} (A13)
    let (status, hdrs, body) = request(&srv.addr, "GET", &tag_uri(ns, "direct-tag"), &[], b"");
    assert_eq!(status, 200);
    assert_eq!(header(&hdrs, "x-kappa-label"), Some(kappa.as_str()));
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains(&kappa));

    // Absent tag resolution
    let (status, _, _) = request(&srv.addr, "GET", &tag_uri(ns, "no-such-tag"), &[], b"");
    assert_eq!(status, 404);
}

#[test]
fn content_before_tag() {
    let srv = TestServer::start();
    let ns = "l2-cbt";
    // PUT /tags/ with a kappa that was never stored
    let (status, _, body) = request(
        &srv.addr,
        "PUT",
        &tag_put_uri(ns, "should-fail", &absent_kappa()),
        &[],
        b"",
    );
    assert_eq!(status, 404);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("TAG_CONTENT_ABSENT"), "body: {text}");
}

#[test]
fn cas_if_match() {
    let srv = TestServer::start();
    let ns = "l2-cas";
    let k1 = push_blob(&srv.addr, ns, b"version one");
    let k2 = push_blob(&srv.addr, ns, b"version two");

    // Bind tag to k1
    request(&srv.addr, "PUT", &tag_put_uri(ns, "cas-tag", &k1), &[], b"");

    // CAS success: If-Match k1, set to k2
    let (status, _, _) = request(
        &srv.addr,
        "PUT",
        &tag_put_uri(ns, "cas-tag", &k2),
        &[("If-Match", &k1)],
        b"",
    );
    assert!(status == 200 || status == 201, "CAS success: {status}");

    // CAS failure: If-Match with wrong expected
    let (status, _, _) = request(
        &srv.addr,
        "PUT",
        &tag_put_uri(ns, "cas-tag", &k1),
        &[("If-Match", &absent_kappa())],
        b"",
    );
    assert!(status == 409 || status == 412, "CAS conflict: {status}");

    // If-None-Match:* on existing tag
    let (status, _, _) = request(
        &srv.addr,
        "PUT",
        &tag_put_uri(ns, "cas-tag", &k1),
        &[("If-None-Match", "*")],
        b"",
    );
    assert!(status == 409 || status == 412, "tag exists: {status}");

    // If-None-Match:* on new tag
    let (status, _, _) = request(
        &srv.addr,
        "PUT",
        &tag_put_uri(ns, "cas-new", &k1),
        &[("If-None-Match", "*")],
        b"",
    );
    assert_eq!(status, 201, "CAS create new: {status}");
}

#[test]
fn two_tags_same_kappa() {
    let srv = TestServer::start();
    let ns = "l2-same-k";
    let content = br#"{"shared":"content"}"#;
    request(&srv.addr, "PUT", &manifest_uri(ns, "tag-a"), &[], content);
    request(&srv.addr, "PUT", &manifest_uri(ns, "tag-b"), &[], content);
    let (_, h1, _) = request(&srv.addr, "GET", &manifest_uri(ns, "tag-a"), &[], b"");
    let (_, h2, _) = request(&srv.addr, "GET", &manifest_uri(ns, "tag-b"), &[], b"");
    assert_eq!(
        header(&h1, "x-kappa-label"),
        header(&h2, "x-kappa-label"),
        "two tags over same content resolve to same kappa"
    );
}

#[test]
fn resolve_by_direct_kappa() {
    let srv = TestServer::start();
    let ns = "l2-direct-k";
    let content = br#"{"direct":"resolve"}"#;
    let (_, hdrs, _) = request(&srv.addr, "PUT", &manifest_uri(ns, "named"), &[], content);
    let kappa = header(&hdrs, "x-kappa-label").unwrap().to_string();
    let (status, _, body) = request(&srv.addr, "GET", &manifest_uri(ns, &kappa), &[], b"");
    assert_eq!(status, 200);
    assert_eq!(body, content, "direct kappa resolve bypasses tags");
}

#[test]
fn tag_list_timestamp_range() {
    let srv = TestServer::start();
    let ns = "l2-ts";
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "2026-07-20T00:00:00"),
        &[],
        b"ts1",
    );
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "2026-07-20T12:00:00"),
        &[],
        b"ts2",
    );
    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &tag_list_uri_params(ns, "after=2026-07-19T23:00:00&before=2026-07-20T06:00:00"),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("2026-07-20T00:00:00"), "T00 in range: {text}");
    assert!(
        !text.contains("2026-07-20T12:00:00"),
        "T12 not in range: {text}"
    );
}

#[test]
fn tag_list_descending() {
    let srv = TestServer::start();
    let ns = "l2-desc";
    for tag in ["alpha", "bravo", "charlie"] {
        request(
            &srv.addr,
            "PUT",
            &manifest_uri(ns, tag),
            &[],
            format!("d-{tag}").as_bytes(),
        );
    }
    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &tag_list_uri_params(ns, "order=desc"),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    let c_pos = text.find("charlie").unwrap();
    let b_pos = text.find("bravo").unwrap();
    let a_pos = text.find("alpha").unwrap();
    assert!(c_pos < b_pos && b_pos < a_pos, "descending order: {text}");
}
