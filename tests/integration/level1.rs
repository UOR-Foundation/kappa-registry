use super::common::*;

#[test]
fn version_check() {
    let srv = TestServer::start();
    let (status, _, body) = request(&srv.addr, "GET", version_uri(), &[], b"");
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("kappa-distribution"), "body: {text}");
}

#[test]
fn health_probes() {
    let srv = TestServer::start();
    for probe in ["live", "ready", "startup"] {
        let (status, _, _) = request(&srv.addr, "GET", &health_uri(probe), &[], b"");
        assert_eq!(status, 200, "probe {probe}");
    }
}

#[test]
fn blob_put_get_head_delete() {
    let srv = TestServer::start();
    let ns = "l1-crud";
    let blobs = test_blobs();
    let hello = blob(&blobs, "hello");

    let (status, hdrs, _) = request(&srv.addr, "PUT", &hello.blob_path(ns), &[], hello.content);
    assert_eq!(status, 201);
    assert_eq!(header(&hdrs, "x-kappa-label"), Some(hello.sha256.as_str()));

    let (status, _, _) = request(&srv.addr, "PUT", &hello.blob_path(ns), &[], hello.content);
    assert_eq!(status, 200, "idempotent re-PUT");

    let (status, hdrs, body) = request(&srv.addr, "GET", &hello.blob_path(ns), &[], b"");
    assert_eq!(status, 200);
    assert_eq!(body, hello.content);
    assert_eq!(header(&hdrs, "x-kappa-label"), Some(hello.sha256.as_str()));
    assert_eq!(header(&hdrs, "x-kappa-axis"), Some("sha256"));

    let (status, hdrs, body) = request(&srv.addr, "HEAD", &hello.blob_path(ns), &[], b"");
    assert_eq!(status, 200);
    assert!(body.is_empty(), "HEAD has no body");
    assert_eq!(header(&hdrs, "x-kappa-label"), Some(hello.sha256.as_str()));

    let (status, _, _) = request(&srv.addr, "GET", &blob_uri(ns, &absent_kappa()), &[], b"");
    assert_eq!(status, 404);

    let (status, _, _) = request(&srv.addr, "DELETE", &hello.blob_path(ns), &[], b"");
    assert_eq!(status, 202);

    let (status, _, _) = request(&srv.addr, "GET", &hello.blob_path(ns), &[], b"");
    assert_eq!(status, 404, "deleted blob gone");
}

#[test]
fn blob_verify_on_put_rejects_mismatch() {
    let srv = TestServer::start();
    let (status, _, body) = request(
        &srv.addr,
        "PUT",
        &blob_uri("l1-verify", &absent_kappa()),
        &[],
        b"actual content",
    );
    assert_eq!(status, 400);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("DIGEST_INVALID"), "body: {text}");
}

#[test]
fn blob_exact_bytes_preserved() {
    let srv = TestServer::start();
    let ns = "l1-exact";
    let blobs = test_blobs();
    let uf = blob(&blobs, "unknown_fields");
    request(&srv.addr, "PUT", &uf.blob_path(ns), &[], uf.content);
    let (_, _, body) = request(&srv.addr, "GET", &uf.blob_path(ns), &[], b"");
    assert_eq!(body, uf.content, "exact bytes preserved");
}

#[test]
fn blob_empty() {
    let srv = TestServer::start();
    let ns = "l1-empty";
    let blobs = test_blobs();
    let empty = blob(&blobs, "empty");
    let (status, _, _) = request(&srv.addr, "PUT", &empty.blob_path(ns), &[], empty.content);
    assert!(status == 201 || status == 200);
    let (status, _, body) = request(&srv.addr, "GET", &empty.blob_path(ns), &[], b"");
    assert_eq!(status, 200);
    assert!(body.is_empty());
}

#[test]
fn content_type_round_trip() {
    let srv = TestServer::start();
    let ns = "l1-ct";
    let blobs = test_blobs();
    let jb = blob(&blobs, "json_ct");
    request(
        &srv.addr,
        "PUT",
        &jb.blob_path(ns),
        &[("Content-Type", "application/json")],
        jb.content,
    );
    let (_, hdrs, _) = request(&srv.addr, "GET", &jb.blob_path(ns), &[], b"");
    let ct = header(&hdrs, "content-type").unwrap_or("");
    assert!(ct.contains("application/json"), "ct echoed: {ct}");
}

#[test]
fn content_type_default_octet_stream() {
    let srv = TestServer::start();
    let ns = "l1-noct";
    let blobs = test_blobs();
    let nc = blob(&blobs, "no_content_type");
    request(&srv.addr, "PUT", &nc.blob_path(ns), &[], nc.content);
    let (_, hdrs, _) = request(&srv.addr, "GET", &nc.blob_path(ns), &[], b"");
    let ct = header(&hdrs, "content-type").unwrap_or("application/octet-stream");
    assert!(
        ct.contains("octet-stream"),
        "expected octet-stream default, got: {ct}"
    );
}

#[test]
fn chunked_upload_and_cancel() {
    let srv = TestServer::start();
    let ns = "l1-upload";
    let content = b"assembled from two chunks";
    let kappa = push_blob(&srv.addr, "l1-upload-dummy", b"dummy"); // just to test push_blob helper
    let _ = kappa;

    let full_kappa = kappa_registry::kappa::KappaLabel::sha256(content)
        .as_str()
        .to_string();
    let (c1, c2) = content.split_at(10);

    // Start session
    let (status, hdrs, _) = request(&srv.addr, "POST", &upload_start_uri(ns), &[], b"");
    assert_eq!(status, 202);
    let loc = header(&hdrs, "location").unwrap().to_string();

    // Chunk 1
    let (status, _, _) = request(&srv.addr, "PATCH", &loc, &[("Content-Range", "0-9")], c1);
    assert_eq!(status, 202);

    // Out-of-order chunk
    let (status, _, _) = request(
        &srv.addr,
        "PATCH",
        &loc,
        &[("Content-Range", "99-108")],
        b"xxxxxxxxxx",
    );
    assert_eq!(status, 416, "out-of-order chunk should be 416");

    // Recovery
    let (status, hdrs, _) = request(&srv.addr, "GET", &loc, &[], b"");
    assert_eq!(status, 204);
    assert!(header(&hdrs, "range").is_some());

    // Chunk 2
    let range2 = format!("{}-{}", c1.len(), content.len() - 1);
    let (status, _, _) = request(&srv.addr, "PATCH", &loc, &[("Content-Range", &range2)], c2);
    assert_eq!(status, 202);

    // Complete
    let complete = format!("{loc}?kappa={full_kappa}");
    let (status, hdrs, _) = request(&srv.addr, "PUT", &complete, &[], b"");
    assert_eq!(status, 201);
    assert_eq!(header(&hdrs, "x-kappa-label"), Some(full_kappa.as_str()));

    // Verify blob is retrievable
    let (status, _, body) = request(&srv.addr, "GET", &blob_uri(ns, &full_kappa), &[], b"");
    assert_eq!(status, 200);
    assert_eq!(body, content);

    // Cancel a different session
    let (_, hdrs2, _) = request(&srv.addr, "POST", &upload_start_uri(ns), &[], b"");
    let loc2 = header(&hdrs2, "location").unwrap().to_string();
    let (status, _, _) = request(&srv.addr, "DELETE", &loc2, &[], b"");
    assert_eq!(status, 204);
    let (status, _, _) = request(&srv.addr, "GET", &loc2, &[], b"");
    assert_eq!(status, 404, "cancelled session gone");
}

#[test]
fn mount_existing_blob() {
    let srv = TestServer::start();
    let ns = "l1-mount";
    let kappa = push_blob(&srv.addr, ns, b"mount me");
    let (status, hdrs, _) = request(
        &srv.addr,
        "POST",
        &upload_start_mount_uri(ns, &kappa),
        &[],
        b"",
    );
    assert_eq!(status, 201, "mount existing returns 201");
    let loc = header(&hdrs, "location").unwrap_or("");
    assert!(loc.contains(&kappa));
}

#[test]
fn mount_absent_falls_back() {
    let srv = TestServer::start();
    let (status, hdrs, _) = request(
        &srv.addr,
        "POST",
        &upload_start_mount_uri("l1-mount-absent", &absent_kappa()),
        &[],
        b"",
    );
    assert_eq!(status, 202, "mount absent falls back to upload");
    assert!(header(&hdrs, "location").unwrap_or("").contains("_uploads"));
}

#[test]
fn multi_blob_push() {
    let srv = TestServer::start();
    let ns = "l1-multi";
    let blobs = test_blobs();
    for b in &blobs {
        let (status, _, _) = request(&srv.addr, "PUT", &b.blob_path(ns), &[], b.content);
        assert!(
            status == 201 || status == 200,
            "push {} failed: {status}",
            b.name
        );
    }
    for b in &blobs {
        let (status, _, body) = request(&srv.addr, "GET", &b.blob_path(ns), &[], b"");
        assert_eq!(status, 200, "get {} failed", b.name);
        assert_eq!(body, b.content, "exact bytes for {}", b.name);
    }
}

#[test]
fn multi_label_push() {
    let srv = TestServer::start();
    let ns = "l1-also";
    let content = b"multi-label content";
    let sha_k = kappa_registry::kappa::KappaLabel::sha256(content)
        .as_str()
        .to_string();
    let blake_k = kappa_registry::kappa::KappaLabel::blake3(content)
        .as_str()
        .to_string();
    let path = format!("{}?also={blake_k}", blob_uri(ns, &sha_k));

    let (status, hdrs, _) = request(&srv.addr, "PUT", &path, &[], content);
    assert_eq!(status, 201);
    assert_eq!(header(&hdrs, "x-kappa-label"), Some(sha_k.as_str()));

    // Both kappas resolve
    let (status, _, body) = request(&srv.addr, "GET", &blob_uri(ns, &sha_k), &[], b"");
    assert_eq!(status, 200);
    assert_eq!(body, content);
    let (status, _, body) = request(&srv.addr, "GET", &blob_uri(ns, &blake_k), &[], b"");
    assert_eq!(status, 200);
    assert_eq!(body, content);
}

#[test]
fn multi_label_bad_also_rejected() {
    let srv = TestServer::start();
    let ns = "l1-bad-also";
    let content = b"multi-label reject test";
    let sha_k = kappa_registry::kappa::KappaLabel::sha256(content)
        .as_str()
        .to_string();
    let bad_also = absent_kappa();
    let path = format!("{}?also={bad_also}", blob_uri(ns, &sha_k));

    let (status, _, _) = request(&srv.addr, "PUT", &path, &[], content);
    assert_eq!(status, 400, "bad also kappa rejected");
}
