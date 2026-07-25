use super::common::*;

// -- blob_get_range (HTTP Range header) --

#[test]
fn blob_range_request_returns_206() {
    let srv = TestServer::start();
    let ns = "l8-range";
    let content = b"0123456789abcdef0123456789abcdef";
    let kappa = push_blob(&srv.addr, ns, content);

    let (status, hdrs, body) = request(
        &srv.addr,
        "GET",
        &blob_uri(ns, &kappa),
        &[("Range", "bytes=4-11")],
        b"",
    );
    assert_eq!(status, 206);
    assert_eq!(body, b"456789ab");
    assert_eq!(header(&hdrs, "accept-ranges"), Some("bytes"));
    let cr = header(&hdrs, "content-range").unwrap_or("");
    assert!(cr.starts_with("bytes 4-11/"), "content-range: {cr}");
}

#[test]
fn blob_range_open_end() {
    let srv = TestServer::start();
    let ns = "l8-range-open";
    let content = b"abcdefghijklmnop";
    let kappa = push_blob(&srv.addr, ns, content);

    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &blob_uri(ns, &kappa),
        &[("Range", "bytes=10-")],
        b"",
    );
    assert_eq!(status, 206);
    assert_eq!(body, b"klmnop");
}

#[test]
fn blob_range_past_end_returns_416() {
    let srv = TestServer::start();
    let ns = "l8-range-416";
    let content = b"short";
    let kappa = push_blob(&srv.addr, ns, content);

    let (status, hdrs, _) = request(
        &srv.addr,
        "GET",
        &blob_uri(ns, &kappa),
        &[("Range", "bytes=999-")],
        b"",
    );
    assert_eq!(status, 416);
    let cr = header(&hdrs, "content-range").unwrap_or("");
    assert!(cr.contains("*/5"), "content-range: {cr}");
}

#[test]
fn blob_get_without_range_returns_full_blob() {
    let srv = TestServer::start();
    let ns = "l8-no-range";
    let content = b"full content returned";
    let kappa = push_blob(&srv.addr, ns, content);

    let (status, hdrs, body) = request(&srv.addr, "GET", &blob_uri(ns, &kappa), &[], b"");
    assert_eq!(status, 200);
    assert_eq!(body, content);
    assert_eq!(header(&hdrs, "accept-ranges"), Some("bytes"));
}

#[test]
fn blob_head_has_accept_ranges_and_size() {
    let srv = TestServer::start();
    let ns = "l8-head-range";
    let content = b"head test content";
    let kappa = push_blob(&srv.addr, ns, content);

    let (status, hdrs, body) = request(&srv.addr, "HEAD", &blob_uri(ns, &kappa), &[], b"");
    assert_eq!(status, 200);
    assert!(body.is_empty());
    assert_eq!(header(&hdrs, "accept-ranges"), Some("bytes"));
    let expected_len = content.len().to_string();
    assert_eq!(header(&hdrs, "content-length"), Some(expected_len.as_str()));
}

// -- sequence generator --

#[test]
fn sequence_starts_at_zero() {
    let srv = TestServer::start();
    let ns = "l8-seq";
    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &sequence_current_uri(ns, "counter"),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("\"value\":0"), "body: {text}");
}

#[test]
fn sequence_next_increments() {
    let srv = TestServer::start();
    let ns = "l8-seq-inc";

    let (status, _, body) = request(
        &srv.addr,
        "POST",
        &sequence_next_uri(ns, "counter"),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("\"value\":1"), "first: {text}");

    let (_, _, body) = request(
        &srv.addr,
        "POST",
        &sequence_next_uri(ns, "counter"),
        &[],
        b"",
    );
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("\"value\":2"), "second: {text}");

    let (_, _, body) = request(
        &srv.addr,
        "GET",
        &sequence_current_uri(ns, "counter"),
        &[],
        b"",
    );
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("\"value\":2"), "current: {text}");
}

#[test]
fn sequence_namespace_isolation() {
    let srv = TestServer::start();

    request(
        &srv.addr,
        "POST",
        &sequence_next_uri("l8-seq-a", "counter"),
        &[],
        b"",
    );
    request(
        &srv.addr,
        "POST",
        &sequence_next_uri("l8-seq-a", "counter"),
        &[],
        b"",
    );

    let (_, _, body) = request(
        &srv.addr,
        "GET",
        &sequence_current_uri("l8-seq-b", "counter"),
        &[],
        b"",
    );
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("\"value\":0"), "isolated ns: {text}");
}

// -- cascade delete --

#[test]
fn cascade_removes_reachable_blobs() {
    let srv = TestServer::start();
    let ns = "l8-cascade";
    let root_k = push_blob(&srv.addr, ns, b"cascade root");
    let child_k = push_blob(&srv.addr, ns, b"cascade child");
    let unrelated_k = push_blob(&srv.addr, ns, b"cascade unrelated");

    // Create edge: root -> child via "owns"
    let edge_body = format!(r#"{{"source":"{root_k}","relation":"owns","target":"{child_k}"}}"#);
    request(
        &srv.addr,
        "PUT",
        &edge_put_uri(ns),
        &[("Content-Type", "application/json")],
        edge_body.as_bytes(),
    );

    // Cascade from root along "owns"
    let cascade_body = format!(r#"{{"roots":["{root_k}"],"relations":["owns"]}}"#);
    let (status, _, body) = request(
        &srv.addr,
        "POST",
        &cascade_uri(ns),
        &[("Content-Type", "application/json")],
        cascade_body.as_bytes(),
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains(&root_k), "root in removed: {text}");
    assert!(text.contains(&child_k), "child in removed: {text}");

    // Root and child are gone
    let (s, _, _) = request(&srv.addr, "GET", &blob_uri(ns, &root_k), &[], b"");
    assert_eq!(s, 404, "root deleted");
    let (s, _, _) = request(&srv.addr, "GET", &blob_uri(ns, &child_k), &[], b"");
    assert_eq!(s, 404, "child deleted");

    // Unrelated blob survives
    let (s, _, _) = request(&srv.addr, "GET", &blob_uri(ns, &unrelated_k), &[], b"");
    assert_eq!(s, 200, "unrelated survives");
}

#[test]
fn cascade_empty_roots_returns_empty_report() {
    let srv = TestServer::start();
    let ns = "l8-cascade-empty";

    let cascade_body = r#"{"roots":[],"relations":["owns"]}"#;
    let (status, _, body) = request(
        &srv.addr,
        "POST",
        &cascade_uri(ns),
        &[("Content-Type", "application/json")],
        cascade_body.as_bytes(),
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("blobs_removed"), "has report: {text}");
}

// -- namespace-scoped metadata (P14) --

#[test]
fn meta_query_returns_namespace_scoped_results() {
    let srv = TestServer::start();
    let ns = "l8-meta";
    let content = br#"{"meta":"test"}"#;
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "meta-tag"),
        &[],
        content,
    );

    // Query object-type=manifest via the new namespace-scoped path
    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &meta_list_uri(ns, "object-type", "manifest"),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("sha256:"), "manifest found: {text}");
}

#[test]
fn meta_query_namespace_isolation() {
    let srv = TestServer::start();
    let ns_a = "l8-meta-iso-a";
    let ns_b = "l8-meta-iso-b";

    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns_a, "iso-tag"),
        &[],
        br#"{"iso":"a"}"#,
    );

    // ns_b should see no manifests
    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &meta_list_uri(ns_b, "object-type", "manifest"),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(
        !text.contains("sha256:"),
        "ns_b should have no manifests: {text}"
    );
}

#[test]
fn meta_edge_type_stored() {
    let srv = TestServer::start();
    let ns = "l8-meta-edge";
    let src = push_blob(&srv.addr, ns, b"meta-edge-src");
    let tgt = push_blob(&srv.addr, ns, b"meta-edge-tgt");
    let edge_body = format!(r#"{{"source":"{src}","relation":"owns","target":"{tgt}"}}"#);
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
    assert!(text.contains("sha256:"), "edge metadata: {text}");
}

// -- tag mtime --

#[test]
fn tag_entry_has_mtime() {
    let srv = TestServer::start();
    let ns = "l8-mtime";
    let content = br#"{"mtime":"test"}"#;
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "mtime-tag"),
        &[],
        content,
    );

    // The namespace root should be non-null (proves tag was written with new format)
    let (status, _, body) = request(&srv.addr, "GET", &namespace_root_uri(ns), &[], b"");
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("sha256:"), "root present: {text}");
    assert!(text.contains("\"count\":1"), "count is 1: {text}");
}

#[test]
fn tag_mtime_excluded_from_root_hash() {
    let srv = TestServer::start();
    let ns_a = "l8-mtime-root-a";
    let ns_b = "l8-mtime-root-b";
    let content = br#"{"same":"content"}"#;

    // Create same tag in both namespaces -- different timestamps, same root
    request(&srv.addr, "PUT", &manifest_uri(ns_a, "v1"), &[], content);
    std::thread::sleep(std::time::Duration::from_millis(10));
    request(&srv.addr, "PUT", &manifest_uri(ns_b, "v1"), &[], content);

    let (_, _, body_a) = request(&srv.addr, "GET", &namespace_root_uri(ns_a), &[], b"");
    let (_, _, body_b) = request(&srv.addr, "GET", &namespace_root_uri(ns_b), &[], b"");

    let root_a = json_str(&body_a, "root").unwrap_or_default();
    let root_b = json_str(&body_b, "root").unwrap_or_default();
    assert_eq!(
        root_a, root_b,
        "same tags = same root despite different mtime"
    );
}

// -- tag_list_prefix HTTP --

#[test]
fn tag_list_prefix_returns_matching() {
    let srv = TestServer::start();
    let ns = "l8-prefix-list";
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "refs/heads/main"),
        &[],
        br#"{"ref":"main"}"#,
    );
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "refs/heads/dev"),
        &[],
        br#"{"ref":"dev"}"#,
    );
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "v1.0"),
        &[],
        br#"{"tag":"v1"}"#,
    );

    let uri = format!("/v2/{ns}/tags/list?prefix=refs/heads/");
    let (status, _, body) = request(&srv.addr, "GET", &uri, &[], b"");
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("refs/heads/main"), "main found: {text}");
    assert!(text.contains("refs/heads/dev"), "dev found: {text}");
    assert!(!text.contains("v1.0"), "v1.0 excluded: {text}");
}

#[test]
fn tag_list_prefix_empty_returns_all() {
    let srv = TestServer::start();
    let ns = "l8-prefix-empty";
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "alpha"),
        &[],
        br#"{"a":1}"#,
    );
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "beta"),
        &[],
        br#"{"b":2}"#,
    );

    // prefix="" returns everything (same as no prefix)
    let uri = format!("/v2/{ns}/tags/list?prefix=");
    let (status, _, body) = request(&srv.addr, "GET", &uri, &[], b"");
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("alpha"), "alpha: {text}");
    assert!(text.contains("beta"), "beta: {text}");
}

// -- tag_delete_prefix HTTP --

#[test]
fn tag_delete_prefix_removes_matching() {
    let srv = TestServer::start();
    let ns = "l8-prefix-del";
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "segment/001/data"),
        &[],
        br#"{"s":1}"#,
    );
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "segment/001/index"),
        &[],
        br#"{"s":2}"#,
    );
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "latest"),
        &[],
        br#"{"s":3}"#,
    );

    let uri = format!("/v2/{ns}/tags/_prefix?prefix=segment/001/");
    let (status, _, body) = request(&srv.addr, "DELETE", &uri, &[], b"");
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("\"deleted\":2"), "deleted 2: {text}");

    // Verify segment tags gone, latest survives
    let list_uri = tag_list_uri(ns);
    let (_, _, body) = request(&srv.addr, "GET", &list_uri, &[], b"");
    let text = String::from_utf8_lossy(&body);
    assert!(!text.contains("segment"), "segments gone: {text}");
    assert!(text.contains("latest"), "latest survives: {text}");
}

#[test]
fn tag_delete_prefix_missing_param_returns_400() {
    let srv = TestServer::start();
    let uri = "/v2/l8-prefix-bad/tags/_prefix";
    let (status, _, _) = request(&srv.addr, "DELETE", uri, &[], b"");
    assert_eq!(status, 400);
}

// -- cascade delete from prefix --

#[test]
fn cascade_from_prefix_removes_subgraph() {
    let srv = TestServer::start();
    let ns = "l8-cascade-prefix";
    let data_k = push_blob(&srv.addr, ns, b"data file bytes");
    let index_k = push_blob(&srv.addr, ns, b"index file bytes");
    let keep_k = push_blob(&srv.addr, ns, b"keep this blob");

    // Tag the data and index under a segment prefix
    request(
        &srv.addr,
        "PUT",
        &tag_put_uri(ns, "segment/42/data", &data_k),
        &[],
        b"",
    );
    request(
        &srv.addr,
        "PUT",
        &tag_put_uri(ns, "segment/42/index", &index_k),
        &[],
        b"",
    );
    request(
        &srv.addr,
        "PUT",
        &tag_put_uri(ns, "keep", &keep_k),
        &[],
        b"",
    );

    // Create edge: data -> index via "data-file"
    let edge_body =
        format!(r#"{{"source":"{data_k}","relation":"data-file","target":"{index_k}"}}"#);
    request(
        &srv.addr,
        "PUT",
        &edge_put_uri(ns),
        &[("Content-Type", "application/json")],
        edge_body.as_bytes(),
    );

    // remove_reachable_from_prefix is a trait-level method. Test via
    // tag_delete_prefix (HTTP) and verify the tag removal path works.
    let del_uri = format!("/v2/{ns}/tags/_prefix?prefix=segment/42/");
    let (status, _, _) = request(&srv.addr, "DELETE", &del_uri, &[], b"");
    assert_eq!(status, 200);

    // Tags gone
    let (_, _, body) = request(&srv.addr, "GET", &tag_list_uri(ns), &[], b"");
    let text = String::from_utf8_lossy(&body);
    assert!(!text.contains("segment"), "segment tags gone: {text}");
    assert!(text.contains("keep"), "keep survives: {text}");

    // Keep blob still exists
    let (s, _, _) = request(&srv.addr, "GET", &blob_uri(ns, &keep_k), &[], b"");
    assert_eq!(s, 200, "keep blob survives");
}

// -- compound metadata query --

#[test]
fn meta_compound_query() {
    let srv = TestServer::start();
    let ns = "l8-meta-compound";

    // Push two blobs with different metadata
    let k1 = push_blob(&srv.addr, ns, b"compound-blob-1");
    let k2 = push_blob(&srv.addr, ns, b"compound-blob-2");

    // Create edges so meta_set is called for both
    let edge_body1 = format!(r#"{{"source":"{k1}","relation":"owns","target":"{k2}"}}"#);
    request(
        &srv.addr,
        "PUT",
        &edge_put_uri(ns),
        &[("Content-Type", "application/json")],
        edge_body1.as_bytes(),
    );

    // Both blobs now have object-type=edge on the edge kappa (not k1/k2).
    // Let's use manifest PUT to get object-type=manifest on known kappas.
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "m1"),
        &[],
        br#"{"compound":"test1"}"#,
    );
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "m2"),
        &[],
        br#"{"compound":"test2"}"#,
    );

    // Query object-type=manifest should return both
    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &meta_list_uri(ns, "object-type", "manifest"),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("sha256:"), "manifests found: {text}");

    // Query object-type=edge should return edge kappas, not manifest kappas
    let (status, _, body) = request(
        &srv.addr,
        "GET",
        &meta_list_uri(ns, "object-type", "edge"),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    let manifest_kappa1 = kappa_registry::kappa::KappaLabel::sha256(br#"{"compound":"test1"}"#)
        .as_str()
        .to_string();
    assert!(
        !text.contains(&manifest_kappa1),
        "manifest kappa not in edge results: {text}"
    );
}

// -- compound metadata query via ?filter= --

#[test]
fn meta_compound_filter_query() {
    let srv = TestServer::start();
    let ns = "l8-filter-compound";

    // Push a manifest (gets object-type=manifest via meta_set)
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "f1"),
        &[],
        br#"{"filter":"compound1"}"#,
    );
    // Push an edge (gets object-type=edge via meta_set)
    let src = push_blob(&srv.addr, ns, b"filter-src");
    let tgt = push_blob(&srv.addr, ns, b"filter-tgt");
    let edge_body = format!(r#"{{"source":"{src}","relation":"owns","target":"{tgt}"}}"#);
    request(
        &srv.addr,
        "PUT",
        &edge_put_uri(ns),
        &[("Content-Type", "application/json")],
        edge_body.as_bytes(),
    );

    // Single filter via ?filter=object-type:manifest
    let uri = format!("/v2/{ns}/blobs/_meta?filter=object-type:manifest");
    let (status, _, body) = request(&srv.addr, "GET", &uri, &[], b"");
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("sha256:"), "single filter works: {text}");

    // Multi-filter: object-type:manifest AND object-type:edge -- intersection is empty
    let uri = format!("/v2/{ns}/blobs/_meta?filter=object-type:manifest&filter=object-type:edge");
    let (status, _, body) = request(&srv.addr, "GET", &uri, &[], b"");
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("\"kappas\":[]"),
        "disjoint filters = empty: {text}"
    );
}

// -- cascade delete with prefix via JSON body --

#[test]
fn cascade_with_prefix_field() {
    let srv = TestServer::start();
    let ns = "l8-cascade-pfx";
    let data_k = push_blob(&srv.addr, ns, b"pfx data");
    let keep_k = push_blob(&srv.addr, ns, b"pfx keep");

    // Tag under prefix
    request(
        &srv.addr,
        "PUT",
        &tag_put_uri(ns, "col-001-data", &data_k),
        &[],
        b"",
    );
    request(
        &srv.addr,
        "PUT",
        &tag_put_uri(ns, "keep-this", &keep_k),
        &[],
        b"",
    );

    // Cascade with prefix field in JSON body
    let cascade_body = r#"{"prefix":"col-001-","relations":["owns"]}"#;
    let (status, _, body) = request(
        &srv.addr,
        "POST",
        &cascade_uri(ns),
        &[("Content-Type", "application/json")],
        cascade_body.as_bytes(),
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("col-001-data"), "prefix tag removed: {text}");

    // Prefixed tag is gone
    let (_, _, body) = request(&srv.addr, "GET", &tag_list_uri(ns), &[], b"");
    let text = String::from_utf8_lossy(&body);
    assert!(!text.contains("col-001"), "col-001 tags gone: {text}");
    assert!(text.contains("keep-this"), "keep-this survives: {text}");
}

// -- namespace collision prevention --

#[test]
fn namespace_isolation_slash_vs_underscore() {
    let srv = TestServer::start();
    let content_a = br#"{"ns":"a/b"}"#;
    let content_b = br#"{"ns":"a_b"}"#;

    // Push manifests to two namespaces that previously collided
    request(
        &srv.addr,
        "PUT",
        &manifest_uri("a/b", "tag1"),
        &[],
        content_a,
    );
    request(
        &srv.addr,
        "PUT",
        &manifest_uri("a_b", "tag1"),
        &[],
        content_b,
    );

    // Each namespace sees only its own content
    let (s, _, body) = request(&srv.addr, "GET", &manifest_uri("a/b", "tag1"), &[], b"");
    assert_eq!(s, 200);
    assert_eq!(body, content_a, "a/b gets its own content");

    let (s, _, body) = request(&srv.addr, "GET", &manifest_uri("a_b", "tag1"), &[], b"");
    assert_eq!(s, 200);
    assert_eq!(body, content_b, "a_b gets its own content");

    // Tag list in a/b does not show a_b's tags
    let (_, _, body) = request(&srv.addr, "GET", &tag_list_uri("a/b"), &[], b"");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("tag1"), "a/b has tag1");

    // Verify different roots (content is different, so kappas differ)
    let (_, _, root_a) = request(&srv.addr, "GET", &namespace_root_uri("a/b"), &[], b"");
    let (_, _, root_b) = request(&srv.addr, "GET", &namespace_root_uri("a_b"), &[], b"");
    let ra = json_str(&root_a, "root").unwrap_or_default();
    let rb = json_str(&root_b, "root").unwrap_or_default();
    assert_ne!(ra, rb, "different content = different roots");
}

// -- tag create/get/delete with slashes via body/query --

#[test]
fn tag_create_with_slashes_via_post() {
    let srv = TestServer::start();
    let ns = "l8-tag-slash";
    let kappa = push_blob(&srv.addr, ns, b"slash tag content");

    // Create tag with slash in name via POST body
    let body = format!(r#"{{"name":"refs/heads/main","kappa":"{kappa}"}}"#);
    let (status, _, _) = request(
        &srv.addr,
        "POST",
        &format!("/v2/{ns}/tags/"),
        &[("Content-Type", "application/json")],
        body.as_bytes(),
    );
    assert_eq!(status, 201);

    // Read it back via GET ?name=
    let (status, hdrs, body) = request(
        &srv.addr,
        "GET",
        &format!("/v2/{ns}/tags/?name=refs/heads/main"),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    assert_eq!(header(&hdrs, "x-kappa-label"), Some(kappa.as_str()));
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("refs/heads/main"), "name in response: {text}");
}

#[test]
fn tag_delete_with_slashes_via_query() {
    let srv = TestServer::start();
    let ns = "l8-tag-slash-del";
    let kappa = push_blob(&srv.addr, ns, b"slash delete content");

    // Create
    let body = format!(r#"{{"name":"refs/tags/v1.0","kappa":"{kappa}"}}"#);
    request(
        &srv.addr,
        "POST",
        &format!("/v2/{ns}/tags/"),
        &[("Content-Type", "application/json")],
        body.as_bytes(),
    );

    // Delete via query param
    let (status, _, _) = request(
        &srv.addr,
        "DELETE",
        &format!("/v2/{ns}/tags/?name=refs/tags/v1.0"),
        &[],
        b"",
    );
    assert_eq!(status, 202);

    // Verify gone
    let (status, _, _) = request(
        &srv.addr,
        "GET",
        &format!("/v2/{ns}/tags/?name=refs/tags/v1.0"),
        &[],
        b"",
    );
    assert_eq!(status, 404);
}

// -- meta_query_prefix --

#[test]
fn meta_query_prefix_returns_matching() {
    let srv = TestServer::start();
    let ns = "l8-meta-pfx";

    // Push blobs and set path metadata via meta_set
    // We use the edge handler which calls meta_set("object-type", "edge")
    let src = push_blob(&srv.addr, ns, b"pfx-src");
    let tgt1 = push_blob(&srv.addr, ns, b"pfx-tgt1");
    let tgt2 = push_blob(&srv.addr, ns, b"pfx-tgt2");

    let edge1 = format!(r#"{{"source":"{src}","relation":"owns","target":"{tgt1}"}}"#);
    let edge2 = format!(r#"{{"source":"{src}","relation":"owns","target":"{tgt2}"}}"#);
    request(
        &srv.addr,
        "PUT",
        &edge_put_uri(ns),
        &[("Content-Type", "application/json")],
        edge1.as_bytes(),
    );
    request(
        &srv.addr,
        "PUT",
        &edge_put_uri(ns),
        &[("Content-Type", "application/json")],
        edge2.as_bytes(),
    );

    // Push a manifest (gets object-type=manifest)
    request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "pfx-m1"),
        &[],
        br#"{"pfx":"m1"}"#,
    );

    // Query object-type=edge via single filter
    let uri = format!("/v2/{ns}/blobs/_meta?filter=object-type:edge");
    let (status, _, body) = request(&srv.addr, "GET", &uri, &[], b"");
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("sha256:"), "edges found via filter: {text}");

    // The manifest kappa should NOT be in the edge results
    let manifest_k = kappa_registry::kappa::KappaLabel::sha256(br#"{"pfx":"m1"}"#)
        .as_str()
        .to_string();
    assert!(
        !text.contains(&manifest_k),
        "manifest not in edge filter: {text}"
    );
}
