use super::common::*;

// ── Multi-Object Transactions (P3) ──────────────────────────────────────

#[test]
fn transaction_begin_put_commit() {
    let srv = TestServer::start();
    let ns = "l6-txn";

    // Begin
    let (status, _, resp) = request(&srv.addr, "POST", &transaction_begin_uri(ns), &[], b"");
    assert_eq!(status, 201);
    let v: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    let txn_id = v["transaction_id"].as_str().unwrap().to_string();
    assert!(!txn_id.is_empty());

    // Put two blobs into the transaction
    let content_a = b"txn-blob-alpha";
    let kappa_a = kappa_registry::kappa::KappaLabel::sha256(content_a)
        .as_str()
        .to_string();
    let (status, _, _) = request(
        &srv.addr,
        "PUT",
        &transaction_put_uri(ns, &txn_id, &kappa_a),
        &[],
        content_a,
    );
    assert_eq!(status, 201);

    let content_b = b"txn-blob-beta";
    let kappa_b = kappa_registry::kappa::KappaLabel::sha256(content_b)
        .as_str()
        .to_string();
    let (status, _, _) = request(
        &srv.addr,
        "PUT",
        &transaction_put_uri(ns, &txn_id, &kappa_b),
        &[],
        content_b,
    );
    assert_eq!(status, 201);

    // Blobs should NOT be visible in the main store yet
    let (status, _, _) = request(&srv.addr, "GET", &blob_uri(ns, &kappa_a), &[], b"");
    assert_eq!(status, 404, "staged blob should not be in main store");

    // Commit
    let (status, _, resp) = request(
        &srv.addr,
        "POST",
        &transaction_commit_uri(ns, &txn_id),
        &[],
        b"",
    );
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    let promoted = v["promoted"].as_array().unwrap();
    assert_eq!(promoted.len(), 2, "both blobs promoted");

    // Blobs should now be visible in the main store
    let (status, _, body) = request(&srv.addr, "GET", &blob_uri(ns, &kappa_a), &[], b"");
    assert_eq!(status, 200);
    assert_eq!(body, content_a);

    let (status, _, body) = request(&srv.addr, "GET", &blob_uri(ns, &kappa_b), &[], b"");
    assert_eq!(status, 200);
    assert_eq!(body, content_b);
}

#[test]
fn transaction_abort_discards() {
    let srv = TestServer::start();
    let ns = "l6-txn-abort";

    let (status, _, resp) = request(&srv.addr, "POST", &transaction_begin_uri(ns), &[], b"");
    assert_eq!(status, 201);
    let v: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    let txn_id = v["transaction_id"].as_str().unwrap().to_string();

    let content = b"abort-me";
    let kappa = kappa_registry::kappa::KappaLabel::sha256(content)
        .as_str()
        .to_string();
    request(
        &srv.addr,
        "PUT",
        &transaction_put_uri(ns, &txn_id, &kappa),
        &[],
        content,
    );

    // Abort
    let (status, _, _) = request(
        &srv.addr,
        "DELETE",
        &transaction_abort_uri(ns, &txn_id),
        &[],
        b"",
    );
    assert_eq!(status, 204);

    // Blob should not exist in main store
    let (status, _, _) = request(&srv.addr, "GET", &blob_uri(ns, &kappa), &[], b"");
    assert_eq!(status, 404, "aborted blob should not be in main store");

    // Committing the aborted transaction should fail
    let (status, _, _) = request(
        &srv.addr,
        "POST",
        &transaction_commit_uri(ns, &txn_id),
        &[],
        b"",
    );
    assert_eq!(status, 404, "aborted transaction should not be committable");
}

#[test]
fn transaction_put_verifies_digest() {
    let srv = TestServer::start();
    let ns = "l6-txn-verify";

    let (_, _, resp) = request(&srv.addr, "POST", &transaction_begin_uri(ns), &[], b"");
    let v: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    let txn_id = v["transaction_id"].as_str().unwrap().to_string();

    // Put with wrong kappa
    let wrong_kappa = format!("sha256:{}", "0".repeat(64));
    let (status, _, _) = request(
        &srv.addr,
        "PUT",
        &transaction_put_uri(ns, &txn_id, &wrong_kappa),
        &[],
        b"actual content",
    );
    assert!(
        status == 409 || status == 400,
        "wrong digest should be rejected: {status}"
    );
}

#[test]
fn transaction_idempotent_put() {
    let srv = TestServer::start();
    let ns = "l6-txn-idem";

    let (_, _, resp) = request(&srv.addr, "POST", &transaction_begin_uri(ns), &[], b"");
    let v: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    let txn_id = v["transaction_id"].as_str().unwrap().to_string();

    let content = b"idempotent-blob";
    let kappa = kappa_registry::kappa::KappaLabel::sha256(content)
        .as_str()
        .to_string();

    let (status1, _, _) = request(
        &srv.addr,
        "PUT",
        &transaction_put_uri(ns, &txn_id, &kappa),
        &[],
        content,
    );
    assert_eq!(status1, 201);

    let (status2, _, _) = request(
        &srv.addr,
        "PUT",
        &transaction_put_uri(ns, &txn_id, &kappa),
        &[],
        content,
    );
    assert_eq!(status2, 200, "idempotent re-put returns 200");
}

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

// ── Bundle Bulk Transfer (P8) ────────────────────────────────────────────

#[test]
fn bundle_create_and_ingest() {
    let srv = TestServer::start();
    let ns = "l6-bundle";

    // Push blobs to the source namespace
    let ka = push_blob(&srv.addr, ns, b"bundle-alpha");
    let kb = push_blob(&srv.addr, ns, b"bundle-beta");
    let kc = push_blob(&srv.addr, ns, b"bundle-gamma");

    // Create bundle
    let create_body = format!(r#"{{"kappas":["{ka}","{kb}","{kc}"],"delta":false}}"#);
    let (status, hdrs, bundle_bytes) = request(
        &srv.addr,
        "POST",
        &bundle_create_uri(ns),
        &[("Content-Type", "application/json")],
        create_body.as_bytes(),
    );
    assert_eq!(status, 200);
    assert_eq!(
        header(&hdrs, "content-type"),
        Some("application/x-kappa-bundle")
    );
    assert!(!bundle_bytes.is_empty(), "bundle is not empty");
    // Verify KBND magic
    assert_eq!(&bundle_bytes[..4], b"KBND", "bundle has KBND magic");

    // Delete the blobs from the source
    request(&srv.addr, "DELETE", &blob_uri(ns, &ka), &[], b"");
    request(&srv.addr, "DELETE", &blob_uri(ns, &kb), &[], b"");
    request(&srv.addr, "DELETE", &blob_uri(ns, &kc), &[], b"");

    // Verify they are gone
    let (status, _, _) = request(&srv.addr, "GET", &blob_uri(ns, &ka), &[], b"");
    assert_eq!(status, 404, "blob deleted before ingest");

    // Ingest the bundle
    let (status, _, resp) = request(
        &srv.addr,
        "POST",
        &bundle_ingest_uri(ns),
        &[("Content-Type", "application/x-kappa-bundle")],
        &bundle_bytes,
    );
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    let ingested = v["ingested"].as_array().unwrap();
    assert_eq!(ingested.len(), 3, "all 3 blobs ingested");

    // Verify blobs are back
    let (status, _, body) = request(&srv.addr, "GET", &blob_uri(ns, &ka), &[], b"");
    assert_eq!(status, 200);
    assert_eq!(body, b"bundle-alpha");

    let (status, _, body) = request(&srv.addr, "GET", &blob_uri(ns, &kb), &[], b"");
    assert_eq!(status, 200);
    assert_eq!(body, b"bundle-beta");

    let (status, _, body) = request(&srv.addr, "GET", &blob_uri(ns, &kc), &[], b"");
    assert_eq!(status, 200);
    assert_eq!(body, b"bundle-gamma");
}

#[test]
fn bundle_ingest_rejects_corrupted() {
    let srv = TestServer::start();
    let ns = "l6-bundle-corrupt";

    let ka = push_blob(&srv.addr, ns, b"corrupt-test");
    let create_body = format!(r#"{{"kappas":["{ka}"],"delta":false}}"#);
    let (_, _, mut bundle) = request(
        &srv.addr,
        "POST",
        &bundle_create_uri(ns),
        &[("Content-Type", "application/json")],
        create_body.as_bytes(),
    );

    // Corrupt the trailer
    let last = bundle.len() - 1;
    bundle[last] ^= 0xFF;

    let (status, _, _) = request(
        &srv.addr,
        "POST",
        &bundle_ingest_uri(ns),
        &[("Content-Type", "application/x-kappa-bundle")],
        &bundle,
    );
    assert!(
        status == 409 || status == 400,
        "corrupted bundle rejected: {status}"
    );
}

#[test]
fn bundle_create_with_delta() {
    let srv = TestServer::start();
    let ns = "l6-bundle-delta";

    // Large similar blobs: 200+ lines each, differing by a few lines.
    // Delta compression needs content large enough for 16-byte block
    // matching to find significant overlap.
    let mut base_lines = Vec::new();
    for i in 0..100 {
        base_lines.push(format!("line-{i:04}-base-padding-content-here\n"));
    }
    let base_str = base_lines.join("");
    let base = base_str.as_bytes();

    let mut var1_lines = base_lines.clone();
    var1_lines[10] = "line-0010-MODIFIED-variant-one!!\n".to_string();
    var1_lines[50] = "line-0050-MODIFIED-variant-one!!\n".to_string();
    let var1_str = var1_lines.join("");
    let var1 = var1_str.as_bytes();

    let mut var2_lines = base_lines.clone();
    var2_lines[20] = "line-0020-CHANGED-variant-two!!\n".to_string();
    var2_lines[80] = "line-0080-CHANGED-variant-two!!\n".to_string();
    let var2_str = var2_lines.join("");
    let var2 = var2_str.as_bytes();

    let kb = push_blob(&srv.addr, ns, base);
    let k1 = push_blob(&srv.addr, ns, var1);
    let k2 = push_blob(&srv.addr, ns, var2);

    let total_raw_size = base.len() + var1.len() + var2.len();

    // Create bundle with delta=true
    let create_body = format!(r#"{{"kappas":["{kb}","{k1}","{k2}"],"delta":true}}"#);
    let (status, hdrs, bundle_bytes) = request(
        &srv.addr,
        "POST",
        &bundle_create_uri(ns),
        &[("Content-Type", "application/json")],
        create_body.as_bytes(),
    );
    assert_eq!(status, 200);
    assert_eq!(
        header(&hdrs, "content-type"),
        Some("application/x-kappa-bundle")
    );
    assert_eq!(&bundle_bytes[..4], b"KBND");

    // Bundle with deltas should be smaller than raw content
    // (minus header/trailer overhead which is small)
    assert!(
        bundle_bytes.len() < total_raw_size,
        "delta bundle ({}) should be smaller than raw ({})",
        bundle_bytes.len(),
        total_raw_size,
    );

    // Delete originals
    request(&srv.addr, "DELETE", &blob_uri(ns, &kb), &[], b"");
    request(&srv.addr, "DELETE", &blob_uri(ns, &k1), &[], b"");
    request(&srv.addr, "DELETE", &blob_uri(ns, &k2), &[], b"");

    let (status, _, _) = request(&srv.addr, "GET", &blob_uri(ns, &kb), &[], b"");
    assert_eq!(status, 404, "blob deleted before ingest");

    // Ingest the delta bundle
    let (status, _, resp) = request(
        &srv.addr,
        "POST",
        &bundle_ingest_uri(ns),
        &[("Content-Type", "application/x-kappa-bundle")],
        &bundle_bytes,
    );
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    let ingested = v["ingested"].as_array().unwrap();
    assert_eq!(ingested.len(), 3, "all 3 blobs ingested from delta bundle");

    // Verify all blobs recovered with correct content
    let (status, _, body) = request(&srv.addr, "GET", &blob_uri(ns, &kb), &[], b"");
    assert_eq!(status, 200);
    assert_eq!(body, base);

    let (status, _, body) = request(&srv.addr, "GET", &blob_uri(ns, &k1), &[], b"");
    assert_eq!(status, 200);
    assert_eq!(body, var1);

    let (status, _, body) = request(&srv.addr, "GET", &blob_uri(ns, &k2), &[], b"");
    assert_eq!(status, 200);
    assert_eq!(body, var2);
}

#[test]
fn bundle_empty_kappas_rejected() {
    let srv = TestServer::start();
    let ns = "l6-bundle-empty";

    let (status, _, _) = request(
        &srv.addr,
        "POST",
        &bundle_create_uri(ns),
        &[("Content-Type", "application/json")],
        br#"{"kappas":[]}"#,
    );
    assert_eq!(status, 400, "empty kappas list rejected");
}
