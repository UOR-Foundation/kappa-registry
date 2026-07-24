use super::common::*;

#[test]
fn compose_g2_commutative() {
    let srv = TestServer::start();
    let ns = "l4-g2";
    let ka = push_blob(&srv.addr, ns, b"operand alpha");
    let kb = push_blob(&srv.addr, ns, b"operand beta");

    let body_ab = format!(r#"{{"operands":["{ka}","{kb}"]}}"#);
    let (status, _, resp) = request(
        &srv.addr,
        "POST",
        &compose_uri(ns, "g2"),
        &[("Content-Type", "application/json")],
        body_ab.as_bytes(),
    );
    assert_eq!(status, 200);
    let composed_ab = json_str(&resp, "composed").unwrap();
    let witness = json_str(&resp, "witness").unwrap();
    let op = json_str(&resp, "operation").unwrap();
    assert_eq!(op, "g2");
    assert!(composed_ab.starts_with("sha256:"));
    assert!(witness.starts_with("sha256:"));

    // Reversed operands produce same composed kappa (commutativity)
    let body_ba = format!(r#"{{"operands":["{kb}","{ka}"]}}"#);
    let (status, _, resp) = request(
        &srv.addr,
        "POST",
        &compose_uri(ns, "g2"),
        &[("Content-Type", "application/json")],
        body_ba.as_bytes(),
    );
    assert_eq!(status, 200);
    let composed_ba = json_str(&resp, "composed").unwrap();
    assert_eq!(composed_ab, composed_ba, "g2 is commutative");

    // Composed blob is retrievable
    let (status, _, _) = request(&srv.addr, "GET", &blob_uri(ns, &composed_ab), &[], b"");
    assert_eq!(status, 200);
}

#[test]
fn compose_axis_mismatch() {
    let srv = TestServer::start();
    let ns = "l4-axis";
    let ka = push_blob(&srv.addr, ns, b"sha256 operand");
    // Construct a blake3 kappa for the same content
    let kb = kappa_registry::kappa::KappaLabel::blake3(b"blake3 operand")
        .as_str()
        .to_string();
    push_blob_with_kappa(&srv.addr, ns, &kb, b"blake3 operand");

    let body = format!(r#"{{"operands":["{ka}","{kb}"]}}"#);
    let (status, _, resp) = request(
        &srv.addr,
        "POST",
        &compose_uri(ns, "g2"),
        &[("Content-Type", "application/json")],
        body.as_bytes(),
    );
    assert_eq!(status, 422);
    let text = String::from_utf8_lossy(&resp);
    assert!(text.contains("AXIS_MISMATCH"), "body: {text}");
}

#[test]
fn witness_retrievable() {
    let srv = TestServer::start();
    let ns = "l4-wit";
    let ka = push_blob(&srv.addr, ns, b"witness operand");

    let body = format!(r#"{{"operands":["{ka}"]}}"#);
    let (status, _, resp) = request(
        &srv.addr,
        "POST",
        &compose_uri(ns, "e8"),
        &[("Content-Type", "application/json")],
        body.as_bytes(),
    );
    assert_eq!(status, 200);
    let composed = json_str(&resp, "composed").unwrap();

    let (status, hdrs, body) = request(&srv.addr, "GET", &witness_uri(ns, &composed), &[], b"");
    assert_eq!(status, 200);
    assert!(header(&hdrs, "x-kappa-label").is_some());
    // Witness header: label_width=71, fp_width=32
    assert!(body.len() >= 4);
    let lw = u16::from_le_bytes([body[0], body[1]]);
    let fw = u16::from_le_bytes([body[2], body[3]]);
    assert_eq!(lw, 71);
    assert_eq!(fw, 32);
}

#[test]
fn schema_register_get_list() {
    let srv = TestServer::start();
    let ns = "l4-schema";
    let schema = br#"{"scope":"test","format":"json-schema","validation":{"type":"object"}}"#;

    let (status, hdrs, _) = request(
        &srv.addr,
        "PUT",
        &schema_uri(ns, "test-scope"),
        &[("Content-Type", "application/json")],
        schema,
    );
    assert_eq!(status, 201);
    let sk = header(&hdrs, "x-kappa-label").unwrap().to_string();

    let (status, hdrs, body) = request(&srv.addr, "GET", &schema_uri(ns, "test-scope"), &[], b"");
    assert_eq!(status, 200);
    assert_eq!(header(&hdrs, "x-kappa-label"), Some(sk.as_str()));
    assert_eq!(body, schema);

    let (status, _, body) = request(&srv.addr, "GET", &schema_list_uri(ns), &[], b"");
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("test-scope"), "schema in list: {text}");
}

#[test]
fn f4_mirror_collapse() {
    let srv = TestServer::start();
    let ns = "l4-f4";
    let ka = push_blob(&srv.addr, ns, b"f4 operand");

    let body1 = format!(r#"{{"operands":["{ka}"]}}"#);
    let (status, _, resp1) = request(
        &srv.addr,
        "POST",
        &compose_uri(ns, "f4"),
        &[("Content-Type", "application/json")],
        body1.as_bytes(),
    );
    assert_eq!(status, 200);
    let f4_kappa = json_str(&resp1, "composed").unwrap();

    let ka_parsed = kappa_registry::kappa::KappaLabel::parse(&ka).unwrap();
    let complement = ka_parsed.complement();
    let comp_k = complement.as_str().to_string();
    push_blob_with_kappa(&srv.addr, ns, &comp_k, b"f4 operand");

    let body2 = format!(r#"{{"operands":["{comp_k}"]}}"#);
    let (status, _, resp2) = request(
        &srv.addr,
        "POST",
        &compose_uri(ns, "f4"),
        &[("Content-Type", "application/json")],
        body2.as_bytes(),
    );
    assert_eq!(status, 200);
    let f4_mirror = json_str(&resp2, "composed").unwrap();
    assert_eq!(f4_kappa, f4_mirror, "f4 mirror collapse");
}

#[test]
fn schema_does_not_alter_kappa() {
    let srv = TestServer::start();
    let ns = "l4-schema-id";
    let content = br#"{"name":"valid"}"#;
    let expected = kappa_registry::kappa::KappaLabel::sha256(content)
        .as_str()
        .to_string();

    // Push same content to a namespace with no schema
    push_blob(&srv.addr, "l4-noscope", content);

    // Push via manifest to a namespace (schema may or may not exist)
    let (_, hdrs, _) = request(
        &srv.addr,
        "PUT",
        &manifest_uri(ns, "schema-pass"),
        &[],
        content,
    );
    let scoped_k = header(&hdrs, "x-kappa-label").unwrap();
    assert_eq!(scoped_k, expected, "schema does not alter kappa");
}
