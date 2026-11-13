//! Integration tests for the Prism mailbox (prism/identity/3), through the
//! real server binary: post opaque messages under a topic and read the
//! newest back, the identity-origin write policy, public reads and typed
//! failures.

mod helpers;
#[allow(unused_imports)]
use helpers::*;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

const ORIGIN: &str = "http://localhost:8790";
const TOPIC: &str = "prism-sync:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn mailbox_server() -> (ServerGuard, String, tempfile::TempDir) {
    start_server_with_env(&[("KAPPA_PASSKEY_ORIGINS", ORIGIN)])
}

fn post(
    c: &reqwest::blocking::Client,
    url: &str,
    origin: &str,
    message: &[u8],
) -> (u16, serde_json::Value) {
    let resp = c
        .post(url)
        .header("content-type", "application/octet-stream")
        .header("origin", origin)
        .body(message.to_vec())
        .send()
        .unwrap_or_else(|e| panic!("POST failed: {e}"));
    let status = resp.status().as_u16();
    let text = resp.text().unwrap_or_else(|e| panic!("read body: {e}"));
    let json = serde_json::from_str(&text).unwrap_or_else(|e| panic!("body {text:?}: {e}"));
    (status, json)
}

#[test]
fn messages_are_kept_once_and_read_by_anyone() {
    let (_guard, base, _tmp) = mailbox_server();
    let c = client();
    let url = format!("{base}/prism/topic/{TOPIC}");
    let (status, body) = post(&c, &url, ORIGIN, b"sealed one");
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["newly"], true);
    let (status, body) = post(&c, &url, ORIGIN, b"sealed two");
    assert_eq!(status, 201, "{body}");
    let (status, body) = post(&c, &url, ORIGIN, b"sealed one");
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["newly"], false);

    let resp = c
        .get(&url)
        .header("origin", "https://any.example")
        .send()
        .unwrap_or_else(|e| panic!("GET failed: {e}"));
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .map(|v| v.as_bytes()),
        Some(b"*".as_slice())
    );
    let text = resp.text().unwrap_or_else(|e| panic!("read body: {e}"));
    let body: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("body {text:?}: {e}"));
    assert_eq!(body["topic"], TOPIC);
    let expected = serde_json::json!([
        URL_SAFE_NO_PAD.encode(b"sealed one"),
        URL_SAFE_NO_PAD.encode(b"sealed two")
    ]);
    assert_eq!(body["messages"], expected, "{text}");
}

#[test]
fn browser_writes_come_only_from_identity_origins() {
    let (_guard, base, _tmp) = mailbox_server();
    let c = client();
    let url = format!("{base}/prism/topic/{TOPIC}");
    let preflight = c
        .request(reqwest::Method::OPTIONS, &url)
        .header("origin", ORIGIN)
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type")
        .send()
        .unwrap_or_else(|e| panic!("preflight failed: {e}"));
    assert_eq!(preflight.status(), 204);
    assert_eq!(
        preflight
            .headers()
            .get("access-control-allow-origin")
            .map(|v| v.as_bytes()),
        Some(ORIGIN.as_bytes())
    );
    let (status, body) = post(&c, &url, "https://evil.example", b"spam");
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"], "origin");
}

#[test]
fn unknown_topics_and_bad_names_are_typed() {
    let (_guard, base, _tmp) = mailbox_server();
    let c = client();
    let resp = c
        .get(format!("{base}/prism/topic/{TOPIC}"))
        .send()
        .unwrap_or_else(|e| panic!("GET failed: {e}"));
    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().unwrap_or_else(|e| panic!("JSON: {e}"));
    assert_eq!(body["error"], "topic");

    let (status, body) = post(&c, &format!("{base}/prism/topic/not-a-topic"), ORIGIN, b"m");
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "request");
}

#[test]
fn the_generic_api_cannot_write_the_mailbox() {
    let (_guard, base, _tmp) = mailbox_server();
    let c = client();
    let resp = c
        .put(format!(
            "{base}/v2/kappa/identity/prism/tags/topic?kappa=sha256:00"
        ))
        .send()
        .unwrap_or_else(|e| panic!("PUT failed: {e}"));
    let status = resp.status().as_u16();
    assert_eq!(
        status,
        403,
        "generic write to the mailbox namespace: {:?}",
        resp.text()
    );
}
