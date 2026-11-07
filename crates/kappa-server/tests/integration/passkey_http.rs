//! Integration tests for the /passkey/ routes (prism/identity/1), through
//! the real server binary: register a first key, bind a second, read both,
//! revoke one; plus the CORS policy and namespace isolation.

mod helpers;
#[allow(unused_imports)]
use helpers::*;

use kappa_module_passkey::testing::Authenticator;
use kappa_module_passkey::webauthn::Assertion;

const ORIGIN: &str = "http://localhost:8790";

fn passkey_server() -> (ServerGuard, String, tempfile::TempDir) {
    start_server_with_env(&[("KAPPA_PASSKEY_ORIGINS", ORIGIN)])
}

fn challenge(c: &reqwest::blocking::Client, base: &str) -> String {
    let resp = c
        .post(format!("{base}/passkey/challenge"))
        .send()
        .unwrap_or_else(|e| panic!("challenge request failed: {e}"));
    assert_eq!(resp.status(), 200, "challenge: {:?}", resp.text());
    let body: serde_json::Value = resp
        .json()
        .unwrap_or_else(|e| panic!("challenge JSON: {e}"));
    body["challenge"]
        .as_str()
        .unwrap_or_else(|| panic!("no challenge in {body}"))
        .to_string()
}

fn post(
    c: &reqwest::blocking::Client,
    url: String,
    body: &serde_json::Value,
) -> (u16, serde_json::Value) {
    let resp = c
        .post(url)
        .header("content-type", "application/json")
        .header("origin", ORIGIN)
        .body(body.to_string())
        .send()
        .unwrap_or_else(|e| panic!("POST failed: {e}"));
    let status = resp.status().as_u16();
    let text = resp.text().unwrap_or_else(|e| panic!("read body: {e}"));
    let json = serde_json::from_str(&text).unwrap_or_else(|e| panic!("body {text:?}: {e}"));
    (status, json)
}

fn get(c: &reqwest::blocking::Client, url: String) -> (u16, serde_json::Value, Option<String>) {
    let resp = c
        .get(url)
        .send()
        .unwrap_or_else(|e| panic!("GET failed: {e}"));
    let status = resp.status().as_u16();
    let allow = resp.headers().get("access-control-allow-origin").map(|v| {
        v.to_str()
            .unwrap_or_else(|e| panic!("header: {e}"))
            .to_string()
    });
    let text = resp.text().unwrap_or_else(|e| panic!("read body: {e}"));
    let json = serde_json::from_str(&text).unwrap_or_else(|e| panic!("body {text:?}: {e}"));
    (status, json, allow)
}

fn with_binding(
    mut body: serde_json::Value,
    account: &str,
    assertion: &Assertion,
) -> serde_json::Value {
    let mut binding = serde_json::to_value(assertion).unwrap_or_else(|e| panic!("assertion: {e}"));
    binding["account"] = serde_json::Value::String(account.to_string());
    body["binding"] = binding;
    body
}

#[test]
fn register_bind_read_and_revoke() {
    let (_guard, base, _tmp) = passkey_server();
    let c = client();
    let first = Authenticator::p256();
    let second = Authenticator::p256();

    let (status, created) = post(
        &c,
        format!("{base}/passkey/register"),
        &first.register(&challenge(&c, &base), ORIGIN, |_| {}),
    );
    assert_eq!(status, 201, "register first: {created}");
    let account = first.key();
    assert_eq!(created["key"], account);
    assert_eq!(created["account"], account);

    let bind = first.assert(
        &format!("prism/identity/bind/1\n{account}\n{}", second.key()),
        ORIGIN,
        |_| {},
    );
    let body = with_binding(
        second.register(&challenge(&c, &base), ORIGIN, |_| {}),
        &account,
        &bind,
    );
    let (status, bound) = post(&c, format!("{base}/passkey/register"), &body);
    assert_eq!(status, 201, "bind second: {bound}");
    assert_eq!(bound["account"], account);

    for auth in [&first, &second] {
        let (status, record, allow) = get(
            &c,
            format!("{base}/passkey/credential/{}", auth.credential_id()),
        );
        assert_eq!(status, 200, "credential lookup: {record}");
        assert_eq!(record["key"], auth.key());
        assert_eq!(record["account"], account);
        assert_eq!(record["spec"], "prism/identity/key/1");
        assert_eq!(allow.as_deref(), Some("*"));
    }

    let (status, listing, _) = get(&c, format!("{base}/passkey/account/{account}"));
    assert_eq!(status, 200, "account: {listing}");
    assert_eq!(
        listing["keys"].as_array().map(Vec::len),
        Some(2),
        "{listing}"
    );

    let revoke = first.assert(
        &format!("prism/identity/revoke/1\n{account}\n{}", second.key()),
        ORIGIN,
        |_| {},
    );
    let body = serde_json::json!({ "account": account, "key": second.key(), "assertion": revoke });
    let (status, revoked) = post(&c, format!("{base}/passkey/revoke"), &body);
    assert_eq!(status, 200, "revoke: {revoked}");
    assert_eq!(revoked["revoked"], true);

    let (status, gone, _) = get(
        &c,
        format!("{base}/passkey/credential/{}", second.credential_id()),
    );
    assert_eq!(status, 410, "revoked lookup: {gone}");
    assert_eq!(gone["error"], "revoked");

    // The same challenge cannot register twice.
    let used = challenge(&c, &base);
    let (status, _) = post(
        &c,
        format!("{base}/passkey/register"),
        &Authenticator::p256().register(&used, ORIGIN, |_| {}),
    );
    assert_eq!(status, 201);
    let (status, replay) = post(
        &c,
        format!("{base}/passkey/register"),
        &Authenticator::p256().register(&used, ORIGIN, |_| {}),
    );
    assert_eq!(status, 400, "replay: {replay}");
    assert_eq!(replay["error"], "challenge");
}

#[test]
fn writes_allow_only_identity_origins() {
    let (_guard, base, _tmp) = passkey_server();
    let c = client();
    let preflight = |origin: &str| {
        c.request(reqwest::Method::OPTIONS, format!("{base}/passkey/register"))
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .send()
            .unwrap_or_else(|e| panic!("preflight failed: {e}"))
    };
    let allowed = preflight(ORIGIN);
    assert_eq!(allowed.status(), 204);
    assert_eq!(
        allowed
            .headers()
            .get("access-control-allow-origin")
            .map(|v| v.as_bytes()),
        Some(ORIGIN.as_bytes())
    );
    let refused = preflight("https://evil.example");
    assert_eq!(refused.status(), 204);
    assert!(refused
        .headers()
        .get("access-control-allow-origin")
        .is_none());

    // A browser write from any other origin is refused before the handler.
    let resp = c
        .post(format!("{base}/passkey/challenge"))
        .header("origin", "https://evil.example")
        .send()
        .unwrap_or_else(|e| panic!("POST failed: {e}"));
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().unwrap_or_else(|e| panic!("JSON: {e}"));
    assert_eq!(body["error"], "origin");
}

#[test]
fn the_generic_api_cannot_write_passkey_records() {
    let (_guard, base, _tmp) = passkey_server();
    let c = client();
    let resp = c
        .put(format!(
            "{base}/v2/kappa/identity/passkey/tags/credential?kappa=sha256:00"
        ))
        .send()
        .unwrap_or_else(|e| panic!("PUT failed: {e}"));
    let status = resp.status().as_u16();
    assert_eq!(
        status,
        403,
        "generic write to the passkey namespace: {:?}",
        resp.text()
    );
}

#[test]
fn unknown_lookups_are_typed() {
    let (_guard, base, _tmp) = passkey_server();
    let c = client();
    let missing = Authenticator::p256();
    let (status, body, _) = get(
        &c,
        format!("{base}/passkey/credential/{}", missing.credential_id()),
    );
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["error"], "credential");
    let (status, body, _) = get(&c, format!("{base}/passkey/account/{}", missing.key()));
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["error"], "account");
}
