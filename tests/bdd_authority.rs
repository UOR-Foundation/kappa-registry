//! Steps for the node authority interface: rotation and status, through the
//! real server over HTTP.

use cucumber::{then, when};
use http::StatusCode;

use super::BddWorld;

/// Bearer token of the configured root-token delegate.
pub const ROOT_TOKEN: &str = "bdd-root";

const GUARANTEES: [&str; 4] = ["custody", "key_removal", "authorization", "revocation"];

fn base(w: &BddWorld) -> String {
    w.app
        .as_ref()
        .expect("scenario must create an app")
        .base_url
        .clone()
}

async fn record(w: &mut BddWorld, response: reqwest::Response) {
    w.status = Some(response.status());
    w.content_type = response.headers().get("content-type").map(|value| {
        value
            .to_str()
            .expect("valid Content-Type header")
            .to_owned()
    });
    w.body = response.bytes().await.expect("read response").to_vec();
}

fn json(w: &BddWorld) -> serde_json::Value {
    serde_json::from_slice(&w.body).unwrap_or_else(|error| {
        panic!(
            "response is not JSON ({error}): {}",
            String::from_utf8_lossy(&w.body)
        )
    })
}

async fn read_status(w: &mut BddWorld, token: Option<&str>) {
    let mut request = reqwest::Client::new().get(format!("{}/_node/authority", base(w)));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    record(w, request.send().await.expect("authority status request")).await;
}

async fn rotate(w: &mut BddWorld, token: Option<&str>) {
    rotate_with(w, token, None).await;
}

async fn rotate_with(w: &mut BddWorld, token: Option<&str>, body: Option<String>) {
    let mut request = reqwest::Client::new().post(format!("{}/_node/authority/rotate", base(w)));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request
            .header("content-type", "application/json")
            .body(body);
    }
    record(w, request.send().await.expect("rotation request")).await;
}

/// Distinguishes the namespaces created by successive administration
/// checks in one test process.
static ADMINISTRATION: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[when("I read the node authority status as the root delegate")]
async fn status_as_root(w: &mut BddWorld) {
    read_status(w, Some(ROOT_TOKEN)).await;
}

#[then("the node signs with an active committed authority and every guarantee holds")]
fn startup_status(w: &mut BddWorld) {
    assert_eq!(
        w.status,
        Some(StatusCode::OK),
        "{}",
        String::from_utf8_lossy(&w.body)
    );
    let status = json(w);
    assert_eq!(status["availability"], "active", "{status}");
    assert_eq!(status["commit"], "known", "{status}");
    assert_eq!(status["retired"], serde_json::json!([]), "{status}");
    for guarantee in GUARANTEES {
        assert_eq!(
            status["completion"][guarantee], true,
            "{guarantee}: {status}"
        );
    }
    let current = status["current"]
        .as_str()
        .expect("current anchor")
        .to_owned();
    w.authorities = vec![current];
}

#[when("I rotate the node signing authority as the root delegate")]
async fn rotate_as_root(w: &mut BddWorld) {
    rotate(w, Some(ROOT_TOKEN)).await;
}

#[when("I rotate the node signing authority without credentials")]
async fn rotate_anonymously(w: &mut BddWorld) {
    rotate(w, None).await;
}

#[when(expr = "I rotate the node signing authority as the root delegate with the body {string}")]
async fn rotate_with_body(w: &mut BddWorld, body: String) {
    rotate_with(w, Some(ROOT_TOKEN), Some(body)).await;
}

#[then(expr = "the rotation is refused with status {int}")]
fn rotation_refused(w: &mut BddWorld, status: u16) {
    assert_eq!(
        w.status.map(|observed| observed.as_u16()),
        Some(status),
        "{}",
        String::from_utf8_lossy(&w.body)
    );
}

#[then("the rotation committed from the previous authority with every guarantee holding")]
fn rotation_committed(w: &mut BddWorld) {
    assert_eq!(
        w.status,
        Some(StatusCode::OK),
        "{}",
        String::from_utf8_lossy(&w.body)
    );
    let report = json(w);
    let previous = w.authorities.last().expect("an observed authority").clone();
    assert_eq!(report["retired"], previous.as_str(), "{report}");
    let current = report["current"]
        .as_str()
        .expect("current anchor")
        .to_owned();
    assert_ne!(current, previous, "{report}");
    for guarantee in GUARANTEES {
        assert_eq!(
            report["completion"][guarantee], true,
            "{guarantee}: {report}"
        );
    }
    w.authorities.push(current);
}

#[then("the status names the latest authority as active with every earlier one retired")]
fn status_after_rotation(w: &mut BddWorld) {
    assert_eq!(
        w.status,
        Some(StatusCode::OK),
        "{}",
        String::from_utf8_lossy(&w.body)
    );
    let status = json(w);
    let (latest, earlier) = w.authorities.split_last().expect("observed authorities");
    assert_eq!(status["current"], latest.as_str(), "{status}");
    assert_eq!(status["commit"], "known", "{status}");
    assert_eq!(status["availability"], "active", "{status}");
    assert_eq!(status["retired"], serde_json::json!(earlier), "{status}");
    for guarantee in GUARANTEES {
        assert_eq!(
            status["completion"][guarantee], true,
            "{guarantee}: {status}"
        );
    }
}

#[then("the node authority is unchanged")]
async fn authority_unchanged(w: &mut BddWorld) {
    read_status(w, Some(ROOT_TOKEN)).await;
    let status = json(w);
    let latest = w.authorities.last().expect("an observed authority");
    assert_eq!(status["current"], latest.as_str(), "{status}");
}

#[then("the registry reports ready")]
async fn ready(w: &mut BddWorld) {
    let response = reqwest::Client::new()
        .get(format!("{}/v2/_health/ready", base(w)))
        .send()
        .await
        .expect("readiness request");
    assert_eq!(response.status(), StatusCode::OK);
}

#[then("the root delegate can still administer the registry")]
async fn root_delegate_administers(w: &mut BddWorld) {
    let check = ADMINISTRATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let namespace = format!("bdd-authority-{}-{check}", w.authorities.len());
    let response = reqwest::Client::new()
        .post(format!("{}/v2/{namespace}/_namespace/create", base(w)))
        .bearer_auth(ROOT_TOKEN)
        .send()
        .await
        .expect("namespace creation");
    let status = response.status();
    let body = response.text().await.expect("namespace creation body");
    assert_eq!(status, StatusCode::CREATED, "{body}");
}
