//! Post-handler validation. Logs warnings when OCI-required response
//! headers are missing from successful blob/manifest responses.
//! Does NOT modify or reject responses. Safety net for handler bugs.

use topcoat::context::{try_app_context, CxBuilder};
use topcoat::router::{Body, Method, Next, StatusCode};

use super::request_id::RequestId;

pub fn response_compliance_layer<'a>(
    cx: &'a mut CxBuilder,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let path = topcoat::router::uri(cx).path().to_owned();
        let method = topcoat::router::method(cx).clone();
        let rid = try_app_context::<RequestId>(cx)
            .map(|r| r.0.clone())
            .unwrap_or_default();

        let response = next.run(cx, body).await?;

        if response.status() == StatusCode::OK {
            let h = response.headers();

            if is_blob(&path) {
                check(h, "docker-content-digest", &path, &rid);
                check(h, "content-type", &path, &rid);
                check(h, "accept-ranges", &path, &rid);
                check(h, "x-kappa-label", &path, &rid);
                check(h, "x-kappa-axis", &path, &rid);
                if method == Method::HEAD {
                    check(h, "content-length", &path, &rid);
                }
            } else if path.contains("/manifests/") {
                check(h, "docker-content-digest", &path, &rid);
                check(h, "content-type", &path, &rid);
                if method == Method::HEAD {
                    check(h, "content-length", &path, &rid);
                }
            } else if h
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                == Some("text/event-stream")
            {
                check(h, "cache-control", &path, &rid);
            }
        }

        Ok(response)
    })
}

fn is_blob(path: &str) -> bool {
    path.contains("/blobs/") && !path.contains("/uploads") && !path.contains("/_meta")
}

fn check(
    headers: &topcoat::router::HeaderMap,
    name: &str,
    path: &str,
    request_id: &str,
) {
    if !headers.contains_key(name) {
        tracing::warn!(
            header = name,
            path = path,
            request_id = request_id,
            "required response header missing"
        );
    }
}
