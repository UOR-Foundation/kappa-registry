//! ETag generation, Cache-Control headers, and If-None-Match / 304 handling.
//! Runs post-handler on the response.

use topcoat::context::CxBuilder;
use topcoat::router::{Body, Next, StatusCode};

pub fn cache_layer<'a>(
    cx: &'a mut CxBuilder,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let if_none_match = topcoat::router::headers(cx)
            .get("if-none-match")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_owned());
        let path = topcoat::router::uri(cx).path().to_owned();

        let mut response = next.run(cx, body).await?;

        // Cache policy by path pattern
        if path.contains("/blobs/uploads") || path.contains("/_uploads/") {
            response
                .headers_mut()
                .insert("cache-control", "no-store".parse().unwrap());
        } else if is_blob_path(&path) || is_manifest_by_digest(&path) {
            response.headers_mut().insert(
                "cache-control",
                "public, max-age=31536000, immutable".parse().unwrap(),
            );
            set_etag_from_digest(&mut response);
        } else if is_manifest_by_tag(&path) {
            response
                .headers_mut()
                .insert("cache-control", "no-cache".parse().unwrap());
            set_etag_from_digest(&mut response);
        } else if path.contains("/tags/list") || path.contains("/referrers/") {
            response
                .headers_mut()
                .insert("cache-control", "no-cache".parse().unwrap());
        }

        // 304 Not Modified
        if response.status() == StatusCode::OK {
            if let (Some(ref inm), Some(etag)) = (&if_none_match, response.headers().get("etag")) {
                let etag_str = etag.to_str().unwrap_or("").trim_matches('"');
                if inm == etag_str {
                    *response.status_mut() = StatusCode::NOT_MODIFIED;
                    *response.body_mut() = Body::empty();
                    response.headers_mut().remove("content-length");
                    response.headers_mut().remove("content-type");
                }
            }
        }

        Ok(response)
    })
}

fn set_etag_from_digest(response: &mut topcoat::router::Response) {
    if let Some(digest) = response.headers().get("docker-content-digest").cloned() {
        if let Ok(s) = digest.to_str() {
            if let Ok(val) = format!("\"{}\"", s).parse() {
                response.headers_mut().insert("etag", val);
            }
        }
    }
}

fn is_blob_path(path: &str) -> bool {
    path.contains("/blobs/") && !path.contains("/uploads") && path.contains(':')
}

fn is_manifest_by_digest(path: &str) -> bool {
    path.contains("/manifests/")
        && path
            .rsplit('/')
            .next()
            .is_some_and(|s| s.contains(':'))
}

fn is_manifest_by_tag(path: &str) -> bool {
    path.contains("/manifests/")
        && path
            .rsplit('/')
            .next()
            .is_some_and(|s| !s.contains(':'))
}
