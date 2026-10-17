use topcoat::context::Cx;
use topcoat::router::{Body, Next, StatusCode};

pub fn cache_layer<'a>(cx: &'a Cx, body: Body, next: Next<'a>) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let if_none_match = topcoat::router::request::headers(cx)
            .get("if-none-match")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_owned());
        let path = topcoat::router::request::uri(cx).path().to_owned();

        let mut response = next.run(cx, body).await?;

        if path.contains("/blobs/uploads") || path.contains("/_uploads/") {
            response
                .headers_mut()
                .insert("cache-control", "no-store".parse().unwrap());
        } else if is_immutable(&path) {
            response.headers_mut().insert(
                "cache-control",
                "public, max-age=31536000, immutable".parse().unwrap(),
            );
            set_etag(&mut response);
        } else if path.contains("/manifests/") && !is_digest_ref(&path) {
            response
                .headers_mut()
                .insert("cache-control", "no-cache".parse().unwrap());
            set_etag(&mut response);
        } else if path.contains("/tags/list") || path.contains("/referrers/") {
            response
                .headers_mut()
                .insert("cache-control", "no-cache".parse().unwrap());
        }

        if response.status() == StatusCode::OK
            && let (Some(inm), Some(etag)) = (&if_none_match, response.headers().get("etag"))
        {
            let etag_str = etag.to_str().unwrap_or("").trim_matches('"');
            if inm == etag_str {
                *response.status_mut() = StatusCode::NOT_MODIFIED;
                *response.body_mut() = Body::empty();
                response.headers_mut().remove("content-length");
                response.headers_mut().remove("content-type");
            }
        }

        Ok(response)
    })
}

fn set_etag(response: &mut topcoat::router::response::Response) {
    if let Some(digest) = response.headers().get("docker-content-digest").cloned()
        && let Ok(s) = digest.to_str()
        && let Ok(val) = format!("\"{}\"", s).parse()
    {
        response.headers_mut().insert("etag", val);
    }
}

fn is_immutable(path: &str) -> bool {
    (path.contains("/blobs/") && !path.contains("/uploads") && path.contains(':'))
        || is_digest_ref(path)
}

fn is_digest_ref(path: &str) -> bool {
    path.contains("/manifests/") && path.rsplit('/').next().is_some_and(|s| s.contains(':'))
}
