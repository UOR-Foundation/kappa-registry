use topcoat::context::Cx;
use topcoat::router::{Body, Next};

/// OCI Warning header on OCI and kappa-distribution responses only.
/// Non-OCI responses (S3, Git, Nix) do not receive this header.
pub fn warning_layer<'a>(
    cx: &'a Cx,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let path = topcoat::router::request::uri(cx).path().to_owned();
        let is_oci = path.starts_with("/v2/")
            || path == "/v2"
            || path.starts_with("/v2?")
            || path.starts_with("/identity/")
            || path == "/_status"
            || path.starts_with("/_status/")
            || path == "/openapi.json"
            || path == "/docs";

        if !is_oci {
            return next.run(cx, body).await;
        }

        let mut response = next.run(cx, body).await?;
        response
            .headers_mut()
            .insert("warning", "299 - \"kappa-registry\"".parse().unwrap());
        Ok(response)
    })
}
