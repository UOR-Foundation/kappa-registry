use std::sync::Arc;

use topcoat::context::Cx;
use topcoat::router::response::Response;
use topcoat::router::{Body, Next, StatusCode};

use crate::tasks::disk_pressure::DiskPressure;

/// Cross-protocol disk pressure layer.
///
/// Rejects all state-modifying requests (PUT, POST, PATCH, DELETE)
/// with 507 INSUFFICIENT_STORAGE when the disk pressure flag is set.
/// Read operations (GET, HEAD, OPTIONS) pass through unconditionally.
///
/// This replaces the per-handler DiskPressure checks that were
/// duplicated in OCI blob PUT and manifest PUT. The layer protects
/// all protocols equally: OCI, S3, Git, Nix, AT Protocol, distribution.
pub fn disk_pressure_layer<'a>(
    cx: &'a Cx,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let method = topcoat::router::request::method(cx);
        let is_write = matches!(method.as_str(), "PUT" | "POST" | "PATCH" | "DELETE");

        if is_write
            && let Some(pressure) = kappa_handler::try_service::<Arc<DiskPressure>>(cx)
            && pressure.0.load(std::sync::atomic::Ordering::Relaxed)
        {
            let body_str = r#"{"errors":[{"code":"INSUFFICIENT_STORAGE","message":"disk pressure: insufficient space for write"}]}"#;
            let mut response = Response::new(Body::from(body_str));
            *response.status_mut() =
                StatusCode::from_u16(507).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            response
                .headers_mut()
                .insert("content-type", "application/json".parse().unwrap());
            return Ok(response);
        }

        next.run(cx, body).await
    })
}
