use topcoat::context::{Cx, try_request_context};
use topcoat::router::{Body, Next};

use super::proxy_trust::ClientIp;
use super::request_id::RequestId;

pub fn request_log_layer<'a>(
    cx: &'a Cx,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let start = std::time::Instant::now();
        let method = topcoat::router::request::method(cx).clone();
        let path = topcoat::router::request::uri(cx).path().to_owned();
        let request_id = try_request_context::<RequestId>(cx)
            .map(|r| r.0.clone())
            .unwrap_or_default();
        let client_ip = try_request_context::<ClientIp>(cx)
            .map(|c| c.0)
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

        let stream_request_id = request_id.clone();
        let stream_method = method.clone();
        let stream_path = path.clone();
        let slot = kappa_handler::StreamingErrorSlot::with_observer(move |error| {
            tracing::error!(
                method = %stream_method,
                path = %stream_path,
                request_id = %stream_request_id,
                error = %error,
                "streaming response failed"
            );
        });
        let cx = cx.with(slot);
        let response = next.run(&cx, body).await?;

        let duration = start.elapsed();
        let status = response.status().as_u16();

        if status >= 500 {
            tracing::error!(
                method = %method, path = %path, status,
                duration_ms = duration.as_millis() as u64,
                request_id = %request_id, client_ip = %client_ip,
                "request completed"
            );
        } else if status >= 400 {
            tracing::warn!(
                method = %method, path = %path, status,
                duration_ms = duration.as_millis() as u64,
                request_id = %request_id, client_ip = %client_ip,
                "request completed"
            );
        } else {
            tracing::info!(
                method = %method, path = %path, status,
                duration_ms = duration.as_millis() as u64,
                request_id = %request_id, client_ip = %client_ip,
                "request completed"
            );
        }

        Ok(response)
    })
}
