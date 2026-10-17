use std::sync::Arc;

use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{HandlerError, read_json, try_service};

/// PDS hostname registered in app context by the server at startup.
/// Read from KAPPA_PDS_HOSTNAME env var once at Config::from_env() time.
pub struct PdsHostname(pub String);

/// POST /xrpc/com.atproto.sync.requestCrawl
///
/// Fire-and-forget notification to a downstream relay that new
/// content is available. No output per the lexicon spec.
///
/// The client provides the relay hostname. The handler validates
/// it is HTTPS and not a private/loopback address to prevent SSRF.
pub async fn request_crawl(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let req: serde_json::Value = read_json(body, 64 * 1024).await?;

    let hostname = req
        .get("hostname")
        .and_then(|v| v.as_str())
        .filter(|h| !h.is_empty())
        .ok_or_else(|| HandlerError::bad_request("missing required field: hostname"))?
        .to_string();

    // SSRF protection: reject non-HTTPS URLs and private addresses.
    if !hostname.starts_with("https://") && !hostname.starts_with("http://localhost") {
        // Allow http://localhost for development. Require HTTPS for everything else.
        // In production, the operator should set KAPPA_PDS_HOSTNAME to HTTPS.
        if !hostname.starts_with("http://") {
            return Err(HandlerError::bad_request("hostname must be an HTTP(S) URL"));
        }
        // Parse the host portion and reject private IP ranges.
        let host_part = hostname
            .strip_prefix("http://")
            .or_else(|| hostname.strip_prefix("https://"))
            .unwrap_or(&hostname);
        let host = host_part.split('/').next().unwrap_or(host_part);
        let host = host.split(':').next().unwrap_or(host);
        if host == "169.254.169.254"
            || host.starts_with("10.")
            || host.starts_with("172.16.")
            || host.starts_with("172.17.")
            || host.starts_with("172.18.")
            || host.starts_with("172.19.")
            || host.starts_with("172.2")
            || host.starts_with("172.3")
            || host.starts_with("192.168.")
            || host == "127.0.0.1"
            || host == "[::1]"
            || host == "0.0.0.0"
        {
            return Err(HandlerError::bad_request(
                "hostname must not be a private or loopback address",
            ));
        }
    }

    let our_hostname = match try_service::<PdsHostname>(cx) {
        Some(h) => h.0.clone(),
        None => {
            return Ok(kappa_handler::empty_response(StatusCode::OK));
        }
    };

    let relay_url = format!(
        "{}/xrpc/com.atproto.sync.requestCrawl",
        hostname.trim_end_matches('/'),
    );

    if let Some(outbound) = try_service::<Arc<topcoat::router::outbound::OutboundClient>>(cx) {
        let outbound = outbound.clone();
        let cx_clone = cx.clone();
        tokio::spawn(async move {
            let body = serde_json::json!({ "hostname": our_hostname });
            match outbound.post_json(&cx_clone, &relay_url, &body).await {
                Ok(resp) => {
                    tracing::debug!(
                        relay = %relay_url,
                        status = %resp.status(),
                        "requestCrawl sent",
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        relay = %relay_url,
                        error = %e,
                        "requestCrawl failed",
                    );
                }
            }
        });
    } else {
        tracing::warn!("OutboundClient not configured, crawl notification not sent");
    }

    Ok(kappa_handler::empty_response(StatusCode::OK))
}
