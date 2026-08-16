//! SSE (Server-Sent Events) streaming endpoint.
//!
//! GET /v2/{*ns}/_events -- stream tag mutation events filtered by namespace
//!
//! Query parameters:
//!   prefix: filter events by tag name prefix
//!   since:  replay events with sequence > since before switching to live

use std::borrow::Cow;
use std::sync::Arc;

use topcoat::context::{try_app_context, Cx};
use topcoat::router::{
    Body, Method, Path, Response, RouteFn, RouteFuture, RouterBuilder, StatusCode,
};

use kappa_core::events::EventLog;
use kappa_core::types::NamespaceRef;

use crate::query_param;

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder.route(RouteFn::new(
        Method::GET,
        Cow::Borrowed(Path::new("/v2/{*ns}/_events")),
        events_route,
    ))
}

fn events_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = crate::resolve_ns_read_async(cx).await?;
        let prefix = query_param(cx, "prefix");
        let since: u64 = query_param(cx, "since")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        events(cx, &ns, prefix.as_deref(), since).await
    })
}

async fn events(cx: &Cx, ns: &NamespaceRef, prefix: Option<&str>, since: u64) -> topcoat::Result<Response> {
    let n = ns.clone();
    let pfx = prefix.map(String::from);

    // Access the EventLog from app_context. kappa-server registers
    // Arc<dyn EventLog> (via EventBroadcaster which wraps InMemoryEventLog).
    // If no EventLog is registered, fall back to tag-state reconstruction.
    let sse_body = if let Some(event_log) = try_app_context::<Arc<dyn EventLog>>(cx) {
        let log = event_log.clone();
        let ns_str = ns.as_str().to_string();
        tokio::task::spawn_blocking(move || {
            let events = log.since_sequence(&ns_str, since);
            let mut output = String::new();
            for event in &events {
                if let Some(ref p) = pfx {
                    if !event.name.starts_with(p.as_str()) {
                        continue;
                    }
                }
                // Format as SSE: event type, id (sequence), data (JSON)
                let json = serde_json::to_string(event).unwrap_or_else(|_| "{}".to_owned());
                output.push_str(&format!(
                    "event: {}\nid: {}\ndata: {}\n\n",
                    event.operation.as_str(),
                    event.sequence,
                    json,
                ));
            }
            output
        })
        .await
        .map_err(|e| topcoat::router::error::bad_request(e.to_string()))?
    } else {
        // Fallback: reconstruct from current tag state when no EventLog
        // is registered. This gives a snapshot, not a mutation history.
        let s = crate::store(cx).clone();
        tokio::task::spawn_blocking(move || {
            let tags = s.tag_list(&n).unwrap_or_default();
            let mut output = String::new();
            for (i, tag) in tags.iter().enumerate() {
                if tag.name.starts_with('_') {
                    continue;
                }
                if let Some(ref p) = pfx {
                    if !tag.name.starts_with(p.as_str()) {
                        continue;
                    }
                }
                let seq = (i + 1) as u64;
                if seq <= since {
                    continue;
                }
                output.push_str(&format!(
                    "event: tag_set\nid: {}\ndata: {{\"namespace\":\"{}\",\"name\":\"{}\",\"kappa\":\"{}\"}}\n\n",
                    seq, n.as_str(), tag.name, tag.kappa
                ));
            }
            output
        })
        .await
        .map_err(|e| topcoat::router::error::bad_request(e.to_string()))?
    };

    let mut response = Response::new(Body::from(sse_body));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert("content-type", "text/event-stream".parse().unwrap());
    response
        .headers_mut()
        .insert("cache-control", "no-cache".parse().unwrap());
    Ok(response)
}
