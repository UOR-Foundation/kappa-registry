//! Server-sent mutation events resumable from authenticated history.
//!
//! An event id is `epoch.consumed.root`: the namespace history position
//! after the event ([`kappa_handler::Position`]). A client resumes with the
//! last id it saw (`Last-Event-ID`, or `since`); `since=0` starts from the
//! namespace's first epoch, and no cursor starts after its current head.
//! Delivery reads the namespace's epochs, so catch-up and live delivery are
//! one path and nothing is lost to a buffer. A cursor history cannot
//! continue from produces one `resync_required` event naming why (`ahead`,
//! `diverged` or `unavailable`) and ends the stream; it is never waited on.

use std::sync::Arc;
use std::time::Duration;

use kappa_handler::{
    Delivery, EventStream, HandlerError, Position, PublicationFeed, blocking, head_position,
    query_optional, resolve_ns_read, store,
};
use topcoat::context::Cx;
use topcoat::router::content::sse::{Event, KeepAlive, Sse};
use topcoat::router::response::IntoResponse;
use topcoat::router::{Body, RouterBuilder};

#[cfg(test)]
#[path = "events_sse_tests.rs"]
mod tests;

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder.route(dist_route!(
        topcoat::router::Method::GET,
        "/v2/{*ns}/_events",
        handler
    ))
}

/// The SSE frame for one delivery, and whether the stream ends after it.
fn frame(delivery: &Delivery) -> (topcoat::Result<Event>, bool) {
    match delivery {
        Delivery::Event(event) => (
            Event::new()
                .event(event.operation.as_str())
                .id(event.id())
                .json_data(event),
            false,
        ),
        Delivery::Gap { gap, after } => (
            Event::new()
                .event("resync_required")
                .json_data(&serde_json::json!({
                    "reason": gap.as_str(),
                    "after": after.id(),
                })),
            true,
        ),
    }
}

fn parse_cursor(value: &str) -> Result<Position, HandlerError> {
    Position::parse(value).map_err(HandlerError::bad_request)
}

/// The stream as SSE frames: every delivery until the first gap, which is
/// sent and ends it.
fn sse_frames(
    stream: EventStream,
    prefix: Option<String>,
) -> impl futures_util::Stream<Item = topcoat::Result<Event>> {
    let mut stream = stream;
    if let Some(prefix) = prefix {
        stream.set_filter(move |event| event.name.starts_with(&prefix));
    }
    futures_util::stream::unfold(Some(stream), |state| async move {
        let mut stream = state?;
        let delivery = stream.next().await;
        let (event, ends) = frame(&delivery);
        Some((event, (!ends).then_some(stream)))
    })
}

async fn handler(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let namespace = resolve_ns_read(cx)?;
    let feed = kappa_handler::try_service::<Arc<PublicationFeed>>(cx)
        .cloned()
        .ok_or_else(|| HandlerError::internal("SSE requires PublicationFeed in app context"))?;
    let store = store(cx);
    let query_cursor = query_optional(cx, "since");
    let header_cursor = topcoat::router::request::headers(cx)
        .get("last-event-id")
        .map(|value| value.to_str());
    // A supplied query cursor is authoritative, including when a stale header
    // is malformed. Validate only the selected resume source.
    let requested = match query_cursor {
        Some(value) => Some(parse_cursor(&value)?),
        None => match header_cursor {
            Some(value) => {
                Some(parse_cursor(value.map_err(|_| {
                    HandlerError::bad_request("invalid Last-Event-ID")
                })?)?)
            }
            None => None,
        },
    };
    // Subscribe before the head is read, so a publication between the read
    // and the first wait is delivered.
    let mut stream = EventStream::new(store.clone(), &feed, namespace.clone(), Position::start());
    let position = match requested {
        Some(position) => position,
        None => blocking(move || head_position(&*store, &namespace)).await?,
    };
    stream.reposition(position);
    Sse::new(sse_frames(stream, query_optional(cx, "prefix")))
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(30)))
        .into_response(cx)
        .map_err(|error| HandlerError::internal(format!("SSE response: {error}")))
}
