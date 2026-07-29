//! Event broadcasting and SSE formatting.
//!
//! EventBroadcaster wraps tokio::sync::broadcast for multi-consumer
//! fan-out of tag mutation events. It also writes events to the
//! InMemoryEventLog for persistent query access (catch-up after
//! reconnection).
//!
//! SSE formatting converts TagEvent to text/event-stream format for
//! HTTP streaming endpoints.

use std::sync::Arc;

use tokio::sync::broadcast;

use kappa_core::events::{EventLog, TagEvent};

/// Broadcast channel capacity. Subscribers that fall behind receive
/// a lag notification and must re-sync via RBSR.
pub const EVENT_CHANNEL_CAPACITY: usize = 4096;

/// Multi-consumer event broadcaster backed by persistent event log.
///
/// Every emit() writes to both the persistent log (InMemoryEventLog)
/// and the broadcast channel. Subscribers receive real-time events.
/// Clients that reconnect use the persistent log to catch up via
/// since_sequence().
pub struct EventBroadcaster {
    tx: broadcast::Sender<TagEvent>,
    log: Arc<dyn EventLog>,
}

impl EventBroadcaster {
    pub fn new(log: Arc<dyn EventLog>, capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx, log }
    }

    /// Emit event to both persistent log and broadcast channel.
    ///
    /// The persistent log assigns a monotonic sequence number to the
    /// event. The broadcast channel sends the sequenced event to all
    /// active subscribers. If there are no active subscribers, the
    /// broadcast send is silently dropped (not an error).
    pub fn emit(&self, event: TagEvent) {
        self.log.emit(event.clone());
        let _ = self.tx.send(event);
    }

    /// Subscribe to the real-time event stream.
    ///
    /// Returns a broadcast::Receiver. If the receiver falls behind by
    /// more than EVENT_CHANNEL_CAPACITY events, it receives a
    /// RecvError::Lagged with the count of missed events. The SSE
    /// endpoint converts this to a lag notification so the client
    /// knows to re-sync via RBSR.
    pub fn subscribe(&self) -> broadcast::Receiver<TagEvent> {
        self.tx.subscribe()
    }

    /// Access the persistent event log for historical queries.
    pub fn log(&self) -> &dyn EventLog {
        &*self.log
    }
}

/// Format a TagEvent as an SSE text frame for streaming.
///
/// Format:
/// ```text
/// event: tag_set
/// id: 42
/// data: {"namespace":"ns","name":"tag",...}
///
/// ```
///
/// The event type is the operation name (tag_set, tag_delete, etc).
/// The id is the sequence number for Last-Event-ID reconnection.
/// The data is the full TagEvent serialized as JSON.
pub fn format_sse_event(event: &TagEvent) -> String {
    let json = serde_json::to_string(event).unwrap_or_else(|_| "{}".to_owned());
    format!(
        "event: {}\nid: {}\ndata: {}\n\n",
        event.operation.as_str(),
        event.sequence,
        json,
    )
}

/// Format a lag notification as an SSE event.
///
/// Sent when the subscriber fell behind the broadcast channel and
/// missed events. The client should re-sync by calling the events
/// REST endpoint with its last-seen sequence number, then resume
/// SSE streaming.
pub fn format_lag_event(missed: u64) -> String {
    format!("event: lag\ndata: {{\"missed\":{missed}}}\n\n")
}

/// Check whether a TagEvent matches subscriber filter criteria.
///
/// Namespace filter: if provided, event.namespace must match exactly.
/// Prefix filter: if provided, event.name must start with the prefix.
/// Both filters are optional. If neither is provided, all events match.
pub fn matches_filter(event: &TagEvent, namespace: Option<&str>, prefix: Option<&str>) -> bool {
    if let Some(ns) = namespace {
        if event.namespace != ns {
            return false;
        }
    }
    if let Some(p) = prefix {
        if !event.name.starts_with(p) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_core::events::{InMemoryEventLog, TagEventOp};

    fn make_event(ns: &str, name: &str, seq: u64) -> TagEvent {
        TagEvent {
            namespace: ns.to_owned(),
            name: name.to_owned(),
            value: Some("sha256:abc".to_owned()),
            prev_value: None,
            epoch: 1,
            mtime_ms: 1234567890,
            operation: TagEventOp::Set,
            sequence: seq,
        }
    }

    #[test]
    fn broadcaster_emit_writes_to_log() {
        let log = Arc::new(InMemoryEventLog::new());
        let broadcaster = EventBroadcaster::new(log.clone(), 16);
        broadcaster.emit(make_event("ns", "tag", 0));
        let events = log.recent("ns", 10);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].name, "tag");
    }

    #[test]
    fn broadcaster_emit_sends_to_subscriber() {
        let log = Arc::new(InMemoryEventLog::new());
        let broadcaster = EventBroadcaster::new(log, 16);
        let mut rx = broadcaster.subscribe();
        broadcaster.emit(make_event("ns", "latest", 0));
        let received = rx.try_recv().unwrap();
        assert_eq!(received.namespace, "ns");
        assert_eq!(received.name, "latest");
    }

    #[test]
    fn broadcaster_without_subscribers_does_not_panic() {
        let log = Arc::new(InMemoryEventLog::new());
        let broadcaster = EventBroadcaster::new(log, 16);
        broadcaster.emit(make_event("ns", "tag", 0));
        // No panic = success
    }

    #[test]
    fn format_sse_contains_required_fields() {
        let event = make_event("ns", "tag", 42);
        let sse = format_sse_event(&event);
        assert!(sse.starts_with("event: tag_set\n"));
        assert!(sse.contains("id: 42\n"));
        assert!(sse.contains("data: "));
        assert!(sse.ends_with("\n\n"));
    }

    #[test]
    fn format_lag_event_contains_count() {
        let lag = format_lag_event(100);
        assert!(lag.contains("event: lag"));
        assert!(lag.contains("\"missed\":100"));
    }

    #[test]
    fn filter_matches_namespace() {
        let event = make_event("my-ns", "tag", 5);
        assert!(matches_filter(&event, Some("my-ns"), None));
        assert!(!matches_filter(&event, Some("other-ns"), None));
    }

    #[test]
    fn filter_matches_prefix() {
        let event = make_event("ns", "v1.0", 5);
        assert!(matches_filter(&event, None, Some("v1.")));
        assert!(!matches_filter(&event, None, Some("v2.")));
    }

    #[test]
    fn filter_matches_both() {
        let event = make_event("ns", "v1.0", 5);
        assert!(matches_filter(&event, Some("ns"), Some("v1.")));
        assert!(!matches_filter(&event, Some("ns"), Some("v2.")));
        assert!(!matches_filter(&event, Some("other"), Some("v1.")));
    }

    #[test]
    fn filter_matches_none_allows_all() {
        let event = make_event("any-ns", "any-tag", 5);
        assert!(matches_filter(&event, None, None));
    }
}
