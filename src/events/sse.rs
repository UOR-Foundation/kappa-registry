//! SSE (Server-Sent Events) endpoint for tag mutation streaming.
//!
//! GET /v2/{*ns}/_events?since={seq}
//!
//! Streams TagEvents filtered by namespace. The `since` parameter
//! resumes from a sequence number. If a subscriber falls behind the
//! broadcast channel capacity, a lag event is emitted so the client
//! knows to re-sync via RBSR.

use crate::events::TagEvent;

/// Filter events for a specific namespace and minimum sequence.
pub fn matches_filter(event: &TagEvent, namespace: &str, since: u64) -> bool {
    event.namespace == namespace && event.sequence > since
}

/// Format a TagEvent as an SSE data line.
///
/// Format:
/// ```text
/// event: tag_set
/// id: 42
/// data: {"namespace":"ns","name":"tag",...}
///
/// ```
pub fn format_sse_event(event: &TagEvent) -> String {
    let data = serde_json::to_string(event).unwrap_or_else(|_| "{}".to_owned());
    format!(
        "event: {}\nid: {}\ndata: {}\n\n",
        event.operation.as_str(),
        event.sequence,
        data,
    )
}

/// Format a lag notification as an SSE event.
///
/// Sent when the subscriber fell behind the broadcast channel and
/// missed events. The client should re-sync via RBSR.
pub fn format_lag_event(missed: u64) -> String {
    format!("event: lag\ndata: {{\"missed\":{missed}}}\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::TagEventOp;

    fn test_event(ns: &str, seq: u64) -> TagEvent {
        TagEvent {
            namespace: ns.to_owned(),
            name: "tag".to_owned(),
            value: Some("sha256:abc".to_owned()),
            prev_value: None,
            epoch: 1,
            mtime: 1234567890,
            operation: TagEventOp::Set,
            sequence: seq,
        }
    }

    #[test]
    fn filter_matches_namespace() {
        let event = test_event("my-ns", 5);
        assert!(matches_filter(&event, "my-ns", 0));
        assert!(!matches_filter(&event, "other-ns", 0));
    }

    #[test]
    fn filter_matches_since() {
        let event = test_event("ns", 5);
        assert!(matches_filter(&event, "ns", 4));
        assert!(!matches_filter(&event, "ns", 5));
        assert!(!matches_filter(&event, "ns", 6));
    }

    #[test]
    fn format_sse_contains_required_fields() {
        let event = test_event("ns", 42);
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
}
