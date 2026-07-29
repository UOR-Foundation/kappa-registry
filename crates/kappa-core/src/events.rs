//! EventLog trait (seam S4): mutation event emission and subscription.
//!
//! Every tag mutation produces a TagEvent carrying all information needed
//! for SSE streaming, conflict detection, and RBSR re-sync.
//!
//! InMemoryEventLog stores events in bounded VecDeque per namespace with
//! automatic monotonic sequence number assignment. The sequence counter is
//! global (not per-namespace) so consumers can total-order events across
//! namespaces for cross-namespace consistency checks.
//!
//! EventBroadcaster (in kappa-server) wraps tokio::sync::broadcast for
//! multi-consumer fan-out. SSE formatting (in kappa-server) serializes
//! TagEvent to JSON via the serde::Serialize derive on this struct.
//! kappa-core does not depend on serde_json or tokio.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

const MAX_EVENTS_PER_NAMESPACE: usize = 10_000;

/// The type of tag mutation that occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TagEventOp {
    Set,
    Delete,
    SetIf,
    BatchItem,
    Symbolic,
}

impl TagEventOp {
    pub fn as_str(&self) -> &'static str {
        match self {
            TagEventOp::Set => "tag_set",
            TagEventOp::Delete => "tag_delete",
            TagEventOp::SetIf => "tag_set_if",
            TagEventOp::BatchItem => "tag_batch_item",
            TagEventOp::Symbolic => "tag_symbolic",
        }
    }
}

/// A complete event record for a tag mutation.
///
/// Carries all information needed for SSE streaming, conflict detection,
/// and re-sync. serde::Serialize derived so downstream crates (kappa-server)
/// can serialize to JSON for SSE without kappa-core depending on serde_json.
///
/// `value` is Option<String>: Some(kappa) for set, None for delete.
/// This is type-level disambiguation -- an empty string would be ambiguous
/// between "deleted" and "set to empty content".
///
/// `sequence` is assigned by InMemoryEventLog::emit(), not by the caller.
/// Callers construct TagEvent with sequence: 0 and the EventLog overwrites
/// it with the next monotonic value. This prevents duplicate or out-of-order
/// sequences from caller bugs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TagEvent {
    /// The namespace where the mutation occurred.
    pub namespace: String,
    /// The tag name that was mutated.
    pub name: String,
    /// New value (None for delete).
    pub value: Option<String>,
    /// Previous value (None for create).
    pub prev_value: Option<String>,
    /// The namespace epoch after this mutation.
    pub epoch: u64,
    /// Modification timestamp in milliseconds since unix epoch.
    pub mtime_ms: u64,
    /// The type of mutation.
    pub operation: TagEventOp,
    /// Per-namespace sequence number for this event.
    /// Assigned by InMemoryEventLog::emit, not by the caller.
    pub sequence: u64,
}

/// Trait for event storage backends.
///
/// Implementations must be thread-safe. emit() assigns a monotonic
/// sequence number before storing the event. recent() and since_sequence()
/// provide query access for catch-up after reconnection.
pub trait EventLog: Send + Sync {
    /// Record an event. The implementation assigns a monotonic sequence
    /// number to the event before storing it.
    fn emit(&self, event: TagEvent);

    /// Return the most recent `limit` events for a namespace,
    /// newest first.
    fn recent(&self, namespace: &str, limit: usize) -> Vec<TagEvent>;

    /// Return all events for a namespace with sequence > after,
    /// in chronological order. Used for catch-up after reconnection:
    /// client sends its last-seen sequence, server returns everything
    /// since then.
    fn since_sequence(&self, namespace: &str, after: u64) -> Vec<TagEvent>;
}

/// In-memory event log with bounded VecDeque per namespace.
///
/// When a namespace reaches MAX_EVENTS_PER_NAMESPACE, the oldest event
/// is evicted (pop_front) before the new event is appended (push_back).
/// O(1) eviction.
///
/// The sequence counter is global (AtomicU64) so events from different
/// namespaces are total-ordered. This enables cross-namespace consistency
/// checks without vector clocks.
pub struct InMemoryEventLog {
    log: RwLock<HashMap<String, VecDeque<TagEvent>>>,
    sequence: AtomicU64,
}

impl InMemoryEventLog {
    pub fn new() -> Self {
        Self {
            log: RwLock::new(HashMap::new()),
            sequence: AtomicU64::new(1),
        }
    }
}

impl Default for InMemoryEventLog {
    fn default() -> Self {
        Self::new()
    }
}

impl EventLog for InMemoryEventLog {
    fn emit(&self, mut event: TagEvent) {
        event.sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let mut log = self.log.write().expect("event log lock poisoned");
        let events = log.entry(event.namespace.clone()).or_default();
        if events.len() >= MAX_EVENTS_PER_NAMESPACE {
            events.pop_front();
        }
        events.push_back(event);
    }

    fn recent(&self, namespace: &str, limit: usize) -> Vec<TagEvent> {
        let log = self.log.read().expect("event log lock poisoned");
        log.get(namespace)
            .map(|events| events.iter().rev().take(limit).cloned().collect())
            .unwrap_or_default()
    }

    fn since_sequence(&self, namespace: &str, after: u64) -> Vec<TagEvent> {
        let log = self.log.read().expect("event log lock poisoned");
        log.get(namespace)
            .map(|events| {
                events
                    .iter()
                    .filter(|e| e.sequence > after)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(ns: &str, name: &str) -> TagEvent {
        TagEvent {
            namespace: ns.to_owned(),
            name: name.to_owned(),
            value: Some("sha256:abc".to_owned()),
            prev_value: None,
            epoch: 1,
            mtime_ms: 1234567890,
            operation: TagEventOp::Set,
            sequence: 0, // assigned by emit
        }
    }

    fn make_delete_event(ns: &str, name: &str) -> TagEvent {
        TagEvent {
            namespace: ns.to_owned(),
            name: name.to_owned(),
            value: None,
            prev_value: Some("sha256:old".to_owned()),
            epoch: 2,
            mtime_ms: 1234567891,
            operation: TagEventOp::Delete,
            sequence: 0,
        }
    }

    #[test]
    fn emit_assigns_monotonic_sequence() {
        let log = InMemoryEventLog::new();
        log.emit(make_event("ns", "a"));
        log.emit(make_event("ns", "b"));
        let events = log.since_sequence("ns", 0);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[1].sequence, 2);
        assert!(events[0].sequence < events[1].sequence);
    }

    #[test]
    fn recent_returns_newest_first() {
        let log = InMemoryEventLog::new();
        log.emit(make_event("ns", "a"));
        log.emit(make_event("ns", "b"));
        log.emit(make_event("ns", "c"));
        let events = log.recent("ns", 2);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].name, "c");
        assert_eq!(events[1].name, "b");
    }

    #[test]
    fn since_sequence_filters_correctly() {
        let log = InMemoryEventLog::new();
        log.emit(make_event("ns", "a"));
        log.emit(make_event("ns", "b"));
        log.emit(make_event("ns", "c"));
        let events = log.since_sequence("ns", 1);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].name, "b");
        assert_eq!(events[1].name, "c");
    }

    #[test]
    fn since_sequence_returns_empty_when_caught_up() {
        let log = InMemoryEventLog::new();
        log.emit(make_event("ns", "a"));
        assert!(log.since_sequence("ns", 1).is_empty());
        assert!(log.since_sequence("ns", 99).is_empty());
    }

    #[test]
    fn empty_namespace_returns_empty() {
        let log = InMemoryEventLog::new();
        assert!(log.recent("nonexistent", 10).is_empty());
        assert!(log.since_sequence("nonexistent", 0).is_empty());
    }

    #[test]
    fn namespaces_isolated() {
        let log = InMemoryEventLog::new();
        log.emit(make_event("ns1", "a"));
        log.emit(make_event("ns2", "b"));
        assert_eq!(log.recent("ns1", 10).len(), 1);
        assert_eq!(log.recent("ns2", 10).len(), 1);
        assert_eq!(log.recent("ns1", 10)[0].name, "a");
        assert_eq!(log.recent("ns2", 10)[0].name, "b");
    }

    #[test]
    fn evicts_oldest_at_capacity() {
        let log = InMemoryEventLog::new();
        for i in 0..MAX_EVENTS_PER_NAMESPACE + 1 {
            log.emit(make_event("ns", &format!("t{}", i)));
        }
        let events = log.since_sequence("ns", 0);
        assert_eq!(events.len(), MAX_EVENTS_PER_NAMESPACE);
        // t0 (seq 1) was evicted; t1 (seq 2) is now first
        assert_eq!(events[0].name, "t1");
        assert_eq!(events[0].sequence, 2);
    }

    #[test]
    fn sequence_is_global_across_namespaces() {
        let log = InMemoryEventLog::new();
        log.emit(make_event("ns1", "a"));
        log.emit(make_event("ns2", "b"));
        log.emit(make_event("ns1", "c"));
        let ns1 = log.since_sequence("ns1", 0);
        let ns2 = log.since_sequence("ns2", 0);
        assert_eq!(ns1[0].sequence, 1); // a
        assert_eq!(ns2[0].sequence, 2); // b
        assert_eq!(ns1[1].sequence, 3); // c
    }

    #[test]
    fn delete_event_has_none_value() {
        let log = InMemoryEventLog::new();
        log.emit(make_delete_event("ns", "gone"));
        let events = log.recent("ns", 1);
        assert_eq!(events.len(), 1);
        assert!(events[0].value.is_none());
        assert_eq!(events[0].prev_value.as_deref(), Some("sha256:old"));
        assert_eq!(events[0].operation, TagEventOp::Delete);
    }

    #[test]
    fn tag_event_op_as_str() {
        assert_eq!(TagEventOp::Set.as_str(), "tag_set");
        assert_eq!(TagEventOp::Delete.as_str(), "tag_delete");
        assert_eq!(TagEventOp::SetIf.as_str(), "tag_set_if");
        assert_eq!(TagEventOp::BatchItem.as_str(), "tag_batch_item");
        assert_eq!(TagEventOp::Symbolic.as_str(), "tag_symbolic");
    }

    #[test]
    fn recent_with_zero_limit_returns_empty() {
        let log = InMemoryEventLog::new();
        log.emit(make_event("ns", "a"));
        assert!(log.recent("ns", 0).is_empty());
    }

    #[test]
    fn recent_with_limit_exceeding_count_returns_all() {
        let log = InMemoryEventLog::new();
        log.emit(make_event("ns", "a"));
        log.emit(make_event("ns", "b"));
        let events = log.recent("ns", 100);
        assert_eq!(events.len(), 2);
    }
}
