//! Tag mutation event broadcasting and SSE streaming.
//!
//! Every tag mutation emits a TagEvent to a broadcast channel.
//! The SSE endpoint streams events filtered by namespace.
//! Lag events on overflow trigger RBSR re-sync.
//!
//! The broadcaster is passed as a callback to store methods,
//! NOT as a cx/framework dependency -- keeps store framework-agnostic.

pub mod sse;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// A tag mutation event.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Modification timestamp in milliseconds since epoch.
    pub mtime: u64,
    /// The type of mutation.
    pub operation: TagEventOp,
    /// Per-namespace sequence number for this event.
    /// Derived from (epoch, batch_index) to avoid a second redb write.
    pub sequence: u64,
}

/// The type of tag mutation that occurred.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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

/// Broadcast channel capacity. Subscribers that fall behind receive
/// a lag notification and must re-sync via RBSR.
pub const EVENT_CHANNEL_CAPACITY: usize = 4096;

/// Event broadcaster wrapper for app_context registration.
pub struct EventBroadcaster {
    sender: broadcast::Sender<TagEvent>,
}

impl EventBroadcaster {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self { sender }
    }

    /// Emit a tag event. Best-effort: if channel is full, the event
    /// is dropped and subscribers will receive a lag notification.
    pub fn emit(&self, event: TagEvent) {
        // Ignore send error (no active receivers is not an error).
        let _ = self.sender.send(event);
    }

    /// Subscribe to the event stream.
    pub fn subscribe(&self) -> broadcast::Receiver<TagEvent> {
        self.sender.subscribe()
    }
}

impl Default for EventBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_and_receive() {
        let broadcaster = EventBroadcaster::new();
        let mut rx = broadcaster.subscribe();

        let event = TagEvent {
            namespace: "test-ns".to_owned(),
            name: "latest".to_owned(),
            value: Some("sha256:abc".to_owned()),
            prev_value: None,
            epoch: 1,
            mtime: 1234567890,
            operation: TagEventOp::Set,
            sequence: 1,
        };

        broadcaster.emit(event.clone());

        let received = rx.try_recv().unwrap();
        assert_eq!(received.namespace, "test-ns");
        assert_eq!(received.name, "latest");
        assert_eq!(received.epoch, 1);
    }

    #[test]
    fn emit_without_subscribers_does_not_panic() {
        let broadcaster = EventBroadcaster::new();
        broadcaster.emit(TagEvent {
            namespace: "ns".to_owned(),
            name: "tag".to_owned(),
            value: None,
            prev_value: None,
            epoch: 0,
            mtime: 0,
            operation: TagEventOp::Delete,
            sequence: 0,
        });
        // No panic = success
    }

    #[test]
    fn tag_event_op_as_str() {
        assert_eq!(TagEventOp::Set.as_str(), "tag_set");
        assert_eq!(TagEventOp::Delete.as_str(), "tag_delete");
        assert_eq!(TagEventOp::SetIf.as_str(), "tag_set_if");
        assert_eq!(TagEventOp::BatchItem.as_str(), "tag_batch_item");
        assert_eq!(TagEventOp::Symbolic.as_str(), "tag_symbolic");
    }
}
