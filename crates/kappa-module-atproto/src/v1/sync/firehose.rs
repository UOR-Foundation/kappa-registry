//! `com.atproto.sync.subscribeRepos`: every repository's commits, in the
//! order this node published them.
//!
//! Frame sequence numbers are the [`PublicationFeed`]'s: each published
//! epoch holds one sequence number per mutation, so a frame's `seq` names
//! one mutation of one epoch and a cursor resumes inside an epoch. The feed
//! keeps a bounded ring of recent publications; the frames themselves are
//! read from each epoch's authenticated ledger, never from a buffer of
//! events. A cursor the ring no longer covers gets an `OutdatedCursor`
//! info frame and the stream continues from the oldest retained
//! publication; a cursor past the latest sequence gets `FutureCursor` and
//! the connection closes; a subscriber further than `max_lag` behind is
//! told it is outdated and skipped forward rather than replayed without
//! bound.

use std::sync::Arc;
use std::time::Duration;

use topcoat::context::Cx;
use topcoat::router::Body;
use topcoat::router::content::websocket::{Message, WebSocket, WebSocketUpgrade};
use topcoat::router::request::FromRequest;

use kappa_handler::{
    HandlerError, MutationEvent, Notice, PublicationFeed, blocking, committed_ledger,
    events_from_ledger, query_optional_parsed, store, try_service,
};
use kappa_store::traits::KappaStore;

use super::frame;

/// Firehose configuration registered in app context.
pub struct FirehoseConfig {
    /// Sequence numbers a subscriber may fall behind before it is told it
    /// is outdated and moved to the oldest retained publication.
    pub max_lag: u64,
    pub heartbeat_interval_ms: u64,
    pub force_json: bool,
}

impl Default for FirehoseConfig {
    fn default() -> Self {
        Self {
            max_lag: 10_000,
            heartbeat_interval_ms: 30_000,
            force_json: false,
        }
    }
}

/// Publications read per pass of the ring.
const NOTICE_BATCH: usize = 64;

/// GET /xrpc/com.atproto.sync.subscribeRepos
pub async fn subscribe_repos(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let cursor: Option<u64> = query_optional_parsed(cx, "cursor")?;
    let store = store(cx);
    let config = try_service::<Arc<FirehoseConfig>>(cx)
        .cloned()
        .unwrap_or_else(|| Arc::new(FirehoseConfig::default()));
    let feed = try_service::<Arc<PublicationFeed>>(cx)
        .cloned()
        .ok_or_else(|| HandlerError::internal("firehose requires PublicationFeed"))?;
    let upgrade = WebSocketUpgrade::from_request(cx, body)
        .await
        .map_err(|e| HandlerError::bad_request(e.to_string()))?;
    upgrade
        .protocols(["atproto-sync.v1"])
        .max_write_buffer_size(1024 * 1024)
        .on_upgrade(move |socket| {
            let session = Session {
                socket,
                store,
                feed,
                config,
            };
            session.run(cursor)
        })
        .map_err(|e| HandlerError::internal(e.to_string()))
}

struct Session {
    socket: WebSocket,
    store: Arc<dyn KappaStore>,
    feed: Arc<PublicationFeed>,
    config: Arc<FirehoseConfig>,
}

impl Session {
    async fn run(mut self, cursor: Option<u64>) {
        // Subscribed before the first read of the ring.
        let mut changed = self.feed.watch_all();
        let mut seq = match cursor {
            Some(cursor) => {
                let next = self.feed.after(cursor, 0).next;
                if cursor >= next {
                    self.info(
                        "FutureCursor",
                        &format!("cursor {cursor} is past {}", next - 1),
                    )
                    .await;
                    return;
                }
                cursor
            }
            None => self.feed.after(0, 0).next.saturating_sub(1),
        };
        let mut heartbeat =
            tokio::time::interval(Duration::from_millis(self.config.heartbeat_interval_ms));
        heartbeat.tick().await;
        loop {
            changed.borrow_and_update();
            let batch = self.feed.after(seq, NOTICE_BATCH);
            let latest = batch.next.saturating_sub(1);
            if seq.saturating_add(1) < batch.oldest
                || latest.saturating_sub(seq) > self.config.max_lag
            {
                // Past the discarded notices and within `max_lag` of the
                // latest, so the next pass makes progress.
                let resumed = batch
                    .oldest
                    .saturating_sub(1)
                    .max(latest.saturating_sub(self.config.max_lag));
                let message = format!("cursor {seq} is outdated; continuing after {resumed}");
                if !self
                    .send(Self::outdated(self.config.force_json, &message))
                    .await
                {
                    return;
                }
                seq = resumed;
                continue;
            }
            if batch.notices.is_empty() {
                tokio::select! {
                    woken = changed.changed() => if woken.is_err() { return },
                    _ = heartbeat.tick() => {
                        if !self.send(Message::Ping(bytes::Bytes::new())).await {
                            return;
                        }
                    }
                }
                continue;
            }
            for notice in batch.notices {
                match self.deliver(&notice, seq).await {
                    Some(delivered) => seq = delivered,
                    None => return,
                }
            }
        }
    }

    /// Send the frames of `notice` after `seq`; the last sequence number
    /// covered, or `None` when the connection must close.
    async fn deliver(&mut self, notice: &Notice, seq: u64) -> Option<u64> {
        let events = match Self::events(Arc::clone(&self.store), notice.clone()).await {
            Ok(events) => events,
            Err(error) => {
                self.info(
                    "Error",
                    &format!("epoch {} unreadable: {error}", notice.epoch),
                )
                .await;
                return None;
            }
        };
        if events.len() as u64 != notice.count {
            self.info(
                "Error",
                &format!(
                    "epoch {} holds {} mutations, published as {}",
                    notice.epoch,
                    events.len(),
                    notice.count
                ),
            )
            .await;
            return None;
        }
        let mut covered = seq;
        for (event, frame_seq) in events.iter().zip(notice.sequence..) {
            if frame_seq <= seq {
                continue;
            }
            match self.frame(event, frame_seq) {
                // A bookkeeping mutation has no frame but its sequence
                // number is still consumed.
                Ok(None) => {}
                Ok(Some(message)) => {
                    if !self.send(message).await {
                        return None;
                    }
                }
                Err(error) => {
                    self.info("Error", &error.to_string()).await;
                    return None;
                }
            }
            covered = frame_seq;
        }
        Some(covered.max(notice.last()))
    }

    /// The events of `notice`'s epoch, read from its ledger. Takes owned
    /// handles so the session's socket is not held across the read.
    async fn events(
        store: Arc<dyn KappaStore>,
        notice: Notice,
    ) -> Result<Vec<MutationEvent>, HandlerError> {
        blocking(move || {
            let mutations = committed_ledger(&*store, &notice.namespace, &notice.root)?;
            events_from_ledger(
                notice.namespace.display_name(),
                notice.epoch,
                &notice.root,
                &mutations,
            )
        })
        .await
    }

    fn frame(&self, event: &MutationEvent, seq: u64) -> Result<Option<Message>, HandlerError> {
        if self.config.force_json {
            Ok(frame::to_json(event, seq)?.map(Message::text))
        } else {
            Ok(frame::to_cbor(event, seq)?.map(|frame| Message::binary(bytes::Bytes::from(frame))))
        }
    }

    fn outdated(force_json: bool, message: &str) -> Message {
        if force_json {
            Message::text(frame::outdated_cursor_json(message))
        } else {
            Message::binary(bytes::Bytes::from(frame::outdated_cursor_cbor(message)))
        }
    }

    /// Send `name`/`message` as an info frame. A failed send needs no
    /// handling: every caller closes the connection next.
    async fn info(&mut self, name: &str, message: &str) {
        let frame = if self.config.force_json {
            Message::text(frame::info_json(name, message))
        } else {
            Message::binary(bytes::Bytes::from(frame::info_cbor(name, message)))
        };
        if !self.send(frame).await {
            tracing::debug!(name, "firehose subscriber left before the info frame");
        }
    }

    async fn send(&mut self, message: Message) -> bool {
        self.socket.send(message).await.is_ok()
    }
}
