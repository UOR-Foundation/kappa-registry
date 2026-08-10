//! CRDT collaboration WebSocket endpoint.
//!
//! GET /v2/{*ns}/_crdt/{doc}/_ws -- bidirectional CRDT document channel.
//! Subprotocol: kappa-crdt.v1
//!
//! Binary messages carry CRDT state updates. Text messages carry
//! awareness (ephemeral presence). Document state is persisted to
//! blob storage when the last client leaves.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{broadcast, RwLock};
use topcoat::context::{app_context, Cx};
use topcoat::router::FromRequest;
use topcoat::router::{Body, RouteFuture};
use topcoat::router::websocket::{Message, WebSocketUpgrade};

use kappa_core::store::KappaStore;

use crate::path_param;

/// Manages CRDT document rooms.
pub struct CrdtManager {
    rooms: RwLock<HashMap<String, CrdtRoom>>,
    store: Arc<dyn KappaStore>,
}

struct CrdtRoom {
    state: Vec<u8>,
    sender: broadcast::Sender<Bytes>,
    client_count: usize,
}

impl CrdtManager {
    pub fn new(store: Arc<dyn KappaStore>) -> Self {
        Self {
            rooms: RwLock::new(HashMap::new()),
            store,
        }
    }

    pub async fn join(&self, ns: &str, doc: &str) -> (broadcast::Receiver<Bytes>, Vec<u8>) {
        let key = format!("{}/{}", ns, doc);
        let mut rooms = self.rooms.write().await;
        let room = rooms.entry(key.clone()).or_insert_with(|| {
            let state = self.load_state(ns, doc).unwrap_or_default();
            let (sender, _) = broadcast::channel(256);
            CrdtRoom {
                state,
                sender,
                client_count: 0,
            }
        });
        room.client_count += 1;
        let rx = room.sender.subscribe();
        let state = room.state.clone();
        (rx, state)
    }

    pub async fn apply_update(&self, ns: &str, doc: &str, update: Bytes) {
        let key = format!("{}/{}", ns, doc);
        let mut rooms = self.rooms.write().await;
        if let Some(room) = rooms.get_mut(&key) {
            room.state.extend_from_slice(&update);
            let _ = room.sender.send(update);
        }
    }

    pub async fn leave(&self, ns: &str, doc: &str) {
        let key = format!("{}/{}", ns, doc);
        let mut rooms = self.rooms.write().await;
        let should_remove = rooms
            .get_mut(&key)
            .map(|room| {
                room.client_count = room.client_count.saturating_sub(1);
                room.client_count == 0
            })
            .unwrap_or(false);
        if should_remove {
            if let Some(room) = rooms.remove(&key) {
                self.save_state(ns, doc, &room.state);
            }
        }
    }

    fn save_state(&self, ns: &str, doc: &str, state: &[u8]) {
        if state.is_empty() {
            return;
        }
        let kappa = kappa_core::kappa::kappa_from_bytes(state);
        let _ = self.store.ingest_verified(&kappa,state);
        let _ = self.store.tag_set(ns, &format!("_crdt/{}", doc), &kappa);
    }

    fn load_state(&self, ns: &str, doc: &str) -> Option<Vec<u8>> {
        let tag = self
            .store
            .tag_get(ns, &format!("_crdt/{}", doc))
            .ok()?;
        self.store.blob_get(&tag.kappa).ok()
    }
}

pub fn ws_crdt_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let ns = path_param(cx, "ns").to_string();
        let doc = path_param(cx, "doc").to_string();
        let crdt = app_context::<Arc<CrdtManager>>(cx).clone();
        let upgrade = WebSocketUpgrade::from_request(cx, body).await?;

        upgrade
            .protocols(["kappa-crdt.v1"])
            .max_message_size(1_048_576)
            .on_upgrade(move |mut socket| async move {
                let (mut rx, initial) = crdt.join(&ns, &doc).await;

                if socket.send(Message::binary(initial)).await.is_err() {
                    crdt.leave(&ns, &doc).await;
                    return;
                }

                loop {
                    tokio::select! {
                        update = rx.recv() => {
                            match update {
                                Ok(data) => {
                                    if socket.send(Message::binary(data)).await.is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        msg = socket.recv() => {
                            match msg {
                                Some(Ok(Message::Binary(data))) => {
                                    crdt.apply_update(&ns, &doc, data).await;
                                }
                                Some(Ok(Message::Close(_))) | None => break,
                                _ => {}
                            }
                        }
                    }
                }

                crdt.leave(&ns, &doc).await;
            })
    })
}
