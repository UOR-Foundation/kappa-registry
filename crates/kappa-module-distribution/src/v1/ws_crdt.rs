use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{RwLock, broadcast, watch};
use topcoat::context::{Cx, try_request_context};
use topcoat::router::content::websocket::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use topcoat::router::request::FromRequest;
use topcoat::router::{Body, RouterBuilder};

use kappa_handler::{HandlerError, ResolvedNamespace, blocking, path_param};
use kappa_store::axis::Axis;
use kappa_store::namespace::NamespaceRef;
use kappa_store::tag::TagUpdate;
use kappa_store::time::Clock;
use kappa_store::traits::KappaStore;
use kappa_store::{ContentIdentity, PreparationBounds, Published, StoreError, publish_if_changed};

/// Maximum CRDT room state size in bytes per room.
const MAX_ROOM_STATE_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// CRDT collaboration room manager.
///
/// Manages room lifecycle: join, update, leave, persist. Updates accumulate
/// in memory; a room's state is persisted when its last client leaves, as
/// one published execution that stores the state and moves the room's
/// `_crdt/{doc}` tag. Concurrent persists serialize on the store's writer.
///
/// The server MUST call `shutdown()` during graceful shutdown to
/// persist all active room state. If the server crashes with active
/// rooms, state since last save is lost.
///
/// MAX_CONCURRENT_ROOMS is configurable via the CrdtConfig registered
/// in app context. Default: 1000. IoT deployments set lower values.
pub struct CrdtManager {
    rooms: RwLock<Rooms>,
    store: Arc<dyn KappaStore>,
    clock: Arc<dyn Clock>,
    max_rooms: usize,
}

/// Configuration for CRDT room limits. Registered in app context
/// by the server. The operator sets max_rooms based on deployment
/// memory budget: max_rooms * MAX_ROOM_STATE_BYTES = total CRDT memory.
pub struct CrdtConfig {
    pub max_rooms: usize,
}

impl Default for CrdtConfig {
    fn default() -> Self {
        Self { max_rooms: 1000 }
    }
}

/// Room registry guarded by one lock that is never held across a persist.
#[derive(Default)]
struct Rooms {
    active: HashMap<String, CrdtRoom>,
    /// Documents whose final state is being persisted, keyed like `active`.
    /// The persisting task owns the paired sender and drops it after the
    /// persist completes and this entry is removed; it never sends. A join
    /// for the document waits on the receiver, so it loads the state the
    /// persist published instead of the state before it.
    persisting: HashMap<String, watch::Receiver<()>>,
}

struct CrdtRoom {
    namespace: NamespaceRef,
    doc: String,
    state: Vec<u8>,
    sender: broadcast::Sender<Bytes>,
    client_count: usize,
}

#[derive(Debug)]
pub enum JoinError {
    StoreError(String),
    RoomLimitReached,
}

fn room_key(ns: &NamespaceRef, doc: &str) -> String {
    format!("{}/{}", ns.as_str(), doc)
}

impl CrdtManager {
    pub fn new(store: Arc<dyn KappaStore>, clock: Arc<dyn Clock>, config: &CrdtConfig) -> Self {
        Self {
            rooms: RwLock::new(Rooms::default()),
            store,
            clock,
            max_rooms: config.max_rooms,
        }
    }

    pub async fn join(
        &self,
        ns: &NamespaceRef,
        doc: &str,
    ) -> Result<(broadcast::Receiver<Bytes>, Vec<u8>), JoinError> {
        let key = room_key(ns, doc);
        let mut rooms = loop {
            let rooms = self.rooms.write().await;
            let Some(pending) = rooms.persisting.get(&key) else {
                break rooms;
            };
            let mut pending = pending.clone();
            drop(rooms);
            // Ends when the persisting task drops its sender; it never sends.
            while pending.changed().await.is_ok() {}
        };
        if let Some(room) = rooms.active.get_mut(&key) {
            room.client_count += 1;
            return Ok((room.sender.subscribe(), room.state.clone()));
        }
        if rooms.active.len() >= self.max_rooms {
            return Err(JoinError::RoomLimitReached);
        }
        let store = self.store.clone();
        let (namespace, document) = (ns.clone(), doc.to_string());
        let loaded =
            tokio::task::spawn_blocking(move || load_state(&*store, &namespace, &document))
                .await
                .map_err(|error| {
                    JoinError::StoreError(format!("room load task failed: {error}"))
                })?;
        let state = match loaded {
            Ok(state) => state.unwrap_or_default(),
            Err(e) => {
                tracing::error!(
                    error = %e, doc = doc, ns = %ns,
                    "CRDT room load failed with store error, refusing to create room"
                );
                return Err(JoinError::StoreError(e.to_string()));
            }
        };
        let (sender, rx) = broadcast::channel(256);
        let state_clone = state.clone();
        rooms.active.insert(
            key,
            CrdtRoom {
                namespace: ns.clone(),
                doc: doc.to_string(),
                state,
                sender,
                client_count: 1,
            },
        );
        drop(rooms);
        Ok((rx, state_clone))
    }

    /// Apply a CRDT update. Returns false if the update was rejected
    /// because it would exceed the room state size limit.
    pub async fn apply_update(&self, ns: &NamespaceRef, doc: &str, update: Bytes) -> bool {
        let key = room_key(ns, doc);
        let mut rooms = self.rooms.write().await;
        if let Some(room) = rooms.active.get_mut(&key) {
            if room.state.len() + update.len() > MAX_ROOM_STATE_BYTES {
                tracing::warn!(
                    doc = doc, ns = %ns,
                    current = room.state.len(),
                    update = update.len(),
                    limit = MAX_ROOM_STATE_BYTES,
                    "CRDT room state size limit exceeded, update rejected"
                );
                return false;
            }
            room.state.extend_from_slice(&update);
            // A send fails only when no receiver is subscribed; the state
            // is accumulated regardless.
            if room.sender.send(update).is_err() {
                tracing::trace!(doc, ns = %ns, "CRDT update had no subscribers");
            }
        }
        true
    }

    /// Leave a room; the last client to leave persists its state.
    ///
    /// The room is removed and marked persisting under the rooms lock, which
    /// is then released, so other rooms proceed during the persist. A join
    /// of the same document waits on the marker and loads the published
    /// state.
    pub async fn leave(&self, ns: &NamespaceRef, doc: &str) {
        let key = room_key(ns, doc);
        let mut rooms = self.rooms.write().await;
        let last = rooms.active.get_mut(&key).is_some_and(|room| {
            room.client_count = room.client_count.saturating_sub(1);
            room.client_count == 0
        });
        let Some(room) = last.then(|| rooms.active.remove(&key)).flatten() else {
            return;
        };
        let (done, pending) = watch::channel(());
        rooms.persisting.insert(key.clone(), pending);
        drop(rooms);
        self.save_state(room).await;
        self.finish_persist(&[key], done).await;
    }

    /// Persist all active room state. Called by the server during
    /// graceful shutdown. Drains all rooms, marking each persisting.
    pub async fn shutdown(&self) {
        let (done, pending) = watch::channel(());
        let mut rooms = self.rooms.write().await;
        let drained: Vec<(String, CrdtRoom)> = rooms.active.drain().collect();
        for (key, _) in &drained {
            rooms.persisting.insert(key.clone(), pending.clone());
        }
        drop(rooms);
        let mut keys = Vec::with_capacity(drained.len());
        for (key, room) in drained {
            self.save_state(room).await;
            keys.push(key);
        }
        self.finish_persist(&keys, done).await;
    }

    /// Clear the persisting markers of `keys`, then release their waiters by
    /// dropping `done`. Clearing first means a released join finds no marker.
    async fn finish_persist(&self, keys: &[String], done: watch::Sender<()>) {
        let mut rooms = self.rooms.write().await;
        for key in keys {
            rooms.persisting.remove(key);
        }
        drop(rooms);
        drop(done);
    }

    /// Persist a room's state. There is no client left to report to, so a
    /// failure is logged.
    async fn save_state(&self, room: CrdtRoom) {
        if room.state.is_empty() {
            return;
        }
        let store = self.store.clone();
        let clock = self.clock.clone();
        let doc = room.doc.clone();
        let persisted = tokio::task::spawn_blocking(move || {
            persist_state(&*store, &room.namespace, &room.doc, &room.state, &*clock)
        })
        .await;
        match persisted {
            Ok(Ok(Some(published))) => {
                tracing::debug!(doc, epoch = published.epoch_number, "CRDT state published");
            }
            Ok(Ok(None)) => {}
            Ok(Err(error)) => tracing::error!(%error, doc, "CRDT state persist failed"),
            Err(error) => tracing::error!(%error, doc, "CRDT state persist task failed"),
        }
    }
}

/// Publish `state` as document `doc` of namespace `ns` in one execution:
/// the state content and the `_crdt/{doc}` tag naming it. State equal to the
/// published state publishes nothing and returns `None`.
///
/// Runs on a blocking worker. The state is prepared before the execution
/// takes the store's writer; an unchanged state releases the preparation
/// with the aborted execution.
pub fn persist_state(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    doc: &str,
    state: &[u8],
    clock: &dyn Clock,
) -> Result<Option<Published>, StoreError> {
    let tag = format!("_crdt/{doc}");
    let prepared = store.prepare_content(
        ContentIdentity::Computed(Axis::Sha256),
        &mut &state[..],
        PreparationBounds {
            maximum: MAX_ROOM_STATE_BYTES as u64,
            deadline: std::time::Instant::now() + kappa_handler::WRITE_DEADLINE,
        },
    )?;
    let kappa = prepared.identity().clone();
    publish_if_changed(store, ns, clock, |execution| {
        if execution
            .tag_get_raw(&tag)?
            .is_some_and(|entry| entry.kappa == kappa && entry.symref.is_none())
        {
            return Ok(false);
        }
        execution.content_install(prepared)?;
        execution.tag_put(&tag, &TagUpdate::Set { kappa })?;
        Ok(true)
    })
}

/// Published state of document `doc`, or `None` when it was never saved.
fn load_state(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    doc: &str,
) -> Result<Option<Vec<u8>>, StoreError> {
    let Some(tag) = kappa_store::absent(store.tag_get(ns, &format!("_crdt/{doc}")))? else {
        return Ok(None);
    };
    store.blob_get_in(ns, &tag.kappa).map(Some)
}

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder.route(dist_route!(
        topcoat::router::Method::GET,
        "/v2/{*ns}/_crdt/{doc}/_ws",
        handler
    ))
}

/// The request's namespace, created in its own published execution when
/// the request is its first use. Room state persists after the request has
/// ended, so the namespace must exist before the upgrade.
async fn ensure_namespace(cx: &Cx) -> Result<NamespaceRef, HandlerError> {
    match try_request_context::<ResolvedNamespace>(cx) {
        Some(ResolvedNamespace::Exists(ns)) => Ok(ns.clone()),
        Some(ResolvedNamespace::NotFound { name, protocol }) => {
            let store = kappa_handler::store(cx);
            let owner = kappa_handler::caller_anchor(cx);
            let clock = kappa_handler::service::<Arc<dyn Clock>>(cx).clone();
            let (name, protocol) = (name.clone(), protocol.clone());
            blocking(move || {
                kappa_store::namespace_ensure(
                    &*store,
                    &name,
                    owner.as_ref(),
                    protocol.as_ref(),
                    &*clock,
                )
            })
            .await
        }
        Some(ResolvedNamespace::NoNamespace) | None => {
            Err(HandlerError::bad_request("no namespace in request path"))
        }
    }
}

/// Send a close frame. The connection is ending either way; a failed send
/// means the peer is already gone.
async fn close(socket: &mut WebSocket, code: u16, reason: String) {
    if socket
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })))
        .await
        .is_err()
    {
        tracing::debug!(code, "CRDT close frame not delivered");
    }
}

async fn handler(cx: &Cx, body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let crdt: Arc<CrdtManager> = kappa_handler::try_service::<Arc<CrdtManager>>(cx)
        .cloned()
        .ok_or_else(|| HandlerError::internal("CRDT manager not configured"))?;
    let doc = path_param(cx, "doc")?;
    let ns = ensure_namespace(cx).await?;

    let upgrade = WebSocketUpgrade::from_request(cx, body)
        .await
        .map_err(|e| HandlerError::bad_request(e.to_string()))?;

    upgrade
        .protocols(["kappa-crdt.v1"])
        .max_message_size(1_048_576)
        .on_upgrade(move |mut socket| async move {
            let (mut rx, initial) = match crdt.join(&ns, &doc).await {
                Ok(result) => result,
                Err(JoinError::StoreError(reason)) => {
                    close(&mut socket, 1011, format!("room load failed: {reason}")).await;
                    return;
                }
                Err(JoinError::RoomLimitReached) => {
                    close(&mut socket, 1013, "CRDT room limit reached".into()).await;
                    return;
                }
            };

            if socket.send(Message::binary(initial)).await.is_err() {
                crdt.leave(&ns, &doc).await;
                return;
            }

            loop {
                tokio::select! {
                    update = rx.recv() => {
                        match update {
                            Ok(data) => {
                                if socket.send(Message::binary(data)).await.is_err() { break; }
                            }
                            Err(_) => break,
                        }
                    }
                    msg = socket.recv() => {
                        match msg {
                            Some(Ok(Message::Binary(data))) => {
                                if !crdt.apply_update(&ns, &doc, data).await {
                                    close(&mut socket, 1008, "room state size limit exceeded".into()).await;
                                    break;
                                }
                            }
                            Some(Ok(Message::Close(_))) | None => break,
                            _ => {}
                        }
                    }
                }
            }

            crdt.leave(&ns, &doc).await;
        })
        .map_err(|e| HandlerError::internal(e.to_string()))
}
