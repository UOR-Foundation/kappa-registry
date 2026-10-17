//! Resumable delivery of one namespace's mutation events from its
//! authenticated history.
//!
//! A [`Position`] names a point in the namespace's epoch chain: an epoch,
//! how many of its ledger's mutations were consumed, and that epoch's
//! signed root. Delivery reads epochs from the store, so catch-up and live
//! delivery are the same operation at different distances from the head,
//! and there is no separate buffer that could drop events.
//!
//! A position the history cannot continue from is reported as a [`Gap`]
//! instead of being waited on or skipped:
//!
//! - `ahead`: the position's epoch is past the namespace's head;
//! - `diverged`: the epoch at the position's number has another root (the
//!   namespace was recreated, or the cursor belongs to another history);
//! - `unavailable`: an epoch or ledger the delivery needs cannot be read.
//!
//! Wakeups come from the [`PublicationFeed`]; the stream subscribes before
//! its first read, so a publication racing the read is never missed.

use std::collections::VecDeque;
use std::sync::Arc;

use tokio::sync::watch;

use kappa_store::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::traits::KappaStore;

use crate::event_feed::PublicationFeed;
use crate::events::{MutationEvent, events_from_ledger};
use crate::execute::committed_ledger;

/// Events read per store pass.
pub const READ_BATCH: usize = 256;

/// A point in one namespace's history: after the first `consumed`
/// mutations of `epoch`, whose root is `root` once known. Epoch 0 is the
/// point before the first epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Position {
    pub epoch: u64,
    pub consumed: u64,
    pub root: Option<String>,
}

impl Position {
    /// Before the namespace's first epoch.
    pub const fn start() -> Self {
        Self {
            epoch: 0,
            consumed: 0,
            root: None,
        }
    }

    /// Just after `event`.
    pub fn after(event: &MutationEvent) -> Self {
        Self {
            epoch: event.epoch,
            consumed: event.index.saturating_add(1),
            root: Some(event.root.clone()),
        }
    }

    /// `0` for [`Position::start`], otherwise `epoch.consumed.root`, the
    /// form [`MutationEvent::id`] produces.
    pub fn id(&self) -> String {
        match &self.root {
            Some(root) => format!("{}.{}.{root}", self.epoch, self.consumed),
            None if self.epoch == 0 => "0".to_string(),
            None => format!("{}.{}", self.epoch, self.consumed),
        }
    }

    /// Parse `0` or `epoch.consumed.root`. The root must be a valid kappa;
    /// it is kept in its canonical form so it compares with the store's.
    pub fn parse(value: &str) -> Result<Self, String> {
        if value == "0" {
            return Ok(Self::start());
        }
        let mut parts = value.splitn(3, '.');
        let (Some(epoch), Some(consumed), Some(root)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err("event cursor must be 0 or epoch.consumed.root".into());
        };
        let epoch = parse_unsigned(epoch, "epoch")?;
        if epoch == 0 {
            return Err("event cursor epoch must be positive".into());
        }
        let consumed = parse_unsigned(consumed, "consumed count")?;
        let root = Kappa::parse(root)
            .map_err(|error| format!("event cursor root: {error}"))?
            .to_string();
        Ok(Self {
            epoch,
            consumed,
            root: Some(root),
        })
    }
}

fn parse_unsigned(value: &str, what: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("invalid event cursor {what}"));
    }
    value
        .parse()
        .map_err(|_| format!("event cursor {what} exceeds u64"))
}

/// Why history cannot continue from a position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gap {
    Ahead,
    Diverged,
    Unavailable,
}

impl Gap {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ahead => "ahead",
            Self::Diverged => "diverged",
            Self::Unavailable => "unavailable",
        }
    }
}

/// The outcome of one read of history.
#[derive(Debug)]
pub enum Read {
    /// Events after the position, in history order, and the position after
    /// the last of them.
    Events(Vec<MutationEvent>, Position),
    /// Nothing after the position yet.
    Idle,
    Gap(Gap),
}

/// The position after everything `ns` has published: where a subscriber
/// that asked for no history starts.
pub fn head_position(store: &dyn KappaStore, ns: &NamespaceRef) -> Result<Position, StoreError> {
    let (epoch, root) = match store.epoch_current(ns) {
        Ok(head) => head,
        Err(StoreError::NotFound(_)) => return Ok(Position::start()),
        Err(error) => return Err(error),
    };
    let consumed = committed_ledger(store, ns, &root)?.len() as u64;
    Ok(Position {
        epoch,
        consumed,
        root: Some(root.to_string()),
    })
}

/// Up to `limit` events of `ns` after `position`.
pub fn read_events(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    position: &Position,
    limit: usize,
) -> Result<Read, StoreError> {
    let (head, head_root) = match store.epoch_current(ns) {
        Ok(head) => head,
        Err(StoreError::NotFound(_)) if position.epoch == 0 => return Ok(Read::Idle),
        Err(StoreError::NotFound(_)) => return Ok(Read::Gap(Gap::Ahead)),
        Err(error) => return Err(error),
    };
    if position.epoch > head {
        return Ok(Read::Gap(Gap::Ahead));
    }
    let mut at = if position.epoch == 0 {
        Position {
            epoch: 1,
            consumed: 0,
            root: None,
        }
    } else {
        position.clone()
    };
    let mut out = Vec::new();
    while out.len() < limit && at.epoch <= head {
        let root = if at.epoch == head {
            head_root.clone()
        } else {
            match store.epoch_get_by_number(ns, at.epoch) {
                Ok(root) => root,
                Err(StoreError::NotFound(_)) => return Ok(Read::Gap(Gap::Unavailable)),
                Err(error) => return Err(error),
            }
        };
        let root_id = root.to_string();
        if at
            .root
            .as_ref()
            .is_some_and(|expected| *expected != root_id)
        {
            return Ok(Read::Gap(Gap::Diverged));
        }
        let mutations = match committed_ledger(store, ns, &root) {
            Ok(mutations) => mutations,
            Err(StoreError::NotFound(_)) => return Ok(Read::Gap(Gap::Unavailable)),
            Err(error) => return Err(error),
        };
        let total = mutations.len() as u64;
        if at.consumed > total {
            return Ok(Read::Gap(Gap::Diverged));
        }
        let skip = usize::try_from(at.consumed)
            .map_err(|_| StoreError::Internal("event cursor exceeds addressable ledger".into()))?;
        let take = (limit - out.len()).min(mutations.len() - skip);
        let events = events_from_ledger(
            ns.display_name(),
            at.epoch,
            &root,
            &mutations[skip..skip + take],
        )?;
        out.extend(events.into_iter().map(|mut event| {
            event.index += at.consumed;
            event
        }));
        at.consumed += take as u64;
        at.root = Some(root_id);
        if at.consumed < total || at.epoch == head {
            break;
        }
        at = Position {
            epoch: at.epoch + 1,
            consumed: 0,
            root: None,
        };
    }
    if out.is_empty() {
        return Ok(Read::Idle);
    }
    Ok(Read::Events(out, at))
}

/// What a stream yields.
#[derive(Debug)]
pub enum Delivery {
    Event(MutationEvent),
    /// History cannot continue from `after`, the position of the last
    /// event delivered. The stream yields nothing further until it is
    /// repositioned.
    Gap {
        gap: Gap,
        after: Position,
    },
}

type Filter = Box<dyn Fn(&MutationEvent) -> bool + Send + Sync>;

/// A resumable subscription to one namespace's events.
///
/// [`EventStream::next`] is cancel-safe: the position advances only when
/// an event is returned, so dropping a pending call loses nothing.
pub struct EventStream {
    store: Arc<dyn KappaStore>,
    namespace: NamespaceRef,
    changed: watch::Receiver<u64>,
    position: Position,
    pending: VecDeque<MutationEvent>,
    filter: Filter,
    stopped: bool,
}

impl EventStream {
    /// Subscribe to `namespace` from `position`. The feed subscription is
    /// taken here, before any read.
    pub fn new(
        store: Arc<dyn KappaStore>,
        feed: &PublicationFeed,
        namespace: NamespaceRef,
        position: Position,
    ) -> Self {
        Self {
            changed: feed.watch(&namespace),
            store,
            namespace,
            position,
            pending: VecDeque::new(),
            filter: Box::new(|_| true),
            stopped: false,
        }
    }

    /// Deliver only events `filter` accepts; the others still advance the
    /// position.
    pub fn set_filter(&mut self, filter: impl Fn(&MutationEvent) -> bool + Send + Sync + 'static) {
        self.filter = Box::new(filter);
    }

    /// Continue from `position` instead, resuming a stopped stream.
    pub fn reposition(&mut self, position: Position) {
        self.position = position;
        self.pending.clear();
        self.stopped = false;
    }

    pub const fn position(&self) -> &Position {
        &self.position
    }

    pub const fn stopped(&self) -> bool {
        self.stopped
    }

    /// The next delivered event, or the gap that stops the stream. A
    /// stopped stream pends until it is repositioned.
    pub async fn next(&mut self) -> Delivery {
        let mut skipped = 0usize;
        loop {
            if self.stopped {
                std::future::pending::<()>().await;
            }
            while let Some(event) = self.pending.pop_front() {
                self.position = Position::after(&event);
                if (self.filter)(&event) {
                    return Delivery::Event(event);
                }
                skipped += 1;
                // A permanently rejecting filter must not monopolize an
                // executor thread while history replenishes.
                if skipped == READ_BATCH {
                    skipped = 0;
                    tokio::task::yield_now().await;
                }
            }
            // Acknowledge notices before the read: a publication after it
            // leaves the receiver changed, so the wait below returns.
            self.changed.borrow_and_update();
            let store = Arc::clone(&self.store);
            let namespace = self.namespace.clone();
            let position = self.position.clone();
            let read = tokio::task::spawn_blocking(move || {
                read_events(&*store, &namespace, &position, READ_BATCH)
            })
            .await;
            match read {
                Ok(Ok(Read::Events(events, _))) => self.pending = events.into(),
                Ok(Ok(Read::Idle)) => {
                    if self.changed.changed().await.is_err() {
                        return self.stop(Gap::Unavailable);
                    }
                }
                Ok(Ok(Read::Gap(gap))) => return self.stop(gap),
                Ok(Err(error)) => {
                    tracing::warn!(%error, namespace = %self.namespace, "event history read failed");
                    return self.stop(Gap::Unavailable);
                }
                Err(error) => {
                    tracing::error!(%error, namespace = %self.namespace, "event history task failed");
                    return self.stop(Gap::Unavailable);
                }
            }
        }
    }

    fn stop(&mut self, gap: Gap) -> Delivery {
        self.stopped = true;
        Delivery::Gap {
            gap,
            after: self.position.clone(),
        }
    }
}
