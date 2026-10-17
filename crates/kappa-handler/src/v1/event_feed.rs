//! Publication notices: the wakeup side of event delivery.
//!
//! A notice says that a namespace published an epoch. It carries no
//! events: a consumer rereads authenticated history from the store
//! ([`crate::event_stream`]), so a lost, coalesced or duplicated notice
//! can delay delivery but can never lose, reorder or invent an event.
//!
//! Two views of the same notices:
//!
//! - per namespace, a `watch` of the namespace's latest published epoch,
//!   which wakes the subscribers of that namespace only. The watch of a
//!   namespace exists while it has a subscriber; a publication to a
//!   namespace nobody watches drops its entry, so the map is bounded by
//!   the namespaces currently watched;
//! - registry-wide, a bounded ring of the most recent notices, each holding
//!   a range of feed sequence numbers, one per mutation of its epoch. The
//!   ring is what a registry-wide consumer (the AT Protocol firehose)
//!   resumes from; a cursor older than the ring is reported as outdated,
//!   never silently skipped.

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};

use dashmap::DashMap;
use tokio::sync::watch;

use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;

/// One publication: `count` feed sequence numbers starting at `sequence`,
/// one per mutation of `epoch`, whose signed root is `root`.
#[derive(Debug, Clone)]
pub struct Notice {
    pub sequence: u64,
    pub count: u64,
    pub namespace: NamespaceRef,
    pub epoch: u64,
    pub root: Kappa,
}

impl Notice {
    /// The last feed sequence number this notice holds, or the one before
    /// its first when it holds none.
    pub const fn last(&self) -> u64 {
        self.sequence.saturating_add(self.count).saturating_sub(1)
    }
}

/// Notices after a cursor and the ring's bounds when they were captured.
#[derive(Debug, Clone)]
pub struct NoticeBatch {
    pub notices: Vec<Notice>,
    /// The first sequence number the ring still holds; a cursor before
    /// `oldest - 1` names discarded notices.
    pub oldest: u64,
    /// The sequence number the next notice will start at; a cursor at or
    /// past it names history this feed never produced.
    pub next: u64,
}

struct Ring {
    notices: VecDeque<Notice>,
    next: u64,
}

/// Notices of every publication this process makes.
pub struct PublicationFeed {
    heads: DashMap<[u8; 16], watch::Sender<u64>>,
    ring: Mutex<Ring>,
    capacity: usize,
    changed: watch::Sender<u64>,
}

impl PublicationFeed {
    /// A feed retaining `capacity` notices whose first notice starts at
    /// feed sequence `first_sequence` (at least 1).
    pub fn new(capacity: usize, first_sequence: u64) -> Self {
        let first_sequence = first_sequence.max(1);
        Self {
            heads: DashMap::new(),
            ring: Mutex::new(Ring {
                notices: VecDeque::with_capacity(capacity.min(4096)),
                next: first_sequence,
            }),
            capacity,
            changed: watch::channel(first_sequence - 1).0,
        }
    }

    /// Record that `namespace` published `epoch` with signed root `root`
    /// and `count` mutations.
    pub fn publish(&self, namespace: &NamespaceRef, epoch: u64, root: &Kappa, count: u64) {
        let id = *namespace.id();
        let watched = self.heads.get(&id).map(|head| {
            head.send_replace(epoch);
            head.receiver_count() != 0
        });
        if watched == Some(false) {
            self.heads
                .remove_if(&id, |_, head| head.receiver_count() == 0);
        }
        // Ring state is consistent after every statement, so a poisoned
        // lock (a panic elsewhere while it was held) leaves usable state.
        let mut ring = self.ring.lock().unwrap_or_else(PoisonError::into_inner);
        let sequence = ring.next;
        ring.next = sequence.saturating_add(count);
        ring.notices.push_back(Notice {
            sequence,
            count,
            namespace: namespace.clone(),
            epoch,
            root: root.clone(),
        });
        while ring.notices.len() > self.capacity {
            ring.notices.pop_front();
        }
        let latest = ring.next.saturating_sub(1);
        drop(ring);
        self.changed.send_replace(latest);
    }

    /// A watch of `namespace`'s latest published epoch. Subscribe before
    /// reading history: a publication after the subscription marks the
    /// receiver changed, so no wakeup is lost between the read and the
    /// wait.
    pub fn watch(&self, namespace: &NamespaceRef) -> watch::Receiver<u64> {
        self.heads
            .entry(*namespace.id())
            .or_insert_with(|| watch::channel(0).0)
            .subscribe()
    }

    /// A watch of the latest feed sequence number of any publication.
    pub fn watch_all(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    /// Up to `limit` notices holding a sequence number after `after`.
    pub fn after(&self, after: u64, limit: usize) -> NoticeBatch {
        let ring = self.ring.lock().unwrap_or_else(PoisonError::into_inner);
        NoticeBatch {
            notices: ring
                .notices
                .iter()
                .filter(|notice| notice.count != 0 && notice.last() > after)
                .take(limit)
                .cloned()
                .collect(),
            oldest: ring
                .notices
                .front()
                .map_or(ring.next, |notice| notice.sequence),
            next: ring.next,
        }
    }

    /// Namespaces with a watch entry; bounded by the namespaces watched.
    pub fn watched(&self) -> usize {
        self.heads.len()
    }
}
