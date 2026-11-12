//! Authorization dependencies and the stripes that order them against
//! publication.
//!
//! An execution that decides under an authorization row (a session, a
//! credential, the trust position) records what it observed:
//!
//! - `Owned`: the row was present in its owner's view, at the revision
//!   that last wrote it. A row rewritten to an equal value has a new
//!   revision, so a revoke-and-restore between the observation and the
//!   publication is still a change;
//! - `Unowned`: no published view held the row, with the claim shard's
//!   version read with the observation. Any claim transition in that shard
//!   since, the key created and removed again included, invalidates it.
//!   A key whose claim exists but whose holder's view lacks the row (a
//!   reservation not yet published) is observed `Unowned` at that version;
//!   the reservation's settlement advances the version;
//! - `Live`: a session the execution read live at its time authorizes it
//!   only while the session's own expiry rule admits the time the
//!   publication is installed at. An unchanged row expires all the same,
//!   so a publication installed later than its execution (a retained
//!   publication resolved afterwards) is checked against the time of its
//!   installation, never the time it was prepared at.
//!
//! An execution that reserves a key it observed unowned checks the
//! observation when it reserves; the reservation then excludes every other
//! writer of the key, so the dependency needs no later check.
//!
//! Validation and the namespace pointer store run under the stripes of
//! every key the execution depends on or writes. A publication that writes
//! an authorization row holds that row's stripe across its own store, so a
//! revocation either publishes before the dependent execution validates or
//! waits until it has published: no revocation lands between a successful
//! validation and the store it authorized. Stripes are taken in ascending
//! index order and released together, and no other lock is acquired while
//! they are held except the leaf locks of claims and locators, so stripe
//! acquisition cannot deadlock.

use std::collections::BTreeSet;
use std::hash::BuildHasher;
use std::sync::{Mutex, MutexGuard, PoisonError};

use kappa_types::clock::ClockMs;
use kappa_types::work::Dimension;

use super::InMemoryStore;
use super::claims::{ClaimKey, Holder, ShardVersion};
use super::identity_local::row_revision;
use kappa_store::identity_ops::{credential_grace_live, session_expired};

const STRIPES: usize = 256;
const STRIPES_U64: u64 = 256;

/// What an execution observed of an authorization key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dependency {
    /// The row was present in `holder`'s published view, last written at
    /// `revision`.
    Owned {
        key: ClaimKey,
        holder: Holder,
        revision: u64,
    },
    /// No published view held the row; `at` is the claim shard version read
    /// with the observation.
    Unowned { key: ClaimKey, at: ShardVersion },
    /// The session `key` was live at the execution's time, with the encoded
    /// deadline `expires_at_ms` its row carries.
    Live { key: ClaimKey, expires_at_ms: i64 },
    /// A grace secret returned by a credential read remains usable only
    /// before its exclusive deadline.
    Grace { key: ClaimKey, expires_at_ms: i64 },
}

impl Dependency {
    pub const fn key(&self) -> &ClaimKey {
        match self {
            Self::Owned { key, .. }
            | Self::Unowned { key, .. }
            | Self::Live { key, .. }
            | Self::Grace { key, .. } => key,
        }
    }

    /// Whether the time-bounded authorization this observation records
    /// still holds at `now`, under the same rule its read decided by.
    /// Revision and absence observations are not time-bounded.
    pub const fn live_at(&self, now: ClockMs) -> bool {
        match self {
            Self::Live { expires_at_ms, .. } => !session_expired(*expires_at_ms, now),
            Self::Grace { expires_at_ms, .. } => credential_grace_live(*expires_at_ms, now),
            Self::Owned { .. } | Self::Unowned { .. } => true,
        }
    }
}

pub struct Stripes {
    locks: Box<[Mutex<()>]>,
    hasher: std::hash::RandomState,
}

impl Default for Stripes {
    fn default() -> Self {
        Self {
            locks: (0..STRIPES).map(|_| Mutex::new(())).collect(),
            hasher: std::hash::RandomState::new(),
        }
    }
}

/// Held stripes; released together on drop.
pub struct HeldStripes<'a> {
    _guards: Vec<MutexGuard<'a, ()>>,
}

impl Stripes {
    fn stripe_of(&self, key: &ClaimKey) -> usize {
        // The remainder is below `STRIPES`, which fits usize.
        usize::try_from(self.hasher.hash_one(key) % STRIPES_U64).unwrap_or(0)
    }

    /// Hold the stripes of every key in `keys`, in ascending order. The
    /// guarded data is `()`: a lock a panicking thread poisoned orders
    /// nothing differently, so it is taken all the same.
    pub fn hold<'k>(&self, keys: impl IntoIterator<Item = &'k ClaimKey>) -> HeldStripes<'_> {
        let stripes: BTreeSet<usize> = keys.into_iter().map(|key| self.stripe_of(key)).collect();
        HeldStripes {
            _guards: stripes
                .into_iter()
                .map(|stripe| {
                    self.locks[stripe]
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                })
                .collect(),
        }
    }
}

/// Whether writing `key` must hold its stripe across publication: the
/// authorization rows, which executions of other namespaces depend on.
pub const fn guarded(key: &ClaimKey) -> bool {
    matches!(
        key,
        ClaimKey::Session(_) | ClaimKey::Credential(_) | ClaimKey::Trust
    )
}

/// The keys whose stripes a publication holds from validation through its
/// store: every key it `depends` on and every authorization key it
/// `writes`, borrowed, so holding them copies no key.
pub fn protected_keys<'a>(
    depends: &'a [Dependency],
    writes: &'a [ClaimKey],
) -> impl Iterator<Item = &'a ClaimKey> {
    depends.iter().map(Dependency::key).chain(writes)
}

/// The work of holding the stripes of `protected_keys(depends, writes)`,
/// charged before it is done: one entry hashed per key, and the stripe
/// set and guards `Stripes::hold` allocates, at most one of each per
/// stripe.
pub fn protection_work(depends: &[Dependency], writes: &[ClaimKey]) -> [(Dimension, u64); 2] {
    let keys = depends.len().saturating_add(writes.len());
    let held = keys.min(STRIPES);
    let per_stripe = size_of::<usize>() + size_of::<MutexGuard<'static, ()>>();
    [
        (Dimension::Entries, keys as u64),
        (
            Dimension::BytesAllocated,
            held.saturating_mul(per_stripe) as u64,
        ),
    ]
}

/// Whether every dependency in `dependencies` still holds at `now`: each row
/// observed present is held by the same holder at the same revision, each
/// key observed absent is unchanged, and each time-bounded authorization is
/// still live at `now`. Called under the stripes of every dependency key.
pub fn dependencies_hold(store: &InMemoryStore, dependencies: &[Dependency], now: ClockMs) -> bool {
    dependencies.iter().all(|dependency| {
        dependency.live_at(now)
            && match dependency {
                Dependency::Owned {
                    key,
                    holder,
                    revision,
                } => {
                    store.claims.observe(key).holder == Some(*holder)
                        && store
                            .holder_view(*holder)
                            .and_then(|view| row_revision(&view, key))
                            == Some(*revision)
                }
                Dependency::Unowned { at, .. } => store.claims.unchanged(*at),
                Dependency::Live { .. } | Dependency::Grace { .. } => true,
            }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_and_grace_keep_their_distinct_deadline_rules() {
        let session = Dependency::Live {
            key: ClaimKey::Session("s".into()),
            expires_at_ms: 100,
        };
        let grace = Dependency::Grace {
            key: ClaimKey::Credential("c".into()),
            expires_at_ms: 100,
        };
        assert!(session.live_at(ClockMs::from_raw(100)));
        assert!(!session.live_at(ClockMs::from_raw(101)));
        assert!(grace.live_at(ClockMs::from_raw(99)));
        assert!(!grace.live_at(ClockMs::from_raw(100)));
    }

    #[test]
    fn stripes_order_two_holders_of_one_key() {
        let stripes = std::sync::Arc::new(Stripes::default());
        let key = ClaimKey::Session("s".into());
        let held = stripes.hold([&key]);
        let contender = std::sync::Arc::clone(&stripes);
        let (started, start) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let key = ClaimKey::Session("s".into());
            started.send(()).ok();
            drop(contender.hold([&key]));
        });
        start.recv().ok();
        assert!(
            !waiter.is_finished(),
            "a second holder of one key was admitted"
        );
        drop(held);
        assert!(waiter.join().is_ok());
    }

    #[test]
    fn duplicate_keys_take_one_stripe() {
        let stripes = Stripes::default();
        let key = ClaimKey::Trust;
        // Holding a key twice in one call must not deadlock on itself.
        drop(stripes.hold([&key, &key]));
        assert!(guarded(&key));
        assert!(!guarded(&ClaimKey::Handle("x".into())));
    }
}
