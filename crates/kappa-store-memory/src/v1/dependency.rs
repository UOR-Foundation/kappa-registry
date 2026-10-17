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
//!   the reservation's settlement advances the version.
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

use super::claims::{ClaimKey, Holder, ShardVersion};

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
}

impl Dependency {
    pub const fn key(&self) -> &ClaimKey {
        match self {
            Self::Owned { key, .. } | Self::Unowned { key, .. } => key,
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
pub struct Held<'a> {
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
    pub fn hold<'k>(&self, keys: impl IntoIterator<Item = &'k ClaimKey>) -> Held<'_> {
        let stripes: BTreeSet<usize> = keys.into_iter().map(|key| self.stripe_of(key)).collect();
        Held {
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

#[cfg(test)]
mod tests {
    use super::*;

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
