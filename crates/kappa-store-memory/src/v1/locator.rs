//! A sharded projection from a key to the namespaces whose views hold it.
//!
//! A locator never decides: a lookup takes its candidates and confirms
//! each against the candidate namespace's published view. A contribution
//! records the namespace incarnation and the revision that registered it.
//! A publication registers the keys its candidate view gained after every
//! check that can refuse it has passed and immediately before it stores
//! the view, and, still holding the namespace writer, unregisters the keys
//! the view lost after the store. Nothing between registration and the
//! store can fail, so a registration never needs undoing; and because one
//! writer per namespace performs both, a removal never races a readmission
//! of the same key by the same namespace. A contribution whose revision is
//! past the namespace's published view belongs to a publication in
//! progress and is not yet visible.
//!
//! A locator is discovery, never a dependency: absence of a candidate is
//! not evidence an execution decides under. Exclusive keys an execution
//! depends on are claims (`claims`), whose observations are versioned.
//!
//! Shards are locked for the map operation only. Lookups copy a bounded
//! number of candidates out and confirm them after the shard is released;
//! no shard is held while another namespace's view is read.

use std::collections::BTreeMap;
use std::hash::{BuildHasher, Hash};
use std::ops::Bound;
use std::sync::{PoisonError, RwLock};

use super::view::NamespaceId;

/// Shards per locator.
pub const SHARDS: usize = 64;
const SHARDS_U64: u64 = 64;

/// One namespace's contribution to a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contribution {
    pub namespace: NamespaceId,
    pub incarnation: u64,
    pub revision: u64,
}

type Owners = BTreeMap<NamespaceId, (u64, u64)>;

/// Candidates of one key.
#[derive(Debug)]
pub struct Observed {
    pub candidates: Vec<Contribution>,
    /// The namespace to continue after when more candidates exist.
    pub more: Option<NamespaceId>,
}

pub struct Locator<K> {
    shards: Box<[RwLock<BTreeMap<K, Owners>>]>,
    hasher: std::hash::RandomState,
}

impl<K: Ord + Hash + Clone> Default for Locator<K> {
    fn default() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| RwLock::new(BTreeMap::new())).collect(),
            hasher: std::hash::RandomState::new(),
        }
    }
}

/// Up to `limit` contributions of `owners` from `from`, and where to
/// continue.
fn page(
    owners: &Owners,
    from: Bound<&NamespaceId>,
    limit: usize,
) -> (Vec<Contribution>, Option<NamespaceId>) {
    // A page always makes progress, so a continuation is never lost.
    let limit = limit.max(1);
    let mut taken = Vec::new();
    let mut more = None;
    for (namespace, (incarnation, revision)) in
        owners.range::<NamespaceId, _>((from, Bound::Unbounded))
    {
        if taken.len() == limit {
            more = taken.last().map(|last: &Contribution| last.namespace);
            break;
        }
        taken.push(Contribution {
            namespace: *namespace,
            incarnation: *incarnation,
            revision: *revision,
        });
    }
    (taken, more)
}

impl<K: Ord + Hash + Clone> Locator<K> {
    fn shard_of(&self, key: &K) -> usize {
        // The remainder is below `SHARDS`, which fits usize.
        usize::try_from(self.hasher.hash_one(key) % SHARDS_U64).unwrap_or(0)
    }

    // Shard state is consistent after every statement, so a lock a
    // panicking thread poisoned is still usable.
    fn read(&self, shard: usize) -> std::sync::RwLockReadGuard<'_, BTreeMap<K, Owners>> {
        self.shards[shard]
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self, shard: usize) -> std::sync::RwLockWriteGuard<'_, BTreeMap<K, Owners>> {
        self.shards[shard]
            .write()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Record `contribution` for `key`. A key the namespace already
    /// contributes keeps its earlier contribution: the view that holds the
    /// key unchanged keeps the registration it was published under.
    pub fn register(&self, key: &K, contribution: Contribution) {
        let mut shard = self.write(self.shard_of(key));
        shard
            .entry(key.clone())
            .or_default()
            .entry(contribution.namespace)
            .or_insert((contribution.incarnation, contribution.revision));
    }

    /// Forget `namespace`'s contribution to `key` from incarnation
    /// `incarnation`, registered at or before `published`: the view that no
    /// longer holds the key replaced the view that did. Called under the
    /// namespace's writer, so no readmission of the key by the namespace
    /// can interleave.
    pub fn unregister(&self, key: &K, namespace: NamespaceId, incarnation: u64, published: u64) {
        let mut shard = self.write(self.shard_of(key));
        let Some(owners) = shard.get_mut(key) else {
            return;
        };
        if owners
            .get(&namespace)
            .is_some_and(|(held, revision)| *held == incarnation && *revision <= published)
        {
            owners.remove(&namespace);
            if owners.is_empty() {
                shard.remove(key);
            }
        }
    }

    /// Up to `limit` candidates of `key` after `after`.
    #[cfg(test)]
    pub fn observe(&self, key: &K, after: Option<&NamespaceId>, limit: usize) -> Observed {
        self.observe_from(key, after.map_or(Bound::Unbounded, Bound::Excluded), limit)
    }

    /// Up to `limit` candidates of `key` from `from`.
    pub fn observe_from(&self, key: &K, from: Bound<&NamespaceId>, limit: usize) -> Observed {
        let (candidates, more) = self
            .read(self.shard_of(key))
            .get(key)
            .map_or_else(|| (Vec::new(), None), |owners| page(owners, from, limit));
        Observed { candidates, more }
    }

    /// Up to `key_limit` keys from `lower`, in key order across every
    /// shard, each with up to `owner_limit` candidates and the namespace to
    /// continue its candidates after. A shard contributes at most
    /// `key_limit` keys, so the work is bounded by `SHARDS * key_limit`
    /// keys and `SHARDS * key_limit * owner_limit` candidates copied.
    #[allow(clippy::type_complexity)]
    pub fn range(
        &self,
        lower: Bound<&K>,
        key_limit: usize,
        owner_limit: usize,
    ) -> Vec<(K, Vec<Contribution>, Option<NamespaceId>)> {
        let mut merged: BTreeMap<K, (Vec<Contribution>, Option<NamespaceId>)> = BTreeMap::new();
        for index in 0..SHARDS {
            let shard = self.read(index);
            for (key, owners) in shard
                .range::<K, _>((lower, Bound::Unbounded))
                .take(key_limit)
            {
                if merged.len() == key_limit
                    && merged.last_key_value().is_some_and(|(last, _)| key > last)
                {
                    break;
                }
                merged.insert(key.clone(), page(owners, Bound::Unbounded, owner_limit));
            }
            drop(shard);
            while merged.len() > key_limit {
                merged.pop_last();
            }
        }
        merged
            .into_iter()
            .map(|(key, (owners, more))| (key, owners, more))
            .collect()
    }
}

#[cfg(test)]
#[path = "locator_tests.rs"]
mod tests;
