//! Identity-directed discovery of committed content settlement has not yet
//! projected.
//!
//! The completed catalog projection (`projection::Family::Catalog`)
//! locates content for a read that names no
//! namespace, but it lags every commit by design. This index covers the
//! lag: each publication registers the identities its transaction
//! installed rows for, under its storage instance, before it commits; the
//! registration is owned by the publication's [`crate::unsettled::Parked`]
//! ownership and dropped with it, which happens on a known noncommit, after
//! recovery for an unknown outcome, or after settlement projected the epoch
//! into the catalog. Recovery registers the identities of epochs a restart
//! found unsettled, in bounded chunks, each its own [`Registration`].
//! Content committed before a read is therefore either registered here,
//! already in the catalog, or covered by an explicit discovery gap
//! (`store_access::Coverage`), and a lookup is one keyed probe whatever the
//! number of unsettled namespaces.
//!
//! Beside content identities the index registers identity predicates a
//! query must answer completely: the revocations and the watermarks an
//! asserter issued ([`DiscoveryKey`]). A revocation's own identity is not
//! known to a caller asking whether an asserter's assertion stands, so it
//! is discovered by the predicate, never by scanning unsettled namespaces.
//!
//! The index is a locator, never evidence: every candidate is confirmed by
//! its instance's committed row. Its population is bounded by
//! `max_identities`; a publication whose registration would exceed it is
//! refused before it commits (backpressure, never discard). Registrations
//! are counted per (key, instance), so two unsettled epochs of one
//! instance registering one key hold it until both settle.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use kappa_store::{Kappa, StoreError};

use crate::storage_instance::StorageInstance;

const SHARDS: usize = 64;

/// What a registration makes discoverable before settlement projects it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DiscoveryKey {
    /// A row of the content with this identity.
    Content(Kappa),
    /// A revocation issued by this asserter.
    RevocationsBy(Kappa),
    /// A watermark issued by this asserter.
    WatermarksBy(Kappa),
}

impl DiscoveryKey {
    const fn kappa(&self) -> &Kappa {
        match self {
            Self::Content(kappa) | Self::RevocationsBy(kappa) | Self::WatermarksBy(kappa) => kappa,
        }
    }
}

type Shard = BTreeMap<DiscoveryKey, BTreeMap<StorageInstance, u64>>;

/// Unsettled keys by the storage instances that registered them.
pub struct UnsettledIndex {
    shards: Vec<Mutex<Shard>>,
    max_identities: u64,
    held: Mutex<u64>,
}

/// The keys one publication, or one recovery chunk, registered; removed
/// from the index when dropped.
pub struct Registration {
    index: Arc<UnsettledIndex>,
    instance: StorageInstance,
    identities: Vec<DiscoveryKey>,
}

impl UnsettledIndex {
    pub fn new(max_identities: u64) -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(Shard::new())).collect(),
            max_identities,
            held: Mutex::new(0),
        }
    }

    /// The shard holding `identity`. A shard is changed only by single
    /// map-entry insertions and removals, so a panic elsewhere while it was
    /// held cannot leave it half-written; a poisoned shard is recovered
    /// rather than turning every later registration, release and lookup of
    /// its identities into an error.
    fn shard(&self, identity: &DiscoveryKey) -> MutexGuard<'_, Shard> {
        self.slot(identity)
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The shard mutex `identity` is selected into.
    fn slot(&self, identity: &DiscoveryKey) -> &Mutex<Shard> {
        let key = identity.kappa().key_bytes();
        let selector = key.last().copied().unwrap_or_default();
        &self.shards[usize::from(selector) % SHARDS]
    }

    fn held(&self) -> MutexGuard<'_, u64> {
        // The count is a plain integer updated in one statement; a panic
        // elsewhere while it was held cannot leave it half-written.
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Register `identities` under `instance`. Refused, registering
    /// nothing, when the index would exceed its bound.
    pub fn register(
        self: &Arc<Self>,
        instance: StorageInstance,
        identities: Vec<DiscoveryKey>,
    ) -> Result<Registration, StoreError> {
        self.insert(instance, identities, true)
    }

    /// Register identities that are already committed whether or not the
    /// bound admits them: unsettled epochs a restart found. The population
    /// may exceed the bound; while it does, every bounded registration is
    /// refused, so no fresh publication is admitted against discovery
    /// capacity this one holds. Overflow of the counter is still refused.
    pub fn register_beyond_bound(
        self: &Arc<Self>,
        instance: StorageInstance,
        identities: Vec<DiscoveryKey>,
    ) -> Result<Registration, StoreError> {
        self.insert(instance, identities, false)
    }

    fn insert(
        self: &Arc<Self>,
        instance: StorageInstance,
        mut identities: Vec<DiscoveryKey>,
        bounded: bool,
    ) -> Result<Registration, StoreError> {
        identities.sort();
        identities.dedup();
        let count = u64::try_from(identities.len())
            .map_err(|_| StoreError::CapacityExceeded("registration size exceeds u64".into()))?;
        let mut held = self.held();
        let next = held
            .checked_add(count)
            .filter(|next| !bounded || *next <= self.max_identities)
            .ok_or_else(|| {
                StoreError::CapacityExceeded(format!(
                    "unsettled identity index at {} of {} cannot register {count}; settlement must catch up",
                    *held, self.max_identities
                ))
            })?;
        *held = next;
        drop(held);
        for identity in &identities {
            let mut shard = self.shard(identity);
            let count = shard
                .entry(identity.clone())
                .or_default()
                .entry(instance)
                .or_insert(0);
            *count = count.saturating_add(1);
            drop(shard);
        }
        Ok(Registration {
            index: Arc::clone(self),
            instance,
            identities,
        })
    }

    /// The storage instances holding an unsettled registration of
    /// `identity`.
    pub fn candidates(&self, identity: &DiscoveryKey) -> Vec<StorageInstance> {
        self.shard(identity)
            .get(identity)
            .map(|owners| owners.keys().copied().collect())
            .unwrap_or_default()
    }

    /// The identities currently registered, across every instance.
    #[cfg(test)]
    pub fn held_identities(&self) -> u64 {
        *self.held()
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        for identity in &self.identities {
            let mut shard = self.index.shard(identity);
            if let Some(owners) = shard.get_mut(identity) {
                if let Some(count) = owners.get_mut(&self.instance) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        owners.remove(&self.instance);
                    }
                }
                if owners.is_empty() {
                    shard.remove(identity);
                }
            }
        }
        let released = u64::try_from(self.identities.len()).unwrap_or(u64::MAX);
        let mut held = self.index.held();
        *held = held.saturating_sub(released);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_instance::Incarnation;

    fn instance(byte: u8) -> StorageInstance {
        StorageInstance::new([byte; 16], Incarnation::Known([byte; 16]))
    }

    fn content(name: &[u8]) -> DiscoveryKey {
        DiscoveryKey::Content(Kappa::sha256(name))
    }

    #[test]
    fn registrations_are_counted_bounded_and_released_on_drop() -> Result<(), StoreError> {
        let index = Arc::new(UnsettledIndex::new(3));
        let a = content(b"a");
        let b = content(b"b");
        let first = index.register(instance(1), vec![a.clone(), a.clone(), b.clone()])?;
        assert_eq!(index.held_identities(), 2, "duplicates register once");
        let second = index.register(instance(1), vec![a.clone()])?;
        assert!(matches!(
            index.register(instance(2), vec![b.clone()]),
            Err(StoreError::CapacityExceeded(_))
        ));
        assert_eq!(
            index.held_identities(),
            3,
            "a refused registration holds nothing"
        );
        assert_eq!(index.candidates(&a), vec![instance(1)]);
        drop(first);
        assert_eq!(
            index.candidates(&a),
            vec![instance(1)],
            "the second epoch still holds a"
        );
        assert!(index.candidates(&b).is_empty());
        drop(second);
        assert!(index.candidates(&a).is_empty());
        assert_eq!(index.held_identities(), 0);
        let both = index.register(instance(2), vec![b.clone()])?;
        let other = index.register(instance(3), vec![b.clone()])?;
        assert_eq!(index.candidates(&b), vec![instance(2), instance(3)]);
        drop((both, other));
        assert!(index.candidates(&content(b"absent")).is_empty());
        Ok(())
    }

    /// A predicate key is discovered by its predicate alone, and never
    /// answers a content lookup of the same identity, nor the reverse.
    #[test]
    fn predicate_keys_are_distinct_from_content_keys() -> Result<(), StoreError> {
        let index = Arc::new(UnsettledIndex::new(4));
        let asserter = Kappa::sha256(b"asserter");
        let revocations = DiscoveryKey::RevocationsBy(asserter.clone());
        let held = index.register(instance(4), vec![revocations.clone()])?;
        assert_eq!(index.candidates(&revocations), vec![instance(4)]);
        assert!(
            index
                .candidates(&DiscoveryKey::Content(asserter.clone()))
                .is_empty()
        );
        assert!(
            index
                .candidates(&DiscoveryKey::WatermarksBy(asserter))
                .is_empty()
        );
        drop(held);
        assert!(index.candidates(&revocations).is_empty());
        Ok(())
    }

    /// Two instances of one namespace hold separate registrations: an old
    /// instance's release never removes a new instance's candidate.
    #[test]
    fn instances_of_one_namespace_register_separately() -> Result<(), StoreError> {
        let index = Arc::new(UnsettledIndex::new(4));
        let a = content(b"shared");
        let old = StorageInstance::new([9; 16], Incarnation::Known([1; 16]));
        let new = StorageInstance::new([9; 16], Incarnation::Known([2; 16]));
        let held_old = index.register(old, vec![a.clone()])?;
        let held_new = index.register(new, vec![a.clone()])?;
        drop(held_old);
        assert_eq!(index.candidates(&a), vec![new]);
        drop(held_new);
        assert!(index.candidates(&a).is_empty());
        Ok(())
    }

    type Register = fn(
        &Arc<UnsettledIndex>,
        StorageInstance,
        Vec<DiscoveryKey>,
    ) -> Result<Registration, StoreError>;

    /// Registration as it was: the count is charged, then each shard is
    /// locked fallibly, so an already poisoned shard returns midway with
    /// the count charged and no `Registration` to release it.
    fn fallible_lock_register(
        index: &Arc<UnsettledIndex>,
        instance: StorageInstance,
        mut identities: Vec<DiscoveryKey>,
    ) -> Result<Registration, StoreError> {
        identities.sort();
        identities.dedup();
        let count = u64::try_from(identities.len())
            .map_err(|_| StoreError::CapacityExceeded("registration size exceeds u64".into()))?;
        let mut held = index.held();
        *held = held.saturating_add(count);
        drop(held);
        for identity in &identities {
            let mut shard = index.slot(identity).lock().map_err(|_| {
                StoreError::Internal("unsettled identity index shard poisoned".into())
            })?;
            let count = shard
                .entry(identity.clone())
                .or_default()
                .entry(instance)
                .or_insert(0);
            *count = count.saturating_add(1);
            drop(shard);
        }
        Ok(Registration {
            index: Arc::clone(index),
            instance,
            identities,
        })
    }

    /// Panic while holding the shard of `identity`, which poisons it.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the guard is held through the panic: that is what poisons the shard"
    )]
    fn poison(index: &UnsettledIndex, identity: &DiscoveryKey) {
        let held = index.shard(identity);
        panic!("poison the shard while holding {} entries", held.len());
    }

    /// Whether `register`, on an index whose shard was poisoned by a panic
    /// elsewhere, registers the identity, answers lookups with it, and
    /// leaves neither the identity nor its count behind once released.
    fn tolerates_a_poisoned_shard(register: Register) -> bool {
        let index = Arc::new(UnsettledIndex::new(4));
        let a = content(b"poisoned");
        let poisoner = std::thread::scope(|scope| scope.spawn(|| poison(&index, &a)).join());
        assert!(
            poisoner.is_err() && index.slot(&a).is_poisoned(),
            "control: the identity's shard is poisoned"
        );
        let registration = register(&index, instance(7), vec![a.clone()]).ok();
        let answered = registration.is_some() && index.candidates(&a) == vec![instance(7)];
        drop(registration);
        answered && index.candidates(&a).is_empty() && index.held_identities() == 0
    }

    #[test]
    fn a_poisoned_shard_still_registers_releases_and_answers() {
        assert!(
            !tolerates_a_poisoned_shard(fallible_lock_register),
            "control: the check catches the leaked count of the fallible lock"
        );
        assert!(tolerates_a_poisoned_shard(UnsettledIndex::register));
    }
}
