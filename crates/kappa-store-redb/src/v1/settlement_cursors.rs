//! The epoch cursors settlement and recovery keep across steps
//! (`settlement_ledger`), at most one per storage instance and purpose,
//! each owning one activity grant of its namespace until it is verified or
//! discarded, and each charged one unit of the store's cursor pool
//! ([`CapacityPool`], `max_epoch_cursors` units) for as long as it lives.
//!
//! A cursor's charge is owned by exactly one of:
//!
//! - the map, between steps (`by_key`);
//! - one [`CheckedOut`] guard, while its read advances, registered under a
//!   lease (`out`) that names its instance and purpose and whether an
//!   invalidation revoked it;
//! - one [`Releasing`] owner, while a cursor invalidation detached from the
//!   map ends (`releasing`).
//!
//! Every transfer between them, reserving a new charge and releasing one,
//! happens under the one `EpochCursors` lock, so the pool's use always
//! equals `by_key.len() + out.len() + releasing`
//! ([`EpochCursors::assert_accounted`]). A cursor (and its activity grant,
//! whose end may evict the namespace) ends outside the lock, and only then
//! is its charge released under it: a grant never outlives its charge.
//!
//! Leases are issued only when a checked-out owner is created, never
//! wrapped, and bounded in number by the pool. Invalidation (`forget_*`)
//! issues nothing: it revokes the matching checked-out owners and detaches
//! the matching retained ones in one hold of the lock. A revoked owner is
//! never retained; its read is read again from its start, its consumer told
//! to restart.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use kappa_store::capacity::{CapacityError, CapacityPool, Reservation};
use kappa_store::work::{Meter, Work};
use kappa_store::{EpochRoot, StoreError};

use super::apply::ElementPreparation;
use super::ledger::{Advance, CursorOpen, EpochCursor};
use super::stage::Staged;
use super::SettlementStop;
use crate::storage_instance::StorageInstance;
use crate::PersistentStore;

#[cfg(test)]
#[path = "settlement_cursors_tests.rs"]
mod tests;

/// Why an epoch is being read: its consumers stage different things, so
/// each keeps its own cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Purpose {
    /// Projection into the registry, advancing `SETTLED`.
    Settle,
    /// Measurement and registration of pre-restart ownership.
    Reconstruct,
}

/// What one read of an epoch reached.
pub enum EpochRead {
    /// The epoch is read and verified: everything delivered is admitted.
    Verified(EpochRoot),
    /// The resource named stopped the read part way (the meter refused the
    /// next unit, or the consumer deferred the element pending); calling
    /// again with the same resources cannot advance it. The cursor is kept
    /// for the next read, its pending element with it, once the consumer's
    /// work is known committed ([`EpochReadGuard::committed`]), unless an
    /// invalidation revoked it meanwhile: the next read then opens the epoch
    /// afresh and restarts its consumer.
    Pending(SettlementStop),
    /// No read was opened: the resource named was unavailable. No effect
    /// was delivered and the consumer was not restarted; work performed
    /// while attempting admission stays charged.
    Deferred(SettlementStop),
}

/// Whether a consumer applied an element or deferred it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectProgress {
    /// Every effect is applied and the element finished.
    Applied,
    /// Nothing is applied: the resource named was unavailable. The element
    /// stays pending in the cursor and is delivered again.
    Deferred(SettlementStop),
}

/// One element of an epoch delivered for application: its effects, the
/// preparation of them retained with the pending element (built by the
/// consumer, kept by the cursor across deferrals), the work the cursor does
/// once they are applied (`finalization`), and that work itself, which the
/// consumer runs ([`Self::finish`]) inside the one unit it admitted for the
/// element, after its effects are applied.
pub struct Element<'a> {
    effects: &'a [Staged],
    prepared: &'a mut Option<ElementPreparation>,
    finalization: Work,
    finish: &'a mut dyn FnMut(&mut dyn Meter) -> Result<(), StoreError>,
}

impl<'a> Element<'a> {
    pub(super) fn new(
        effects: &'a [Staged],
        prepared: &'a mut Option<ElementPreparation>,
        finalization: Work,
        finish: &'a mut dyn FnMut(&mut dyn Meter) -> Result<(), StoreError>,
    ) -> Self {
        Self {
            effects,
            prepared,
            finalization,
            finish,
        }
    }

    /// The element's effects, in emission order.
    pub(super) const fn effects(&self) -> &'a [Staged] {
        self.effects
    }

    /// The preparation retained with the element, taken for one delivery.
    pub(super) fn take_prepared(&mut self) -> Option<ElementPreparation> {
        self.prepared.take()
    }

    /// Return the preparation to the element, kept with it while it stays
    /// pending. A kept preparation outlives its transaction, so its
    /// registry-dependent writes are marked stale here, the one path every
    /// retained preparation takes.
    pub(super) fn keep_prepared(&mut self, mut prepared: ElementPreparation) {
        prepared.retained_between_transactions();
        *self.prepared = Some(prepared);
    }

    /// The bound of the cursor's work once the effects are applied, to be
    /// admitted with them.
    pub(super) const fn finalization(&self) -> &Work {
        &self.finalization
    }

    /// Move the cursor past the element, its work accounted on `unit`, the
    /// unit admitted for the element. Called once, after every effect is
    /// applied and before `EffectProgress::Applied` is returned.
    pub(super) fn finish(&mut self, unit: &mut dyn Meter) -> Result<(), StoreError> {
        (self.finish)(unit)
    }
}

/// What an epoch's effects are delivered to.
pub trait EpochConsumer {
    /// The epoch is being read from its start, within `work`: anything
    /// staged from an earlier read of it is stale.
    fn restart(&mut self, work: &mut dyn Meter) -> Result<(), StoreError>;

    /// Apply every effect of `element` or none, within `work`: whatever is
    /// prepared is charged as it is done, then one unit is admitted for the
    /// element's application and its finalization, the effects applied and
    /// the element finished inside it. A resource unavailable before that
    /// unit is admitted defers the element, applying nothing; the work done
    /// by then stays charged. The effects are unadmitted until the read is
    /// verified.
    fn apply(
        &mut self,
        element: Element<'_>,
        work: &mut dyn Meter,
    ) -> Result<EffectProgress, StoreError>;
}

/// The key a cursor is kept under.
type Key = (StorageInstance, Purpose);

/// A cursor between steps with the charge it holds. Fields drop in
/// declaration order: the cursor and its grant, then the charge.
struct Held {
    cursor: EpochCursor,
    charge: Reservation,
}

/// The record of one checked-out owner.
struct Checkout {
    instance: StorageInstance,
    purpose: Purpose,
    /// An invalidation of its instance or namespace ran while it was out:
    /// it is never retained.
    revoked: bool,
}

/// The cursors between steps, the checked-out owners by lease, the owners
/// being released, and the pool each is charged to.
pub struct EpochCursors {
    by_key: BTreeMap<Key, Held>,
    next_lease: u64,
    out: BTreeMap<u64, Checkout>,
    releasing: u64,
    pool: Arc<CapacityPool>,
}

impl EpochCursors {
    /// No cursor, room for `capacity`.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            by_key: BTreeMap::new(),
            next_lease: 0,
            out: BTreeMap::new(),
            releasing: 0,
            pool: Arc::new(CapacityPool::new(
                "settlement epoch cursors",
                u64::try_from(capacity).unwrap_or(u64::MAX),
            )),
        }
    }

    /// The next lease number, refused rather than wrapped. Nothing is
    /// changed until the caller registers it (`register`).
    fn available_lease(&self) -> Result<u64, StoreError> {
        if self.next_lease == u64::MAX {
            return Err(StoreError::Internal(
                "settlement cursor lease numbers exhausted".into(),
            ));
        }
        Ok(self.next_lease)
    }

    /// Register `lease`, obtained from `available_lease` under this hold of
    /// the lock, as checked out for `key`.
    fn register(&mut self, lease: u64, key: Key) {
        self.next_lease = lease + 1;
        self.out.insert(
            lease,
            Checkout {
                instance: key.0,
                purpose: key.1,
                revoked: false,
            },
        );
    }

    /// Revoke every checked-out owner whose key `matches`, and detach every
    /// retained cursor whose key `matches` into owners that release them.
    fn invalidate(&mut self, matches: impl Fn(&Key) -> bool) -> Vec<Held> {
        for checkout in self.out.values_mut() {
            if matches(&(checkout.instance, checkout.purpose)) {
                checkout.revoked = true;
            }
        }
        let detached: Vec<Held> = self
            .by_key
            .extract_if(.., |key, _| matches(key))
            .map(|(_, held)| held)
            .collect();
        self.releasing += detached.len() as u64;
        detached
    }

    /// The pool's use is exactly the cursors held, checked out and being
    /// released. Read under the lock every change is made under.
    #[cfg(test)]
    fn assert_accounted(&self) {
        assert_eq!(
            self.pool.used(),
            self.by_key.len() as u64 + self.out.len() as u64 + self.releasing,
            "every cursor charge is owned by the map, one checked-out owner, or one releasing owner"
        );
    }
}

/// What returning a checked-out cursor to the map did.
pub(super) enum Retention {
    /// The cursor and its charge are held by the map.
    Retained,
    /// An invalidation revoked the owner while it was out: nothing was
    /// retained, and the guard releases its cursor and charge.
    Revoked,
}

/// One cursor's charge, and its cursor once opened or taken from the map,
/// owned outside the map under its lease. Dropping it releases both (see
/// the module documentation); [`Self::retain`] returns the cursor to the
/// map instead.
struct CheckedOut<'s> {
    cursors: &'s Mutex<EpochCursors>,
    lease: u64,
    cursor: Option<EpochCursor>,
    charge: Option<Reservation>,
}

impl<'s> CheckedOut<'s> {
    /// Take the cursor of `key` out of the map, if one is held. A lease
    /// that cannot be issued leaves the retained cursor where it was.
    fn take(cursors: &'s Mutex<EpochCursors>, key: Key) -> Result<Option<Self>, StoreError> {
        let mut locked = lock(cursors);
        if !locked.by_key.contains_key(&key) {
            return Ok(None);
        }
        let lease = locked.available_lease()?;
        let Some(held) = locked.by_key.remove(&key) else {
            return Ok(None);
        };
        locked.register(lease, key);
        drop(locked);
        Ok(Some(Self {
            cursors,
            lease,
            cursor: Some(held.cursor),
            charge: Some(held.charge),
        }))
    }

    /// Reserve the charge of a new cursor for `key`; `None` when the pool
    /// is full.
    fn reserve(cursors: &'s Mutex<EpochCursors>, key: Key) -> Result<Option<Self>, StoreError> {
        let mut locked = lock(cursors);
        let lease = locked.available_lease()?;
        let charge = match locked.pool.reserve(1) {
            Ok(charge) => charge,
            Err(CapacityError::Exhausted { .. }) => return Ok(None),
            Err(error) => return Err(StoreError::CapacityExceeded(error.to_string())),
        };
        locked.register(lease, key);
        drop(locked);
        Ok(Some(Self {
            cursors,
            lease,
            cursor: None,
            charge: Some(charge),
        }))
    }

    fn cursor(&mut self) -> Result<&mut EpochCursor, StoreError> {
        self.cursor
            .as_mut()
            .ok_or_else(|| StoreError::Internal("checked-out cursor holds no cursor".into()))
    }

    /// The epoch the owned cursor reads. A guard holding no cursor here is
    /// a defect of this module, refused rather than taken as stale.
    fn epoch(&self) -> Result<u64, StoreError> {
        self.cursor
            .as_ref()
            .map(EpochCursor::epoch)
            .ok_or_else(|| StoreError::Internal("checked-out cursor holds no cursor".into()))
    }

    /// Return the cursor to the map under its lease's key, its charge with
    /// it, unless an invalidation revoked the lease. An entry already held
    /// under the key is left untouched and refused. Whenever nothing is
    /// retained this guard keeps its resources, and its drop releases them.
    fn retain(mut self) -> Result<Retention, StoreError> {
        if self.cursor.is_none() || self.charge.is_none() {
            return Err(StoreError::Internal(
                "a cursor is retained without its cursor or charge".into(),
            ));
        }
        // The lock is released before `self` drops on any return: locals
        // drop before parameters.
        let mut locked = lock(self.cursors);
        let (key, revoked) = {
            let checkout = locked.out.get(&self.lease).ok_or_else(|| {
                StoreError::Internal("a checked-out cursor holds no lease".into())
            })?;
            ((checkout.instance, checkout.purpose), checkout.revoked)
        };
        if revoked {
            return Ok(Retention::Revoked);
        }
        match locked.by_key.entry(key) {
            std::collections::btree_map::Entry::Occupied(_) => Err(StoreError::Internal(
                "two cursors of one instance and purpose were held".into(),
            )),
            std::collections::btree_map::Entry::Vacant(entry) => {
                let (Some(cursor), Some(charge)) = (self.cursor.take(), self.charge.take()) else {
                    return Err(StoreError::Internal(
                        "a cursor is retained without its cursor or charge".into(),
                    ));
                };
                entry.insert(Held { cursor, charge });
                locked.out.remove(&self.lease);
                Ok(Retention::Retained)
            }
        }
    }
}

impl Drop for CheckedOut<'_> {
    fn drop(&mut self) {
        // The grant ends outside the lock: ending it may evict the namespace.
        drop(self.cursor.take());
        let mut locked = lock(self.cursors);
        drop(self.charge.take());
        locked.out.remove(&self.lease);
    }
}

/// Retained cursors an invalidation detached, accounted as releasing until
/// each has ended.
struct Releasing<'s> {
    cursors: &'s Mutex<EpochCursors>,
    detached: Vec<Held>,
}

impl Drop for Releasing<'_> {
    fn drop(&mut self) {
        for Held { cursor, charge } in std::mem::take(&mut self.detached) {
            // The grant ends outside the lock, then the charge under it.
            drop(cursor);
            let mut locked = lock(self.cursors);
            drop(charge);
            locked.releasing -= 1;
        }
    }
}

/// What one read of an epoch reached, with its cursor still checked out:
/// the cursor's position is only as durable as what its consumer staged,
/// so it is returned to the map only once that is known committed
/// ([`Self::committed`]). Dropped otherwise (an error, an abort, an unknown
/// commit outcome), it releases the cursor and its charge, and the epoch is
/// read again from its start.
pub(super) struct EpochReadGuard<'s> {
    outcome: EpochRead,
    checkout: Option<CheckedOut<'s>>,
}

impl EpochReadGuard<'_> {
    /// What the read reached.
    pub(super) const fn outcome(&self) -> &EpochRead {
        &self.outcome
    }

    /// The consumer's work is committed: a pending read's cursor is kept
    /// for the next read, unless an invalidation revoked it while it was
    /// out, and a verified read's cursor ends. Neither waits on the map's
    /// lock for the cursor's end.
    pub(super) fn committed(mut self) -> Result<(), StoreError> {
        if let (EpochRead::Pending(_), Some(checkout)) = (&self.outcome, self.checkout.take()) {
            match checkout.retain()? {
                Retention::Retained | Retention::Revoked => {}
            }
        }
        Ok(())
    }
}

/// The cursors' lock. Every update is one transfer of ownership under it;
/// a panic elsewhere cannot leave it half-written.
fn lock(cursors: &Mutex<EpochCursors>) -> MutexGuard<'_, EpochCursors> {
    cursors.lock().unwrap_or_else(PoisonError::into_inner)
}

impl PersistentStore {
    /// Read epoch `epoch` of `instance` for `purpose` within `work`,
    /// delivering its effects to `consumer` (see [`EpochRead`]), the cursor
    /// held checked out by the returned guard until the caller knows the
    /// consumer's work committed. A cursor of another epoch was overtaken
    /// and is released before another is reserved.
    pub(super) fn read_epoch(
        &self,
        instance: &StorageInstance,
        epoch: u64,
        purpose: Purpose,
        work: &mut dyn Meter,
        consumer: &mut dyn EpochConsumer,
    ) -> Result<EpochReadGuard<'_>, StoreError> {
        let deferred = |stop| EpochReadGuard {
            outcome: EpochRead::Deferred(stop),
            checkout: None,
        };
        let key = (*instance, purpose);
        let resumable = match CheckedOut::take(&self.epoch_cursors, key)? {
            Some(taken) => {
                if taken.epoch()? == epoch {
                    Some(taken)
                } else {
                    // Overtaken: its cursor and charge are released before
                    // a replacement is admitted.
                    drop(taken);
                    None
                }
            }
            None => None,
        };
        let mut out = match resumable {
            // The consumer continues what this cursor already delivered.
            Some(taken) => taken,
            None => {
                // Opening commits this cursor to two authority checks. A
                // caller that cannot admit that signature allowance must
                // not consume a cursor slot or start namespace I/O. Retained
                // cursors instead admit only their next unfinished stage.
                if work
                    .admits(&[(
                        kappa_store::work::Dimension::Signatures,
                        super::work::EPOCH_SIGNATURES,
                    )])
                    .is_err()
                {
                    return Ok(deferred(SettlementStop::Budget));
                }
                let Some(mut reserved) = CheckedOut::reserve(&self.epoch_cursors, key)? else {
                    return Ok(deferred(SettlementStop::CursorCapacity));
                };
                match EpochCursor::open(self, instance, epoch, self.settlement_limits, work)? {
                    CursorOpen::Opened(cursor) => reserved.cursor = Some(cursor),
                    CursorOpen::Deferred(stop) => return Ok(deferred(stop)),
                }
                // The staged opening and the consumer's restart run inside
                // `advance`: a refusal there is `Pending`, and the cursor is
                // retained with what it established once the step's commit
                // is known.
                reserved
            }
        };
        let authority = self.authority.load();
        let outcome =
            match out
                .cursor()?
                .advance(self.settlement_limits, &authority, work, consumer)?
            {
                Advance::Pending(stop) => EpochRead::Pending(stop),
                Advance::Verified => EpochRead::Verified(out.cursor()?.epoch_root()?.clone()),
            };
        Ok(EpochReadGuard {
            outcome,
            checkout: Some(out),
        })
    }

    /// Invalidate the cursors of keys `matches` selects: checked-out owners
    /// are revoked and retained cursors detached in one hold of the lock,
    /// then the detached ones end after it.
    fn invalidate_cursors(&self, matches: impl Fn(&Key) -> bool) {
        let detached = lock(&self.epoch_cursors).invalidate(matches);
        drop(Releasing {
            cursors: &self.epoch_cursors,
            detached,
        });
    }

    /// Discard every cursor of `instance`, releasing its activity grants:
    /// before its obligation is discharged, and before its storage is
    /// retired, which requires the namespace idle.
    pub(crate) fn forget_cursors(&self, instance: &StorageInstance) {
        self.invalidate_cursors(|(held, _)| held == instance);
    }

    /// Discard every cursor of any instance of namespace `namespace`,
    /// releasing their activity grants, before its storage is retired:
    /// retirement requires the namespace idle, and a partly read epoch is
    /// read again from its start if the storage remains.
    pub(crate) fn forget_namespace_cursors(&self, namespace: &[u8; 16]) {
        self.invalidate_cursors(|(instance, _)| instance.namespace() == namespace);
    }

    /// Cursors held between steps, checked out and being released, after
    /// asserting the pool's use is exactly them.
    #[cfg(test)]
    pub(crate) fn cursors_in_progress(&self) -> usize {
        let cursors = lock(&self.epoch_cursors);
        cursors.assert_accounted();
        cursors.by_key.len()
            + cursors.out.len()
            + usize::try_from(cursors.releasing).unwrap_or(usize::MAX)
    }

    #[cfg(test)]
    pub(crate) fn cursor_diagnostics(&self) -> Vec<String> {
        let cursors = lock(&self.epoch_cursors);
        cursors
            .by_key
            .iter()
            .map(|((instance, purpose), held)| format!("{instance} {purpose:?}: {:?}", held.cursor))
            .collect()
    }
}
