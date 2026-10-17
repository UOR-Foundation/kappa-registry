//! Bounded activity admission, purpose by purpose, and namespace-local
//! database opening.

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};

use kappa_store::StoreError;

use super::gate::WriterGate;
use super::grant::{Maintain, Maintenance, Publish, Purpose, Read, Use};
use super::lifecycle::{Lifecycle, Refusal};
use super::{Active, NamespaceController, NamespaceStorage, NamespaceStorageInner, Opening};

#[cfg(test)]
#[path = "storage_handles_tests.rs"]
mod tests;

/// One namespace's entry in the handle cache: its lifecycle, under the
/// lock that serializes opening, admission and every transition.
#[derive(Default)]
pub(super) struct Slot {
    state: Mutex<Lifecycle>,
}

impl Slot {
    pub(super) fn lock(&self) -> Result<MutexGuard<'_, Lifecycle>, StoreError> {
        self.state
            .lock()
            .map_err(|_| StoreError::Internal("namespace handle lock poisoned".into()))
    }
}

/// Reserve capacity before opening storage. Every error path releases it;
/// success transfers it into Active until the caller releases that activity.
///
/// The reservation also owns the controller's activity count: `admit`
/// raises it once, `end` lowers it once, so the count a controller's
/// eviction reads matches the grants that admitted it.
pub(super) struct ActivityReservation {
    inner: Arc<NamespaceStorageInner>,
    admitted: bool,
}

impl ActivityReservation {
    /// Count this activity on `controller`.
    fn admit(&mut self, controller: &NamespaceController) {
        controller.active.fetch_add(1, Ordering::AcqRel);
        self.admitted = true;
    }

    /// End the activity on `controller` that `admit` counted; a second
    /// call, or one without admission, changes nothing. Capacity is
    /// released when the reservation drops.
    pub(super) fn end(&mut self, controller: &NamespaceController) {
        if std::mem::take(&mut self.admitted) {
            controller.active.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn acquire(inner: &Arc<NamespaceStorageInner>) -> Result<Self, StoreError> {
        inner
            .active_total
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < inner.max_active).then(|| active + 1)
            })
            .map_err(|_| {
                StoreError::CapacityExceeded(format!(
                    "{} namespace activities are active; admission refused",
                    inner.max_active
                ))
            })?;
        Ok(Self {
            inner: Arc::clone(inner),
            admitted: false,
        })
    }
}

impl Drop for ActivityReservation {
    fn drop(&mut self) {
        self.inner.active_total.fetch_sub(1, Ordering::AcqRel);
        #[cfg(test)]
        crate::test_hooks::activity_released();
        NamespaceStorage {
            inner: Arc::clone(&self.inner),
        }
        .evict_idle();
    }
}

impl NamespaceStorage {
    /// Hold `id` open to read its committed state.
    pub(crate) fn admit_read(&self, id: &[u8; 16]) -> Result<Active<Read>, StoreError> {
        self.admit(id, &Opening::Existing)
    }

    /// Hold `id` open for an execution, creating its storage under
    /// `Opening::Create`.
    pub(crate) fn admit_publish(
        &self,
        id: &[u8; 16],
        opening: &Opening,
    ) -> Result<Active<Publish>, StoreError> {
        self.admit(id, opening)
    }

    /// Hold `id`'s writer gate for maintenance, waiting for the writer in
    /// progress; or the lifecycle's refusal, before or after the wait.
    pub(crate) fn maintain(
        &self,
        id: &[u8; 16],
    ) -> Result<Result<Maintenance, Refusal>, StoreError> {
        let grant = match self.try_admit::<Maintain>(id, &Opening::Existing)? {
            Ok(grant) => grant,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let gate = WriterGate::hold(grant.controller())?;
        Ok(grant.standing()?.map(|()| Maintenance::new(gate, grant)))
    }

    /// Hold `id`'s writer gate for maintenance without waiting: `None`
    /// while a writer holds it or a retirement intent holds the namespace,
    /// both of which end on their own.
    pub(crate) fn try_maintain(&self, id: &[u8; 16]) -> Result<Option<Maintenance>, StoreError> {
        let grant = match self.try_admit::<Maintain>(id, &Opening::Existing)? {
            Ok(grant) => grant,
            Err(Refusal::Retiring) => return Ok(None),
            Err(refusal) => return Err(refusal.into_error(id)),
        };
        let Some(gate) = WriterGate::try_hold(grant.controller())? else {
            return Ok(None);
        };
        match grant.standing()? {
            Ok(()) => Ok(Some(Maintenance::new(gate, grant))),
            Err(Refusal::Retiring) => Ok(None),
            Err(refusal) => Err(refusal.into_error(id)),
        }
    }

    /// Admit an activity of `id` for `P`; a refusal is its error.
    fn admit<P: Purpose>(&self, id: &[u8; 16], opening: &Opening) -> Result<Active<P>, StoreError> {
        self.try_admit(id, opening)?
            .map_err(|refusal| refusal.into_error(id))
    }

    /// Admit an activity of `id` for `P` under its slot's lifecycle,
    /// opening its storage when the slot holds none: the grant, or the
    /// lifecycle's refusal.
    fn try_admit<P: Purpose>(
        &self,
        id: &[u8; 16],
        opening: &Opening,
    ) -> Result<Result<Active<P>, Refusal>, StoreError> {
        let mut reservation = ActivityReservation::acquire(&self.inner)?;
        // The map guard ends here. Filesystem I/O is protected only by this
        // namespace's slot; unrelated namespaces can open concurrently.
        let slot = Arc::clone(self.inner.open.entry(*id).or_default().value());
        let mut held = slot.lock()?;
        let stamp = self.inner.uses.fetch_add(1, Ordering::Relaxed);
        let controller = match self.opened(&mut held, id, opening, P::USE, stamp)? {
            Ok(controller) => controller,
            Err(refusal) => return Ok(Err(refusal)),
        };
        reservation.admit(&controller);
        controller.last_used.store(stamp, Ordering::Release);
        drop(held);
        self.evict_idle();
        Ok(Ok(Active::new(controller, slot, reservation)))
    }

    /// The controller `held` serves `purpose` with, opening the storage,
    /// and entering the state its retirement record establishes, when the
    /// slot holds none; or the lifecycle's refusal. Admission is decided
    /// before and after opening.
    pub(super) fn opened(
        &self,
        held: &mut Lifecycle,
        id: &[u8; 16],
        opening: &Opening,
        purpose: Use,
        stamp: u64,
    ) -> Result<Result<Arc<NamespaceController>, Refusal>, StoreError> {
        if let Err(refusal) = held.admit(purpose) {
            return Ok(Err(refusal));
        }
        if matches!(held, Lifecycle::Closed) {
            let controller = Arc::new(NamespaceController::open(&self.inner, *id, opening, stamp)?);
            let fence = self.inner.fences.fence(&controller.instance)?;
            *held = Lifecycle::opened(controller, fence);
            if let Err(refusal) = held.admit(purpose) {
                return Ok(Err(refusal));
            }
        }
        held.controller().cloned().map(Ok).ok_or_else(|| {
            StoreError::Internal("an admitting lifecycle holds no controller".into())
        })
    }

    /// Scan only the bounded handle cache, never the namespace population.
    /// Count idle controllers, not activity grants (several grants may refer
    /// to the same controller). Never wait for a namespace doing storage I/O.
    pub(super) fn evict_idle(&self) {
        let mut candidates = BTreeSet::new();
        for entry in &self.inner.open {
            if Arc::strong_count(entry.value()) != 1 {
                continue;
            }
            let Ok(held) = entry.state.try_lock() else {
                continue;
            };
            if held.evictable() {
                candidates.insert((held.last_used(), *entry.key()));
            }
        }
        let excess = candidates.len().saturating_sub(self.inner.max_idle);
        for (_, id) in candidates.into_iter().take(excess) {
            let removed = self.inner.open.remove_if(&id, |_, slot| {
                // Cloning a slot under the map guard reserves it against
                // eviction before its activity count can be incremented.
                Arc::strong_count(slot) == 1
                    && slot.state.try_lock().is_ok_and(|held| held.evictable())
            });
            // Database close can perform I/O. It happens after remove_if
            // releases the map guard, not while other slots are locked out.
            drop(removed);
        }
    }
}

impl NamespaceController {
    /// No activity and no publication dependency: idle is not sufficient,
    /// since dropping a controller must not release unsettled or
    /// indeterminate publication dependencies. The precondition of eviction
    /// and of a retirement's release.
    pub(super) fn evictable(&self) -> bool {
        self.active.load(Ordering::Acquire) == 0
            && !self.publication_fenced.load(Ordering::Acquire)
            && self
                .writer_pins
                .try_lock()
                .is_ok_and(|pins| pins.is_empty())
            && self
                .unresolved_content
                .try_lock()
                .is_ok_and(|pins| pins.is_empty())
            && self
                .pending_pins
                .try_lock()
                .is_ok_and(|pins| pins.is_empty())
    }
}
