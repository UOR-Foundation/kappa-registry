//! Fixed inline cache metadata and permit-bearing root owners. Replacement
//! touches one slot, and releases the displaced owner outside the lock.

use std::sync::{Arc, Mutex};

use kappa_store::capacity::{CapacityPool, Reservation};
use kappa_store::work::{Dimension, Meter};
use kappa_store::{EpochRoot, Kappa, StoreError};

const SLOTS: usize = 64;

pub(crate) struct EpochCache {
    slots: Mutex<[Option<EpochRoot>; SLOTS]>,
    // Field order keeps the charge until after the slots are destroyed.
    _metadata: Reservation,
}

impl EpochCache {
    pub(crate) fn new(pool: &Arc<CapacityPool>) -> Result<Self, StoreError> {
        let metadata = pool
            .reserve(std::mem::size_of::<Self>() as u64)
            .map_err(|error| StoreError::CapacityExceeded(error.to_string()))?;
        Ok(Self {
            slots: Mutex::new(std::array::from_fn(|_| None)),
            _metadata: metadata,
        })
    }

    fn slot(identity: &Kappa) -> usize {
        identity.digest_bytes().iter().fold(0usize, |hash, byte| {
            hash.wrapping_mul(31).wrapping_add(usize::from(*byte))
        }) % SLOTS
    }

    fn charge(work: &mut dyn Meter) -> Result<(), StoreError> {
        // Covers hashing and comparison of the largest supported identity,
        // including the algorithm axis; no key Vec is constructed.
        work.charge_all(&[(Dimension::Entries, 1), (Dimension::BytesRead, 132)])?;
        Ok(())
    }

    pub(crate) fn get(
        &self,
        identity: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<Option<EpochRoot>, StoreError> {
        Self::charge(work)?;
        let slots = self
            .slots
            .lock()
            .map_err(|_| StoreError::Internal("epoch cache poisoned".into()))?;
        Ok(slots[Self::slot(identity)]
            .as_ref()
            .filter(|root| root.kappa() == identity)
            .cloned())
    }

    /// Callers supply roots returned by the verified record reader, whose
    /// shared owners retain decoded payload and shared-allocation permits.
    pub(crate) fn insert(&self, root: EpochRoot, work: &mut dyn Meter) -> Result<(), StoreError> {
        Self::charge(work)?;
        let index = Self::slot(root.kappa());
        let previous = {
            let mut slots = self
                .slots
                .lock()
                .map_err(|_| StoreError::Internal("epoch cache poisoned".into()))?;
            slots[index].replace(root)
        };
        drop(previous);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn contains_key(&self, identity: &Kappa) -> bool {
        self.slots.lock().unwrap()[Self::slot(identity)]
            .as_ref()
            .is_some_and(|root| root.kappa() == identity)
    }

    #[cfg(test)]
    pub(crate) fn remove(&self, identity: &Kappa) {
        let mut slots = self.slots.lock().unwrap();
        let slot = &mut slots[Self::slot(identity)];
        if slot.as_ref().is_some_and(|root| root.kappa() == identity) {
            *slot = None;
        }
    }

    #[cfg(test)]
    pub(crate) fn clear(&self) {
        *self.slots.lock().unwrap() = std::array::from_fn(|_| None);
    }
}
