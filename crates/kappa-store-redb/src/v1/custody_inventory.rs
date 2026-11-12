//! Account durable candidate ownership independently of committed epoch debt.

use crate::custody::{CustodyPayload, CustodyRecord};
use crate::representation::AllocationId;
use crate::{PersistentStore, storage_instance::StorageInstance};
use kappa_store::{
    StoreError,
    work::{Dimension, Meter},
};
use std::sync::{PoisonError, atomic::Ordering};

#[cfg(test)]
#[path = "custody_inventory_tests.rs"]
mod tests;

impl CustodyRecord {
    /// Walk physical allocations without collecting a second population.
    /// Inline content and aliases hold no allocation debt. Each transition
    /// is charged before inspection, including transitions with no payload.
    pub(crate) fn allocations<'a>(
        &'a self,
        meter: &'a mut dyn Meter,
    ) -> impl Iterator<Item = Result<(AllocationId, u64), StoreError>> + 'a {
        self.transitions.iter().filter_map(move |transition| {
            let allocation: Result<Option<(AllocationId, u64)>, StoreError> = (|| {
                meter.charge(Dimension::Entries, 1)?;
                let CustodyPayload::Content {
                    record,
                    allocated_bytes,
                    ..
                } = &transition.payload
                else {
                    return Ok(None);
                };
                meter.charge_all(&[
                    (Dimension::BytesDecoded, record.len() as u64),
                    (
                        Dimension::BytesAllocated,
                        transition.payload.reconstruction_bound(),
                    ),
                ])?;
                Ok(transition
                    .payload
                    .allocation()?
                    .map(|id| (id, *allocated_bytes)))
            })();
            allocation.transpose()
        })
    }
}

impl PersistentStore {
    pub(crate) fn inventory_custody(
        &self,
        instance: &StorageInstance,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        // Unknown ownership closes admission before any fallible load. A
        // later successful inventory replaces that charge with measured debt.
        {
            let mut debt = self
                .custody_debt
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let std::collections::btree_map::Entry::Vacant(entry) = debt.entry(*instance) {
                entry.insert(
                    self.unsettled
                        .unmeasured(crate::unsettled::Closure::Obligation(*instance))?,
                );
            }
        }
        let Some(maintenance) = self.namespaces.try_maintain(instance.namespace())? else {
            return Err(StoreError::Unavailable(
                "custody inventory waits for its writer".into(),
            ));
        };
        if maintenance.controller().instance != *instance {
            return Err(StoreError::Unavailable(
                "custody storage instance was replaced".into(),
            ));
        }
        let Some(record) = self.load_custody(instance, meter)? else {
            self.custody_debt
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(instance);
            return Ok(());
        };
        self.latest_epoch_ms
            .fetch_max(record.now_ms, Ordering::SeqCst);
        let mut entries = 0u64;
        let mut bytes = 0u64;
        for allocation in record.allocations(meter) {
            let (_, allocated_bytes) = allocation?;
            entries = entries
                .checked_add(1)
                .ok_or_else(|| StoreError::CapacityExceeded("custody entries overflow".into()))?;
            bytes = bytes
                .checked_add(allocated_bytes)
                .ok_or_else(|| StoreError::CapacityExceeded("custody bytes overflow".into()))?;
        }
        self.custody_debt
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(instance)
            .ok_or_else(|| {
                StoreError::Internal("custody inventory lost its ownership charge".into())
            })?
            .measure(entries, bytes)?;
        Ok(())
    }
}
