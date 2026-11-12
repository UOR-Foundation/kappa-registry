//! Reuse live retained allocation ownership during publication reconstruction.

use kappa_store::StoreError;
use kappa_store::work::{Dimension, WorkMeter};

use crate::PersistentStore;
use crate::allocation::Pin;
use crate::storage::NamespaceController;
use crate::unsettled::{Charge, Class};

impl PersistentStore {
    pub(super) fn reserve_reconstructed_pins(
        &self,
        controller: &NamespaceController,
        pins: &[Pin],
        custody: Option<&crate::custody::CustodyRecord>,
        meter: &mut WorkMeter,
    ) -> Result<Charge, StoreError> {
        let retained = controller
            .unresolved_content
            .lock()
            .map_err(|_| StoreError::Internal("retained ownership poisoned".into()))?;
        // The existing pins and charges stay owned by the controller on
        // every refusal. Classification transfers them to settlement only
        // after commitment. Match allocation and measured size, not merely
        // aggregate bytes that might belong to another physical allocation.
        let count = retained.pins.len();
        meter.charge_all(&[
            (Dimension::Entries, count as u64),
            (
                Dimension::BytesAllocated,
                (count as u64)
                    .saturating_mul(size_of::<(crate::representation::AllocationId, u64)>() as u64),
            ),
        ])?;
        let mut covered: Vec<_> = retained
            .pins
            .iter()
            .map(|pin| (*pin.allocation(), pin.bytes()))
            .collect();
        covered.sort_unstable();
        if let Some(custody) = custody {
            let capacity = custody.transitions.len();
            meter.charge(
                Dimension::BytesAllocated,
                (capacity as u64).saturating_mul(
                    2 * size_of::<(crate::representation::AllocationId, u64)>() as u64,
                ),
            )?;
            let mut restored = Vec::with_capacity(capacity);
            let mut debt = self
                .custody_debt
                .lock()
                .map_err(|_| StoreError::Internal("custody debt poisoned".into()))?;
            let charge = match debt.entry(controller.instance) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => entry.insert(
                    self.unsettled
                        .unmeasured(crate::unsettled::Closure::Obligation(controller.instance))?,
                ),
            };
            let mut entries = 0u64;
            let mut bytes = 0u64;
            for allocation in custody.allocations(meter) {
                let allocation = allocation?;
                if covered.binary_search(&allocation).is_err() {
                    entries = entries.checked_add(1).ok_or_else(|| {
                        StoreError::CapacityExceeded("custody entries overflow".into())
                    })?;
                    bytes = bytes.checked_add(allocation.1).ok_or_else(|| {
                        StoreError::CapacityExceeded("custody bytes overflow".into())
                    })?;
                    restored.push(allocation);
                }
            }
            charge.measure(entries, bytes)?;
            covered.reserve_exact(restored.len());
            covered.extend(restored);
            covered.sort_unstable();
        }
        let mut entries = 0u64;
        let mut bytes = 0u64;
        for pin in pins.iter().filter(|pin| !pin.is_charged()) {
            meter.charge(Dimension::Entries, 1)?;
            if covered
                .binary_search(&(*pin.allocation(), pin.bytes()))
                .is_ok()
            {
                // Multiple reconstructed references share the retained
                // physical allocation's existing protection and charge.
                continue;
            }
            entries = entries.checked_add(1).ok_or_else(|| {
                StoreError::CapacityExceeded("reconstructed pin count overflow".into())
            })?;
            bytes = bytes.checked_add(pin.bytes()).ok_or_else(|| {
                StoreError::CapacityExceeded("reconstructed pin bytes overflow".into())
            })?;
        }
        if entries == 0 && bytes == 0 {
            // No new ownership: recovery must not reserve again against its
            // own retained charges or another instance's closing debt.
            self.unsettled.debt(0, 0)
        } else {
            self.unsettled.admit(Class::Ordinary, entries, bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::representation::AllocationId;
    use crate::unsettled::{Closure, Parked};
    use kappa_store::NamespaceRef;

    #[test]
    fn durable_payload_debt_covers_restored_pins_without_live_ownership()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::custody::{CustodyParts, CustodyPayload, CustodyRecord, CustodyTransition};
        use crate::representation::{BlobRecord, ExternalLayout, RepresentationLimits};
        use kappa_store::{Kappa, work::Work};

        let store = crate::test_support::persistent_store()?.into_store();
        let ns = NamespaceRef::deterministic("durable-capacity-transfer");
        let writer = store.test_writer(&ns)?;
        let controller = writer.active.controller();
        let allocation = AllocationId::generate()?;
        let row = BlobRecord::external(
            ExternalLayout {
                stored_size: 128,
                chunk_size: 128,
                chunk_count: 1,
                allocation,
                publication_id: [3; 32],
                chunk_root: [4; 32],
            },
            None,
            RepresentationLimits {
                inline_limit: 1,
                max_components: 1,
            },
        )?;
        // This fixture exercises physical capacity accounting only; its
        // transition bytes are never applied or admitted as epoch evidence.
        let custody = CustodyRecord::new(CustodyParts {
            namespace: *ns.id(),
            incarnation: *controller
                .logical_incarnation(crate::storage::IncarnationUse::Seal)?
                .as_bytes(),
            epoch_number: 1,
            predecessor: None,
            unsigned: Kappa::sha256(b"retained candidate"),
            now_ms: 1,
            activation: None,
            transitions: vec![CustodyTransition {
                mutation: Vec::new(),
                evidence: Vec::new(),
                payload: CustodyPayload::Content {
                    identity: Kappa::sha256(&[9; 128]),
                    aliases: Vec::new(),
                    record: crate::representation_codec::encode(&row),
                    allocated_bytes: 128,
                },
            }],
            reads: Vec::new(),
            work: Work::default(),
        });
        let closed = store.unsettled.unmeasured(Closure::Startup)?;
        let before = store.unsettled.charged();
        let restored = store.protection.pin(allocation)?.with_bytes(128);
        for _ in 0..2 {
            let charge = store.reserve_reconstructed_pins(
                controller,
                std::slice::from_ref(&restored),
                Some(&custody),
                &mut WorkMeter::unbounded(),
            )?;
            assert_eq!(store.unsettled.charged(), (before.0 + 1, before.1 + 128));
            assert_eq!((charge.entries(), charge.bytes()), (0, 0));
        }
        let debt = store
            .custody_debt
            .lock()
            .map_err(|_| "custody debt poisoned")?
            .remove(&controller.instance)
            .ok_or("custody debt absent")?;
        let parked = Parked::new(vec![restored], debt);
        assert_eq!(store.unsettled.charged(), (before.0 + 1, before.1 + 128));
        drop(parked);
        assert_eq!(store.unsettled.charged(), before);
        drop(closed);
        Ok(())
    }

    #[test]
    fn retained_pins_resume_under_closure_but_new_allocations_do_not()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = crate::test_support::persistent_store()?.into_store();
        let ns = NamespaceRef::deterministic("retained-capacity-transfer");
        let writer = store.test_writer(&ns)?;
        let controller = writer.active.controller();
        let allocation = AllocationId::generate()?;
        let held = store.protection.pin(allocation)?.with_bytes(37);
        let charge = store.unsettled.debt(1, 37)?;
        controller
            .unresolved_content
            .lock()
            .map_err(|_| "retained ownership poisoned")?
            .append(Parked::new(vec![held], charge));
        let closed = store.unsettled.unmeasured(Closure::Startup)?;
        let before = store.unsettled.charged();
        let restored = store.protection.pin(allocation)?.with_bytes(37);
        assert!(
            store
                .unsettled
                .reserve(std::slice::from_ref(&restored), Class::Ordinary)
                .is_err()
        );
        let transferred = store.reserve_reconstructed_pins(
            controller,
            std::slice::from_ref(&restored),
            None,
            &mut WorkMeter::unbounded(),
        )?;
        assert_eq!(store.unsettled.charged(), before);
        let other = store
            .protection
            .pin(AllocationId::generate()?)?
            .with_bytes(37);
        assert!(store
            .reserve_reconstructed_pins(controller, &[other], None, &mut WorkMeter::unbounded(),)
            .is_err());
        assert_eq!(store.unsettled.charged(), before);
        assert!(store.protection.is_pinned(&allocation)?);
        drop(transferred);
        drop(closed);
        Ok(())
    }
}
