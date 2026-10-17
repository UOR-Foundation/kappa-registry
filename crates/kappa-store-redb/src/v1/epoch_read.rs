//! Reads of committed epochs: the head of a namespace, recovery of a
//! controller's head state, and the `EpochStore` contract.

use redb::{ReadableDatabase, ReadableTableMetadata};

use kappa_store::epoch_root::EpochRoot;
use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::traits::epoch::EpochStore;

use super::epoch_idx_key;
use crate::PersistentStore;
use crate::namespace_snapshot::InstanceAdmission;
use crate::projection::Family;
use crate::storage::NamespaceController;
use crate::tables::{BLOB_INDEX, EPOCH_CURRENT, EPOCH_INDEX, MUTATION_BUFFER};

impl PersistentStore {
    /// The authenticated root `kappa`, from the process cache, the
    /// registry's completed epoch-root locator (`projection::Family::
    /// EpochRoot`), and the owning storage instance
    /// (`namespace_snapshot::admit_instance`). A root whose instance's
    /// storage is missing or was replaced by another instance is absent when
    /// that instance's retirement record explains it and unavailable
    /// otherwise.
    pub(crate) fn load_epoch_root(&self, kappa: &Kappa) -> Result<EpochRoot, StoreError> {
        if let Some(cached) = self.epoch_cache.get(kappa) {
            return Ok(cached.clone());
        }
        // A root names its namespace, number and time: one instance
        // publishes it; the latest completion answers if more claim it.
        let owner = self
            .projection()?
            .get(Family::EpochRoot, &kappa.key_bytes())?
            .into_iter()
            .max_by_key(|visible| visible.completion)
            .map(|visible| visible.instance)
            .ok_or_else(|| StoreError::NotFound(format!("epoch {kappa}")))?;
        let snapshot = match self.admit_instance(&owner) {
            InstanceAdmission::Held { snapshot, .. } => snapshot,
            InstanceAdmission::Released(_) => {
                return Err(StoreError::NotFound(format!(
                    "epoch {kappa} of retired storage {owner}"
                )));
            }
            InstanceAdmission::Unexplained(error) | InstanceAdmission::Unreadable(error) => {
                return Err(error);
            }
        };
        let root = snapshot
            .view()
            .epoch_root_from_index(&snapshot.table(BLOB_INDEX)?, kappa)?;
        self.epoch_cache.insert(kappa.clone(), root.clone());
        Ok(root)
    }

    /// The head root of `controller`'s namespace from its database.
    pub(crate) fn head_root(
        &self,
        controller: &NamespaceController,
    ) -> Result<Option<EpochRoot>, StoreError> {
        let txn = controller.db.begin_read().map_err(crate::error::redb)?;
        let table = txn.open_table(EPOCH_CURRENT).map_err(crate::error::redb)?;
        match table
            .get(controller.id.as_slice())
            .map_err(crate::error::redb)?
        {
            Some(v) => {
                let decrypted =
                    self.decrypt_bytes(&super::pointer_context(&controller.id), v.value())?;
                let kappa = Kappa::from_key_bytes(&decrypted)?;
                let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
                let root = self
                    .read_view_for(controller)
                    .epoch_root_from_index(&index, &kappa)?;
                if root.namespace_id() != controller.id {
                    return Err(StoreError::Conflict(
                        "epoch pointer crosses namespace identity".into(),
                    ));
                }
                Ok(Some(root))
            }
            None => Ok(None),
        }
    }

    /// Recover `controller`'s head once: its epoch number, the latest
    /// epoch time it bounds rotation by, and its committed time floor.
    /// Called under the controller's writer gate, so it never observes a
    /// head another execution is moving; one read snapshot, no replay.
    pub(crate) fn recover_namespace_head(
        &self,
        controller: &NamespaceController,
    ) -> Result<(), StoreError> {
        use std::sync::atomic::Ordering;
        if controller.head_recovered.load(Ordering::Acquire) {
            return Ok(());
        }
        let txn = controller.db.begin_read().map_err(crate::error::redb)?;
        let floor = self.committed_floor_in(&txn)?;
        let has_history = !txn
            .open_table(EPOCH_CURRENT)
            .map_err(crate::error::redb)?
            .is_empty()
            .map_err(crate::error::redb)?
            || !txn
                .open_table(MUTATION_BUFFER)
                .map_err(crate::error::redb)?
                .is_empty()
                .map_err(crate::error::redb)?
            || !txn
                .open_table(crate::tables::TAGS)
                .map_err(crate::error::redb)?
                .is_empty()
                .map_err(crate::error::redb)?;
        if has_history && floor.is_none() {
            return Err(StoreError::Internal(format!(
                "namespace {} has durable history without time continuity state",
                hex::encode(controller.id)
            )));
        }
        drop(txn);
        if let Some(floor) = floor {
            self.committed_floor_ms
                .fetch_max(floor.encoded().as_i64(), Ordering::SeqCst);
        }
        if let Some(root) = self.head_root(controller)? {
            #[cfg(test)]
            self.hooks.reach(crate::test_hooks::Point::RecoveryHeadRead);
            // Heads carry the latest timestamp of their namespace: epoch
            // timestamps never regress along a chain.
            self.latest_epoch_ms
                .fetch_max(root.timestamp_ms(), Ordering::SeqCst);
            controller
                .epoch_number
                .fetch_max(root.epoch_number(), Ordering::AcqRel);
        }
        controller.head_recovered.store(true, Ordering::Release);
        Ok(())
    }
}

impl EpochStore for PersistentStore {
    fn epoch_state(&self, ns: &NamespaceRef) -> Result<([u8; 32], u64), StoreError> {
        self.persisted_tag_state(ns)
    }

    // Epochs are sealed only by publishing an execution
    // (`EpochExecution::publish` -> `prepare_epoch_transaction` ->
    // `PreparedEpochPublication::publish`), which seals the ledger written by
    // the same writer.
    fn epoch_current(&self, ns: &NamespaceRef) -> Result<(u64, Kappa), StoreError> {
        let snapshot = self.namespace_snapshot(ns)?;
        let root = self
            .head_root(snapshot.controller())?
            .ok_or_else(|| StoreError::NotFound(format!("no epoch for namespace {ns}")))?;
        let epoch_num = root.epoch_number();
        Ok((epoch_num, root.kappa().clone()))
    }

    fn epoch_get(&self, kappa: &Kappa) -> Result<EpochRoot, StoreError> {
        self.load_epoch_root(kappa)
    }

    fn epoch_get_by_number(
        &self,
        ns: &NamespaceRef,
        epoch_number: u64,
    ) -> Result<Kappa, StoreError> {
        let snapshot = self.namespace_snapshot(ns)?;
        let idx_key = epoch_idx_key(ns, epoch_number);
        let table = snapshot.table(EPOCH_INDEX)?;
        let raw = table
            .get(idx_key.as_slice())
            .map_err(crate::error::redb)?
            .ok_or_else(|| {
                StoreError::NotFound(format!("epoch {epoch_number} not found in namespace {ns}"))
            })?;
        let identity = Kappa::from_key_bytes(raw.value())?;
        let root = snapshot
            .view()
            .epoch_root_from_index(&snapshot.table(BLOB_INDEX)?, &identity)?;
        if root.namespace_id() != ns.id() || root.epoch_number() != epoch_number {
            return Err(StoreError::Conflict(
                "epoch index coordinates differ from authenticated root".into(),
            ));
        }
        Ok(identity)
    }
}
