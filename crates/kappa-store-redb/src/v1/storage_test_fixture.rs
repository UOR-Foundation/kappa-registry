//! Namespace storage built directly, without a store, for tests of
//! admission, eviction and lifecycle transitions: no assignment is ever
//! admitted, and retirement records are a table the test writes.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use kappa_store::StoreError;

use super::{AssignmentSource, Fence, NamespaceStorage, Opening, RetirementSource};
use crate::control_plane::{AssignmentRecord, ControlPlanes, NodeId};
use crate::storage_instance::StorageInstance;

struct NoAssignment;

impl AssignmentSource for NoAssignment {
    fn assignment(
        &self,
        _: &[u8; 16],
        _: &redb::Database,
    ) -> Result<Option<AssignmentRecord>, StoreError> {
        Ok(None)
    }
}

/// Retirement records as a table: the fence each instance opens under.
#[derive(Default)]
pub(super) struct Fences(Mutex<HashMap<StorageInstance, Fence>>);

impl Fences {
    pub(super) fn record(&self, instance: StorageInstance, fence: Fence) -> Result<(), StoreError> {
        self.0
            .lock()
            .map_err(|_| StoreError::Internal("test fences poisoned".into()))?
            .insert(instance, fence);
        Ok(())
    }

    /// Remove the record of `instance`, as abandoning an intent does.
    pub(super) fn remove(&self, instance: &StorageInstance) -> Result<(), StoreError> {
        self.0
            .lock()
            .map_err(|_| StoreError::Internal("test fences poisoned".into()))?
            .remove(instance);
        Ok(())
    }
}

impl RetirementSource for Fences {
    fn fence(&self, instance: &StorageInstance) -> Result<Option<Fence>, StoreError> {
        Ok(self
            .0
            .lock()
            .map_err(|_| StoreError::Internal("test fences poisoned".into()))?
            .get(instance)
            .copied())
    }
}

/// Storage at `root` keeping `idle` idle handles and admitting `active`
/// activities, fenced by `fences`.
pub(super) fn storage_fenced(
    root: &Path,
    idle: usize,
    active: usize,
    fences: Arc<Fences>,
) -> NamespaceStorage {
    NamespaceStorage::new(
        root.to_path_buf(),
        idle,
        active,
        Arc::new(ControlPlanes::new(NodeId("local".into()))),
        Arc::new(NoAssignment),
        fences,
        None,
        true,
    )
}

/// Storage at `root` with no retirement recorded.
pub(super) fn storage(root: &Path, idle: usize, active: usize) -> NamespaceStorage {
    storage_fenced(root, idle, active, Arc::default())
}

/// The opening that creates storage under `storage`'s local plane.
pub(super) fn create(storage: &NamespaceStorage) -> Opening {
    Opening::Create {
        plane: Arc::clone(storage.planes().local()),
    }
}
