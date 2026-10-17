//! Lifecycle transitions that retire a namespace's storage.
//!
//! - **Governed retirement** of present storage, in two steps around the
//!   publication of the governing decision.
//!   [`NamespaceStorage::begin_retiring`] takes the writer gate, records a
//!   durable intent (the caller's closure), and enters `Retiring`: reads
//!   continue, nothing publishes or rewrites state, and an activity
//!   admitted earlier is refused when it reaches the gate. The returned
//!   [`RetirementIntent`] holds the gate until it is released, abandoned
//!   or dropped. [`RetirementIntent::release`] records the release once
//!   the namespace holds no other activity and no publication dependency,
//!   and removes the storage; [`RetirementIntent::abandon`] removes the
//!   intent and reopens. An intent dropped unreleased leaves the slot
//!   `Retiring`: its durable record fences the storage at its next open,
//!   and recovery resumes it ([`NamespaceStorage::resume_retiring`]).
//! - **Recorded removal** ([`NamespaceStorage::remove_recorded`]): the
//!   caller decides from the storage evidence read under the slot it holds
//!   ([`StorageEvidence`]) and records durably; the directory is removed
//!   after. For missing storage, for creations proven never to have
//!   committed, and for recovery completing a recorded release.
//!
//! A record whose commit outcome is unknown ([`Recording::Unknown`])
//! leaves the slot `Unresolved`, never reopened: the record may be durable.

use std::sync::Arc;

use kappa_store::StoreError;

use super::gate::{WriterGate, WriterToken};
use super::lifecycle::{Lifecycle, Refusal};
use super::{Active, NamespaceController, NamespaceStorage, Slot, StorageEvidence};

#[cfg(test)]
#[path = "storage_retiring_tests.rs"]
mod tests;

/// Why a retirement record was not committed.
pub enum Recording {
    /// Nothing was committed.
    Refused(StoreError),
    /// The commit itself failed: whether the record is durable is unknown.
    Unknown(StoreError),
}

impl From<StoreError> for Recording {
    fn from(error: StoreError) -> Self {
        Self::Refused(error)
    }
}

impl Recording {
    /// The error, for a caller that does not change state on the outcome.
    pub(crate) fn into_error(self) -> StoreError {
        match self {
            Self::Refused(error) | Self::Unknown(error) => error,
        }
    }
}

/// A durable retirement intent held over present storage: the namespace's
/// writer gate and a read grant on it. Fields drop in declaration order:
/// the gate opens before the grant ends.
pub struct RetirementIntent {
    gate: WriterToken,
    grant: Active,
    storage: NamespaceStorage,
}

impl NamespaceStorage {
    /// Begin retiring the storage of `id`: hold its writer gate (waiting
    /// for an execution in progress), then, under its slot, run `record`,
    /// which makes the intent durable for the controller it is shown, and
    /// enter `Retiring`. Refused when the slot is not open, and when
    /// `record` refuses; nothing changes then.
    pub(crate) fn begin_retiring(
        &self,
        id: &[u8; 16],
        record: impl FnOnce(&NamespaceController) -> Result<(), StoreError>,
    ) -> Result<RetirementIntent, StoreError> {
        let grant = self.admit_read(id)?;
        let gate = WriterGate::hold(grant.controller())?;
        {
            let mut held = grant.slot().lock()?;
            match &*held {
                Lifecycle::Open(controller) if Arc::ptr_eq(controller, grant.controller()) => {}
                _ => {
                    return Err(StoreError::Conflict(format!(
                        "namespace {} changed state before its retirement began",
                        hex::encode(id)
                    )));
                }
            }
            record(grant.controller())?;
            *held = Lifecycle::Retiring(Arc::clone(grant.controller()));
        }
        Ok(RetirementIntent {
            gate,
            grant,
            storage: self.share(),
        })
    }

    /// The intent of a namespace whose slot is `Retiring` (its record
    /// fenced it at open, or an earlier intent was dropped), holding its
    /// writer gate again; `None` in any other state.
    pub(crate) fn resume_retiring(
        &self,
        id: &[u8; 16],
    ) -> Result<Option<RetirementIntent>, StoreError> {
        let grant = match self.admit_read(id) {
            Ok(grant) => grant,
            Err(StoreError::NotFound(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        if !matches!(&*grant.slot().lock()?, Lifecycle::Retiring(_)) {
            return Ok(None);
        }
        let gate = WriterGate::hold(grant.controller())?;
        Ok(Some(RetirementIntent {
            gate,
            grant,
            storage: self.share(),
        }))
    }

    /// Remove the storage of `id` on a decision `record` makes from the
    /// evidence it is shown and records durably. The slot is held from
    /// before the evidence is read until the removal, so no opening or
    /// activity of the namespace interleaves; an open controller must be
    /// idle and held by nothing else. Refused while retiring (a governed
    /// retirement releases through its intent) or unresolved.
    pub(crate) fn remove_recorded(
        &self,
        id: &[u8; 16],
        record: impl FnOnce(&StorageEvidence<'_>) -> Result<(), Recording>,
    ) -> Result<(), StoreError> {
        let slot = self.slot(id);
        let mut held = slot.lock()?;
        let controller = match &*held {
            Lifecycle::Closed | Lifecycle::Released => None,
            Lifecycle::Open(controller)
                if controller.evictable() && Arc::strong_count(controller) == 1 =>
            {
                Some(Arc::clone(controller))
            }
            Lifecycle::Open(_) => {
                return Err(StoreError::Conflict(format!(
                    "namespace {} is active",
                    hex::encode(id)
                )));
            }
            Lifecycle::Retiring(_) => return Err(Refusal::Retiring.into_error(id)),
            Lifecycle::Unresolved => return Err(Refusal::Unresolved.into_error(id)),
        };
        let closed = match &controller {
            Some(_) => None,
            None => Some(self.open_closed(id)),
        };
        let recorded = record(&StorageEvidence::of(controller.as_deref(), closed.as_ref()));
        drop(closed);
        match recorded {
            Err(Recording::Refused(error)) => return Err(error),
            Err(Recording::Unknown(error)) => {
                *held = Lifecycle::Unresolved;
                return Err(error);
            }
            Ok(()) => {}
        }
        *held = Lifecycle::Released;
        drop(controller);
        self.remove_storage(id, &slot, held)
    }

    /// Remove the database directory of `id`, whose slot `held` is
    /// `Released`, then drop the slot from the cache. A failed removal
    /// keeps the slot `Released`; recovery completes it.
    fn remove_storage(
        &self,
        id: &[u8; 16],
        slot: &Arc<Slot>,
        held: std::sync::MutexGuard<'_, Lifecycle>,
    ) -> Result<(), StoreError> {
        let directory = NamespaceController::directory(&self.inner.root, id);
        let result = match std::fs::remove_dir_all(&directory) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(StoreError::Io(error)),
        };
        drop(held);
        if result.is_ok() {
            let removed = self
                .inner
                .open
                .remove_if(id, |_, cached| Arc::ptr_eq(cached, slot));
            // Dropped after `remove_if` released the map's shard lock.
            drop(removed);
        }
        result
    }
}

impl RetirementIntent {
    /// The controller of the storage being retired.
    pub(crate) const fn controller(&self) -> &Arc<NamespaceController> {
        self.grant.controller()
    }

    /// Release the storage: once the namespace holds no activity but this
    /// intent's and no publication dependency, `verify` confirms the
    /// controller is still what the decision names and `record` commits
    /// the release; the slot becomes `Released` and the storage is removed.
    /// Refused, with the slot left `Retiring`, while an activity or a
    /// dependency remains, or when `verify` or `record` refuses; a release
    /// whose commit outcome is unknown leaves the slot `Unresolved`.
    pub(crate) fn release(
        self,
        verify: impl FnOnce(&NamespaceController) -> Result<(), StoreError>,
        record: impl FnOnce() -> Result<(), Recording>,
    ) -> Result<(), StoreError> {
        let Self {
            gate,
            grant,
            storage,
        } = self;
        let controller = Arc::clone(grant.controller());
        let slot = Arc::clone(grant.slot());
        // This intent's own activity ends first; the gate stays held, so no
        // writer proceeds while the release is decided.
        drop(grant);
        let mut held = slot.lock()?;
        if !matches!(&*held, Lifecycle::Retiring(retiring) if Arc::ptr_eq(retiring, &controller)) {
            return Err(StoreError::Internal(
                "a retirement intent's slot is no longer retiring its controller".into(),
            ));
        }
        if !controller.evictable() {
            return Err(StoreError::Conflict(format!(
                "namespace {} still holds an activity or a publication dependency; its retirement is released once they end",
                hex::encode(controller.id)
            )));
        }
        verify(&controller)?;
        match record() {
            Err(Recording::Refused(error)) => return Err(error),
            Err(Recording::Unknown(error)) => {
                *held = Lifecycle::Unresolved;
                return Err(error);
            }
            Ok(()) => {}
        }
        *held = Lifecycle::Released;
        let id = controller.id;
        drop(gate);
        drop(controller);
        storage.remove_storage(&id, &slot, held)
    }

    /// Give up the retirement: `remove` deletes the durable intent, then
    /// the namespace reopens for every purpose. A failed removal leaves
    /// the slot `Retiring`.
    pub(crate) fn abandon(
        self,
        remove: impl FnOnce() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let mut held = self.grant.slot().lock()?;
        remove()?;
        *held = Lifecycle::Open(Arc::clone(self.grant.controller()));
        // The slot reopens before the gate this intent holds is released.
        drop(held);
        Ok(())
    }
}
