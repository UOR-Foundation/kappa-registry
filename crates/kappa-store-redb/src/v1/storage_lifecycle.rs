//! The lifecycle of one namespace's storage slot, and the one admission
//! policy over it.
//!
//! Every activity of a namespace (`storage_grant::Use`) is admitted by
//! [`Lifecycle::admit`] when its grant is issued and again when an
//! exclusive grant takes the writer gate (`writer_gate`), so an activity
//! admitted before a transition is refused at the gate after it. The
//! policy is one exhaustive table: a new state or purpose is one more arm,
//! and the compiler names every arm that must decide.
//!
//! A slot's state survives restart through the retirement records the
//! registry holds (`RETIRED`, see `retirement_record`): when storage is
//! opened, its instance's record is consulted ([`RetirementSource`]) and
//! the slot enters the state the record establishes, before any activity is
//! admitted. Only [`Lifecycle::Unresolved`] is process state: it follows a
//! release whose registry commit outcome is unknown, and after that failure
//! redb admits no further registry write on this handle, so the store is
//! reopened and the record, committed or not, decides.

use std::sync::Arc;

use kappa_store::StoreError;

use super::NamespaceController;
use super::grant::Use;
use crate::storage_instance::StorageInstance;

/// What a namespace's slot holds.
#[derive(Default)]
pub(super) enum Lifecycle {
    /// No controller is open; opening consults the retirement record.
    #[default]
    Closed,
    /// The controller serves every purpose.
    Open(Arc<NamespaceController>),
    /// A durable retirement intent holds the namespace: reads continue,
    /// nothing publishes or rewrites state until the intent is released or
    /// abandoned.
    Retiring(Arc<NamespaceController>),
    /// The instance's release is recorded: nothing is admitted, and its
    /// storage, if any remains, is removed by recovery.
    Released,
    /// A release's registry commit outcome is unknown: nothing is admitted
    /// until the store is reopened and the record decides.
    Unresolved,
}

/// What a recorded retirement says about an instance's storage when that
/// storage is opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fence {
    /// A retirement intent is recorded: the slot opens [`Lifecycle::Retiring`].
    Retiring,
    /// A release is recorded: the slot opens [`Lifecycle::Released`].
    Released,
}

/// The registry's retirement records, as the storage layer consults them.
pub trait RetirementSource: Send + Sync {
    /// The fence the record of `instance` establishes, if any.
    fn fence(&self, instance: &StorageInstance) -> Result<Option<Fence>, StoreError>;
}

/// Why a lifecycle refuses an activity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A retirement intent holds the namespace: only reads proceed, and an
    /// activity that only waits for the intent to end may try again later.
    Retiring,
    /// The instance's release is recorded.
    Released,
    /// A release's commit outcome is unknown.
    Unresolved,
}

impl Refusal {
    /// The error the refusal of an activity of namespace `id` surfaces as.
    pub fn into_error(self, id: &[u8; 16]) -> StoreError {
        let namespace = hex::encode(id);
        match self {
            Self::Retiring => StoreError::Conflict(format!(
                "namespace {namespace} is retiring; it admits reads only"
            )),
            Self::Released => {
                StoreError::NotFound(format!("namespace {namespace} storage retired"))
            }
            Self::Unresolved => StoreError::Unavailable(format!(
                "the retirement of namespace {namespace} has an unknown commit outcome; reopen the store to resolve it"
            )),
        }
    }
}

impl Lifecycle {
    /// Whether an activity for `purpose` is admitted in this state.
    pub(super) const fn admit(&self, purpose: Use) -> Result<(), Refusal> {
        match (self, purpose) {
            (Self::Closed | Self::Open(_), Use::Read | Use::Publish | Use::Maintain)
            | (Self::Retiring(_), Use::Read) => Ok(()),
            (Self::Retiring(_), Use::Publish | Use::Maintain) => Err(Refusal::Retiring),
            (Self::Released, Use::Read | Use::Publish | Use::Maintain) => Err(Refusal::Released),
            (Self::Unresolved, Use::Read | Use::Publish | Use::Maintain) => {
                Err(Refusal::Unresolved)
            }
        }
    }

    /// The state storage opened as `controller` enters, by the fence its
    /// instance's record establishes.
    pub(super) fn opened(controller: Arc<NamespaceController>, fence: Option<Fence>) -> Self {
        match fence {
            None => Self::Open(controller),
            Some(Fence::Retiring) => Self::Retiring(controller),
            Some(Fence::Released) => Self::Released,
        }
    }

    /// The open controller, in a state that holds one.
    pub(super) const fn controller(&self) -> Option<&Arc<NamespaceController>> {
        match self {
            Self::Open(controller) | Self::Retiring(controller) => Some(controller),
            Self::Closed | Self::Released | Self::Unresolved => None,
        }
    }

    /// Whether the slot may be dropped from the handle cache: everything it
    /// holds is either nothing or recovered from durable state at the next
    /// open. An unresolved release is known only to this process.
    pub(super) fn evictable(&self) -> bool {
        match self {
            Self::Closed | Self::Released => true,
            Self::Open(controller) | Self::Retiring(controller) => {
                controller.evictable() && Arc::strong_count(controller) == 1
            }
            Self::Unresolved => false,
        }
    }

    /// The eviction order of an evictable slot: its controller's last use,
    /// or the oldest for a slot holding none.
    pub(super) fn last_used(&self) -> u64 {
        self.controller().map_or(0, |controller| {
            controller
                .last_used
                .load(std::sync::atomic::Ordering::Acquire)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The admission table, row by row: a state change that forgets a
    /// purpose fails here, not in production.
    #[test]
    fn admission_policy() -> Result<(), StoreError> {
        let controller = crate::test_support::controller_for_tests()?;
        let uses = [Use::Read, Use::Publish, Use::Maintain];
        let expect = |state: &Lifecycle, outcomes: [Result<(), Refusal>; 3]| {
            for (purpose, outcome) in uses.into_iter().zip(outcomes) {
                assert_eq!(state.admit(purpose), outcome, "{purpose:?}");
            }
        };
        let retiring = Err(Refusal::Retiring);
        let released = Err(Refusal::Released);
        let unresolved = Err(Refusal::Unresolved);
        expect(&Lifecycle::Closed, [Ok(()), Ok(()), Ok(())]);
        expect(
            &Lifecycle::Open(Arc::clone(&controller)),
            [Ok(()), Ok(()), Ok(())],
        );
        expect(
            &Lifecycle::Retiring(Arc::clone(&controller)),
            [Ok(()), retiring, retiring],
        );
        expect(&Lifecycle::Released, [released, released, released]);
        expect(&Lifecycle::Unresolved, [unresolved, unresolved, unresolved]);
        let id = [7; 16];
        assert!(matches!(
            Refusal::Retiring.into_error(&id),
            StoreError::Conflict(_)
        ));
        assert!(matches!(
            Refusal::Released.into_error(&id),
            StoreError::NotFound(_)
        ));
        assert!(matches!(
            Refusal::Unresolved.into_error(&id),
            StoreError::Unavailable(_)
        ));
        assert!(!Lifecycle::Unresolved.evictable());
        Ok(())
    }
}
