//! The publication gate of a namespace controller.
//!
//! redb serializes write transactions, but releases its writer the moment a
//! transaction is consumed by `commit`, before the committing execution
//! learns the outcome. The fence that an unknown outcome installs would
//! then race the next execution's admission: it could acquire redb's
//! writer, check the fence, find it clear, and proceed while the previous
//! commit is still being classified. This gate is held by an execution
//! from admission through commit classification, so the transition from
//! commit outcome to fence is serialized with every later admission's
//! fence check. The token owns its controller reference, so it has no
//! borrow lifetime and travels with the execution.
//!
//! Only an exclusive grant (`storage_grant::Exclusive`) takes the gate,
//! and its purpose is admitted again once the gate is held: an activity
//! admitted before a lifecycle transition (a retirement holding the
//! namespace) is refused here rather than proceeding after it. The
//! transitions themselves hold the gate through [`WriterGate::hold`],
//! visible to the storage module alone.

use std::sync::{Arc, Condvar, Mutex};

use kappa_store::error::StoreError;

use super::{Active, Exclusive, NamespaceController};

#[derive(Default)]
pub struct WriterGate {
    held: Mutex<bool>,
    released: Condvar,
}

/// Exclusive publication ownership of one controller.
pub struct WriterToken {
    controller: Arc<NamespaceController>,
}

impl WriterGate {
    /// Block until the gate of `active`'s namespace is free, hold it for
    /// the token's life, and admit `active`'s purpose again under it. A
    /// purpose already refused is refused before waiting: a transition
    /// holding the gate is not waited out only to refuse after it.
    pub(crate) fn acquire<P: Exclusive>(active: &Active<P>) -> Result<WriterToken, StoreError> {
        active.readmit()?;
        let token = Self::hold(active.controller())?;
        // A refusal drops the token, opening the gate again.
        active.readmit()?;
        Ok(token)
    }

    /// Block until the gate is free, then hold it for the token's life,
    /// for a lifecycle transition the slot already decided.
    pub(super) fn hold(controller: &Arc<NamespaceController>) -> Result<WriterToken, StoreError> {
        let gate = &controller.writer_gate;
        let mut held = gate
            .held
            .lock()
            .map_err(|_| StoreError::Internal("writer gate poisoned".into()))?;
        while *held {
            held = gate
                .released
                .wait(held)
                .map_err(|_| StoreError::Internal("writer gate poisoned".into()))?;
        }
        *held = true;
        drop(held);
        Ok(WriterToken {
            controller: Arc::clone(controller),
        })
    }

    /// Hold the gate without waiting; `None` while another holds it. The
    /// caller decides admission under it (`NamespaceStorage::try_maintain`).
    pub(super) fn try_hold(
        controller: &Arc<NamespaceController>,
    ) -> Result<Option<WriterToken>, StoreError> {
        let gate = &controller.writer_gate;
        let mut held = gate
            .held
            .lock()
            .map_err(|_| StoreError::Internal("writer gate poisoned".into()))?;
        if *held {
            return Ok(None);
        }
        *held = true;
        drop(held);
        Ok(Some(WriterToken {
            controller: Arc::clone(controller),
        }))
    }
}

impl WriterToken {
    /// The storage instance whose publication this token owns: the one
    /// whose durable records only its holder writes (`custody`).
    pub(crate) fn instance(&self) -> &crate::storage_instance::StorageInstance {
        &self.controller.instance
    }
}

impl Drop for WriterToken {
    fn drop(&mut self) {
        let gate = &self.controller.writer_gate;
        let mut held = gate
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *held = false;
        drop(held);
        gate.released.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use kappa_store::NamespaceRef;

    use super::*;
    use crate::storage::Opening;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn the_gate_is_exclusive_until_the_token_drops() -> TestResult {
        let store = crate::test_support::persistent_store()?.into_store();
        let ns = NamespaceRef::deterministic("gate-exclusive");
        let plane = Arc::clone(store.control_planes().local());
        let first = store
            .namespaces
            .admit_publish(ns.id(), &Opening::Create { plane })?;
        let token = WriterGate::acquire(&first)?;
        assert!(store.namespaces.try_maintain(ns.id())?.is_none());
        drop(token);
        assert!(store.namespaces.try_maintain(ns.id())?.is_some());
        Ok(())
    }

    /// A publication admitted before a retirement began is refused when it
    /// reaches the gate the retirement released to it, not admitted under
    /// the retirement it preceded.
    #[test]
    fn a_grant_admitted_before_a_transition_is_refused_at_the_gate() -> TestResult {
        let store = crate::test_support::persistent_store()?.into_store();
        let ns = NamespaceRef::deterministic("gate-readmission");
        let plane = Arc::clone(store.control_planes().local());
        drop(
            store
                .namespaces
                .admit_publish(ns.id(), &Opening::Create { plane })?,
        );
        let early = store
            .namespaces
            .admit_publish(ns.id(), &Opening::Existing)?;
        let intent = store.namespaces.begin_retiring(ns.id(), |_| Ok(()))?;
        // Dropping the intent unreleased opens the gate and leaves the
        // namespace retiring.
        drop(intent);
        assert!(matches!(
            WriterGate::acquire(&early),
            Err(StoreError::Conflict(_))
        ));
        assert!(matches!(
            store.namespaces.admit_publish(ns.id(), &Opening::Existing),
            Err(StoreError::Conflict(_))
        ));
        Ok(())
    }
}
