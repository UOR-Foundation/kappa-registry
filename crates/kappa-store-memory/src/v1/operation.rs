//! Operation admission. Committed outcomes resolve from authenticated epoch
//! evidence in one namespace view; replay never acquires the writer.

use kappa_store::operation::{OperationOutcomeInput, admit_operation_outcome};
use kappa_store::time::Clock;
use kappa_store::{
    EpochRoot, Execution, ExecutionStore, Kappa, NamespaceRef, OperationAdmission,
    OperationReceipt, StoreError,
};

use super::InMemoryStore;
use super::blob_read;
use super::execution::MemoryExecution;
use super::view::NamespaceView;

impl InMemoryStore {
    fn operation_in(
        &self,
        view: &NamespaceView,
        namespace: &NamespaceRef,
        identity: &[u8; 32],
        request: &Kappa,
    ) -> Result<Option<(EpochRoot, OperationReceipt)>, StoreError> {
        let Some((root_identity, receipt_identity)) = view.operations.get(identity).cloned() else {
            return Ok(None);
        };
        let epoch = self.epoch_in(view, &root_identity)?;
        let receipt_bytes = blob_read::verified(
            view,
            &receipt_identity,
            Some(OperationReceipt::MAX_RESULT_SIZE as u64 + 1024),
        )?;
        let ledger = blob_read::verified(view, epoch.ledger_root(), None)?;
        let receipt = admit_operation_outcome(
            OperationOutcomeInput {
                epoch: &epoch,
                ledger: &ledger,
                receipt_identity: &receipt_identity,
                receipt_bytes: &receipt_bytes,
                namespace,
                identity,
                request,
            },
            &self.authority.load(),
        )?;
        Ok(Some((epoch, receipt)))
    }

    /// Open an execution of `namespace`, holding its writer gate.
    ///
    /// Time is issued only once the gate is held, so the namespace's
    /// executions publish in the order their timestamps were issued.
    pub(crate) fn open_execution(
        &self,
        namespace: &NamespaceRef,
        clock: &dyn Clock,
    ) -> Result<MemoryExecution<'_>, StoreError> {
        let slot = self.slot(namespace.id())?;
        let writer = slot.gate.acquire();
        let now = clock.now()?;
        let execution = MemoryExecution::new(self, writer, slot, namespace, now)?;
        if !execution.candidate().ledger.is_empty() {
            return Err(StoreError::Conflict(
                "namespace has mutations outside epoch execution".into(),
            ));
        }
        Ok(execution)
    }
}

impl ExecutionStore for InMemoryStore {
    fn resolve_operation(
        &self,
        namespace: &NamespaceRef,
        identity: &[u8; 32],
        request: &Kappa,
    ) -> Result<Option<(EpochRoot, OperationReceipt)>, StoreError> {
        self.operation_in(&self.view(namespace.id()), namespace, identity, request)
    }

    fn begin_operation(
        &self,
        namespace: &NamespaceRef,
        identity: [u8; 32],
        request: Kappa,
        clock: &dyn Clock,
    ) -> Result<OperationAdmission<'_>, StoreError> {
        if let Some((epoch, receipt)) =
            self.operation_in(&self.view(namespace.id()), namespace, &identity, &request)?
        {
            return Ok(OperationAdmission::Replay {
                epoch: Box::new(epoch),
                receipt,
            });
        }
        let execution = self.open_execution(namespace, clock)?;
        // Recheck under the writer: a concurrent publication may have
        // committed this operation after the unlocked resolution.
        match self.operation_in(execution.candidate(), namespace, &identity, &request)? {
            Some((epoch, receipt)) => {
                // Release the writer before returning the committed outcome.
                drop(execution);
                Ok(OperationAdmission::Replay {
                    epoch: Box::new(epoch),
                    receipt,
                })
            }
            None => Ok(OperationAdmission::Execute(Box::new(
                execution.with_operation(identity, request),
            ))),
        }
    }

    fn begin_execution(
        &self,
        namespace: &NamespaceRef,
        clock: &dyn Clock,
    ) -> Result<Box<dyn Execution + '_>, StoreError> {
        Ok(Box::new(self.open_execution(namespace, clock)?))
    }
}
