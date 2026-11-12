//! Operation admission. Committed outcomes resolve from authenticated epoch
//! evidence in one namespace view; replay never acquires the writer.

use kappa_store::operation::{OperationOutcomeInput, admit_operation_outcome};
use kappa_store::time::Clock;
use kappa_store::transition::RecordTransition;
use kappa_store::{
    EpochRoot, Execution, ExecutionStore, Kappa, NamespaceRef, OperationAdmission,
    OperationReceipt, PublicationResolution, StoreError, WorkMeter,
};
use kappa_types::work::{Dimension, Meter};

use super::InMemoryStore;
use super::blob_read;
use super::epoch_read::unadmitted_epoch_in;
use super::execution::{MemoryExecution, MemoryPayload, WriteCx};
use super::view::NamespaceView;

/// The most bytes an operation receipt encodes to beyond its result: the
/// 16-byte namespace and incarnation, the 32-byte operation identity, the
/// request's canonical kappa text (at most 140 bytes with its header), and
/// the map header, five labels and five value headers at their widest.
const RECEIPT_FIXED_BOUND: u64 = 16 + 16 + 32 + 140 + 1 + 5 + 5 * 9;

impl WriteCx<'_> {
    /// Apply the receipt binding operation `identity` and `request` to
    /// `result` in this candidate, its encoding charged to the execution's
    /// meter before it is built. Returns the receipt's evidence identity,
    /// which the publication attaches to its root once signed.
    pub(super) fn publish_receipt(
        &mut self,
        identity: [u8; 32],
        request: Kappa,
        result: Vec<u8>,
    ) -> Result<Kappa, StoreError> {
        let bound = RECEIPT_FIXED_BOUND.saturating_add(result.len() as u64);
        self.meter.charge_all(&[
            (Dimension::BytesAllocated, bound),
            (Dimension::BytesHashed, bound),
        ])?;
        let receipt = OperationReceipt::new(
            self.ns,
            &self.incarnation_bytes(),
            &identity,
            request,
            result,
        )?;
        self.apply_record_transition(
            RecordTransition::OperationPublish(receipt),
            MemoryPayload::NoResources,
        )
    }
}

impl InMemoryStore {
    /// The authenticated committed outcome of operation `identity` in
    /// `view`, if any, on `work`: the receipt lookup examined, the epoch
    /// root read and decoded unadmitted, then the receipt and the ledger
    /// each read and verified once, and the outcome admitted by the shared
    /// rule (`admit_operation_outcome`), which admits the epoch with its
    /// ledger exactly once.
    fn operation_in(
        &self,
        view: &NamespaceView,
        namespace: &NamespaceRef,
        identity: &[u8; 32],
        request: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<Option<(EpochRoot, OperationReceipt)>, StoreError> {
        work.charge(Dimension::Entries, 1)?;
        let Some((root_identity, receipt_identity)) = view.operations.get(identity).cloned() else {
            return Ok(None);
        };
        let epoch = unadmitted_epoch_in(view, &root_identity, work, &self.decoded_storage)?;
        let receipt = blob_read::verified(
            view,
            &receipt_identity,
            Some(OperationReceipt::MAX_RESULT_SIZE as u64 + 1024),
            work,
        )?;
        let ledger = blob_read::verified(view, epoch.ledger_root(), None, work)?;
        let receipt = admit_operation_outcome(
            OperationOutcomeInput {
                epoch: &epoch,
                ledger: &ledger,
                receipt: &receipt,
                namespace,
                incarnation: &view.logical_incarnation(),
                identity,
                request,
            },
            &self.authority.load(),
            work,
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
        let execution = MemoryExecution::new(self, writer, slot, namespace, now, clock.retain())?;
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
        self.operation_in(
            &self.view(namespace.id()),
            namespace,
            identity,
            request,
            &mut self.read_meter(),
        )
    }

    /// One read meter covers both resolutions: the unlocked one and the
    /// recheck under the writer.
    fn begin_operation(
        &self,
        namespace: &NamespaceRef,
        identity: [u8; 32],
        request: Kappa,
        clock: &dyn Clock,
    ) -> Result<OperationAdmission<'_>, StoreError> {
        let mut meter = self.read_meter();
        if let Some((epoch, receipt)) = self.operation_in(
            &self.view(namespace.id()),
            namespace,
            &identity,
            &request,
            &mut meter,
        )? {
            return Ok(OperationAdmission::Replay {
                epoch: Box::new(epoch),
                receipt,
            });
        }
        let execution = self.open_execution(namespace, clock)?;
        // Recheck under the writer: a concurrent publication may have
        // committed this operation after the unlocked resolution.
        match self.operation_in(
            execution.candidate(),
            namespace,
            &identity,
            &request,
            &mut meter,
        )? {
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

    fn resolve_publication(
        &self,
        namespace: &NamespaceRef,
        clock: &dyn Clock,
        meter: &mut WorkMeter,
    ) -> Result<PublicationResolution, StoreError> {
        self.resolve_retained(namespace, clock, meter)
    }
}
