//! Admission of executions and operations under a namespace's writer.
//!
//! An execution holds its namespace's controller active and its database
//! writer for its whole life; executions of different namespaces proceed
//! concurrently. Admission is refused while the namespace is fenced (a
//! commit outcome is unknown until recovery) and while it has no admitted
//! control-plane assignment: a namespace nobody decides for publishes
//! nothing.

use std::cell::Cell;

use kappa_store::time::Clock;
use kappa_store::{
    ClockMs, EpochRoot, Execution, Kappa, NamespaceRef, OperationAdmission, StoreError,
};

use super::{Creation, EpochExecution, ExecutionOwnership, PreparedEpochPublication};
use crate::PersistentStore;
use crate::namespace_write::DirectoryGuard;
use crate::settlement::ReleaseGrant;
use crate::storage::{Active, Opening, Publish, WriterGate};

#[cfg(test)]
#[path = "epoch_admission_race_tests.rs"]
mod race_tests;

impl kappa_store::ExecutionStore for PersistentStore {
    fn resolve_operation(
        &self,
        namespace: &NamespaceRef,
        identity: &[u8; 32],
        request: &Kappa,
    ) -> Result<Option<(EpochRoot, kappa_store::OperationReceipt)>, StoreError> {
        Self::resolve_operation(self, namespace, identity, request)
    }

    fn begin_operation(
        &self,
        namespace: &NamespaceRef,
        identity: [u8; 32],
        request: Kappa,
        clock: &dyn Clock,
    ) -> Result<OperationAdmission<'_>, StoreError> {
        self.begin_operation_with(namespace, identity, request, clock, None)
    }

    fn begin_execution(
        &self,
        namespace: &NamespaceRef,
        clock: &dyn Clock,
    ) -> Result<Box<dyn Execution + '_>, StoreError> {
        Ok(Box::new(
            self.begin_epoch_execution(namespace, clock, None)?,
        ))
    }
}

impl PersistentStore {
    /// Admit an operation of `namespace`, carrying `release` into its
    /// execution when it is the governed release of an instance whose
    /// obligation closes the unsettled pool (`settlement_release`): the
    /// one operation admission, `begin_operation` included. A committed
    /// outcome resolves through a read transaction first, so pending
    /// writers cannot block replay of an already published operation; the
    /// grant then drops unused.
    pub(crate) fn begin_operation_with<'s>(
        &'s self,
        namespace: &NamespaceRef,
        identity: [u8; 32],
        request: Kappa,
        clock: &dyn Clock,
        release: Option<ReleaseGrant<'s>>,
    ) -> Result<OperationAdmission<'s>, StoreError> {
        if let Some((epoch, receipt)) =
            Self::resolve_operation(self, namespace, &identity, &request)?
        {
            return Ok(OperationAdmission::Replay {
                epoch: Box::new(epoch),
                receipt,
            });
        }
        self.admit_operation(namespace, identity, request, clock, release)
    }

    /// Recheck uniqueness under the namespace writer before execution.
    fn admit_operation<'s>(
        &'s self,
        namespace: &NamespaceRef,
        identity: [u8; 32],
        request: Kappa,
        clock: &dyn Clock,
        release: Option<ReleaseGrant<'s>>,
    ) -> Result<OperationAdmission<'s>, StoreError> {
        let mut execution = self.begin_execution_with(namespace, clock, None, release)?;
        let outcome = {
            let operations = execution
                .transaction
                .open_table(crate::tables::OPERATION_RECEIPTS)
                .map_err(crate::error::redb)?;
            let blobs = execution
                .transaction
                .open_table(crate::tables::BLOB_INDEX)
                .map_err(crate::error::redb)?;
            self.operation_from_tables(
                execution.controller(),
                &operations,
                &blobs,
                namespace,
                &identity,
                &request,
            )?
        };
        if let Some((epoch, receipt)) = outcome {
            execution.abort()?;
            return Ok(OperationAdmission::Replay {
                epoch: Box::new(epoch),
                receipt,
            });
        }
        execution.operation = Some((identity, request));
        Ok(OperationAdmission::Execute(Box::new(execution)))
    }

    /// Acquire the namespace's writer, then issue the execution's time from
    /// `clock`: issuance order is publication order within the namespace.
    pub fn begin_epoch_execution(
        &self,
        namespace: &NamespaceRef,
        clock: &dyn Clock,
        signer_override: Option<&Kappa>,
    ) -> Result<EpochExecution<'_>, StoreError> {
        self.begin_execution_with(namespace, clock, signer_override, None)
    }

    /// `begin_epoch_execution`, carrying `release` into the execution. A
    /// plain execution is [`Creation::LocalDefault`] whether or not
    /// storage exists: storage a creation left without committing admits
    /// no assignment, and the execution that commits its first epoch is
    /// its creation.
    fn begin_execution_with<'s>(
        &'s self,
        namespace: &NamespaceRef,
        clock: &dyn Clock,
        signer_override: Option<&Kappa>,
        release: Option<ReleaseGrant<'s>>,
    ) -> Result<EpochExecution<'s>, StoreError> {
        match self
            .namespaces
            .admit_publish(namespace.id(), &Opening::Existing)
        {
            Ok(active) => self.begin_execution_on(
                active,
                namespace,
                Creation::LocalDefault,
                clock,
                signer_override,
                release,
            ),
            // No storage: the execution creates the namespace, under this
            // node's local plane as the creation authority. The creation
            // epoch admits the first assignment: the execution's own, or
            // the local plane's recorded at seal; a namespace the
            // directory already knows is not recreated.
            Err(StoreError::NotFound(_)) if !self.directory_knows(namespace)? => {
                let active = self.namespaces.admit_publish(
                    namespace.id(),
                    &Opening::Create {
                        plane: std::sync::Arc::clone(self.control_planes().local()),
                    },
                )?;
                self.begin_execution_on(
                    active,
                    namespace,
                    Creation::LocalDefault,
                    clock,
                    signer_override,
                    release,
                )
            }
            Err(error) => Err(error),
        }
    }

    /// Begin the execution that creates `namespace`, decided by `plane`.
    /// The creation epoch must admit the namespace's first assignment
    /// (`EpochExecution::assign_control_plane`, or the assignment metadata
    /// written directly); an execution that publishes without one is
    /// refused before it seals.
    pub fn begin_creation_execution(
        &self,
        namespace: &NamespaceRef,
        plane: std::sync::Arc<crate::control_plane::ControlPlane>,
        clock: &dyn Clock,
        signer_override: Option<&Kappa>,
    ) -> Result<EpochExecution<'_>, StoreError> {
        let active = self
            .namespaces
            .admit_publish(namespace.id(), &Opening::Create { plane })?;
        self.begin_execution_on(
            active,
            namespace,
            Creation::Explicit,
            clock,
            signer_override,
            None,
        )
    }

    fn begin_execution_on<'s>(
        &'s self,
        active: Active<Publish>,
        namespace: &NamespaceRef,
        creation: Creation,
        clock: &dyn Clock,
        signer_override: Option<&Kappa>,
        release: Option<ReleaseGrant<'s>>,
    ) -> Result<EpochExecution<'s>, StoreError> {
        use redb::ReadableTable;
        let controller = std::sync::Arc::clone(active.controller());
        // Fast refusals before waiting for the writer. Both are rechecked
        // under the gate below: the fence may be installed by the commit
        // this admission waits behind.
        if controller.fenced() {
            return Err(StoreError::Conflict(
                "publication requires recovery after a failed commit".into(),
            ));
        }
        controller.plane()?;
        #[cfg(test)]
        race_tests::before_writer();
        // The gate is held from here until the commit outcome of this
        // execution is classified, so the fence check below is serialized
        // with every commit-to-fence transition of this namespace. Taking
        // it admits the publication again under the namespace's lifecycle:
        // one admitted before a retirement began is refused here.
        let writer = WriterGate::acquire(&active)?;
        if controller.fenced() {
            return Err(StoreError::Conflict(
                "publication requires recovery after a failed commit".into(),
            ));
        }
        // A committed reassignment this controller could not install
        // leaves its authority stale: refresh from the admitted record
        // under the gate, or admit nothing.
        if controller.assignment_is_stale() {
            self.install_assignment(&controller)?;
        }
        // A namespace without an admitted assignment has no decision
        // authority; a namespace being created serves under its creation
        // plane for exactly the epoch that admits one.
        controller.plane()?;
        self.recover_namespace_head(&controller)?;
        // The per-namespace backlog is the durable distance from the
        // settlement checkpoint to the head, not the pins this process
        // happens to hold: it is the same before and after a restart.
        let backlog = self.unsettled_backlog(&controller)?;
        if backlog >= self.max_unsettled_epochs as u64 {
            return Err(StoreError::CapacityExceeded(format!(
                "namespace {namespace} has {backlog} unsettled epochs; settlement must catch up"
            )));
        }
        // An instance holding a recovery obligation has pre-restart
        // unsettled ownership recovery has not settled; it publishes
        // nothing more until settlement discharges the obligation, so its
        // head stays where recovery captured it.
        if self.obligation_held(&controller.instance) {
            return Err(StoreError::CapacityExceeded(format!(
                "namespace {namespace} holds a recovery obligation; settlement must reach its head"
            )));
        }
        let transaction = controller.db.begin_write().map_err(crate::error::redb)?;
        // Pins parked by a previous transaction that never sealed belong to
        // allocations no committed row owns; releasing them makes those
        // allocations reclaimable.
        controller
            .writer_pins
            .lock()
            .map_err(|_| StoreError::Internal("writer pin set poisoned".into()))?
            .clear();
        // Rows recorded by a previous transaction that never published were
        // never registered and never committed; this execution starts clean.
        controller
            .installed_rows
            .lock()
            .map_err(|_| StoreError::Internal("installed row set poisoned".into()))?
            .clear();
        let now = clock.now()?;
        // MUTATION_BUFFER is written only by record_mutation_in_txn inside a
        // write transaction that seal_epoch_in_txn drains before commit, so a
        // committed entry for this namespace is never produced by a
        // well-formed publication. It is corruption or residue; admitting
        // over it would seal those foreign mutations into this epoch.
        {
            let mutations = transaction
                .open_table(crate::tables::MUTATION_BUFFER)
                .map_err(crate::error::redb)?;
            if mutations
                .iter()
                .map_err(crate::error::redb)?
                .next()
                .transpose()
                .map_err(crate::error::redb)?
                .is_some()
            {
                return Err(StoreError::Conflict(
                    "namespace has mutations outside epoch execution".into(),
                ));
            }
        }
        // The buffer is empty, so this execution's mutation keys start at 0.
        controller
            .mutation_seq
            .store(0, std::sync::atomic::Ordering::Relaxed);
        Ok(EpochExecution {
            store: self,
            transaction,
            directory: DirectoryGuard::new(self, controller),
            writer,
            active,
            release,
            namespace: namespace.clone(),
            creation,
            now,
            signer_override: signer_override.cloned(),
            failed: Cell::new(false),
            operation: None,
            deadline: None,
            content_pins: Vec::new(),
            authorization_reads: std::cell::RefCell::new(Vec::new()),
        })
    }

    /// Committed epochs of `controller`'s namespace past its settlement
    /// checkpoint. Read under the writer gate after head recovery, so the
    /// controller's epoch number is the head and no commit moves it.
    fn unsettled_backlog(
        &self,
        controller: &crate::storage::NamespaceController,
    ) -> Result<u64, StoreError> {
        let head = controller
            .epoch_number
            .load(std::sync::atomic::Ordering::Acquire);
        let checkpoint = self
            .settled_epoch(&controller.instance)?
            .map_or(0, |(number, _)| number);
        Ok(head.saturating_sub(checkpoint))
    }

    pub(crate) fn prepare_epoch_transaction<'s>(
        &'s self,
        ownership: ExecutionOwnership<'s>,
        transaction: redb::WriteTransaction,
        namespace: &NamespaceRef,
        creation: Creation,
        now: ClockMs,
        signer_override: Option<&Kappa>,
    ) -> Result<PreparedEpochPublication<'s>, StoreError> {
        let controller = std::sync::Arc::clone(ownership.active.controller());
        self.admit_creation_assignment(&transaction, &controller, namespace, creation, now)?;
        let sealed =
            self.seal_epoch_in_txn(&transaction, &controller, namespace, now, signer_override)?;
        let mut content_pins = sealed.pins;
        {
            let mut parked = controller
                .writer_pins
                .lock()
                .map_err(|_| StoreError::Internal("writer pin set poisoned".into()))?;
            content_pins.append(&mut parked);
        }
        Ok(PreparedEpochPublication {
            store: self,
            transaction,
            directory: ownership.directory,
            writer: ownership.writer,
            active: ownership.active,
            release: ownership.release,
            namespace: namespace.clone(),
            root: sealed.root,
            predecessor: sealed.predecessor,
            assigns: sealed.assigns,
            now,
            deadline: None,
            content_pins,
        })
    }

    /// A namespace whose database admits no assignment is being created,
    /// and its creation epoch must admit one. When the execution wrote
    /// none, a [`Creation::LocalDefault`] creation records the assignment
    /// to this node's local plane (generation 0, the plane's own
    /// guarantees) as explicit ledger evidence, so the decision authority
    /// is always a recorded fact of the namespace, never inferred from
    /// absence; it is refused when the storage is being created under
    /// another plane, whose creation must admit that plane itself. A
    /// [`Creation::Explicit`] creation that wrote none is refused.
    fn admit_creation_assignment(
        &self,
        transaction: &redb::WriteTransaction,
        controller: &crate::storage::NamespaceController,
        namespace: &NamespaceRef,
        creation: Creation,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        if self.namespaces.admitted_assignment(controller)?.is_some() {
            return Ok(());
        }
        match self.namespace_get_meta_in_txn(
            transaction,
            namespace,
            crate::control_plane::ASSIGNMENT_KEY,
        ) {
            Ok(_) => return Ok(()),
            Err(StoreError::NotFound(_)) => {}
            Err(error) => return Err(error),
        }
        if creation == Creation::Explicit {
            return Err(StoreError::Rejected(format!(
                "the creation epoch of {namespace} admits no control-plane assignment"
            )));
        }
        let (plane, _) = controller.plane()?;
        if plane.id != self.control_planes().local().id {
            return Err(StoreError::Rejected(format!(
                "{namespace} is being created under another plane; its creation epoch must admit that plane's assignment"
            )));
        }
        let record = crate::control_plane::AssignmentRecord {
            namespace_id: namespace.id().to_vec(),
            plane: plane.id.0.to_vec(),
            generation: 0,
            requires: plane.agreement.guarantees(),
        };
        self.namespace_put_meta_in_txn(
            transaction,
            namespace,
            crate::control_plane::ASSIGNMENT_KEY,
            &kappa_store::canonical::canonical_bytes(&record),
            now,
        )
    }

    /// Prepare content from a request outside any writer: the trait form
    /// of [`PersistentStore::prepare_representation`].
    fn prepare_for_trait(
        &self,
        identity: kappa_store::ContentIdentity,
        reader: &mut dyn std::io::Read,
        bounds: kappa_store::PreparationBounds,
    ) -> Result<Box<dyn kappa_store::PreparedContent>, StoreError> {
        let prepared = match identity {
            kappa_store::ContentIdentity::Verified(expected) => self.prepare_representation(
                expected.axis(),
                Some(&expected),
                reader,
                None,
                bounds.maximum,
                bounds.deadline,
            )?,
            kappa_store::ContentIdentity::Computed(axis) => self.prepare_representation(
                axis,
                None,
                reader,
                None,
                bounds.maximum,
                bounds.deadline,
            )?,
            kappa_store::ContentIdentity::Compressed {
                identity,
                algorithm,
                uncompressed_size,
            } => self.prepare_compressed_content(
                &identity,
                &algorithm,
                uncompressed_size,
                reader,
                bounds.maximum,
                bounds.deadline,
            )?,
        };
        Ok(Box::new(prepared))
    }
}

impl kappa_store::ContentPreparation for PersistentStore {
    fn prepare_content(
        &self,
        identity: kappa_store::ContentIdentity,
        reader: &mut dyn std::io::Read,
        bounds: kappa_store::PreparationBounds,
    ) -> Result<Box<dyn kappa_store::PreparedContent>, StoreError> {
        self.prepare_for_trait(identity, reader, bounds)
    }
}
