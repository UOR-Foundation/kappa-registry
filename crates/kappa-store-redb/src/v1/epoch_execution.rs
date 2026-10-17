//! Ownership of a sealed epoch and its still-private storage transaction.

use std::cell::{Cell, RefCell};
use std::sync::Arc;
use std::time::Instant;

use redb::ReadableTable;

use kappa_store::{ClockMs, Kappa, NamespaceRef, StoreError};

use crate::PersistentStore;
use crate::allocation::Pin;
use crate::identity_local::AuthorizationRead;
use crate::namespace_write::DirectoryGuard;
use crate::settlement::ReleaseGrant;
use crate::storage::{Active, NamespaceController, Publish, WriterToken};

#[path = "epoch_publication.rs"]
mod publication;
pub use publication::PreparedEpochPublication;

/// What an execution hands to its publication: the directory changes it
/// made, the writer gate, the activity grant and, for a governed release
/// that publishes while the unsettled pool is closed, its release grant
/// (`settlement_release`), all of which outlive the sealed transaction.
/// Built in two places: an execution's `into_publication` and the test
/// seam `prepare_test_writer`.
pub struct ExecutionOwnership<'a> {
    pub(crate) directory: DirectoryGuard<'a>,
    pub(crate) writer: WriterToken,
    pub(crate) active: Active<Publish>,
    pub(crate) release: Option<ReleaseGrant<'a>>,
}

/// Who supplies the first control-plane assignment of a namespace an
/// execution creates. Irrelevant to an execution of a namespace that
/// already admits one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Creation {
    /// A plain execution (`PersistentStore::begin_epoch_execution`),
    /// which creates a namespace that admits no assignment yet under this
    /// node's local plane: when the execution wrote no assignment, the
    /// seal records the local plane's, with its own guarantees. A
    /// namespace whose uncommitted creation is under another plane is that
    /// creation's to complete, and is refused.
    LocalDefault,
    /// Created under a plane the caller chose
    /// (`PersistentStore::begin_creation_execution`): the execution must
    /// admit the assignment itself, or the publication is refused.
    Explicit,
}

#[path = "epoch_execution_namespace.rs"]
mod namespace_ops;

#[path = "epoch_execution_identity.rs"]
mod identity_ops;

#[path = "epoch_execution_contract.rs"]
mod contract;

#[path = "epoch_execution_admission.rs"]
mod admission;

#[path = "epoch_execution_content.rs"]
mod content_ops;

#[path = "epoch_execution_publish.rs"]
mod publish;

/// Private namespace execution. No mutation is visible before publication.
///
/// Dropping this value aborts all of its writes. The execution holds its
/// namespace active and owns its database writer; nothing of another
/// namespace waits on it.
#[must_use = "publish the execution or drop it to abort"]
pub struct EpochExecution<'a> {
    store: &'a PersistentStore,
    /// Declared before the ownership fields: on drop the transaction
    /// aborts first, then the directory changes resolve against the record
    /// still committed, then the writer gate opens, then the activity grant
    /// is released, so the controller is never evicted under an open
    /// transaction and the directory is resolved under the gate.
    transaction: redb::WriteTransaction,
    directory: DirectoryGuard<'a>,
    writer: WriterToken,
    active: Active<Publish>,
    /// Held from admission through commit when this execution is the
    /// governed release of an instance whose obligation closes the pool.
    release: Option<ReleaseGrant<'a>>,
    namespace: NamespaceRef,
    /// How a namespace without an admitted assignment gets one at seal.
    creation: Creation,
    now: ClockMs,
    signer_override: Option<Kappa>,
    failed: Cell<bool>,
    operation: Option<([u8; 32], Kappa)>,
    deadline: Option<Instant>,
    content_pins: Vec<Pin>,
    /// Authorization rows this execution read (`ExecutionReads::session_get`,
    /// `credential_get`), as observed in their admitting namespaces; they
    /// are re-read before publication and a change refuses it
    /// (`identity_local::authorization_reads_hold`).
    authorization_reads: RefCell<Vec<AuthorizationRead>>,
}

impl EpochExecution<'_> {
    pub(crate) const fn controller(&self) -> &Arc<NamespaceController> {
        self.active.controller()
    }

    /// Admit `record` as this namespace's control-plane assignment: the
    /// creation epoch's first, or a reassignment raising the generation
    /// by one. Checked against the planes this node serves before it is
    /// recorded, so an admitted assignment is always decidable here.
    pub fn assign_control_plane(
        &mut self,
        record: &crate::control_plane::AssignmentRecord,
    ) -> Result<(), StoreError> {
        self.ensure_active()?;
        let result = (|| {
            if record.namespace_id != self.namespace.id().as_slice() {
                return Err(StoreError::Rejected(
                    "assignment record names another namespace".into(),
                ));
            }
            let plane = self.store.control_planes().plane_for(Some(record))?;
            let (current, generation) = self.controller().plane()?;
            let admitted = self
                .store
                .namespaces
                .admitted_assignment(self.controller())?;
            match admitted {
                None => {
                    if record.generation != 0 || plane.id != current.id {
                        return Err(StoreError::Rejected(
                            "the creation epoch admits generation 0 under the creating plane"
                                .into(),
                        ));
                    }
                }
                Some(_) => {
                    if record.generation != generation + 1 {
                        return Err(StoreError::Rejected(format!(
                            "reassignment generation {} must be {}",
                            record.generation,
                            generation + 1
                        )));
                    }
                }
            }
            self.store.namespace_put_meta_in_txn(
                &self.transaction,
                &self.namespace,
                crate::control_plane::ASSIGNMENT_KEY,
                &kappa_store::canonical::canonical_bytes(record),
                self.now,
            )
        })();
        self.admit_result(result)
    }

    fn ensure_active(&self) -> Result<(), StoreError> {
        if self.failed.get() {
            return Err(StoreError::Conflict("epoch execution has failed".into()));
        }
        Ok(())
    }

    fn admit_result<T>(&self, result: Result<T, StoreError>) -> Result<T, StoreError> {
        if result.is_err() {
            self.failed.set(true);
        }
        result
    }

    pub fn tag_put(
        &mut self,
        name: &str,
        update: &kappa_store::TagUpdate,
    ) -> Result<(), StoreError> {
        self.ensure_active()?;
        let result =
            self.store
                .tag_put_in_txn(&self.transaction, &self.namespace, name, update, self.now);
        self.admit_result(result).map(|_| ())
    }

    pub fn namespace_info(&self) -> Result<Option<kappa_store::NamespaceInfo>, StoreError> {
        self.ensure_active()?;
        self.admit_result(kappa_store::absent(PersistentStore::namespace_info_in_txn(
            &self.transaction,
            &self.namespace,
        )))
    }

    pub fn sequence_current(&self, name: &str) -> Result<u64, StoreError> {
        self.ensure_active()?;
        self.admit_result(self.store.sequence_current_in_txn(
            &self.transaction,
            &self.namespace,
            name,
        ))
    }

    pub fn sequence_next(&mut self, name: &str) -> Result<u64, StoreError> {
        self.ensure_active()?;
        let result = (|| {
            let value =
                self.store
                    .sequence_next_in_txn(&self.transaction, &self.namespace, name)?;
            let evidence =
                kappa_store::canonical::canonical_bytes(&kappa_store::epoch::SequenceRecord {
                    namespace_id: self.namespace.id().to_vec(),
                    name: name.to_owned(),
                    value,
                });
            let content =
                kappa_store::VerifiedContent::compute(kappa_store::Axis::Sha256, &evidence)?;
            let pin = self.install_record(&content)?;
            self.store.record_mutation_in_txn(
                &self.transaction,
                &self.namespace,
                kappa_store::MutationOp::SequenceUpdate,
                content.kappa().clone(),
                self.now,
                Some(name.to_owned()),
            )?;
            Ok((value, pin))
        })();
        let (value, pin) = self.admit_result(result)?;
        self.content_pins.extend(pin);
        Ok(value)
    }

    /// Install a record this execution produced; the returned pin belongs
    /// in `content_pins`.
    fn install_record(
        &self,
        content: &kappa_store::VerifiedContent,
    ) -> Result<Option<Pin>, StoreError> {
        let (_, pin) = crate::epoch_blob::install_record_in_txn(
            self.store,
            &self.transaction,
            &self.namespace,
            content,
        )?;
        Ok(pin)
    }

    pub fn namespace_transfer(&mut self, new_owner: &Kappa) -> Result<(), StoreError> {
        self.ensure_active()?;
        let result = self.store.namespace_transfer_in_txn(
            &self.transaction,
            &self.namespace,
            new_owner,
            self.now,
        );
        self.admit_result(result)
    }

    pub fn namespace_delete(&mut self) -> Result<(), StoreError> {
        self.ensure_active()?;
        self.directory.touch();
        self.admit_result(self.store.namespace_delete_in_txn(
            &self.transaction,
            &self.namespace,
            self.now,
        ))
    }

    pub fn tag_delete(&mut self, name: &str) -> Result<(), StoreError> {
        self.ensure_active()?;
        let result =
            self.store
                .tag_delete_in_txn(&self.transaction, &self.namespace, name, self.now);
        self.admit_result(result).map(|_| ())
    }

    /// Resolves symbolic references. A dangling reference is absent; a
    /// reference cycle is a failure and latches the execution.
    pub fn tag_get(&self, name: &str) -> Result<Option<kappa_store::TagEntry>, StoreError> {
        self.ensure_active()?;
        self.admit_result(kappa_store::absent(
            kappa_store::tag_resolution::resolve_tag(name, |target| self.read_tag_raw(target)),
        ))
    }

    /// Raw records and symbolic-reference traversal share this execution's writer.
    pub fn tag_get_raw(&self, name: &str) -> Result<Option<kappa_store::TagEntry>, StoreError> {
        self.ensure_active()?;
        self.admit_result(kappa_store::absent(self.read_tag_raw(name)))
    }

    fn read_tag_raw(&self, name: &str) -> Result<kappa_store::TagEntry, StoreError> {
        let key = super::tag::tag_key(&self.namespace, name);
        let table = self
            .transaction
            .open_table(crate::tables::TAGS)
            .map_err(crate::error::redb)?;
        let entry = table
            .get(key.as_slice())
            .map_err(crate::error::redb)?
            .ok_or_else(|| StoreError::NotFound(format!("{}/{name}", self.namespace)))?;
        Ok(kappa_store::canonical::from_canonical(
            &self
                .store
                .decrypt_bytes(&super::tag::tag_context(&key), entry.value())?,
        )?)
    }

    pub fn edge_put(&mut self, input: &kappa_store::EdgeInput) -> Result<Kappa, StoreError> {
        self.ensure_active()?;
        let result = self.store.edge_mutation_put_in_txn(
            &self.transaction,
            &self.namespace,
            input,
            self.now,
        );
        self.admit_result(result)
    }

    /// Every member belongs to this execution; any rejected member prevents
    /// publication of the entire epoch, including mutations preceding the batch.
    pub fn tag_batch_update(
        &mut self,
        updates: &[(String, kappa_store::TagUpdate)],
    ) -> Result<(), StoreError> {
        self.ensure_active()?;
        let result = (|| {
            kappa_store::tag_update::validate_tag_batch(updates)?;
            for (name, update) in updates {
                self.store.tag_put_in_txn(
                    &self.transaction,
                    &self.namespace,
                    name,
                    update,
                    self.now,
                )?;
            }
            Ok(())
        })();
        self.admit_result(result)
    }

    pub fn edge_put_batch(
        &mut self,
        inputs: &[kappa_store::EdgeInput],
    ) -> Result<Vec<Kappa>, StoreError> {
        self.ensure_active()?;
        inputs.iter().map(|input| self.edge_put(input)).collect()
    }

    pub fn edge_delete(&mut self, identity: &Kappa) -> Result<(), StoreError> {
        self.ensure_active()?;
        let result =
            self.store
                .edge_delete_in_txn(&self.transaction, &self.namespace, identity, self.now);
        self.admit_result(result)
    }

    /// Install verified bytes this execution already holds (records it
    /// produces). Content from a request is prepared outside the writer
    /// and installed with `install_content`. A record the namespace did
    /// not already hold is admitted by a `RecordPublish` mutation naming
    /// it, so settlement projects its catalog entry and, for an external
    /// representation, its allocation ownership from the ledger.
    pub fn blob_put(&mut self, content: &kappa_store::VerifiedContent) -> Result<bool, StoreError> {
        self.ensure_active()?;
        let result = (|| {
            let (new, pin) = crate::epoch_blob::install_record_in_txn(
                self.store,
                &self.transaction,
                &self.namespace,
                content,
            )?;
            if new {
                self.store.record_mutation_in_txn(
                    &self.transaction,
                    &self.namespace,
                    kappa_store::MutationOp::RecordPublish,
                    content.kappa().clone(),
                    self.now,
                    None,
                )?;
            }
            Ok((new, pin))
        })();
        let (new, pin) = self.admit_result(result)?;
        self.content_pins.extend(pin);
        Ok(new)
    }

    /// The session under `token` as its admitting namespace holds it now,
    /// recorded as an authorization dependency of this execution.
    pub fn session_get(&self, token: &str) -> Result<Option<(Kappa, Vec<u8>)>, StoreError> {
        self.ensure_active()?;
        let result =
            self.store
                .session_read_for_execution(token, self.now)
                .map(|(read, session)| {
                    self.authorization_reads.borrow_mut().push(read);
                    session
                });
        self.admit_result(result)
    }

    /// The credential under `credential_id` as its admitting namespace
    /// holds it now, recorded as an authorization dependency.
    pub fn credential_get(
        &self,
        credential_id: &str,
    ) -> Result<Option<kappa_store::traits::identity::CredentialLookup>, StoreError> {
        self.ensure_active()?;
        let result = self
            .store
            .credential_read_for_execution(credential_id, self.now)
            .map(|(reads, credential)| {
                self.authorization_reads.borrow_mut().extend(reads);
                credential
            });
        self.admit_result(result)
    }

    /// Every authorization row this execution read must still be what it
    /// read. Checked under this execution's writer gate immediately before
    /// the publication is prepared; the rows live in other namespaces'
    /// databases, so this is the latest point the check can be made and
    /// the publication of a revocation that lands after it is ordered
    /// after this epoch by its own namespace's writer.
    fn authorization_holds(&self) -> Result<(), StoreError> {
        let reads = self.authorization_reads.borrow();
        self.store.authorization_reads_hold(&reads)
    }

    /// Read and verify uncompressed content from this execution, including
    /// its private writes. The allocation limit is checked before allocation.
    pub fn blob_get_verified(
        &self,
        identity: &Kappa,
        maximum: u64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.ensure_active()?;
        self.admit_result(kappa_store::absent(
            self.read_blob_verified(identity, maximum),
        ))
    }

    fn read_blob_verified(&self, identity: &Kappa, maximum: u64) -> Result<Vec<u8>, StoreError> {
        let index = self
            .transaction
            .open_table(crate::tables::BLOB_INDEX)
            .map_err(crate::error::redb)?;
        self.store
            .read_view_for(self.controller())
            .epoch_content_from_index(&index, identity, Some(maximum))
    }

    /// Explicitly release the writer and discard the entire execution.
    pub fn abort(self) -> Result<(), StoreError> {
        self.transaction.abort().map_err(crate::error::redb)
    }
}
