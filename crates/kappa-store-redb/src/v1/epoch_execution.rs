//! Ownership of a sealed epoch and its still-private storage transaction.

use std::cell::{Cell, RefCell};
use std::sync::Arc;
use std::time::Instant;

use kappa_store::work::{Meter, WorkMeter};
use kappa_store::{ClockMs, Kappa, NamespaceRef, StoreError};

use crate::PersistentStore;
use crate::authority::AUTHORITY_TAG_PREFIX;
use crate::identity_local::AuthorizationRead;
use crate::namespace_write::DirectoryGuard;
use crate::settlement::ReleaseGrant;
use crate::storage::{Active, NamespaceController, Publish, WriterToken};
use crate::transition_apply::TxnWriter;

#[path = "epoch_publication.rs"]
mod publication;
pub(crate) use publication::{ActivationOutcome, PreparedEpochPublication};

/// What an execution hands to its publication: the guard of the authority
/// it is sealed under (`epoch::AuthorityGuard`), the directory changes it
/// made, the writer gate, the activity grant and, for a governed release
/// that publishes while the unsettled pool is closed, its release grant
/// (`settlement_release`), all of which outlive the prepared transaction.
/// Built in two places: an execution's `into_publication` and the test
/// seam `prepare_test_writer`.
pub struct ExecutionOwnership<'a, G> {
    pub(crate) guard: G,
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
#[cfg(test)]
pub(crate) use publish::Preparation;

/// Private namespace execution. No mutation is visible before publication.
///
/// Dropping this value aborts all of its writes. The execution holds its
/// namespace active and owns its database writer; nothing of another
/// namespace waits on it.
///
/// It owns one allowance from its admission (`meter`, the store's
/// publication limit, its deadline brought forward to the execution's):
/// every write it makes borrows it, its publication's preparation
/// continues on what remains, and nothing of the execution meters on an
/// allowance of its own.
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
    clock: Arc<dyn kappa_store::time::Clock>,
    signer_override: Option<Kappa>,
    failed: Cell<bool>,
    operation: Option<([u8; 32], Kappa)>,
    deadline: Option<Instant>,
    /// The execution's one allowance, lent to each write it makes.
    meter: RefCell<WorkMeter>,
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
        self.write(|store, txn, ns, now, meter| {
            if record.namespace_id != ns.id().as_slice() {
                return Err(StoreError::Rejected(
                    "assignment record names another namespace".into(),
                ));
            }
            let plane = store.control_planes().plane_for(Some(record))?;
            let (current, generation) = self.controller().plane()?;
            let admitted = store.namespaces.admitted_assignment(self.controller())?;
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
            store.namespace_put_meta_in_txn(
                txn,
                ns,
                crate::control_plane::ASSIGNMENT_KEY,
                &kappa_store::canonical::canonical_bytes(record),
                now,
                meter,
            )
        })
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

    /// Run `operation` on this execution's allowance. An operation already
    /// holding the allowance cannot take it again: that is a defect,
    /// refused. Latching is the caller's: a read decides what absence is
    /// before a failure latches.
    fn lend<T>(
        &self,
        operation: impl FnOnce(&mut dyn Meter) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        match self.meter.try_borrow_mut() {
            Ok(mut meter) => operation(&mut *meter),
            Err(_) => Err(StoreError::Internal(
                "an execution lent its allowance twice".into(),
            )),
        }
    }

    /// Run one write against this execution's transaction on its
    /// allowance ([`Self::lend`]), and latch failure.
    fn write<T>(
        &self,
        operation: impl FnOnce(
            &PersistentStore,
            &redb::WriteTransaction,
            &NamespaceRef,
            ClockMs,
            &mut dyn Meter,
        ) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.ensure_active()?;
        let result = self.lend(|meter| {
            operation(
                self.store,
                &self.transaction,
                &self.namespace,
                self.now,
                meter,
            )
        });
        self.admit_result(result)
    }

    /// Run `write` through the transition boundary over this execution's
    /// transaction, on the execution's allowance: every write of the
    /// execution is applied through it, and the allocation pins of what it
    /// installs are parked on the controller until the seal takes them into
    /// the publication.
    fn with_writer<T>(
        &self,
        write: impl FnOnce(&TxnWriter<'_>) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.write(|store, txn, ns, now, meter| write(&TxnWriter::new(store, txn, ns, now, meter)?))
    }

    /// A tag an ordinary execution may write or remove. Tags under
    /// [`AUTHORITY_TAG_PREFIX`] are the evidence that governs the store's
    /// authority: only an activation writes one ([`Self::record_activation`]),
    /// and nothing changes or removes it, so restart always recovers the
    /// authority they committed.
    fn ordinary_tag(name: &str) -> Result<(), StoreError> {
        if name.starts_with(AUTHORITY_TAG_PREFIX) {
            return Err(StoreError::Rejected(format!(
                "tag {name} is authority activation evidence; only an activation writes it"
            )));
        }
        Ok(())
    }

    pub fn tag_put(
        &mut self,
        name: &str,
        update: &kappa_store::TagUpdate,
    ) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now, meter| {
            Self::ordinary_tag(name)?;
            store.tag_put_in_txn(txn, ns, name, update, now, meter)
        })
        .map(drop)
    }

    /// Record the activation evidence of the authority transition at
    /// `position`: the transition `record`, admitted as a record of this
    /// namespace, under its create-only tag. Called only by the activation
    /// whose governing epoch this execution publishes.
    pub(crate) fn record_activation(
        &mut self,
        position: u64,
        record: &kappa_store::VerifiedContent,
    ) -> Result<(), StoreError> {
        self.blob_put(record)?;
        self.write(|store, txn, ns, now, meter| {
            store.tag_put_in_txn(
                txn,
                ns,
                &crate::authority::activation_tag(position),
                &kappa_store::TagUpdate::CreateIfAbsent {
                    kappa: record.kappa().clone(),
                },
                now,
                meter,
            )
        })
        .map(drop)
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
        self.with_writer(|writer| writer.sequence_next(name))
    }

    pub fn namespace_transfer(&mut self, new_owner: &Kappa) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.namespace_transfer_in_txn(txn, ns, new_owner, now, meter)
        })
    }

    pub fn namespace_delete(&mut self) -> Result<(), StoreError> {
        self.ensure_active()?;
        self.directory.touch();
        self.write(|store, txn, ns, now, meter| store.namespace_delete_in_txn(txn, ns, now, meter))
    }

    pub fn tag_delete(&mut self, name: &str) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now, meter| {
            Self::ordinary_tag(name)?;
            store.tag_delete_in_txn(txn, ns, name, now, meter)
        })
        .map(drop)
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

    /// The tag row `name` as this execution's transaction holds it, read by
    /// the one tag row reader (`tag::tag_row`) on the execution's
    /// allowance.
    fn read_tag_raw(&self, name: &str) -> Result<kappa_store::TagEntry, StoreError> {
        let table = self
            .transaction
            .open_table(crate::tables::TAGS)
            .map_err(crate::error::redb)?;
        self.lend(|work| super::tag::tag_row(self.store, &table, &self.namespace, name, work))?
            .ok_or_else(|| StoreError::NotFound(format!("{}/{name}", self.namespace)))
    }

    pub fn edge_put(&mut self, input: &kappa_store::EdgeInput) -> Result<Kappa, StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.edge_mutation_put_in_txn(txn, ns, input, now, meter)
        })
    }

    /// Every member belongs to this execution; any rejected member prevents
    /// publication of the entire epoch, including mutations preceding the batch.
    pub fn tag_batch_update(
        &mut self,
        updates: &[(String, kappa_store::TagUpdate)],
    ) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now, meter| {
            kappa_store::tag_update::validate_tag_batch(updates)?;
            for (name, _) in updates {
                Self::ordinary_tag(name)?;
            }
            for (name, update) in updates {
                store.tag_put_in_txn(txn, ns, name, update, now, meter)?;
            }
            Ok(())
        })
    }

    pub fn edge_put_batch(
        &mut self,
        inputs: &[kappa_store::EdgeInput],
    ) -> Result<Vec<Kappa>, StoreError> {
        self.ensure_active()?;
        inputs.iter().map(|input| self.edge_put(input)).collect()
    }

    pub fn edge_delete(&mut self, identity: &Kappa) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.edge_delete_in_txn(txn, ns, identity, now, meter)
        })
    }

    /// Install verified bytes this execution already holds (records it
    /// produces). Content from a request is prepared outside the writer
    /// and installed with `install_content`. A record the namespace did
    /// not already hold is admitted by its `RecordPublish` transition, so
    /// settlement projects its catalog entry and, for an external
    /// representation, its allocation ownership from the ledger.
    pub fn blob_put(&mut self, content: &kappa_store::VerifiedContent) -> Result<bool, StoreError> {
        self.with_writer(|writer| writer.admit_record(content))
    }

    /// The session under `token` as its admitting namespace holds it now,
    /// recorded as an authorization dependency of this execution.
    pub fn session_get(&self, token: &str) -> Result<Option<(Kappa, Vec<u8>)>, StoreError> {
        self.ensure_active()?;
        let result = self
            .store
            .session_read_for_execution(token, self.now, self.namespace.id(), &self.transaction)
            .map(|(read, session)| {
                self.authorization_reads.borrow_mut().extend(read);
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
            .credential_read_for_execution(
                credential_id,
                self.now,
                self.namespace.id(),
                &self.transaction,
            )
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
        self.store
            .authorization_reads_hold_at(&reads, self.clock.now()?)
    }

    /// Read and verify uncompressed content from this execution, including
    /// its private writes, on the execution's allowance. The allocation
    /// limit is checked before allocation.
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
        let view = self.store.read_view_for(self.controller());
        self.lend(|meter| view.epoch_content_from_index(&index, identity, Some(maximum), meter))
    }

    /// Explicitly release the writer and discard the entire execution
    /// ([`Self::abandon`]).
    pub fn abort(self) -> Result<(), StoreError> {
        self.abandon()
    }

    /// End this execution unpublished: its transaction aborts first, then
    /// its directory changes resolve against the record still committed,
    /// on what remains of its allowance and under its writer gate, then the
    /// gate opens, the activity grant ends and the release grant ends. A
    /// resolution that fails or that the allowance stops is left to
    /// settlement, journaled; the result is the abort's.
    pub(super) fn abandon(self) -> Result<(), StoreError> {
        let Self {
            transaction,
            directory,
            writer,
            active,
            release,
            namespace,
            meter,
            ..
        } = self;
        let aborted = transaction.abort().map_err(crate::error::redb);
        if let Err(error) = directory.resolve(&mut meter.into_inner()) {
            tracing::warn!(
                namespace = %namespace,
                %error,
                "directory changes of an aborted execution left to settlement"
            );
        }
        drop(writer);
        drop(active);
        drop(release);
        aborted
    }
}
