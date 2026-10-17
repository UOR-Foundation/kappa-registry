//! Sealing, deciding and committing epochs of one namespace.
//!
//! The seal runs inside the namespace's write transaction: it drains the
//! mutation buffer into a ledger, signs the root under the registry
//! authority, installs the records, moves the head pointer and the epoch
//! index. The commit then asks the namespace's control plane to decide
//! the proposal and, only when decided, commits the transaction. A
//! rejected decision aborts; an unresolved decision or a commit whose
//! outcome is unknown fences the namespace (and only it) until recovery.

use std::sync::atomic::Ordering;

use redb::ReadableTable;

use kappa_store::ContentCommitment;
use kappa_store::canonical::from_canonical;
use kappa_store::clock::ClockMs;
use kappa_store::epoch::{EpochMutation, MutationOp};
use kappa_store::epoch_publication::{EpochPublication, EpochPublicationInput};
use kappa_store::epoch_root::EpochRoot;
use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;

use crate::PersistentStore;
use crate::allocation::Pin;
use crate::commitments::{COMMITMENTS_CONTEXT, commitment_entry};
use crate::content_read::ReadView;
use crate::control_plane::{ASSIGNMENT_KEY, Decision};
use crate::encrypted::bound;
use crate::epoch_blob::install_record_in_txn;
use crate::referrers::{Referrer, establish, release};
use crate::storage::NamespaceController;
use crate::tables::{BLOB_INDEX, COMMITMENTS, EPOCH_CURRENT, EPOCH_INDEX, MUTATION_BUFFER};

#[path = "epoch_read.rs"]
mod read;

#[path = "epoch_verify.rs"]
mod verify;

/// A sealed epoch and the allocation pins its records hold until the
/// publication settles.
pub(crate) struct Sealed {
    pub(crate) root: EpochRoot,
    pub(crate) pins: Vec<Pin>,
    pub(crate) predecessor: Option<Kappa>,
    /// Whether the ledger admits a control-plane assignment (`_assign`).
    pub(crate) assigns: bool,
}

/// Why a publication did not commit, classified by what is known.
pub(crate) enum CommitFailure {
    /// The transaction did not commit; nothing of it persists.
    Known(StoreError),
    /// Whether the transaction persisted is unknown; the namespace is
    /// fenced and its dependencies belong to recovery.
    Unknown(StoreError),
}

#[cfg(test)]
#[path = "epoch_execution_tests.rs"]
mod execution_tests;

#[cfg(test)]
#[path = "epoch_recovery_tests.rs"]
mod recovery_tests;

#[cfg(test)]
#[path = "epoch_publication_tests.rs"]
mod publication_tests;

/// The AEAD context of the `EPOCH_CURRENT` pointer of namespace `ns`.
pub(crate) fn pointer_context(ns: &[u8; 16]) -> String {
    bound("epoch_ptr", ns)
}

/// Epoch index key: `[ns_uuid:16][epoch_number_be:8]`.
pub(crate) fn epoch_idx_key(ns: &NamespaceRef, epoch_number: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(24);
    k.extend_from_slice(ns.id());
    k.extend_from_slice(&epoch_number.to_be_bytes());
    k
}

impl PersistentStore {
    fn pending_epoch_mutations(
        txn: &redb::WriteTransaction,
        uuid: &[u8; 16],
    ) -> Result<Vec<EpochMutation>, StoreError> {
        let buffer = txn
            .open_table(MUTATION_BUFFER)
            .map_err(crate::error::redb)?;
        let prefix = uuid.as_slice();
        let end = Self::prefix_successor(prefix);
        let range = match &end {
            Some(end) => buffer
                .range(prefix..end.as_slice())
                .map_err(crate::error::redb)?,
            None => buffer.range(prefix..).map_err(crate::error::redb)?,
        };
        let mut mutations = Vec::new();
        for entry in range {
            let (key, value) = entry.map_err(crate::error::redb)?;
            if !key.value().starts_with(prefix) {
                break;
            }
            mutations.push(from_canonical(value.value())?);
        }
        Ok(mutations)
    }

    pub(crate) fn seal_epoch_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        controller: &NamespaceController,
        ns: &NamespaceRef,
        now: ClockMs,
        signer_override: Option<&Kappa>,
    ) -> Result<Sealed, StoreError> {
        let uuid = ns.id();
        if controller.id != *uuid {
            return Err(StoreError::Conflict(
                "execution namespace differs from its controller".into(),
            ));
        }
        let view = self.read_view_for(controller);
        let (committed_digest, committed_count) = self.tag_state_in_txn(txn, ns)?;
        // Select the predecessor while holding the namespace writer.
        // Publishing another epoch of this namespace cannot race this
        // selection.
        let prev_root_kappa = self.head_pointer(txn, uuid)?;
        let predecessor = prev_root_kappa
            .as_ref()
            .map(|key| {
                let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
                view.epoch_root_from_index(&index, key)
            })
            .transpose()?;
        let mutations = Self::pending_epoch_mutations(txn, uuid)?;
        let assigns = mutations.iter().any(|mutation| {
            mutation.op == MutationOp::MetadataUpdate
                && mutation.context.as_deref() == Some(ASSIGNMENT_KEY)
        });
        let publication = self.sign_epoch(EpochPublicationInput {
            namespace: ns,
            predecessor: predecessor.as_ref(),
            state_root: committed_digest.into_bytes(),
            tag_count: committed_count,
            mutations: &mutations,
            now,
            signer_override,
        })?;
        let mut pins = Vec::new();
        for content in [
            Some(publication.ledger()),
            Some(publication.root_blob()),
            publication.rotation_record(),
        ]
        .into_iter()
        .flatten()
        {
            let (_, pin) = install_record_in_txn(self, txn, ns, content)?;
            pins.extend(pin);
        }
        self.write_commitments(txn, &view, &mutations, publication.root_blob().kappa())?;
        self.edge_put_in_txn(txn, ns, publication.edge(), publication.edge_blob())?;
        for (link, content) in publication.retained_links() {
            self.edge_put_in_txn(txn, ns, link, content)?;
        }
        let epoch_root = publication.into_root();
        self.advance_head(txn, ns, prev_root_kappa.as_ref(), &epoch_root)?;
        Self::drain_mutation_buffer(txn, uuid)?;
        self.record_time_in_txn(txn, now)?;
        Ok(Sealed {
            root: epoch_root,
            pins,
            predecessor: prev_root_kappa,
            assigns,
        })
    }

    /// The root identity `EPOCH_CURRENT` names for namespace `uuid` in
    /// `txn`; `None` before the first epoch.
    fn head_pointer(
        &self,
        txn: &redb::WriteTransaction,
        uuid: &[u8; 16],
    ) -> Result<Option<Kappa>, StoreError> {
        let pointers = txn.open_table(EPOCH_CURRENT).map_err(crate::error::redb)?;
        let Some(pointer) = pointers.get(uuid.as_slice()).map_err(crate::error::redb)? else {
            return Ok(None);
        };
        let bytes = self.decrypt_bytes(&pointer_context(uuid), pointer.value())?;
        Ok(Some(Kappa::from_key_bytes(&bytes)?))
    }

    /// Sign the epoch `input` describes under the committed authority.
    ///
    /// Shared activation is held while signing: no rotation can be between
    /// its commit and its installation, so the authority snapshot is the
    /// one in force. `authority_unresolved` is set only under the exclusive
    /// gate, so reading it under the shared gate observes every unresolved
    /// rotation that completed before this seal.
    fn sign_epoch(&self, input: EpochPublicationInput<'_>) -> Result<EpochPublication, StoreError> {
        let activation = self
            .activation
            .read()
            .map_err(|_| StoreError::Internal("authority activation lock poisoned".into()))?;
        let authority = self.authority.load();
        if self.authority_unresolved.load(Ordering::SeqCst) {
            return Err(StoreError::AuthorityUnresolved {
                outgoing: Box::new(authority.anchor().clone()),
            });
        }
        let publication = EpochPublication::prepare(input, &authority);
        drop(authority);
        drop(activation);
        publication
    }

    /// Record the commitment coordinates of every `ContentPublish` in
    /// `mutations`: the epoch `epoch_identity` that authenticates it and the
    /// commitment content, both resolvable from the signed history.
    fn write_commitments(
        &self,
        txn: &redb::WriteTransaction,
        view: &ReadView,
        mutations: &[EpochMutation],
        epoch_identity: &Kappa,
    ) -> Result<(), StoreError> {
        let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
        let mut entries = Vec::new();
        for mutation in mutations
            .iter()
            .filter(|mutation| mutation.op == MutationOp::ContentPublish)
        {
            let bytes = view.epoch_content_from_index(&index, &mutation.kappa, None)?;
            let commitment: ContentCommitment = from_canonical(&bytes)?;
            entries.push((commitment.identity().key_bytes(), &mutation.kappa));
        }
        drop(index);
        let mut table = txn.open_table(COMMITMENTS).map_err(crate::error::redb)?;
        for (identity_key, commitment) in entries {
            let value = self.encrypt_bytes(
                &bound(COMMITMENTS_CONTEXT, &identity_key),
                &commitment_entry(epoch_identity, commitment)?,
            )?;
            table
                .insert(identity_key.as_slice(), value.as_slice())
                .map_err(crate::error::redb)?;
        }
        Ok(())
    }

    /// Make `epoch_root` the head of `ns`. The head referrer moves with
    /// `EPOCH_CURRENT`: the previous root is now retained by the new root's
    /// predecessor edge, the new root by being the head. The ledger and
    /// every other dependency are retained by the `EpochRoot` edges the
    /// seal writes. The epoch index gains the new root at its number.
    fn advance_head(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        previous: Option<&Kappa>,
        epoch_root: &EpochRoot,
    ) -> Result<(), StoreError> {
        let uuid = ns.id();
        let head = Referrer::epoch_head(ns);
        if let Some(previous) = previous {
            release(self, txn, previous, &head)?;
        }
        establish(self, txn, epoch_root.kappa(), &head)?;
        let root_key = epoch_root.kappa().key_bytes();
        let stored = self.encrypt_bytes(&pointer_context(uuid), &root_key)?;
        txn.open_table(EPOCH_CURRENT)
            .map_err(crate::error::redb)?
            .insert(uuid.as_slice(), stored.as_slice())
            .map_err(crate::error::redb)?;
        let idx_key = epoch_idx_key(ns, epoch_root.epoch_number());
        txn.open_table(EPOCH_INDEX)
            .map_err(crate::error::redb)?
            .insert(idx_key.as_slice(), root_key.as_slice())
            .map_err(crate::error::redb)?;
        Ok(())
    }

    /// Remove every buffered mutation of namespace `uuid`: the seal has
    /// drained them into the ledger.
    fn drain_mutation_buffer(
        txn: &redb::WriteTransaction,
        uuid: &[u8; 16],
    ) -> Result<(), StoreError> {
        let mut buffer = txn
            .open_table(MUTATION_BUFFER)
            .map_err(crate::error::redb)?;
        let prefix = uuid.as_slice();
        match Self::prefix_successor(prefix) {
            Some(end) => buffer
                .retain_in(prefix..end.as_slice(), |_, _| false)
                .map_err(crate::error::redb),
            None => buffer
                .retain_in(prefix.., |_, _| false)
                .map_err(crate::error::redb),
        }
    }

    /// Verify the sealed transaction, decide its proposal through the
    /// namespace's plane, and commit it. Runs under the controller's
    /// writer gate, so the fence an unknown outcome installs is observed
    /// by the next admission.
    pub(crate) fn commit_epoch_transaction(
        &self,
        txn: redb::WriteTransaction,
        controller: &NamespaceController,
        ns: &NamespaceRef,
        root: EpochRoot,
        predecessor: Option<&Kappa>,
        assigns: bool,
    ) -> Result<(u64, Kappa), CommitFailure> {
        self.verify_sealed_transaction(&txn, controller, ns, &root)
            .map_err(CommitFailure::Known)?;
        let number = root.epoch_number();
        let identity = root.kappa().clone();
        // Creation bootstrap: a namespace whose database admits no
        // assignment publishes only the epoch that admits one. The plane
        // it was opened under is provisional authority for exactly that.
        if !assigns
            && self
                .namespaces
                .admitted_assignment(controller)
                .map_err(CommitFailure::Known)?
                .is_none()
        {
            return Err(CommitFailure::Known(StoreError::Rejected(
                "namespace has no admitted control-plane assignment; the creation epoch must admit one"
                    .into(),
            )));
        }
        let proposal = controller
            .proposal(
                predecessor.cloned(),
                number,
                identity.clone(),
                vec![root.ledger_root().clone()],
                root.timestamp_ms(),
            )
            .map_err(CommitFailure::Known)?;
        let (plane, _) = controller.plane().map_err(CommitFailure::Known)?;
        match plane.decide(&proposal) {
            Decision::Decided { position, .. } if position == number => {}
            Decision::Decided { position, .. } => {
                return Err(CommitFailure::Known(StoreError::Conflict(format!(
                    "plane decided position {position} for epoch {number}"
                ))));
            }
            Decision::Rejected(reason) => {
                return Err(CommitFailure::Known(StoreError::Rejected(format!(
                    "control plane {} rejected epoch {number}: {reason}",
                    plane.id.hex()
                ))));
            }
            Decision::Unresolved(reason) => {
                // The decision may have been made elsewhere; this namespace
                // publishes nothing until recovery resolves it.
                if let Err(error) = controller.fence() {
                    return Err(CommitFailure::Unknown(error));
                }
                return Err(CommitFailure::Unknown(
                    StoreError::PublicationIndeterminate {
                        namespace: *ns.id(),
                        epoch_number: number,
                        root: Box::new(identity),
                        detail: format!("decision unresolved: {reason}"),
                    },
                ));
            }
        }
        // Every external representation this transaction installs had its
        // durability established before its row was written
        // (content_prepare); inline rows are durable with this commit.
        // Shared activation across the commit and the bound update. A
        // rotation takes this gate exclusively, so it waits: it never
        // observes this epoch committed while the published-time bound
        // still excludes it.
        let activation = self.activation.read().map_err(|_| {
            CommitFailure::Known(StoreError::Internal(
                "authority activation lock poisoned".into(),
            ))
        })?;
        let committed = txn.commit();
        #[cfg(test)]
        self.hooks.reach(crate::test_hooks::Point::AfterEpochCommit);
        // A failed commit may still have persisted the epoch, so its time
        // bounds rotation exactly as a committed one does; an epoch whose
        // transaction aborted before commit never reaches this point.
        self.latest_epoch_ms
            .fetch_max(root.timestamp_ms(), Ordering::SeqCst);
        drop(activation);
        if let Err(error) = committed {
            // redb can fail after durable publication. Resolve the exact
            // immutable index entry; either way the outcome is not known
            // to this handle until recovery, so the namespace is fenced.
            let classified = match self.resolve_epoch_publication(controller, ns, number, &identity)
            {
                Ok(()) => StoreError::PublicationRecoveryRequired {
                    namespace: *ns.id(),
                    epoch_number: number,
                    root: Box::new(identity),
                    detail: error.to_string(),
                },
                Err(recovery) => StoreError::PublicationIndeterminate {
                    namespace: *ns.id(),
                    epoch_number: number,
                    root: Box::new(identity),
                    detail: format!("commit: {error}; recovery: {recovery}"),
                },
            };
            if let Err(fence) = controller.fence() {
                return Err(CommitFailure::Unknown(fence));
            }
            return Err(CommitFailure::Unknown(classified));
        }
        // Committed: from here nothing is reported as a failure of the
        // publication. The caller parks the pins against this epoch.
        controller.epoch_number.fetch_max(number, Ordering::AcqRel);
        self.epoch_cache.insert(identity.clone(), root);
        if assigns {
            // The admitted assignment is in force from this commit; the
            // controller serves the next execution under it. A failure to
            // install it marks the controller stale: it is logged, never
            // surfaced as a failed publication, and the next admission
            // refreshes from the admitted record or refuses.
            if let Err(error) = self.install_assignment(controller) {
                tracing::error!(
                    namespace = %hex::encode(controller.id),
                    %error,
                    "admitted assignment not installed on the open controller"
                );
            }
        }
        Ok((number, identity))
    }
}
