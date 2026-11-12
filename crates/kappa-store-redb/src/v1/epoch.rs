//! Deciding and committing epochs of one namespace, and the head pointer
//! they move.
//!
//! The seal runs inside the namespace's write transaction (`epoch_seal`):
//! it drains the transition buffer into a ledger, commits the namespace
//! state, signs the root under the authority the publication's guard keeps
//! in force, installs the records and moves the head pointer and the epoch
//! index ([`PersistentStore::advance_head`]). The commit then asks the
//! namespace's control plane to decide the proposal and, only when
//! decided, commits the transaction. A rejected decision aborts; an
//! unresolved decision or a commit whose outcome is unknown fences the
//! namespace (and only it) until recovery.

use std::sync::atomic::Ordering;

use redb::ReadableTable;

use kappa_store::epoch_root::EpochRoot;
use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::work::Meter;

use crate::PersistentStore;
use crate::authority::ActivationHold;
use crate::content_read::ReadView;
use crate::control_plane::Decision;
use crate::encrypted::bound;
use crate::error::CommitFailure;
use crate::referrers::{Referrer, establish, release};
use crate::storage::NamespaceController;
use crate::tables::{EPOCH_CURRENT, EPOCH_INDEX};

#[path = "epoch_read.rs"]
mod read;

#[path = "epoch_verify.rs"]
mod verify;

/// What keeps the authority an epoch is signed under in force from before
/// its seal through its commit classification and published-time update.
/// Owned by the sealed epoch and handed back with every outcome, so the
/// authority an epoch was signed and verified under is the one it commits
/// under, and its owner decides what follows while still holding it.
pub(crate) trait AuthorityGuard<'a> {
    /// The activation whose candidate signs, or `None` for the installed
    /// authority.
    fn activation(&self) -> Option<&ActivationHold<'a>>;
}

/// The shared activation gate, held by an ordinary publication from before
/// its seal until its commit is classified: no activation installs another
/// authority meanwhile. Constructed only by
/// [`PersistentStore::shared_authority`].
pub(crate) struct SharedAuthority<'a> {
    gate: std::sync::RwLockReadGuard<'a, ()>,
}

impl SharedAuthority<'_> {
    /// End ordinary publication's authority exclusion after classification,
    /// before directory reconciliation and settlement handoff.
    pub(crate) fn release(self) {
        drop(self.gate);
    }
}

impl<'a> AuthorityGuard<'a> for SharedAuthority<'a> {
    fn activation(&self) -> Option<&ActivationHold<'a>> {
        None
    }
}

impl<'a> AuthorityGuard<'a> for ActivationHold<'a> {
    fn activation(&self) -> Option<&ActivationHold<'a>> {
        Some(self)
    }
}

/// A sealed epoch: what its commit decides, with the guard of the authority
/// it was signed under.
pub(crate) struct SealedEpoch<G> {
    pub(crate) root: EpochRoot,
    pub(crate) predecessor: Option<Kappa>,
    /// Whether the ledger admits a control-plane assignment (`_assign`).
    pub(crate) assigns: bool,
    pub(crate) guard: G,
}

/// A commit's outcome, with the guard the sealed epoch carried. An unknown
/// outcome has fenced the namespace; its dependencies belong to recovery.
pub(crate) struct Committed<G> {
    pub(crate) outcome: Result<(u64, Kappa), CommitFailure>,
    pub(crate) guard: G,
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

/// Table-encryption context label of `EPOCH_CURRENT` pointers.
pub(crate) const POINTER_CONTEXT: &str = "epoch_ptr";

/// Bytes of an `EPOCH_CURRENT` key: the namespace identity.
pub(crate) const POINTER_KEY_BYTES: usize = 16;

/// Bytes of an epoch index key ([`epoch_idx_key`]): the namespace identity
/// and the big-endian epoch number.
pub(crate) const EPOCH_IDX_KEY_BYTES: usize = 16 + 8;

/// The AEAD context of the `EPOCH_CURRENT` pointer of namespace `ns`.
pub(crate) fn pointer_context(ns: &[u8; 16]) -> String {
    bound(POINTER_CONTEXT, ns)
}

/// Epoch index key: `[ns_uuid:16][epoch_number_be:8]`, held inline, so
/// building it allocates nothing.
pub(crate) fn epoch_idx_key(ns: &NamespaceRef, epoch_number: u64) -> [u8; EPOCH_IDX_KEY_BYTES] {
    let mut key = [0u8; EPOCH_IDX_KEY_BYTES];
    let (namespace, number) = key.split_at_mut(16);
    namespace.copy_from_slice(ns.id());
    number.copy_from_slice(&epoch_number.to_be_bytes());
    key
}

impl PersistentStore {
    /// The guard of the installed authority for an ordinary publication:
    /// the shared activation gate, taken before the seal and held until the
    /// commit is classified.
    pub(crate) fn shared_authority(&self) -> Result<SharedAuthority<'_>, StoreError> {
        self.activation
            .read()
            .map(|gate| SharedAuthority { gate })
            .map_err(|_| StoreError::Internal("authority activation lock poisoned".into()))
    }

    /// A view over `controller`'s database that admits epochs under the
    /// authority a seal uses: the installed one, or the candidate of
    /// `activation`, whose own governing epoch the installed authority does
    /// not yet admit.
    pub(crate) fn sealing_view(
        &self,
        controller: &NamespaceController,
        activation: Option<&ActivationHold<'_>>,
    ) -> ReadView {
        let mut view = self.read_view_for(controller);
        if let Some(hold) = activation {
            view.authority = std::sync::Arc::clone(hold.view());
        }
        view
    }

    /// The root identity `EPOCH_CURRENT` names for namespace `uuid` in
    /// `txn`; `None` before the first epoch.
    pub(crate) fn head_pointer(
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

    /// Make `epoch_root` the head of `ns`. The head referrer moves with
    /// `EPOCH_CURRENT`: the previous root is now retained by the new root's
    /// predecessor edge, the new root by being the head. The ledger and
    /// every other dependency are retained by the `EpochRoot` edges the
    /// seal writes. The epoch index gains the new root at its number.
    pub(crate) fn advance_head(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        previous: Option<&Kappa>,
        epoch_root: &EpochRoot,
    ) -> Result<(), StoreError> {
        let uuid = ns.id();
        let head = Referrer::epoch_head(ns);
        if let Some(previous) = previous {
            release(self, txn, ns, previous, &head)?;
        }
        establish(self, txn, ns, epoch_root.kappa(), &head)?;
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

    /// Verify the sealed transaction, decide its proposal through the
    /// namespace's plane, and commit it, under the guard the sealed epoch
    /// carries: the authority it was signed under stays in force through the
    /// commit's classification and the published-time update. Runs under
    /// the controller's writer gate, so the fence an unknown outcome
    /// installs is observed by the next admission. The verification and,
    /// for an unknown outcome, its resolution read on `work`, the
    /// publication's allowance. The guard is handed back with the outcome.
    pub(crate) fn commit_epoch_transaction<'a, G: AuthorityGuard<'a>>(
        &self,
        txn: redb::WriteTransaction,
        controller: &NamespaceController,
        ns: &NamespaceRef,
        sealed: SealedEpoch<G>,
        work: &mut dyn Meter,
    ) -> Committed<G> {
        let outcome = self.decide_and_commit(txn, controller, ns, &sealed, work);
        Committed {
            outcome,
            guard: sealed.guard,
        }
    }

    /// The body of [`Self::commit_epoch_transaction`], under the guard
    /// `sealed` carries.
    fn decide_and_commit<'a, G: AuthorityGuard<'a>>(
        &self,
        txn: redb::WriteTransaction,
        controller: &NamespaceController,
        ns: &NamespaceRef,
        sealed: &SealedEpoch<G>,
        work: &mut dyn Meter,
    ) -> Result<(u64, Kappa), CommitFailure> {
        let SealedEpoch {
            root,
            predecessor,
            assigns,
            guard,
        } = sealed;
        let predecessor = predecessor.as_ref();
        let activation = guard.activation();
        if let Some(hold) = activation {
            hold.admits(controller, predecessor)
                .map_err(CommitFailure::Known)?;
        }
        let verified_root = self
            .verify_sealed_transaction(&txn, controller, ns, root, activation, work)
            .map_err(CommitFailure::Known)?;
        let number = root.epoch_number();
        let identity = root.kappa().clone();
        // Creation bootstrap: a namespace whose database admits no
        // assignment publishes only the epoch that admits one. The plane
        // it was opened under is provisional authority for exactly that.
        if !*assigns
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
        // The guard is held from the seal through here: an activation
        // takes the gate exclusively, so it waits, and never observes this
        // epoch committed while the published-time bound still excludes it.
        let committed = crate::error::classify_commit(txn.commit());
        #[cfg(test)]
        self.hooks.reach(crate::test_hooks::Point::AfterEpochCommit);
        // A failed commit may still have persisted the epoch, so its time
        // bounds rotation exactly as a committed one does; an epoch whose
        // transaction aborted before commit never reaches this point.
        self.latest_epoch_ms
            .fetch_max(root.timestamp_ms(), Ordering::SeqCst);
        match committed {
            Ok(()) => {}
            // redb rolled the transaction back: nothing of the epoch
            // persists, and its retained custody is resolved like any
            // other known noncommit after the coordinate was consumed.
            Err(CommitFailure::Known(error)) => return Err(CommitFailure::Known(error)),
            Err(CommitFailure::Unknown(error)) => {
                return Err(self.fence_unknown_commit(
                    controller, ns, number, identity, activation, &error, work,
                ));
            }
        }
        // Committed: from here nothing is reported as a failure of the
        // publication. The caller parks the pins against this epoch.
        controller.epoch_number.fetch_max(number, Ordering::AcqRel);
        // Publication is committed; cache admission cannot change its outcome.
        let _ = self.epoch_cache.insert(verified_root, work);
        if *assigns {
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

    /// A commit of epoch `number` (`identity`) of `ns` whose outcome redb
    /// left unknown (`error`): redb can fail after durable publication, so
    /// the exact immutable index entry is resolved, on `work`, to name what
    /// is known, and either way the namespace is fenced until recovery. A
    /// resolution the allowance refuses names nothing known: the outcome
    /// stays indeterminate.
    #[allow(clippy::too_many_arguments)]
    fn fence_unknown_commit(
        &self,
        controller: &NamespaceController,
        ns: &NamespaceRef,
        number: u64,
        identity: Kappa,
        activation: Option<&ActivationHold<'_>>,
        error: &StoreError,
        work: &mut dyn Meter,
    ) -> CommitFailure {
        let classified = match self
            .resolve_epoch_publication(controller, ns, number, &identity, activation, work)
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
        match controller.fence() {
            Ok(()) => CommitFailure::Unknown(classified),
            Err(fence) => CommitFailure::Unknown(fence),
        }
    }
}
