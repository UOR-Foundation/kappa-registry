//! The node's signing authority across the key store, the persistent store
//! and the live [`NodeIdentity`].
//!
//! The persistent store's authority history decides which key signs. Every
//! step that reads that evidence, changes key custody, or observes the
//! lifecycle for status runs under the key store's lifecycle guard
//! ([`kappa_crypto::keystore::NodeKeys`]), and every change of the live
//! authority runs inside [`NodeIdentity::transition`]:
//!
//! - **Startup** ([`establish`]) offers every intact key to the store, lets
//!   the persisted history select the signing key, settles the key store to
//!   it, and only then builds the node identity. [`NodeAuthority::reconcile`]
//!   then publishes the node's complete authority state, including removal
//!   of every retired authority's capability and delegations, before the
//!   node serves. A crash at any point of an earlier rotation resolves to
//!   whatever the store durably committed.
//! - **Rotation** ([`NodeAuthority::rotate`]) stages the next key durably,
//!   has both keys sign the succession, and commits it in the store while
//!   the live authority is held exclusively, so no node signature is
//!   produced between the store's activation of the incoming authority and
//!   the identity's. Outcomes are typed in [`crate::node_outcome`] and never
//!   collapsed: a rotation that did not commit leaves the outgoing
//!   authority live and records what it left in the key store; an unknown
//!   commit outcome makes the identity and the store handle refuse all
//!   signing until a restart; a committed rotation reports each follow-up
//!   guarantee (see [`crate::node_completion`]).
//! - **Divergence** of the live authority from the committed one, found by
//!   rotation or reconciliation, makes the identity refuse all signing
//!   until a restart selects the committed authority.
//!
//! Publication after a commit runs inside the transition under the incoming
//! authority itself, with the lifecycle guard still held, so a second
//! rotation cannot interleave with the first one's publication, and status
//! never observes a rotation half-applied. Recorded guarantees are bound to
//! the authority they describe.

use std::sync::{Arc, Mutex, PoisonError};

use kappa_crypto::keystore::{KeyStore, NodeKeys};
use kappa_crypto::node::{AuthorityView, Availability, NodeIdentity, Successor, TransitionOutcome};
use kappa_crypto::{CryptoError, SigningAuthority};
use kappa_store::kappa::Kappa;
use kappa_store::time::Clock;
use kappa_store::{
    AuthorityRotationError, NamespaceRef, NamespaceStore, SignedPayload, StoreError, Succession,
    SuccessionReason, VerifiedSuccession,
};
use kappa_store_redb::PersistentStore;

use crate::bootstrap;
use crate::node_completion::{Completion, FollowUp};
use crate::node_outcome::{
    AuthorityStatus, EstablishError, Precommit, ReconcileError, Residual, Rotation, RotationError,
    not_attempted,
};
use crate::rotation_witness::RotationWitnesses;

/// The store opened under, and the identity holding, the committed
/// authority, with what startup could not finish in the key store.
pub struct Established {
    pub store: Arc<PersistentStore>,
    pub identity: Arc<NodeIdentity>,
    /// Damage found among node key records. Selection succeeded without
    /// the damaged records; settlement removed them unless `cleanup` says
    /// otherwise.
    pub damaged: Vec<String>,
    /// Removal of staging files, retired keys and the successor pointer.
    /// The committed key and `current` are durable either way; the next
    /// settlement repeats a failed removal.
    pub cleanup: Result<(), CryptoError>,
}

/// Open the store with every intact key the node holds and settle the key
/// store to the authority the store's history committed.
///
/// `open` receives the preferred authority (the one `current` names, or
/// any when that pointer is unusable), every other intact key, and whether
/// history must exist to choose among them.
///
/// # Errors
///
/// `KeyStore` when no intact key exists or settlement fails; `Store` when
/// the store refuses every offered key.
pub fn establish(
    keys: &KeyStore,
    algorithm: &str,
    open: impl FnOnce(
        SigningAuthority,
        Vec<SigningAuthority>,
        bool,
    ) -> Result<PersistentStore, StoreError>,
) -> Result<Established, EstablishError> {
    let lifecycle = keys.node_keys().map_err(EstablishError::KeyStore)?;
    let candidates = lifecycle
        .candidates(algorithm)
        .map_err(EstablishError::KeyStore)?;
    let (preferred, require_history) = match &candidates.current {
        Some(current) => (current.clone(), false),
        None => (
            candidates.keys.first().cloned().ok_or_else(|| {
                EstablishError::KeyStore(CryptoError::IntegrityFailure {
                    path: "node records".into(),
                    reason: "no intact node key".into(),
                })
            })?,
            true,
        ),
    };
    let alternates: Vec<SigningAuthority> = candidates
        .keys
        .into_iter()
        .filter(|key| key.anchor() != preferred.anchor())
        .collect();
    let store = open(preferred, alternates, require_history).map_err(EstablishError::Store)?;
    let committed = store.node_anchor();
    let settled = lifecycle
        .settle(&committed)
        .map_err(EstablishError::KeyStore)?;
    let identity = NodeIdentity::new(&settled);
    let cleanup = candidates.cleanup.and(settled.cleanup);
    Ok(Established {
        store: Arc::new(store),
        identity: Arc::new(identity),
        damaged: candidates.damaged,
        cleanup,
    })
}

/// Which guarantees hold, and for which authority.
#[derive(Clone)]
struct Recorded {
    anchor: Kappa,
    completion: Completion,
}

/// The running node's authority lifecycle.
pub struct NodeAuthority {
    keys: Arc<KeyStore>,
    identity: Arc<NodeIdentity>,
    store: Arc<PersistentStore>,
    clock: Arc<dyn Clock>,
    root_delegate: Option<Kappa>,
    /// Algorithm of a rotation that names none: the configured one.
    algorithm: String,
    /// Countersigns each rotation before it may activate.
    witnesses: Arc<dyn RotationWitnesses>,
    /// Latest outcome of each follow-up guarantee, for the authority it was
    /// established for. Written only under the key store's lifecycle guard.
    recorded: Mutex<Option<Recorded>>,
}

/// The control namespace activations are published in: the root namespace.
fn control_namespace(store: &PersistentStore) -> Result<NamespaceRef, StoreError> {
    store.namespace_resolve(kappa_handler::authority::ROOT_NAMESPACE, None)
}

impl NodeAuthority {
    pub fn new(
        keys: Arc<KeyStore>,
        identity: Arc<NodeIdentity>,
        store: Arc<PersistentStore>,
        clock: Arc<dyn Clock>,
        root_delegate: Option<Kappa>,
        algorithm: String,
        witnesses: Arc<dyn RotationWitnesses>,
    ) -> Self {
        Self {
            keys,
            identity,
            store,
            clock,
            root_delegate,
            algorithm,
            witnesses,
            recorded: Mutex::new(None),
        }
    }

    /// The store's authority history projects every activation its
    /// control namespaces' governing epochs committed. The governing epoch
    /// is the activation's commit; only the projection can lag it.
    fn project_activations(&self) -> Result<(), StoreError> {
        self.store.project_activations()
    }

    pub const fn identity(&self) -> &Arc<NodeIdentity> {
        &self.identity
    }

    /// Which guarantees hold for `anchor`: none, unless they were recorded
    /// for it.
    fn completion_for(&self, anchor: &Kappa) -> Completion {
        self.recorded
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|recorded| &recorded.anchor == anchor)
            .map_or(Completion::NONE, |recorded| recorded.completion)
    }

    fn record(&self, anchor: &Kappa, completion: Completion) {
        *self.recorded.lock().unwrap_or_else(PoisonError::into_inner) = Some(Recorded {
            anchor: anchor.clone(),
            completion,
        });
    }

    /// Record what a rotation that left `anchor` committed established for
    /// custody and key removal; its authorization and revocation stand.
    fn record_custody(&self, anchor: &Kappa, custody: bool, key_removal: bool) {
        let completion = Completion {
            custody,
            key_removal,
            ..self.completion_for(anchor)
        };
        self.record(anchor, completion);
    }

    /// The node's authority as an operator verifies it, observed under the
    /// lifecycle guard so no rotation or reconciliation runs between its
    /// parts. Blocking: it waits for a running rotation to finish.
    ///
    /// # Errors
    ///
    /// `KeyStore` when the lifecycle lock was poisoned by an interrupted
    /// operation.
    pub fn status(&self) -> Result<AuthorityStatus, ReconcileError> {
        let custody = self.keys.node_keys().map_err(ReconcileError::KeyStore)?;
        let established = self.store.node_anchor();
        let status = AuthorityStatus {
            availability: self.identity.status(),
            commit_known: !self.store.authority_unresolved(),
            retired: self.store.retired_authorities(),
            completion: self.completion_for(&established),
            established,
        };
        drop(custody);
        Ok(status)
    }

    /// Bring the key store and the published authority state into
    /// agreement with the store's committed history, and record the outcome
    /// of each guarantee: custody settled to the committed key, every other
    /// node key removed, the live authority's identity, capability and root
    /// delegation published, and everything each retired authority held
    /// revoked. Startup runs it before serving; readiness runs it while any
    /// guarantee is incomplete, so a failed step is retried until it holds.
    ///
    /// # Errors
    ///
    /// When reconciliation cannot run at all: the lifecycle lock is
    /// poisoned or the live authority is unavailable. A live authority that
    /// differs from the committed one is `Diverged`, and the identity then
    /// refuses all signing. Nothing is recorded in these cases.
    pub fn reconcile(&self) -> Result<FollowUp, ReconcileError> {
        let custody = self.keys.node_keys().map_err(ReconcileError::KeyStore)?;
        let committed = self.store.node_anchor();
        match self.identity.status() {
            Availability::Active(live) if live == committed => {}
            Availability::Active(live) => return Err(self.diverge(&custody, live, committed)),
            Availability::Unresolved { last } => {
                return Err(ReconcileError::Unavailable(
                    CryptoError::AuthorityUnresolved {
                        last: Box::new(last),
                    },
                ));
            }
            Availability::Diverged { live, committed } => {
                return Err(ReconcileError::Unavailable(
                    CryptoError::AuthorityDiverged {
                        live: Box::new(live),
                        committed: Box::new(committed),
                    },
                ));
            }
            Availability::Interrupted => {
                return Err(ReconcileError::Unavailable(
                    CryptoError::AuthorityInterrupted,
                ));
            }
        }
        let residual = Residual::of(custody.settle(&committed));
        let store = self.store.as_ref();
        let clock = self.clock.as_ref();
        let authorization =
            bootstrap::publish_live(store, &self.identity, self.root_delegate.as_ref(), clock);
        let revocation =
            bootstrap::revoke_retired(store, &committed, &self.store.retired_authorities(), clock);
        let follow_up = FollowUp {
            custody: residual.custody,
            key_removal: residual.key_removal,
            authorization,
            revocation,
            activation: self.project_activations(),
        };
        self.record(&committed, follow_up.completion());
        drop(custody);
        Ok(follow_up)
    }

    /// Make the identity refuse all signing because its live authority
    /// `live` is not the committed one.
    fn diverge(&self, custody: &NodeKeys<'_>, live: Kappa, committed: Kappa) -> ReconcileError {
        let diverged = || ReconcileError::Diverged {
            live: Box::new(live.clone()),
            committed: Box::new(committed.clone()),
        };
        match self
            .identity
            .transition(custody, |_, _| TransitionOutcome::<(), _>::Diverged {
                committed: committed.clone(),
                error: diverged(),
            }) {
            Ok(_) => diverged(),
            Err(error) => error,
        }
    }

    /// Hand node signing to a freshly generated key of `algorithm`, or of
    /// the configured algorithm. Blocking: run on a blocking worker, and to
    /// completion; its outcome is only known when it returns.
    ///
    /// # Errors
    ///
    /// See [`RotationError`]. Every outcome that touched the key store is
    /// recorded before this returns, so status reports its residue.
    pub fn rotate(&self, algorithm: Option<&str>) -> Result<Rotation, RotationError> {
        let algorithm = algorithm.unwrap_or(&self.algorithm);
        let custody = self.keys.node_keys().map_err(RotationError::KeyStore)?;
        // Evidence read under the lifecycle guard: no other lifecycle
        // operation of this key store can change custody before this
        // rotation acts on it, and every rotation, reconciliation and status
        // of this node takes the same guard first.
        let committed = self.store.node_anchor();
        let outcome = self.identity.transition(&custody, |keys, live| {
            self.step(keys, live, &committed, algorithm)
        });
        let rotation = match outcome {
            Ok((current, rotation)) => {
                self.record(&current, rotation.follow_up.completion());
                rotation
            }
            Err(error) => {
                if let Some((custody_held, removed)) = error.custody_state() {
                    self.record_custody(&committed, custody_held, removed);
                }
                drop(custody);
                return Err(error);
            }
        };
        drop(custody);
        tracing::info!(
            retired = %rotation.retired,
            current = %rotation.current,
            complete = rotation.follow_up.completion().is_complete(),
            "node authority rotated"
        );
        Ok(rotation)
    }

    /// The transition step of [`NodeAuthority::rotate`].
    fn step(
        &self,
        keys: &NodeKeys<'_>,
        live: AuthorityView<'_>,
        committed: &Kappa,
        algorithm: &str,
    ) -> TransitionOutcome<Rotation, RotationError> {
        if live.anchor() != committed {
            return TransitionOutcome::Diverged {
                committed: committed.clone(),
                error: RotationError::Diverged {
                    live: Box::new(live.anchor().clone()),
                    committed: Box::new(committed.clone()),
                },
            };
        }
        // Finish any earlier settlement first, so a successor left by an
        // earlier unresolved rotation is resolved against the committed
        // history before another is staged.
        let earlier = Residual::of(keys.settle(committed));
        if !earlier.holds() {
            return TransitionOutcome::Unchanged(RotationError::Custody(Box::new(earlier)));
        }
        let staged = match keys.stage_successor(algorithm) {
            Ok(staged) => staged,
            // Staging can fail after publishing the successor's record:
            // settling to the committed (outgoing) authority discards it.
            Err(cause) => {
                return TransitionOutcome::Unchanged(RotationError::Staging {
                    cause,
                    residual: Box::new(Residual::of(keys.settle(committed))),
                });
            }
        };
        let next = Successor::from(&staged);
        let staging_cleanup = staged.cleanup;
        let not_committed = |cause| {
            // Nothing committed: settling to the committed (outgoing)
            // authority removes the staged key and its pointer.
            TransitionOutcome::Unchanged(RotationError::NotCommitted {
                cause,
                residual: Box::new(Residual::of(keys.settle(committed))),
            })
        };
        let succession = match self.succession(live, next.view()) {
            Ok(succession) => succession,
            Err(cause) => return not_committed(cause),
        };
        let witnessed = control_namespace(&self.store).and_then(|control| {
            let domain = self.store.activation_domain(&control)?;
            let witnesses = self.witnesses.countersign(
                succession.inner(),
                &self.store.authority_origin(),
                domain,
            )?;
            Ok((control, witnesses))
        });
        let (control, witnesses) = match witnessed {
            Ok(witnessed) => witnessed,
            Err(cause) => return not_committed(Precommit::Witness(cause)),
        };
        match self.store.rotate_authority(
            next.authority().clone(),
            succession,
            witnesses,
            &control,
            self.clock.as_ref(),
        ) {
            Ok(()) => {}
            Err(AuthorityRotationError::NotCommitted(error)) => {
                return not_committed(Precommit::Store(error));
            }
            Err(AuthorityRotationError::Indeterminate(error)) => {
                // The staged key may be the committed one: it is kept, and
                // nothing signs until the next start settles.
                return TransitionOutcome::Unresolved(RotationError::Indeterminate(error));
            }
            Err(AuthorityRotationError::Retained(error)) => {
                // The staged key may still become the installed one when the
                // retained governing publication is resolved: it is kept,
                // and nothing signs until then.
                return TransitionOutcome::Unresolved(RotationError::Retained(error));
            }
        }
        // Committed: the incoming authority signs from here on, whether or
        // not the key store records it yet.
        let (custody, key_removal) = match keys.settle(next.anchor()) {
            // The successor's staging copy is part of what must be removed.
            Ok(settled) => (Ok(()), staging_cleanup.and(settled.cleanup)),
            Err(error) => (Err(error), Err(not_attempted())),
        };
        let store = self.store.as_ref();
        let clock = self.clock.as_ref();
        let authorization =
            bootstrap::publish_current(store, next.view(), self.root_delegate.as_ref(), clock);
        let revocation = bootstrap::revoke_retired(
            store,
            next.anchor(),
            &self.store.retired_authorities(),
            clock,
        );
        let rotation = Rotation {
            retired: live.anchor().clone(),
            current: next.anchor().clone(),
            follow_up: FollowUp {
                custody,
                key_removal,
                authorization,
                revocation,
                activation: self.project_activations(),
            },
        };
        TransitionOutcome::Installed(next, rotation)
    }

    /// The dual-signed succession from `live` to `next`, effective now.
    fn succession(
        &self,
        live: AuthorityView<'_>,
        next: AuthorityView<'_>,
    ) -> Result<VerifiedSuccession, Precommit> {
        let now = self
            .clock
            .now()
            .map_err(|error| Precommit::Succession(StoreError::from(error)))?;
        let record = kappa_crypto::signed_types::sign_succession(
            Succession {
                old_anchor: live.anchor().clone(),
                new_anchor: next.anchor().clone(),
                reason: SuccessionReason::Rotation,
                effective_at_ms: now.as_i64(),
                chain_anchor: None,
                prev_identifier: None,
                old_cose_signature: SignedPayload::empty(),
                new_cose_signature: SignedPayload::empty(),
            },
            live.signer(),
            next.signer(),
        )
        .map_err(Precommit::Signing)?;
        VerifiedSuccession::verify(
            record,
            live.signer().algorithm(),
            live.signer().public_key(),
            next.signer().algorithm(),
            next.signer().public_key(),
        )
        .map_err(Precommit::Succession)
    }
}
