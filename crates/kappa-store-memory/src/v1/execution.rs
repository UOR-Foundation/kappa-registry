//! Operation-owned execution over a private candidate namespace view.
//!
//! An execution holds its namespace's writer gate for its whole life and
//! writes a clone of the namespace's published view, which shares every
//! node it does not change. Nothing is visible until publication stores
//! the candidate into the namespace's slot with one pointer store. Dropping
//! or aborting discards the candidate, releases its claims and succession
//! reservations, and drops the allocations it held, whose files are then
//! owed to cleanup.
//!
//! Publication, in order:
//!
//! 1. under the shared activation gate, seal the receipt, ledger and epoch
//!    into the candidate and check the deadline;
//! 2. compute the projection changes against the base view;
//! 3. hold the stripes of every authorization key the execution depends on
//!    or writes, and validate every dependency it recorded;
//! 4. register the projection keys the candidate gained; nothing between
//!    this and the store can fail, so a registration is never undone;
//! 5. store the candidate: the publication decision;
//! 6. settle claims and succession reservations, unregister the keys the
//!    view lost, raise the lineage summary, then release the stripes, the
//!    activation gate and, with the execution, the writer gate.
//!
//! Every step that can fail precedes the store. Everything after it only
//! moves ownership the store already decided, and cannot fail, so a
//! publication that stored its view always reports success.

use std::cell::{Cell, RefCell};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use kappa_store::{
    Axis, ClockMs, Execution, Kappa, MutationOp, NamespaceRef, OperationReceipt, Published,
    StoreError, VerifiedContent, canonical::canonical_bytes,
};

use super::claims::{ClaimKey, Holder};
use super::dependency::{Dependency, guarded};
use super::projection::Changes;
use super::view::NamespaceView;
use super::writers::WriterToken;
use super::{InMemoryStore, Slot};

/// What one publication attempt owns in the shared structures.
pub struct Attempt {
    pub id: u64,
    pub holder: Holder,
    /// Claims this attempt reserved or released.
    claims: Vec<ClaimKey>,
    /// Old anchors of the succession links this attempt reserved.
    successions: Vec<Kappa>,
    /// Authorization keys this attempt writes, whose stripes it holds
    /// across its store.
    guarded: Vec<ClaimKey>,
}

/// A write against the candidate view.
pub struct WriteCx<'e> {
    pub store: &'e InMemoryStore,
    pub view: &'e mut NamespaceView,
    pub ns: &'e NamespaceRef,
    pub now: ClockMs,
    attempt: &'e mut Attempt,
    dependencies: &'e RefCell<Vec<Dependency>>,
}

impl WriteCx<'_> {
    /// Append a mutation to the ledger the epoch seals.
    pub fn record(&mut self, op: MutationOp, kappa: Kappa, context: Option<String>) {
        self.view.record(op, kappa, self.now, context);
    }

    /// Reserve `key` for this attempt. An absence of `key` this execution
    /// observed must still hold when it reserves, since the reservation
    /// then excludes every other writer and replaces the observation.
    pub fn reserve(&mut self, key: ClaimKey) -> Result<(), StoreError> {
        {
            let mut dependencies = self.dependencies.borrow_mut();
            if let Some(index) = dependencies.iter().position(|dependency| {
                matches!(dependency, Dependency::Unowned { key: observed, .. } if *observed == key)
            }) {
                if let Dependency::Unowned { at, .. } = dependencies[index]
                    && !self.store.claims.unchanged(at)
                {
                    return Err(StoreError::Conflict(format!(
                        "{key:?} changed after this execution observed it absent"
                    )));
                }
                dependencies.swap_remove(index);
            }
        }
        if self
            .store
            .claims
            .reserve(&key, self.attempt.holder, self.attempt.id)?
        {
            self.attempt.claims.push(key.clone());
        }
        if guarded(&key) {
            self.attempt.guarded.push(key);
        }
        Ok(())
    }

    /// Reserve the namespace alias `name` in `protocol` (empty for global)
    /// under the alias admission rule.
    pub fn reserve_alias(&mut self, name: &str, protocol: &str) -> Result<(), StoreError> {
        self.store
            .claims
            .reserve_alias(name, protocol, self.attempt.holder, self.attempt.id)?;
        self.attempt.claims.push(ClaimKey::Alias {
            name: name.to_owned(),
            protocol: protocol.to_owned(),
        });
        Ok(())
    }

    /// Release `key`, which this namespace holds, with the publication.
    pub fn release(&mut self, key: ClaimKey) {
        if self
            .store
            .claims
            .release(&key, self.attempt.holder, self.attempt.id)
        {
            self.attempt.claims.push(key.clone());
        }
        if guarded(&key) {
            self.attempt.guarded.push(key);
        }
    }

    /// Hold `key`'s stripe across this attempt's store: the attempt
    /// rewrites a row of `key` it already holds.
    pub fn attempt_guard(&mut self, key: ClaimKey) {
        if guarded(&key) {
            self.attempt.guarded.push(key);
        }
    }

    /// Reserve the succession link `record` for this attempt.
    pub fn reserve_succession(
        &mut self,
        record: &kappa_types::identity::Succession,
    ) -> Result<(), StoreError> {
        if self
            .store
            .successions
            .reserve(record, self.attempt.holder.namespace, self.attempt.id)?
        {
            self.attempt.successions.push(record.old_anchor.clone());
        }
        Ok(())
    }
}

/// A read against the candidate view.
pub struct ReadCx<'e> {
    pub store: &'e InMemoryStore,
    pub view: &'e NamespaceView,
    pub ns: &'e NamespaceRef,
    pub now: ClockMs,
    pub holder: Holder,
    dependencies: &'e RefCell<Vec<Dependency>>,
}

impl ReadCx<'_> {
    /// Record an authorization dependency for validation at publication.
    pub fn depend(&self, dependency: Dependency) {
        self.dependencies.borrow_mut().push(dependency);
    }
}

/// Private namespace execution. Dropping it aborts every write.
#[must_use = "publish the execution or drop it to abort"]
pub struct MemoryExecution<'a> {
    store: &'a InMemoryStore,
    slot: Arc<Slot>,
    base: Arc<NamespaceView>,
    candidate: NamespaceView,
    namespace: NamespaceRef,
    now: ClockMs,
    failed: Cell<bool>,
    operation: Option<([u8; 32], Kappa)>,
    deadline: Option<Instant>,
    attempt: Attempt,
    dependencies: RefCell<Vec<Dependency>>,
    /// Set once the attempt's claims and reservations are settled, by
    /// publication or by abort.
    settled: bool,
    // Declared last: the writer gate is released after everything above,
    // so no other execution of the namespace starts before this one's
    // bookkeeping is done.
    _writer: WriterToken,
}

impl Drop for MemoryExecution<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.store.claims.settle(
                &self.attempt.claims,
                self.attempt.holder,
                self.attempt.id,
                false,
            );
            self.store.successions.abort(
                &self.attempt.successions,
                self.attempt.holder.namespace,
                self.attempt.id,
            );
        }
    }
}

impl<'a> MemoryExecution<'a> {
    pub(crate) fn new(
        store: &'a InMemoryStore,
        writer: WriterToken,
        slot: Arc<Slot>,
        namespace: &NamespaceRef,
        now: ClockMs,
    ) -> Result<Self, StoreError> {
        let base = slot.view.load_full();
        let mut candidate = NamespaceView::clone(&base);
        candidate.revision = base.next_revision()?;
        let holder = Holder {
            namespace: *namespace.id(),
            incarnation: base.incarnation,
        };
        Ok(Self {
            store,
            slot,
            base,
            candidate,
            namespace: namespace.clone(),
            now,
            failed: Cell::new(false),
            operation: None,
            deadline: None,
            attempt: Attempt {
                id: store.attempt()?,
                holder,
                claims: Vec::new(),
                successions: Vec::new(),
                guarded: Vec::new(),
            },
            dependencies: RefCell::new(Vec::new()),
            settled: false,
            _writer: writer,
        })
    }

    pub(crate) const fn candidate(&self) -> &NamespaceView {
        &self.candidate
    }

    pub(super) const fn namespace_ref(&self) -> &NamespaceRef {
        &self.namespace
    }

    pub(super) const fn issued_at(&self) -> ClockMs {
        self.now
    }

    /// Bind this execution to an operation identity; publication then
    /// requires a persisted result.
    pub(crate) const fn with_operation(mut self, identity: [u8; 32], request: Kappa) -> Self {
        self.operation = Some((identity, request));
        self
    }

    fn ensure_active(&self) -> Result<(), StoreError> {
        if self.failed.get() {
            return Err(StoreError::Conflict("epoch execution has failed".into()));
        }
        Ok(())
    }

    fn admit<T>(&self, result: Result<T, StoreError>) -> Result<T, StoreError> {
        if result.is_err() {
            self.failed.set(true);
        }
        result
    }

    const fn read_cx(&self) -> ReadCx<'_> {
        ReadCx {
            store: self.store,
            view: &self.candidate,
            ns: &self.namespace,
            now: self.now,
            holder: self.attempt.holder,
            dependencies: &self.dependencies,
        }
    }

    pub(super) fn read<T>(
        &self,
        read: impl FnOnce(&ReadCx<'_>) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.ensure_active()?;
        self.admit(read(&self.read_cx()))
    }

    /// Keyed read: absence is a value and does not latch the execution.
    pub(super) fn lookup<T>(
        &self,
        read: impl FnOnce(&ReadCx<'_>) -> Result<T, StoreError>,
    ) -> Result<Option<T>, StoreError> {
        self.ensure_active()?;
        self.admit(kappa_store::absent(read(&self.read_cx())))
    }

    pub(super) fn write<T>(
        &mut self,
        write: impl FnOnce(&mut WriteCx<'_>) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.ensure_active()?;
        let mut cx = WriteCx {
            store: self.store,
            view: &mut self.candidate,
            ns: &self.namespace,
            now: self.now,
            attempt: &mut self.attempt,
            dependencies: &self.dependencies,
        };
        let result = write(&mut cx);
        self.admit(result)
    }

    /// The execution's namespace after a rename inside it.
    pub(super) fn set_namespace(&mut self, namespace: NamespaceRef) {
        self.namespace = namespace;
    }

    /// Whether every recorded dependency still holds. Called under the
    /// stripes of every dependency key.
    fn dependencies_hold(&self) -> bool {
        self.dependencies
            .borrow()
            .iter()
            .all(|dependency| match dependency {
                Dependency::Owned {
                    key,
                    holder,
                    revision,
                } => {
                    self.store.claims.observe(key).holder == Some(*holder)
                        && self
                            .store
                            .holder_view(*holder)
                            .and_then(|view| super::identity_local::row_revision(&view, key))
                            == Some(*revision)
                }
                Dependency::Unowned { at, .. } => self.store.claims.unchanged(*at),
            })
    }

    /// Publish this execution while the caller holds the activation gate
    /// exclusively: the authority activation that installs a new signer and
    /// publishes its evidence as that signer's first epoch.
    pub(crate) fn publish_under_activation(self) -> Result<Published, StoreError> {
        self.finish_with(None, true)
    }

    /// Seal and publish the candidate (see the module documentation).
    fn finish(self, result: Option<Vec<u8>>) -> Result<Published, StoreError> {
        self.finish_with(result, false)
    }

    fn finish_with(
        mut self,
        result: Option<Vec<u8>>,
        activation_held: bool,
    ) -> Result<Published, StoreError> {
        self.ensure_active()?;
        let store = self.store;
        let activation =
            if activation_held {
                None
            } else {
                Some(store.activation.read().map_err(|_| {
                    StoreError::Internal("authority activation lock poisoned".into())
                })?)
            };
        let receipt = match (self.operation.clone(), result) {
            (Some((identity, request)), Some(result)) => {
                let receipt = OperationReceipt::new(&self.namespace, &identity, request, result)?;
                let content = VerifiedContent::compute(Axis::Sha256, &canonical_bytes(&receipt))?;
                let receipt_identity = content.kappa().clone();
                self.write(|cx| {
                    cx.publish_content(&content)?;
                    cx.record(MutationOp::OperationPublish, receipt_identity.clone(), None);
                    Ok(())
                })?;
                Some((identity, receipt_identity))
            }
            (Some(_), None) => {
                return Err(StoreError::Conflict(
                    "operation execution requires a persisted result".into(),
                ));
            }
            (None, Some(_)) => {
                return Err(StoreError::Conflict(
                    "execution has no operation identity".into(),
                ));
            }
            (None, None) => None,
        };
        let (epoch_number, root) = self.write(|cx| cx.seal(None))?;
        if let Some((identity, receipt)) = receipt {
            self.candidate
                .operations
                .insert(identity, (root.clone(), receipt));
        }
        // The last point before visibility: a caller that has already timed
        // out must not observe a publication it was told had failed.
        if let Some(deadline) = self.deadline {
            let overrun = Instant::now().saturating_duration_since(deadline);
            if !overrun.is_zero() {
                return Err(StoreError::DeadlineExceeded {
                    namespace: *self.namespace.id(),
                    overrun_ms: u64::try_from(overrun.as_millis()).unwrap_or(u64::MAX),
                });
            }
        }
        let changes = Changes::between(*self.namespace.id(), &self.base, &self.candidate);
        let keys: Vec<ClaimKey> = self
            .dependencies
            .borrow()
            .iter()
            .map(|dependency| dependency.key().clone())
            .chain(self.attempt.guarded.iter().cloned())
            .collect();
        let stripes = store.stripes.hold(&keys);
        if !self.dependencies_hold() {
            return Err(StoreError::Conflict(
                "an authorization row this execution depends on changed before it published".into(),
            ));
        }
        let sealed_ms = self.candidate.latest_epoch_ms;
        store.projections.register(&changes);
        // The publication decision. Nothing below can fail.
        let candidate = std::mem::take(&mut self.candidate);
        self.slot.view.store(Arc::new(candidate));
        self.settled = true;
        store.claims.settle(
            &self.attempt.claims,
            self.attempt.holder,
            self.attempt.id,
            true,
        );
        store.successions.commit(
            &self.attempt.successions,
            self.attempt.holder.namespace,
            self.attempt.id,
        );
        store.projections.unregister(&changes);
        if let Some(sealed_ms) = sealed_ms {
            store.latest_epoch_ms.fetch_max(sealed_ms, Ordering::AcqRel);
        }
        drop(stripes);
        drop(activation);
        Ok(Published { epoch_number, root })
    }
}

impl Execution for MemoryExecution<'_> {
    fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = Some(deadline);
    }
    fn publish(self: Box<Self>) -> Result<Published, StoreError> {
        (*self).finish(None)
    }
    fn publish_result(self: Box<Self>, result: Vec<u8>) -> Result<Published, StoreError> {
        (*self).finish(Some(result))
    }
    fn abort(self: Box<Self>) -> Result<(), StoreError> {
        drop(self);
        Ok(())
    }
}
