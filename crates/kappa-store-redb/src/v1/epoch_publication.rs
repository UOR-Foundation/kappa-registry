//! A sealed epoch awaiting its commit: the decided publication of one
//! execution, with the ownership the execution handed over.

use std::sync::Arc;
use std::time::Instant;

use kappa_store::{ClockMs, EpochRoot, Kappa, NamespaceRef, StoreError};

use crate::PersistentStore;
use crate::epoch::CommitFailure;
use crate::namespace_write::DirectoryGuard;
use crate::settlement::ReleaseGrant;
use crate::storage::{Active, Publish, WriterToken};
use crate::unsettled::Class;

/// The storage transaction cannot be accessed after signing. Dropping the
/// publication aborts redb's transaction; only `publish` makes it visible.
#[must_use = "publish the signed epoch or drop it to abort its transaction"]
pub struct PreparedEpochPublication<'a> {
    pub(super) store: &'a PersistentStore,
    /// Field order as in `EpochExecution`: transaction, then directory
    /// changes, then gate, then activity grant, then release grant.
    pub(super) transaction: redb::WriteTransaction,
    pub(super) directory: DirectoryGuard<'a>,
    pub(super) writer: WriterToken,
    pub(super) active: Active<Publish>,
    /// Decides the publication's admission class: a governed release
    /// publishing while its instance's obligation closes the pool.
    pub(super) release: Option<ReleaseGrant<'a>>,
    pub(super) namespace: NamespaceRef,
    pub(super) root: EpochRoot,
    pub(super) predecessor: Option<Kappa>,
    pub(super) assigns: bool,
    pub(super) now: ClockMs,
    pub(super) deadline: Option<Instant>,
    pub(super) content_pins: Vec<crate::allocation::Pin>,
}

impl PreparedEpochPublication<'_> {
    #[cfg(test)]
    pub(crate) const fn root(&self) -> &EpochRoot {
        &self.root
    }

    /// Commit without a seal: the crate-private seam tests drive to show
    /// that a root from another transaction, or a transaction changed
    /// after sealing, is refused.
    #[cfg(test)]
    pub(crate) fn commit_test_transaction(
        store: &PersistentStore,
        writer: crate::test_support::TestWriter,
        ns: &NamespaceRef,
        root: EpochRoot,
    ) -> Result<(u64, Kappa), StoreError> {
        let predecessor = root.prev_identifier().cloned();
        let controller = Arc::clone(writer.active.controller());
        let result = store.commit_epoch_transaction(
            writer.txn,
            &controller,
            ns,
            root,
            predecessor.as_ref(),
            true,
        );
        drop(writer.writer);
        drop(writer.active);
        match result {
            Ok(published) => Ok(published),
            Err(CommitFailure::Known(error) | CommitFailure::Unknown(error)) => Err(error),
        }
    }

    pub(crate) fn publish(self) -> Result<(u64, Kappa), StoreError> {
        // The last point before the commit makes the epoch visible: a caller
        // that has already timed out must not observe a publication it was
        // told had failed. Returning drops, and so aborts, the transaction.
        if let Some(deadline) = self.deadline {
            let overrun = Instant::now().saturating_duration_since(deadline);
            if !overrun.is_zero() {
                return Err(StoreError::DeadlineExceeded {
                    namespace: *self.namespace.id(),
                    overrun_ms: u64::try_from(overrun.as_millis()).unwrap_or(u64::MAX),
                });
            }
        }
        let controller = Arc::clone(self.active.controller());
        // Unsettled ownership is reserved before the commit: a publication
        // the node-wide bound cannot hold is refused here, with its
        // transaction dropped and so aborted, and nothing is charged. From
        // here the charge travels with the pins in `parked`, and is
        // released only when `parked` drops. The class is decided here
        // only: a governed release carrying its grant takes no charge and
        // is admitted while its obligation closes the pool. The grant is
        // held until this publication returns.
        let class = self
            .release
            .as_ref()
            .map_or(Class::Ordinary, Class::Resolving);
        let charge = self.store.unsettled.reserve(&self.content_pins, class)?;
        // Every identity this transaction wrote a row for is registered
        // before the commit, so a read by identity alone finds it from the
        // commit on; the registration is parked with the ownership and
        // dropped when this epoch settles into the catalog, at once on a
        // known noncommit, and by recovery for an unknown outcome. A
        // registration the index cannot hold refuses the publication here,
        // with nothing committed.
        let installed = std::mem::take(
            &mut *controller
                .installed_rows
                .lock()
                .map_err(|_| StoreError::Internal("installed row set poisoned".into()))?,
        );
        let registration = self
            .store
            .unsettled_index
            .register(controller.instance, installed)?;
        let parked = crate::unsettled::Parked::new(self.content_pins, charge)
            .with_registration(registration);
        // Durable before the commit, under the gate: a crash after the
        // commit finds the instance pending and recovery settles it.
        self.store.mark_unsettled(&controller.instance)?;
        // The gate is held across the commit and its classification, so
        // an unknown outcome fences the namespace before the next
        // admission can observe the gate open.
        let published = match self.store.commit_epoch_transaction(
            self.transaction,
            &controller,
            &self.namespace,
            self.root,
            self.predecessor.as_ref(),
            self.assigns,
        ) {
            Ok(published) => published,
            // Known noncommit: nothing persisted; `parked` drops here,
            // releasing the pins and their charge, and the allocations
            // become reclaimable.
            Err(CommitFailure::Known(error)) => return Err(error),
            // Unknown: the namespace is fenced; every allocation
            // dependency, and its charge, belongs to recovery until it
            // resolves, and so do the directory changes, which settlement
            // resolves against the outcome a fresh open recovers.
            Err(CommitFailure::Unknown(error)) => {
                controller
                    .unresolved_content
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .append(parked);
                self.directory.disarm();
                return Err(error);
            }
        };
        self.store.raise_committed_floor(self.now);
        // Committed: the installed allocations are owned by their rows in
        // the namespace database, and by the registry's projection once
        // this epoch settles. The pins and their charge stay parked until
        // then; the retired rows' allocations are reclaimed by that
        // settlement.
        controller.park_until_settled(published.0, parked);
        // The directory follows the committed record under the gate, so a
        // reader resolves the publication's aliases once it returns. A
        // failure is not the publication's: the epoch is committed, its
        // journal durable and its instance pending, so settlement resolves
        // the directory at the head; until then a reservation resolves to
        // nothing and a released alias still resolves.
        if let Err(error) = self.directory.resolve() {
            tracing::warn!(
                namespace = %self.namespace,
                epoch = published.0,
                %error,
                "directory changes of a committed epoch left to settlement"
            );
        }
        drop(self.writer);
        Ok(published)
    }
}
