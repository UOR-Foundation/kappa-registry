//! Activity grants: a namespace held open, for one purpose.
//!
//! Admission decides per purpose from the slot's lifecycle, in one table
//! (`storage_lifecycle`). The purpose is part of the grant's type, so what
//! a grant can reach is decided by the compiler: only an [`Exclusive`]
//! grant can take the namespace's writer gate (`writer_gate`), so a read
//! admitted while a retirement holds the namespace can never publish.

use std::marker::PhantomData;
use std::sync::Arc;

use kappa_store::StoreError;

use super::NamespaceController;
use super::gate::WriterToken;
use super::handles::{ActivityReservation, Slot};
use super::lifecycle::Refusal;

/// What an activity is admitted for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Use {
    /// Reading committed state: lookups, settlement, recovery visits.
    Read,
    /// An execution that publishes an epoch.
    Publish,
    /// Rewriting derived state under the writer gate, publishing nothing.
    Maintain,
}

mod sealed {
    pub trait Sealed {}
}

/// The purpose a grant is admitted for.
pub trait Purpose: sealed::Sealed + 'static {
    const USE: Use;
}

/// A purpose that holds the namespace's writer gate.
pub trait Exclusive: Purpose {}

/// Reading committed state.
pub enum Read {}
/// Publishing an epoch.
pub enum Publish {}
/// Rewriting derived state under the writer gate.
pub enum Maintain {}

impl sealed::Sealed for Read {}
impl sealed::Sealed for Publish {}
impl sealed::Sealed for Maintain {}

impl Purpose for Read {
    const USE: Use = Use::Read;
}
impl Purpose for Publish {
    const USE: Use = Use::Publish;
}
impl Purpose for Maintain {
    const USE: Use = Use::Maintain;
}

impl Exclusive for Publish {}
impl Exclusive for Maintain {}

/// An activity grant: the controller is in use for `P` and is not evicted
/// while the grant lives.
pub struct Active<P: Purpose = Read> {
    controller: Arc<NamespaceController>,
    /// The slot that admitted the grant, whose lifecycle readmits it.
    slot: Arc<Slot>,
    /// Owns the controller's activity count and the admission capacity
    /// until this activity ends. Kept after `controller` and `slot`: fields
    /// drop in declaration order, so eviction triggered by the grant's
    /// destructor sees both references released.
    activity_grant: ActivityReservation,
    /// `fn() -> P` keeps the grant `Send` and `Sync` whatever `P` is.
    purpose: PhantomData<fn() -> P>,
}

impl<P: Purpose> Active<P> {
    pub(super) const fn new(
        controller: Arc<NamespaceController>,
        slot: Arc<Slot>,
        activity_grant: ActivityReservation,
    ) -> Self {
        Self {
            controller,
            slot,
            activity_grant,
            purpose: PhantomData,
        }
    }

    pub(crate) const fn controller(&self) -> &Arc<NamespaceController> {
        &self.controller
    }

    /// The slot that admitted the grant.
    pub(super) const fn slot(&self) -> &Arc<Slot> {
        &self.slot
    }

    /// Whether the slot's lifecycle admits this grant's purpose now: an
    /// activity admitted before a lifecycle transition proceeds only if the
    /// state it finds now admits it.
    pub(super) fn standing(&self) -> Result<Result<(), Refusal>, StoreError> {
        Ok(self.slot.lock()?.admit(P::USE))
    }

    /// [`Self::standing`], a refusal being its error.
    pub(crate) fn readmit(&self) -> Result<(), StoreError> {
        self.standing()?
            .map_err(|refusal| refusal.into_error(&self.controller.id))
    }
}

impl<P: Purpose> Drop for Active<P> {
    fn drop(&mut self) {
        self.activity_grant.end(&self.controller);
    }
}

/// Exclusive maintenance of one namespace: its writer gate, held under a
/// maintenance grant until [`Maintenance::finish`] (or drop, in the same
/// order: the gate opens before the grant ends).
pub struct Maintenance {
    gate: WriterToken,
    grant: Active<Maintain>,
}

impl Maintenance {
    pub(super) const fn new(gate: WriterToken, grant: Active<Maintain>) -> Self {
        Self { gate, grant }
    }

    pub(crate) const fn controller(&self) -> &Arc<NamespaceController> {
        self.grant.controller()
    }

    /// End the maintenance: the writer gate opens, then the grant ends.
    pub(crate) fn finish(self) {
        let Self { gate, grant } = self;
        drop(gate);
        drop(grant);
    }
}
