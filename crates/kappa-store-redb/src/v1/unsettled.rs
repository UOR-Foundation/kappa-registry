//! The node-wide bound on unsettled publication ownership.
//!
//! Between a namespace's commit and its settlement the registry's
//! projection does not yet own the epoch's allocations; the publishing
//! execution's pins are parked on the controller to protect them. That
//! ownership is explicit and bounded here: every parked pin is charged as
//! one entry and the physical bytes its allocation occupies (payload and
//! sidecar, measured by the preparation that wrote them), across every
//! namespace.
//!
//! The charge is a value: a [`Charge`] is reserved and released when it
//! drops, so no path that releases pins can forget to release their
//! charge. Ownership is continuous from preparation to settlement:
//!
//! - a preparation reserves its charge before it returns
//!   (`PersistentStore::prepare_representation`), carried by its pin
//!   (`Pin::charged`); a preparation dropped uninstalled releases it;
//! - an execution's pins carry their charges into the publication, which
//!   reserves only for pins that carry none (records sealed in the
//!   transaction) before it commits, refused with nothing committed when
//!   the bound would be exceeded;
//! - the committed epoch parks the pins with every charge in one
//!   [`Parked`] until its settlement drops it; an unknown outcome moves
//!   it to the controller's unresolved set, where recovery drops it. The
//!   epoch's registration in the unsettled identity index
//!   (`unsettled_index`) is parked with them, so the identities stay
//!   discoverable exactly until the catalog holds them;
//! - unsettled ownership a restart finds and cannot settle is charged
//!   as debt (`UnsettledBudget::debt`), beyond the bound if it must be, so
//!   no fresh publication is admitted against capacity the debt holds;
//!   ownership a restart cannot even measure is not charged as zero: its
//!   charge closes the pool until it is released
//!   (`UnsettledBudget::unmeasured`), and names why ([`Closure`]).
//!
//! Two concepts, kept apart. **Admission** ([`UnsettledBudget::admit`])
//! decides whether new ownership may be taken on, by the one table over the
//! pool's state and the admission's [`Class`]. **Accounting** (`debt`,
//! `unmeasured`) charges ownership that already exists, which no pool state
//! refuses.
//!
//! Charges are summed with checked arithmetic; a sum the counters cannot
//! hold is refused, never saturated, and a refused charge changes no
//! counter. The charge is a conservative admission reservation: pins
//! protecting one allocation twice charge it twice.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use kappa_store::error::StoreError;

use crate::allocation::Pin;
use crate::settlement::ReleaseGrant;
use crate::storage_instance::StorageInstance;
use crate::unsettled_index::Registration;

#[cfg(test)]
#[path = "unsettled_tests.rs"]
mod tests;

/// Why the pool is closed: ownership nobody has measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Closure {
    /// The ownership present at open, until recovery's first clean
    /// enumeration has recorded every obligation with its own charge.
    Startup,
    /// The ownership of this instance's recovery obligation, not yet
    /// measured: storage missing or unreadable, or a reconstruction in
    /// progress.
    Obligation(StorageInstance),
}

/// What ends a [`Closure`]. Every closure declares one, and none is
/// blocked by the closure it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// Recovery finishes enumerating the obligations present at open; it
    /// writes the registry only.
    Enumeration,
    /// Settlement or reconstruction reaches the instance's head (registry
    /// only), restored storage does, or the instance's governed release
    /// publishes, admitted while the pool is closed by its
    /// [`ReleaseGrant`] ([`Class::Resolving`]).
    SettlementOrRelease,
}

impl Closure {
    /// How this closure ends. Exhaustive: a new cause declares its exit.
    pub(crate) const fn exit(self) -> Exit {
        match self {
            Self::Startup => Exit::Enumeration,
            Self::Obligation(_) => Exit::SettlementOrRelease,
        }
    }
}

impl std::fmt::Display for Closure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Startup => formatter.write_str("the ownership present at open"),
            Self::Obligation(instance) => {
                write!(formatter, "the unmeasured ownership of {instance}")
            }
        }
    }
}

impl std::fmt::Display for Exit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Enumeration => "recovery enumerates the obligations present at open",
            Self::SettlementOrRelease => {
                "settlement reaches its head, its storage is restored, or its governed release publishes"
            }
        })
    }
}

/// Why new ownership is being admitted. A copyable view: a resolving class
/// borrows its grant, so passing the class never moves the grant.
#[derive(Clone, Copy)]
pub enum Class<'r> {
    /// Ownership any publication or preparation takes on.
    Ordinary,
    /// The publication of a governed release that ends the closure of the
    /// grant's instance: it adds no allocation ownership, so it is
    /// admitted while the pool is closed or over its bound, and any charge
    /// it would take is refused.
    Resolving(&'r ReleaseGrant<'r>),
}

#[derive(Default)]
struct Held {
    entries: u64,
    bytes: u64,
    /// The unmeasured charges held, by cause: while any is, every ordinary
    /// admission is refused.
    closures: BTreeMap<Closure, u64>,
}

/// The bound and the current charge.
pub struct UnsettledBudget {
    max_entries: u64,
    max_bytes: u64,
    held: Mutex<Held>,
}

/// A reservation against an [`UnsettledBudget`]; released on drop.
pub struct Charge {
    budget: Arc<UnsettledBudget>,
    entries: u64,
    bytes: u64,
    /// The closure this charge holds (`UnsettledBudget::unmeasured`).
    closure: Option<Closure>,
}

impl Charge {
    pub(crate) const fn entries(&self) -> u64 {
        self.entries
    }

    pub(crate) const fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        if self.entries == 0 && self.bytes == 0 && self.closure.is_none() {
            return;
        }
        let mut held = self.budget.held();
        held.entries = held.entries.saturating_sub(self.entries);
        held.bytes = held.bytes.saturating_sub(self.bytes);
        if let Some(closure) = self.closure
            && let Some(count) = held.closures.get_mut(&closure)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                held.closures.remove(&closure);
            }
        }
    }
}

/// Pins parked for one committed epoch with the charges they hold, each
/// kept as the value it was reserved as: nothing is merged, so nothing
/// can be released by a merge. An epoch without pins is parked too, with
/// no charge: parked epochs are the per-namespace backlog.
#[derive(Default)]
pub struct Parked {
    pub(crate) pins: Vec<Pin>,
    charges: Vec<Charge>,
    registrations: Vec<Registration>,
}

impl Parked {
    /// Park `pins` with the charges they carry and `charge`, the
    /// publication's reservation for the pins that carried none.
    pub(crate) fn new(mut pins: Vec<Pin>, charge: Charge) -> Self {
        let mut charges: Vec<Charge> = pins.iter_mut().filter_map(Pin::take_charge).collect();
        charges.push(charge);
        Self {
            pins,
            charges,
            registrations: Vec::new(),
        }
    }

    /// Hold the publication's registration in the unsettled identity
    /// index for as long as this ownership is held.
    #[must_use]
    pub(crate) fn with_registration(mut self, registration: Registration) -> Self {
        self.registrations.push(registration);
        self
    }

    /// Pins parked outside any budget: for controller-level tests that
    /// exercise parking and release without a store.
    #[cfg(test)]
    pub(crate) const fn uncharged(pins: Vec<Pin>) -> Self {
        Self {
            pins,
            charges: Vec::new(),
            registrations: Vec::new(),
        }
    }

    /// No pins, no charge and no registration: nothing is held.
    pub(crate) const fn is_empty(&self) -> bool {
        self.pins.is_empty() && self.charges.is_empty() && self.registrations.is_empty()
    }

    pub(crate) fn entries(&self) -> u64 {
        self.charges
            .iter()
            .fold(0, |total, charge| total.saturating_add(charge.entries()))
    }

    pub(crate) fn bytes(&self) -> u64 {
        self.charges
            .iter()
            .fold(0, |total, charge| total.saturating_add(charge.bytes()))
    }

    pub(crate) fn append(&mut self, mut other: Self) {
        self.pins.append(&mut other.pins);
        self.charges.append(&mut other.charges);
        self.registrations.append(&mut other.registrations);
    }
}

impl UnsettledBudget {
    pub(crate) const fn new(max_entries: u64, max_bytes: u64) -> Self {
        Self {
            max_entries,
            max_bytes,
            held: Mutex::new(Held {
                entries: 0,
                bytes: 0,
                closures: BTreeMap::new(),
            }),
        }
    }

    fn held(&self) -> MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn charge(self: &Arc<Self>, entries: u64, bytes: u64, closure: Option<Closure>) -> Charge {
        Charge {
            budget: Arc::clone(self),
            entries,
            bytes,
            closure,
        }
    }

    /// Admit `entries` and `bytes` of new ownership for `class`: the one
    /// admission decision. Refused, reserving nothing:
    ///
    /// - `Resolving` with any nonzero charge;
    /// - `Ordinary` while a closure holds the pool, naming every cause and
    ///   its exit; when the bound would be exceeded; when the counters
    ///   would overflow.
    ///
    /// `Resolving` of nothing is admitted in every pool state.
    pub(crate) fn admit(
        self: &Arc<Self>,
        class: Class<'_>,
        entries: u64,
        bytes: u64,
    ) -> Result<Charge, StoreError> {
        match class {
            Class::Resolving(_) if entries == 0 && bytes == 0 => {
                return Ok(self.charge(0, 0, None));
            }
            Class::Resolving(grant) => {
                return Err(StoreError::CapacityExceeded(format!(
                    "the release of {} publishes while unsettled ownership is closed and may take none; {entries} entries and {bytes} bytes refused",
                    grant.instance()
                )));
            }
            Class::Ordinary => {}
        }
        let mut held = self.held();
        if !held.closures.is_empty() {
            let causes = held
                .closures
                .keys()
                .map(|closure| format!("{closure} (until {})", closure.exit()))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(StoreError::CapacityExceeded(format!(
                "unsettled publication ownership is closed by {causes}"
            )));
        }
        let overflow = || StoreError::CapacityExceeded("unsettled charge counter overflow".into());
        let next_entries = held.entries.checked_add(entries).ok_or_else(overflow)?;
        let next_bytes = held.bytes.checked_add(bytes).ok_or_else(overflow)?;
        if next_entries > self.max_entries || next_bytes > self.max_bytes {
            return Err(StoreError::CapacityExceeded(format!(
                "unsettled publication ownership at {} entries and {} bytes cannot take {entries} entries and {bytes} bytes within {} entries and {} bytes; settlement must catch up",
                held.entries, held.bytes, self.max_entries, self.max_bytes
            )));
        }
        held.entries = next_entries;
        held.bytes = next_bytes;
        drop(held);
        Ok(self.charge(entries, bytes, None))
    }

    /// Admit, for `class`, one entry per pin that carries no charge of its
    /// own and the bytes each such pin's allocation occupies (`Pin::bytes`,
    /// measured at preparation; no storage is inspected here). Pins already
    /// charged by their preparation are not charged twice.
    pub(crate) fn reserve(
        self: &Arc<Self>,
        pins: &[Pin],
        class: Class<'_>,
    ) -> Result<Charge, StoreError> {
        let mut entries = 0u64;
        let mut bytes = 0u64;
        for pin in pins.iter().filter(|pin| !pin.is_charged()) {
            entries += 1;
            bytes = bytes.checked_add(pin.bytes()).ok_or_else(|| {
                StoreError::CapacityExceeded("unsettled byte reservation overflow".into())
            })?;
        }
        self.admit(class, entries, bytes)
    }

    /// Charge ownership that exists whether or not the bound admits it:
    /// unsettled epochs a restart found and could not settle. The charge
    /// may exceed the bound; while it does, every ordinary admission is
    /// refused, which is the point: nothing is admitted against capacity
    /// the debt holds. Overflow of either counter is still refused,
    /// charging neither: both sums are checked before either is assigned.
    pub(crate) fn debt(self: &Arc<Self>, entries: u64, bytes: u64) -> Result<Charge, StoreError> {
        let mut held = self.held();
        let overflow = || StoreError::CapacityExceeded("unsettled charge counter overflow".into());
        let next_entries = held.entries.checked_add(entries).ok_or_else(overflow)?;
        let next_bytes = held.bytes.checked_add(bytes).ok_or_else(overflow)?;
        held.entries = next_entries;
        held.bytes = next_bytes;
        drop(held);
        Ok(self.charge(entries, bytes, None))
    }

    /// Charge ownership a restart found and could not measure, for
    /// `closure`. Unknown ownership is not zero ownership: while the
    /// returned charge is held the pool is closed and every ordinary
    /// admission is refused, whatever the counters say. Debt is still
    /// charged. Released when what the closure's exit names happens and the
    /// charge drops.
    pub(crate) fn unmeasured(self: &Arc<Self>, closure: Closure) -> Result<Charge, StoreError> {
        let mut held = self.held();
        // Checked before the map changes, so a refused closure leaves no
        // zero-count cause holding the pool closed.
        let next = held
            .closures
            .get(&closure)
            .map_or(Some(1), |count| count.checked_add(1))
            .ok_or_else(|| {
                StoreError::CapacityExceeded("unsettled closure counter overflow".into())
            })?;
        held.closures.insert(closure, next);
        drop(held);
        Ok(self.charge(0, 0, Some(closure)))
    }

    /// The current charge, `(entries, bytes)`.
    #[cfg(test)]
    pub(crate) fn charged(&self) -> (u64, u64) {
        let held = self.held();
        (held.entries, held.bytes)
    }

    /// The closures holding the pool, each once.
    #[cfg(test)]
    pub(crate) fn closures(&self) -> Vec<Closure> {
        self.held().closures.keys().copied().collect()
    }
}
