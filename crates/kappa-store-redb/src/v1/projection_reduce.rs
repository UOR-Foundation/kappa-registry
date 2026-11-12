//! The one ordered reduction of projection versions (`projection`): per
//! (logical key, instance) group, the eligible version greatest in (epoch,
//! sequence), compared explicitly rather than read off the physical (epoch,
//! attempt, sequence) order.
//!
//! Version keys hold a group's versions contiguously. A reduction holds only
//! the group being reduced and one finished group awaiting delivery
//! ([`Reduction`]); a group is delivered when the next one begins or the
//! range ends. Every version is examined inside one unit admitted on the
//! caller's meter at [`selection_unit`], the end of the range included. A
//! step reports why it returned ([`Reduced`]): the range ended, the caller
//! stopped it, or the meter refused with everything processed kept in the
//! state, which a caller may resume over a range rebuilt after
//! [`Reduction::position`] in the same snapshot.
//!
//! The delivery contract ([`Emit`]): a caller inspects the offered delivery
//! by reference, secures every fallible allocation and conversion its output
//! needs, then takes it and does only work already secured. A refusal before
//! the take leaves the delivery pending in the state; a refusal after it is
//! a defect of the caller, reported as one, never as a refusal that kept
//! everything.

use std::ops::ControlFlow;

use kappa_store::StoreError;
use kappa_store::work::{Dimension, Meter, Work, WorkExhausted};

use super::visibility::visibility_unit;
use super::{Version, VersionBounds, VersionKey};
use crate::redb_cursor::Rows;
use crate::storage_instance::StorageInstance;

/// The work of examining one version at most, as one aggregate
/// (`Work::total`): the row examined, its key and value read, its value
/// decoded, the copies it makes (the decoded logical key, the processed
/// position, the payload), and the visibility decision of its attempt. The
/// end of a range is observed inside the same unit. Computed once with the
/// settlement limits.
pub fn selection_unit(bounds: &VersionBounds) -> Result<Work, Dimension> {
    let mut bound = vec![
        (Dimension::Entries, 1),
        (Dimension::BytesRead, bounds.key()),
        (Dimension::BytesRead, bounds.value()),
        (Dimension::BytesDecoded, bounds.value()),
        (Dimension::BytesAllocated, bounds.key()),
        (Dimension::BytesAllocated, bounds.key()),
        (Dimension::BytesAllocated, bounds.value()),
    ];
    bound.extend(visibility_unit()?.as_bound());
    Work::total(&bound)
}

/// What a reduction's caller decides of one version, by the canonical
/// policy of its owner (`visibility`, or a stage's own attempt beside it):
/// `Some` with its completion sequence when it may be selected, `None` when
/// it is passed over. Runs inside the version's admitted unit.
pub(crate) type Eligible<'a> =
    dyn FnMut(&VersionKey, &mut dyn Meter) -> Result<Option<u64>, StoreError> + 'a;

/// A finished group's newest eligible version, offered to the caller.
pub(crate) struct Delivery {
    pub(crate) logical: Vec<u8>,
    pub(crate) instance: StorageInstance,
    pub(crate) completion: u64,
    pub(crate) version: Version,
}

/// What a reduction offers each finished group to (see the module
/// documentation): the caller takes the delivery (`Option::take`) and
/// returns `Continue`, or returns `Break` once it has its answer, taken or
/// not. Runs on the caller's meter, outside any unit.
pub(crate) type Emit<'a> =
    dyn FnMut(&mut Option<Delivery>, &mut dyn Meter) -> Result<ControlFlow<()>, StoreError> + 'a;

/// A group's selected version: its semantic order within the group
/// (epoch, sequence), its completion sequence (the order among instances),
/// and the version.
struct Selected {
    order: (u64, u64),
    completion: u64,
    version: Version,
}

/// The group being reduced: its logical key and instance, and its newest
/// eligible version so far.
struct Group {
    logical: Vec<u8>,
    instance: StorageInstance,
    selected: Option<Selected>,
}

/// A reduction's state across steps: the group being reduced, a finished
/// group not yet delivered, the last physical key fully processed (every
/// row up to it is reflected in this state), the last key of the last
/// finished group (`boundary`), and whether the range was observed to end.
/// A complete-or-refused read drops it with a refusal; a resumable
/// traversal keeps it and rebuilds its range after `position`.
#[derive(Default)]
pub(crate) struct Reduction {
    current: Option<Group>,
    pending: Option<Group>,
    position: Option<Vec<u8>>,
    boundary: Option<Vec<u8>>,
    exhausted: bool,
}

impl Reduction {
    /// The last physical key fully processed: internal traversal progress,
    /// from which this state's range is rebuilt in the same snapshot. It may
    /// be ahead of a finished group not yet delivered, whose rows it already
    /// reflects, so it is never by itself a public continuation: a caller
    /// that resumes from it resumes with this state.
    pub(crate) fn position(&self) -> Option<&[u8]> {
        self.position.as_deref()
    }

    /// Prepare this state to resume in another transaction than the one it
    /// was advanced in. Compaction changes no group's selection
    /// (`projection_compact`), so every finished group's selection, the one
    /// awaiting delivery included, stays the answer; but it removes rows, so
    /// a group read only part way is no longer reflected by its partial
    /// selection (a fold can remove both a retained version and the
    /// tombstone after it). That group is dropped and the range rebuilt from
    /// the last finished group's boundary, so it is read again whole. A
    /// change of what is eligible is the caller's to detect
    /// (`ProjectionStage::protection`); this resume is valid only together
    /// with that check.
    pub(crate) fn resume_in_new_transaction(
        &mut self,
        work: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        if self.current.is_none() {
            return Ok(());
        }
        let copied = self.boundary.as_ref().map_or(0, Vec::len) as u64;
        work.charge(Dimension::BytesAllocated, copied)?;
        self.current = None;
        self.position = self.boundary.clone();
        self.exhausted = false;
        Ok(())
    }
}

/// Why a reduction step returned.
#[derive(Debug)]
pub(crate) enum Reduced {
    /// The range ended and every finished group was delivered.
    Exhausted,
    /// The caller has its answer; rows may remain.
    Stopped,
    /// The meter refused the next unit, or the caller refused before taking
    /// its delivery; the state holds everything processed, nothing was
    /// skipped.
    Refused(WorkExhausted),
}

impl Reduced {
    /// The outcome of a read that answers completely or not at all: a
    /// refusal is the read's refusal. For complete-or-refused adapters only:
    /// it merges the end of the range with the caller's own stop, which a
    /// resumable traversal must tell apart by inspecting the variants.
    pub(crate) fn complete(self) -> Result<(), StoreError> {
        match self {
            Self::Exhausted | Self::Stopped => Ok(()),
            Self::Refused(refused) => Err(StoreError::WorkRefused(refused)),
        }
    }
}

/// A reduction offered its caller nothing: every offer holds a delivery.
pub(crate) fn undelivered() -> StoreError {
    StoreError::Internal("a projection reduction offered no delivery".into())
}

/// Offer `group`'s selection to `emit`, keeping it pending in `state`
/// unless taken; `None` when the reduction continues.
fn deliver(
    state: &mut Reduction,
    group: Group,
    work: &mut dyn Meter,
    emit: &mut Emit<'_>,
) -> Result<Option<Reduced>, StoreError> {
    let Group {
        logical,
        instance,
        selected,
    } = group;
    let Some(Selected {
        order,
        completion,
        version,
    }) = selected
    else {
        // A group holding no eligible version delivers nothing.
        return Ok(None);
    };
    let mut offered = Some(Delivery {
        logical,
        instance,
        completion,
        version,
    });
    let flow = emit(&mut offered, work);
    let taken = offered.is_none();
    if let Some(Delivery {
        logical,
        instance,
        completion,
        version,
    }) = offered
    {
        state.pending = Some(Group {
            logical,
            instance,
            selected: Some(Selected {
                order,
                completion,
                version,
            }),
        });
    }
    match flow {
        Ok(ControlFlow::Continue(())) if taken => Ok(None),
        Ok(ControlFlow::Continue(())) => Err(StoreError::Internal(
            "a reduction's caller continued without taking its delivery".into(),
        )),
        Ok(ControlFlow::Break(())) => Ok(Some(Reduced::Stopped)),
        Err(StoreError::WorkRefused(refused)) if !taken => Ok(Some(Reduced::Refused(refused))),
        Err(StoreError::WorkRefused(refused)) => Err(StoreError::Internal(format!(
            "a reduction's caller took its delivery and then refused: {refused}"
        ))),
        Err(error) => Err(error),
    }
}

/// Advance `state` over `versions` toward the newest eligible version of
/// each (logical key, instance) group, offering each finished group that
/// holds one to `emit` (see the module documentation). `bounds` refuses an
/// oversized row before it is copied; `unit` is the admitted bound of one
/// version's examination. A finished group is delivered before the next row
/// is read; a delivery the caller refuses stays pending, and a group begun
/// by the row that finished the previous one stays the current group.
pub(crate) fn reduce_groups(
    state: &mut Reduction,
    versions: &mut Rows<'_, &'static [u8]>,
    bounds: &VersionBounds,
    unit: &Work,
    work: &mut dyn Meter,
    eligible: &mut Eligible<'_>,
    emit: &mut Emit<'_>,
) -> Result<Reduced, StoreError> {
    let unit_bound = unit.as_bound();
    loop {
        if let Some(group) = state.pending.take() {
            if let Some(stop) = deliver(state, group, work, emit)? {
                return Ok(stop);
            }
            continue;
        }
        if state.exhausted {
            match state.current.take() {
                Some(group) => {
                    state.pending = Some(group);
                    continue;
                }
                None => return Ok(Reduced::Exhausted),
            }
        }
        let mut admitted = match work.admit(&unit_bound) {
            Ok(admitted) => admitted,
            Err(refused) => return Ok(Reduced::Refused(refused)),
        };
        admitted.account(Dimension::Entries, 1)?;
        let Some(entry) = versions.next() else {
            state.exhausted = true;
            continue;
        };
        let (key, value) = entry?;
        let (key, value) = (key.value(), value.value());
        bounds.check(key, value)?;
        admitted.account(Dimension::BytesRead, (key.len() + value.len()) as u64)?;
        admitted.account(Dimension::BytesAllocated, key.len() as u64)?;
        let version = VersionKey::decode(key)?;
        let selected = match eligible(&version, &mut admitted)? {
            Some(completion) => {
                admitted.account(Dimension::BytesDecoded, value.len() as u64)?;
                admitted.account(Dimension::BytesAllocated, value.len() as u64)?;
                Some(Selected {
                    order: (version.epoch, version.sequence),
                    completion,
                    version: Version::decode(value)?,
                })
            }
            None => None,
        };
        admitted.account(Dimension::BytesAllocated, key.len() as u64)?;
        let continues = state.current.as_ref().is_some_and(|group| {
            group.logical == version.logical && group.instance == version.instance
        });
        // A new group begins after the previous one's last row: that row is
        // the boundary a resume in another transaction retreats to. The
        // position moves into it rather than being copied.
        let previous = state.position.replace(key.to_vec());
        if !continues {
            state.boundary = previous;
        }
        if continues {
            if let (Some(group), Some(incoming)) = (state.current.as_mut(), selected)
                && group
                    .selected
                    .as_ref()
                    .is_none_or(|held| incoming.order > held.order)
            {
                group.selected = Some(incoming);
            }
        } else {
            state.pending = state.current.replace(Group {
                logical: version.logical,
                instance: version.instance,
                selected,
            });
        }
    }
}
