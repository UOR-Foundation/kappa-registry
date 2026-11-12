//! Admission of one succession link into a backend's successor index.
//!
//! Every anchor has at most one successor, but several anchors may succeed
//! into the same new anchor, so the index is a forest of chains that can
//! join. The store promises that every chain it admits resolves: no chain
//! holds more than `SUCCESSION_CHAIN_MAX` links and none is cyclic. A link
//! `old -> new` lengthens every chain through it to
//! `depth(old) + 1 + forward(new)`, where `depth(x)` is the longest chain
//! ending at `x` and `forward(new)` is the number of links after `new`.
//! Checking only the forward side would admit a link appended at the head
//! of a full chain, or one joining two long chains.
//!
//! Backends keep `depth` as a persisted index beside the successor records
//! and update both in the transaction that admits the link. Admission then
//! costs one depth lookup plus a forward walk bounded by the chain limit.
//!
//! The decision is one state machine ([`SuccessionPlan`]) running on the
//! caller's own allowance: the operation's meter, never one of its own. It
//! asks for one observation at a time ([`SuccessionPlan::step`], borrowing
//! the key it names from the plan, so asking again allocates nothing) and
//! holds everything decided so far, so a backend that answers across
//! several bounded steps resumes it where it stopped, and one that answers
//! at once drives it to completion ([`plan_succession_link`]). The record's
//! canonical encoding is produced under the same meter in the store's
//! encoding storage (`canonical::bounded_canonical_bytes`); the plan holds
//! it with its live reservation and hands both to the backend, which writes
//! the bytes as the record's row and releases the reservation with them.
//! Every allocation of a plan is
//! charged on the meter before it is made (`work::reserve_charged` for each
//! buffer's growth); a refused charge leaves the plan's decision state as
//! it was, so the same observation may be given again. A semantic rejection
//! is final. Backends supply the observations, charging their own reads,
//! and apply the outcome; none decides admission itself.

use std::mem;
use std::sync::Arc;

use kappa_types::canonical::{Canonical, bounded_canonical_bytes};
use kappa_types::capacity::CapacityPool;
use kappa_types::error::StoreError;
use kappa_types::identity::{SUCCESSION_CHAIN_MAX, Succession};
use kappa_types::kappa::Kappa;
use kappa_types::work::{Dimension, Meter, reserve_charged};

/// The depth updates admitting one new link: `(anchor key bytes, depth)`
/// for its new anchor and every anchor after it.
pub type DepthUpdates = Vec<(Vec<u8>, u64)>;

/// The observation a plan needs next, naming key bytes the plan holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuccessionNeed<'a> {
    /// The next protected canonical row held for the old anchor, or none
    /// once every one has been offered.
    Holder,
    /// The depth of the anchor with these key bytes: the longest chain
    /// ending at it, 0 for an anchor no chain ends at.
    Depth(&'a [u8]),
    /// The new anchor of the record indexed under these key bytes, if any.
    Successor(&'a [u8]),
}

/// What a plan needs next, or that it is complete and its outcome may be
/// taken ([`SuccessionPlan::finish`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuccessionPlanStep<'a> {
    Need(SuccessionNeed<'a>),
    Complete,
}

/// An observation answering the plan's [`SuccessionNeed`], of the same
/// kind.
#[derive(Clone, Copy, Debug)]
pub enum SuccessionObservation<'a> {
    Holder(Option<&'a [u8]>),
    Depth(u64),
    Successor(Option<&'a Kappa>),
}

/// How a completed plan admits its link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SuccessionOutcome {
    /// An identical record is already admitted for the old anchor: every
    /// held row was compared, and admission changes nothing.
    Existing,
    /// The link is new: these depth updates admit it.
    New(DepthUpdates),
}

/// Where a plan is.
enum Phase {
    /// Comparing held rows for the old anchor; `seen` once one was offered.
    Holders { seen: bool },
    /// Every held row compared and none offered: the old anchor's depth.
    Base,
    /// Walking forward from the new anchor: `forward` holds it and every
    /// anchor after it found so far.
    Forward { base: u64, forward: Vec<Vec<u8>> },
    /// Each anchor of the walk, in order, takes the greater of its depth
    /// and its depth through the new link.
    Depths {
        base: u64,
        forward: Vec<Vec<u8>>,
        updates: DepthUpdates,
    },
    /// The outcome, until it is taken.
    Complete(SuccessionOutcome),
}

/// The admission of one succession link (see the module documentation).
pub struct SuccessionPlan {
    /// The record's canonical encoding with its live reservation.
    canonical: Canonical,
    old_anchor: Kappa,
    old_key: Vec<u8>,
    /// The walk's start: copied into the walk, kept for every rewind.
    new_key: Vec<u8>,
    limit: u64,
    phase: Phase,
}

/// Bytes of an anchor's key: its discriminant and digest.
fn key_len(anchor: &Kappa) -> u64 {
    1 + anchor.digest_bytes().len() as u64
}

/// The chain depth through the new link after `links` anchors of the walk.
fn through(base: u64, links: usize) -> Result<u64, StoreError> {
    let links = u64::try_from(links)
        .map_err(|_| StoreError::Internal("succession walk length exceeds u64".into()))?;
    base.checked_add(links)
        .ok_or_else(|| StoreError::Internal("succession depth overflow".into()))
}

/// The walk's chain through the new link after `links` anchors, refused
/// once it would pass `limit`.
fn within_limit(limit: u64, base: u64, links: usize) -> Result<(), StoreError> {
    if through(base, links)? > limit {
        return Err(StoreError::CapacityExceeded(format!(
            "succession chain would exceed {SUCCESSION_CHAIN_MAX} links"
        )));
    }
    Ok(())
}

fn mismatched() -> StoreError {
    StoreError::Internal("a succession plan was answered with another observation".into())
}

impl SuccessionPlan {
    /// The plan admitting `record`, on `meter`: the operation's allowance.
    /// Rejects a link to itself before any work. The record's canonical
    /// encoding (held to compare held rows with, and written as its row) is
    /// produced under `meter` in live storage reserved from `storage`, and
    /// the two anchor keys the plan holds are charged on it before they are
    /// built.
    pub fn new(
        record: &Succession,
        meter: &mut dyn Meter,
        storage: &Arc<CapacityPool>,
    ) -> Result<Self, StoreError> {
        if record.old_anchor == record.new_anchor {
            return Err(StoreError::Rejected(
                "succession cannot target itself".into(),
            ));
        }
        let limit = u64::try_from(SUCCESSION_CHAIN_MAX)
            .map_err(|_| StoreError::Internal("succession chain limit exceeds u64".into()))?;
        let canonical = bounded_canonical_bytes(record, meter, storage)?;
        meter.charge(
            Dimension::BytesAllocated,
            key_len(&record.old_anchor) + key_len(&record.new_anchor),
        )?;
        Ok(Self {
            canonical,
            old_anchor: record.old_anchor.clone(),
            old_key: record.old_anchor.key_bytes(),
            new_key: record.new_anchor.key_bytes(),
            limit,
            phase: Phase::Holders { seen: false },
        })
    }

    /// Discard every observation the plan holds (the holders seen, the base
    /// depth, the walk, the depth updates, a completed outcome) and ask for
    /// them again from the first: what was observed belongs to the
    /// transaction it was observed in. The record's encoding and both keys
    /// are kept; nothing is allocated or encoded again.
    pub fn rewind(&mut self) {
        self.phase = Phase::Holders { seen: false };
    }

    /// The record's canonical encoding, written as its row once the link is
    /// admitted.
    pub fn canonical(&self) -> &[u8] {
        self.canonical.as_ref()
    }

    /// How the link is admitted, once the plan is complete.
    pub const fn outcome(&self) -> Option<&SuccessionOutcome> {
        match &self.phase {
            Phase::Complete(outcome) => Some(outcome),
            _ => None,
        }
    }

    /// What the plan needs next, the same until it is answered and borrowed
    /// from the plan, or that it is complete. Allocates nothing.
    pub fn step(&self) -> Result<SuccessionPlanStep<'_>, StoreError> {
        let need = match &self.phase {
            Phase::Holders { .. } => SuccessionNeed::Holder,
            Phase::Base => SuccessionNeed::Depth(&self.old_key),
            Phase::Forward { forward, .. } => SuccessionNeed::Successor(
                forward
                    .last()
                    .ok_or_else(|| StoreError::Internal("succession walk lost its start".into()))?,
            ),
            Phase::Depths {
                forward, updates, ..
            } => SuccessionNeed::Depth(forward.get(updates.len()).ok_or_else(|| {
                StoreError::Internal("succession depths overran the walk".into())
            })?),
            Phase::Complete(_) => return Ok(SuccessionPlanStep::Complete),
        };
        Ok(SuccessionPlanStep::Need(need))
    }

    /// Answer the plan's current need, every allocation it makes charged on
    /// `meter` first: a refused charge (`WorkRefused`) leaves the plan's
    /// decision state where it was, and the work charged before it stays
    /// charged. Rejects a held row that differs from the record
    /// (`Conflict`), a walk that returns to the old anchor (`Rejected`), and
    /// a chain longer than `SUCCESSION_CHAIN_MAX` (`CapacityExceeded`), each
    /// as soon as it is decided, so a damaged index cannot make admission
    /// walk unboundedly.
    pub fn answer(
        &mut self,
        observation: SuccessionObservation<'_>,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let next = match (&mut self.phase, observation) {
            (Phase::Holders { seen }, SuccessionObservation::Holder(Some(held))) => {
                // The comparison examines one value and at most the shorter
                // of the two encodings, charged before it runs: a refusal
                // leaves `seen` and the phase as they were.
                let compared = held.len().min(self.canonical.as_ref().len()) as u64;
                meter.charge_all(&[(Dimension::Entries, 1), (Dimension::BytesRead, compared)])?;
                if held != self.canonical.as_ref() {
                    return Err(StoreError::Conflict(
                        "anchor already has another succession record".into(),
                    ));
                }
                *seen = true;
                return Ok(());
            }
            (Phase::Holders { seen: true }, SuccessionObservation::Holder(None)) => {
                Phase::Complete(SuccessionOutcome::Existing)
            }
            (Phase::Holders { seen: false }, SuccessionObservation::Holder(None)) => Phase::Base,
            (Phase::Base, SuccessionObservation::Depth(base)) => {
                within_limit(self.limit, base, 1)?;
                meter.charge(Dimension::BytesAllocated, self.new_key.len() as u64)?;
                let mut forward = Vec::new();
                reserve_charged(meter, &mut forward)?;
                forward.push(self.new_key.clone());
                Phase::Forward { base, forward }
            }
            (Phase::Forward { .. }, SuccessionObservation::Successor(Some(next)))
                if *next == self.old_anchor =>
            {
                return Err(StoreError::Rejected("succession would form a cycle".into()));
            }
            (Phase::Forward { base, forward }, SuccessionObservation::Successor(Some(next))) => {
                let links = forward.len().checked_add(1).ok_or_else(|| {
                    StoreError::Internal("succession walk length overflow".into())
                })?;
                within_limit(self.limit, *base, links)?;
                meter.charge(Dimension::BytesAllocated, key_len(next))?;
                reserve_charged(meter, forward)?;
                forward.push(next.key_bytes());
                return Ok(());
            }
            (Phase::Forward { base, forward }, SuccessionObservation::Successor(None)) => {
                Phase::Depths {
                    base: *base,
                    forward: mem::take(forward),
                    updates: Vec::new(),
                }
            }
            (
                Phase::Depths {
                    base,
                    forward,
                    updates,
                },
                SuccessionObservation::Depth(current),
            ) => {
                let links = updates.len().checked_add(1).ok_or_else(|| {
                    StoreError::Internal("succession walk length overflow".into())
                })?;
                let key = forward.get(updates.len()).ok_or_else(|| {
                    StoreError::Internal("succession depths overran the walk".into())
                })?;
                let depth = current.max(through(*base, links)?);
                meter.charge(Dimension::BytesAllocated, key.len() as u64)?;
                reserve_charged(meter, updates)?;
                updates.push((key.clone(), depth));
                if updates.len() < forward.len() {
                    return Ok(());
                }
                Phase::Complete(SuccessionOutcome::New(mem::take(updates)))
            }
            _ => return Err(mismatched()),
        };
        self.phase = next;
        Ok(())
    }

    /// The outcome of a complete plan; the encoding and its reservation are
    /// released.
    pub fn finish(self) -> Result<SuccessionOutcome, StoreError> {
        self.admitted().map(|admitted| admitted.outcome)
    }

    /// The outcome of a complete plan with the record's encoding, whose
    /// reservation the backend holds until it has written the bytes.
    pub fn admitted(self) -> Result<Admitted, StoreError> {
        match self.phase {
            Phase::Complete(outcome) => Ok(Admitted {
                outcome,
                canonical: self.canonical,
            }),
            _ => Err(StoreError::Internal(
                "a succession plan was finished before it completed".into(),
            )),
        }
    }
}

/// A link driven to its admission decision: how it is admitted, and the
/// record's canonical encoding the plan produced with the live reservation
/// that owns it, which the backend writes as the record's row without
/// encoding it again and releases with the bytes.
pub struct Admitted {
    pub outcome: SuccessionOutcome,
    pub canonical: Canonical,
}

/// [`SuccessionPlan`] driven to completion on `meter`, the operation's
/// allowance, its encoding held in `storage`, with observations available
/// at once. `existing` holds every protected canonical row for the old
/// anchor; `depth_of` returns 0 for an anchor no chain ends at, and
/// `successor_of` the new anchor of the record indexed under an anchor's
/// key bytes, each charging its own reads on the meter it is given.
pub fn plan_succession_link<'a>(
    record: &Succession,
    meter: &mut dyn Meter,
    storage: &Arc<CapacityPool>,
    existing: impl IntoIterator<Item = &'a [u8]>,
    depth_of: impl FnMut(&[u8], &mut dyn Meter) -> Result<u64, StoreError>,
    successor_of: impl FnMut(&[u8], &mut dyn Meter) -> Result<Option<Kappa>, StoreError>,
) -> Result<Admitted, StoreError> {
    let mut plan = SuccessionPlan::new(record, meter, storage)?;
    drive(&mut plan, meter, existing, depth_of, successor_of)?;
    plan.admitted()
}

/// Drive `plan` from where it is to completion on `meter`, with
/// observations available at once (see [`plan_succession_link`]): the one
/// driver of the planner. A refusal returns with the plan where the refused
/// answer left it.
pub fn drive<'a>(
    plan: &mut SuccessionPlan,
    meter: &mut dyn Meter,
    existing: impl IntoIterator<Item = &'a [u8]>,
    mut depth_of: impl FnMut(&[u8], &mut dyn Meter) -> Result<u64, StoreError>,
    mut successor_of: impl FnMut(&[u8], &mut dyn Meter) -> Result<Option<Kappa>, StoreError>,
) -> Result<(), StoreError> {
    let mut existing = existing.into_iter();
    loop {
        let observed = match plan.step()? {
            SuccessionPlanStep::Complete => return Ok(()),
            SuccessionPlanStep::Need(SuccessionNeed::Holder) => Observed::Holder(existing.next()),
            SuccessionPlanStep::Need(SuccessionNeed::Depth(key)) => {
                Observed::Depth(depth_of(key, meter)?)
            }
            SuccessionPlanStep::Need(SuccessionNeed::Successor(key)) => {
                Observed::Successor(successor_of(key, meter)?)
            }
        };
        let observation = match &observed {
            Observed::Holder(held) => SuccessionObservation::Holder(*held),
            Observed::Depth(depth) => SuccessionObservation::Depth(*depth),
            Observed::Successor(next) => SuccessionObservation::Successor(next.as_ref()),
        };
        plan.answer(observation, meter)?;
    }
}

/// An observation owned by the driver while the plan is answered.
enum Observed<'a> {
    Holder(Option<&'a [u8]>),
    Depth(u64),
    Successor(Option<Kappa>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_types::canonical::canonical_bytes;
    use kappa_types::work::{WorkLimit, WorkMeter};
    use std::collections::BTreeMap;

    fn key(index: u8) -> Vec<u8> {
        Kappa::sha256(&[index]).key_bytes()
    }

    /// Encoding storage no test exhausts.
    fn storage() -> Arc<CapacityPool> {
        Arc::new(CapacityPool::new("test encodings", u64::MAX))
    }

    fn link(old: u8, new: u8) -> Succession {
        Succession {
            old_anchor: Kappa::sha256(&[old]),
            new_anchor: Kappa::sha256(&[new]),
            reason: kappa_types::identity::SuccessionReason::Rotation,
            effective_at_ms: 0,
            chain_anchor: None,
            prev_identifier: None,
            old_cose_signature: kappa_types::SignedPayload::empty(),
            new_cose_signature: kappa_types::SignedPayload::empty(),
        }
    }

    fn plan_link<'a>(
        record: &Succession,
        existing: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<SuccessionOutcome, StoreError> {
        plan_succession_link(
            record,
            &mut WorkMeter::unbounded(),
            &storage(),
            existing,
            |_, _| Ok(0),
            |_, _| Ok(None),
        )
        .map(|admitted| admitted.outcome)
    }

    #[test]
    fn admission_rejects_self_and_changed_record_but_accepts_exact_replay() -> Result<(), StoreError>
    {
        let record = link(1, 2);
        let bytes = canonical_bytes(&record);
        let pool = storage();
        let admitted = plan_succession_link(
            &record,
            &mut WorkMeter::unbounded(),
            &pool,
            [],
            |_, _| Ok(0),
            |_, _| Ok(None),
        )?;
        assert!(matches!(admitted.outcome, SuccessionOutcome::New(_)));
        assert_eq!(
            admitted.canonical.as_ref(),
            bytes,
            "the admitted encoding is the record's canonical row"
        );
        assert_eq!(
            pool.used(),
            bytes.len() as u64,
            "the backend receives the encoding with its live reservation"
        );
        drop(admitted);
        assert_eq!(pool.used(), 0, "released with the bytes");
        assert_eq!(
            plan_succession_link(
                &record,
                &mut WorkMeter::unbounded(),
                &storage(),
                [bytes.as_slice()],
                |_, _| panic!("replay must not plan depths"),
                |_, _| panic!("replay must not walk")
            )?
            .outcome,
            SuccessionOutcome::Existing
        );
        let mut changed = record.clone();
        changed.effective_at_ms += 1;
        assert!(matches!(
            plan_link(&changed, [bytes.as_slice()]),
            Err(StoreError::Conflict(_))
        ));
        assert!(matches!(
            plan_link(&link(1, 1), []),
            Err(StoreError::Rejected(_))
        ));
        let conflicting = canonical_bytes(&changed);
        assert!(
            matches!(
                plan_link(&record, [bytes.as_slice(), conflicting.as_slice()]),
                Err(StoreError::Conflict(_))
            ),
            "an identical first holder does not hide a conflicting later one"
        );
        Ok(())
    }

    /// The plan's canonical encoding is the bounded encoding of the record
    /// on the caller's meter: an allowance that cannot hold it refuses the
    /// plan, typed, before any key is built.
    #[test]
    fn a_plan_encodes_its_record_on_the_callers_allowance() -> Result<(), StoreError> {
        let record = link(1, 2);
        let encoded = canonical_bytes(&record).len() as u64;
        let pool = storage();
        let mut short =
            WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesAllocated, encoded - 1));
        assert!(matches!(
            SuccessionPlan::new(&record, &mut short, &pool),
            Err(StoreError::WorkRefused(_))
        ));
        assert_eq!(pool.used(), 0);
        let keys = key_len(&record.old_anchor) + key_len(&record.new_anchor);
        let mut exact =
            WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesAllocated, encoded + keys));
        let plan = SuccessionPlan::new(&record, &mut exact, &pool)?;
        assert_eq!(plan.canonical.as_ref(), canonical_bytes(&record));
        assert_eq!(exact.remaining(Dimension::BytesAllocated), 0);
        assert_eq!(pool.used(), encoded, "the plan holds its encoding live");
        drop(plan);
        assert_eq!(pool.used(), 0);
        let full = Arc::new(CapacityPool::new("full encodings", encoded - 1));
        assert!(
            matches!(
                SuccessionPlan::new(&record, &mut WorkMeter::unbounded(), &full),
                Err(StoreError::CapacityExceeded(_))
            ),
            "storage that cannot hold the encoding refuses the plan"
        );
        Ok(())
    }

    /// A plan asks for the held rows, the old anchor's depth, the forward
    /// walk and each walked anchor's depth, in that order, one at a time,
    /// repeating a need until it is answered; answering out of kind is a
    /// defect, not an observation, and finishing early is a defect.
    #[test]
    fn a_plan_asks_one_observation_at_a_time() -> Result<(), StoreError> {
        let record = link(1, 2);
        let next = Kappa::sha256(&[3]);
        let mut work = WorkMeter::unbounded();
        let pool = storage();
        let mut plan = SuccessionPlan::new(&record, &mut work, &pool)?;
        let holder = SuccessionPlanStep::Need(SuccessionNeed::Holder);
        assert_eq!(plan.step()?, holder);
        assert_eq!(plan.step()?, holder, "repeated until answered");
        plan.answer(SuccessionObservation::Holder(None), &mut work)?;
        assert_eq!(
            plan.step()?,
            SuccessionPlanStep::Need(SuccessionNeed::Depth(&key(1)))
        );
        plan.answer(SuccessionObservation::Depth(5), &mut work)?;
        assert_eq!(
            plan.step()?,
            SuccessionPlanStep::Need(SuccessionNeed::Successor(&key(2)))
        );
        plan.answer(SuccessionObservation::Successor(Some(&next)), &mut work)?;
        assert_eq!(
            plan.step()?,
            SuccessionPlanStep::Need(SuccessionNeed::Successor(&key(3)))
        );
        plan.answer(SuccessionObservation::Successor(None), &mut work)?;
        assert_eq!(
            plan.step()?,
            SuccessionPlanStep::Need(SuccessionNeed::Depth(&key(2)))
        );
        plan.answer(SuccessionObservation::Depth(0), &mut work)?;
        assert_eq!(
            plan.step()?,
            SuccessionPlanStep::Need(SuccessionNeed::Depth(&key(3)))
        );
        plan.answer(SuccessionObservation::Depth(9), &mut work)?;
        assert_eq!(plan.step()?, SuccessionPlanStep::Complete);
        assert_eq!(
            plan.finish()?,
            SuccessionOutcome::New(vec![(key(2), 6), (key(3), 9)]),
            "each anchor keeps the greater of its depth and its depth through the link"
        );
        let mut wrong = SuccessionPlan::new(&record, &mut work, &pool)?;
        assert!(matches!(
            wrong.answer(SuccessionObservation::Depth(0), &mut work),
            Err(StoreError::Internal(_))
        ));
        assert!(matches!(
            SuccessionPlan::new(&record, &mut work, &pool)?.finish(),
            Err(StoreError::Internal(_))
        ));
        drop(wrong);
        assert_eq!(pool.used(), 0, "every plan released its encoding");
        Ok(())
    }

    /// Asking again names the same key the plan holds, allocating nothing;
    /// an answer whose allocation the meter refuses leaves the plan exactly
    /// where it was, and the same answer then advances it.
    #[test]
    fn a_refused_answer_keeps_the_plan_and_needs_borrow_its_keys() -> Result<(), StoreError> {
        let record = link(1, 2);
        let mut work = WorkMeter::unbounded();
        let mut plan = SuccessionPlan::new(&record, &mut work, &storage())?;
        plan.answer(SuccessionObservation::Holder(None), &mut work)?;
        let first = match plan.step()? {
            SuccessionPlanStep::Need(SuccessionNeed::Depth(key)) => key.as_ptr(),
            other => return Err(StoreError::Internal(format!("unexpected {other:?}"))),
        };
        let second = match plan.step()? {
            SuccessionPlanStep::Need(SuccessionNeed::Depth(key)) => key.as_ptr(),
            other => return Err(StoreError::Internal(format!("unexpected {other:?}"))),
        };
        assert_eq!(
            first, second,
            "a repeated need borrows the key the plan holds"
        );
        let mut refusing =
            WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesAllocated, 0));
        assert!(matches!(
            plan.answer(SuccessionObservation::Depth(5), &mut refusing),
            Err(StoreError::WorkRefused(_))
        ));
        assert_eq!(refusing.used().get(Dimension::BytesAllocated), 0);
        assert_eq!(
            plan.step()?,
            SuccessionPlanStep::Need(SuccessionNeed::Depth(&key(1))),
            "the refused answer changed nothing"
        );
        plan.answer(SuccessionObservation::Depth(5), &mut work)?;
        assert_eq!(
            plan.step()?,
            SuccessionPlanStep::Need(SuccessionNeed::Successor(&key(2)))
        );
        let next = Kappa::sha256(&[3]);
        let mut refusing =
            WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesAllocated, 0));
        assert!(matches!(
            plan.answer(SuccessionObservation::Successor(Some(&next)), &mut refusing),
            Err(StoreError::WorkRefused(_))
        ));
        assert_eq!(
            plan.step()?,
            SuccessionPlanStep::Need(SuccessionNeed::Successor(&key(2))),
            "a refused step of the walk keeps the walk where it was"
        );
        plan.answer(SuccessionObservation::Successor(Some(&next)), &mut work)?;
        assert_eq!(
            plan.step()?,
            SuccessionPlanStep::Need(SuccessionNeed::Successor(&key(3)))
        );
        Ok(())
    }

    /// Comparing a held row against the plan's encoding is charged before it
    /// runs: a meter that refuses it leaves the plan where it was, and the
    /// same row then answers the need on a meter that admits it.
    #[test]
    fn a_refused_comparison_keeps_the_holder_unseen() -> Result<(), StoreError> {
        let record = link(1, 2);
        let held = canonical_bytes(&record);
        let mut work = WorkMeter::unbounded();
        let mut plan = SuccessionPlan::new(&record, &mut work, &storage())?;
        let mut refusing = WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesRead, 0));
        assert!(matches!(
            plan.answer(SuccessionObservation::Holder(Some(&held)), &mut refusing),
            Err(StoreError::WorkRefused(_))
        ));
        assert_eq!(refusing.used().get(Dimension::Entries), 0);
        plan.answer(
            SuccessionObservation::Holder(None),
            &mut WorkMeter::unbounded(),
        )?;
        assert_eq!(
            plan.step()?,
            SuccessionPlanStep::Need(SuccessionNeed::Depth(&key(1))),
            "the refused comparison did not mark a holder seen"
        );
        let mut replay = SuccessionPlan::new(&record, &mut work, &storage())?;
        let before = *work.used();
        replay.answer(SuccessionObservation::Holder(Some(&held)), &mut work)?;
        assert_eq!(
            work.used().since(&before).get(Dimension::BytesRead),
            held.len() as u64,
            "the comparison is charged its bytes"
        );
        replay.answer(SuccessionObservation::Holder(None), &mut work)?;
        assert_eq!(replay.finish()?, SuccessionOutcome::Existing);
        Ok(())
    }

    /// A rewind drops every observation and keeps the encoding: the plan
    /// asks for the holders again, encodes nothing again, and driven again
    /// reaches the same outcome as a fresh plan.
    #[test]
    fn a_rewound_plan_keeps_its_encoding_and_asks_again() -> Result<(), StoreError> {
        let record = link(1, 2);
        let mut work = WorkMeter::unbounded();
        let mut plan = SuccessionPlan::new(&record, &mut work, &storage())?;
        let encoded = plan.canonical().as_ptr();
        drive(&mut plan, &mut work, [], |_, _| Ok(4), |_, _| Ok(None))?;
        assert_eq!(
            plan.outcome(),
            Some(&SuccessionOutcome::New(vec![(key(2), 5)]))
        );
        plan.rewind();
        assert_eq!(plan.outcome(), None);
        assert_eq!(
            plan.step()?,
            SuccessionPlanStep::Need(SuccessionNeed::Holder)
        );
        let before = *work.used();
        drive(&mut plan, &mut work, [], |_, _| Ok(0), |_, _| Ok(None))?;
        assert_eq!(
            plan.outcome(),
            Some(&SuccessionOutcome::New(vec![(key(2), 1)])),
            "the new observations decide the outcome"
        );
        assert_eq!(plan.canonical().as_ptr(), encoded, "never encoded again");
        assert_eq!(
            work.used().since(&before).get(Dimension::BytesRead),
            0,
            "no holder was compared and nothing was encoded"
        );
        Ok(())
    }

    #[derive(Default)]
    struct Index {
        successor: BTreeMap<Vec<u8>, Kappa>,
        depth: BTreeMap<Vec<u8>, u64>,
    }

    impl Index {
        fn admit(&mut self, old: u8, new: u8) -> Result<(), StoreError> {
            let record = link(old, new);
            let admitted = plan_succession_link(
                &record,
                &mut WorkMeter::unbounded(),
                &storage(),
                [],
                |anchor, _| Ok(self.depth.get(anchor).copied().unwrap_or(0)),
                |anchor, _| Ok(self.successor.get(anchor).cloned()),
            )?;
            self.successor.insert(key(old), record.new_anchor);
            if let SuccessionOutcome::New(updates) = admitted.outcome {
                self.depth.extend(updates);
            }
            Ok(())
        }
    }

    #[test]
    fn head_origin_and_join_growth_share_one_bound() -> Result<(), StoreError> {
        let mut head = Index::default();
        for index in 0..64 {
            head.admit(index, index + 1)?;
        }
        assert_eq!(head.depth.get(&key(64)), Some(&64));
        assert!(matches!(
            head.admit(64, 65),
            Err(StoreError::CapacityExceeded(_))
        ));

        let mut origin = Index::default();
        for index in 1..65 {
            origin.admit(index, index + 1)?;
        }
        assert!(matches!(
            origin.admit(0, 1),
            Err(StoreError::CapacityExceeded(_))
        ));

        let mut join = Index::default();
        for index in 0..32 {
            join.admit(index, index + 1)?;
            join.admit(100 + index, 101 + index)?;
        }
        assert!(matches!(
            join.admit(32, 100),
            Err(StoreError::CapacityExceeded(_))
        ));
        // A 31-link chain joins the same 32-link chain into exactly 64.
        for index in 50..81 {
            join.admit(index, index + 1)?;
        }
        join.admit(81, 100)?;
        assert_eq!(join.depth.get(&key(132)), Some(&64));
        assert_eq!(join.depth.get(&key(100)), Some(&32));
        Ok(())
    }

    #[test]
    fn cycles_are_rejected_and_depths_take_the_longest_path() -> Result<(), StoreError> {
        let mut index = Index::default();
        index.admit(0, 1)?;
        index.admit(1, 2)?;
        assert!(matches!(index.admit(2, 0), Err(StoreError::Rejected(_))));
        // A short branch joining at 2 does not lower its depth.
        index.admit(9, 2)?;
        assert_eq!(index.depth.get(&key(2)), Some(&2));
        index.admit(2, 3)?;
        assert_eq!(index.depth.get(&key(3)), Some(&3));
        Ok(())
    }

    #[test]
    fn joins_keep_the_longest_depth_downstream() -> Result<(), StoreError> {
        let mut index = Index::default();
        for (old, new) in [(0, 1), (1, 2), (2, 3), (20, 21), (21, 3), (3, 4)] {
            index.admit(old, new)?;
        }
        // 0->1->2->3->4 is longer than 20->21->3->4.
        assert_eq!(index.depth.get(&key(3)), Some(&3));
        assert_eq!(index.depth.get(&key(4)), Some(&4));
        assert_eq!(index.depth.get(&key(21)), Some(&1));
        Ok(())
    }
}
