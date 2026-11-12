//! Registry-wide projections of namespace views.
//!
//! Each projection is a [`Locator`] from a key to the namespaces whose
//! views hold it; claims (`claims`) and the succession graph
//! (`succession_graph`) cover the keys only one namespace may hold. A
//! publication computes the keys its candidate view gained and lost against
//! its base view ([`Changes`]): the diff of each persistent map visits only
//! its unshared structure, so the cost follows what changed rather than
//! what the namespace holds. Unchanged keys keep their contributions.
//!
//! The lifecycle follows the publication (`execution`):
//!
//! - [`Projections::register_from`] inserts each gained key once the
//!   publication is signed and installed in its candidate, before the view
//!   store, each key charged as work before it is registered. Its position
//!   is the publication's: a publication stopped part way keeps the
//!   registrations it made and continues from the first it did not. A
//!   registration under a revision the namespace has not published is not
//!   visible: lookups confirm every candidate against the published view
//!   (`InMemoryStore::confirm`);
//! - after the view store, still under the namespace writer,
//!   [`Projections::unregister`] removes each lost key.
//!
//! Registration and removal take only the locators' shard locks.

use std::ops::Bound;

use imbl::OrdMap;
use imbl::ordmap::DiffItem;
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::work::{Dimension, WorkMeter};

use super::locator::{Contribution, Locator};
use super::view::{NamespaceId, NamespaceView};

/// Every registry projection.
#[derive(Default)]
pub struct Projections {
    pub content: Locator<Kappa>,
    pub epochs: Locator<Kappa>,
    /// Namespace record name, tombstoned records included, for listing.
    pub names: Locator<String>,
    pub binding_sources: Locator<String>,
    pub binding_targets: Locator<Kappa>,
    pub assertions: Locator<Kappa>,
    pub assertion_asserters: Locator<Kappa>,
    pub assertion_subjects: Locator<String>,
    pub revocations: Locator<Kappa>,
    pub revocation_asserters: Locator<Kappa>,
    pub watermarks: Locator<Kappa>,
    pub watermark_asserters: Locator<Kappa>,
    pub handles: Locator<String>,
    pub handle_anchors: Locator<Kappa>,
    pub devices: Locator<Kappa>,
    pub prekeys: Locator<Kappa>,
}

/// Keys one projection gained and lost.
struct Delta<K> {
    gained: Vec<K>,
    lost: Vec<K>,
}

impl<K> Default for Delta<K> {
    fn default() -> Self {
        Self {
            gained: Vec::new(),
            lost: Vec::new(),
        }
    }
}

/// Bytes one projection key retains in a delta: its own size and the heap
/// it owns.
trait Retained {
    fn retained(&self) -> u64;
}

impl Retained for Kappa {
    fn retained(&self) -> u64 {
        size_of::<Self>() as u64
    }
}

impl Retained for String {
    fn retained(&self) -> u64 {
        (size_of::<Self>() + self.len()) as u64
    }
}

/// Charge one diff item examined.
fn examined(meter: &mut WorkMeter) -> Result<(), StoreError> {
    Ok(meter.charge(Dimension::Entries, 1)?)
}

/// Push a clone of `key` into `keys`, its retained bytes charged first.
fn retain<K: Clone + Retained>(
    keys: &mut Vec<K>,
    key: &K,
    meter: &mut WorkMeter,
) -> Result<(), StoreError> {
    meter.charge(Dimension::BytesAllocated, key.retained())?;
    keys.push(key.clone());
    Ok(())
}

fn delta<K: Ord + Clone + Retained, V: PartialEq>(
    base: &OrdMap<K, V>,
    candidate: &OrdMap<K, V>,
    meter: &mut WorkMeter,
) -> Result<Delta<K>, StoreError> {
    let mut out = Delta::default();
    for item in base.diff(candidate) {
        examined(meter)?;
        match item {
            DiffItem::Add(key, _) => retain(&mut out.gained, key, meter)?,
            DiffItem::Remove(key, _) => retain(&mut out.lost, key, meter)?,
            DiffItem::Update { .. } => {}
        }
    }
    Ok(out)
}

/// The identities a view gained and lost as held bytes: its logical
/// admissions and its retained evidence together (`NamespaceView::holds`).
/// An identity moving between the two, or held by both while one is
/// removed, stays registered; only an identity neither map holds any longer
/// is lost. An identity changed in both maps is recorded once.
fn held(
    base: &NamespaceView,
    candidate: &NamespaceView,
    meter: &mut WorkMeter,
) -> Result<Delta<Kappa>, StoreError> {
    let mut out = Delta::default();
    for (before, after) in [
        (&base.admitted, &candidate.admitted),
        (&base.evidence, &candidate.evidence),
    ] {
        for item in before.diff(after) {
            examined(meter)?;
            match item {
                DiffItem::Add(identity, _) if !base.holds(identity) => {
                    retain(&mut out.gained, identity, meter)?;
                }
                DiffItem::Remove(identity, _) if !candidate.holds(identity) => {
                    retain(&mut out.lost, identity, meter)?;
                }
                DiffItem::Add(..) | DiffItem::Remove(..) | DiffItem::Update { .. } => {}
            }
        }
    }
    for keys in [&mut out.gained, &mut out.lost] {
        keys.sort_unstable();
        keys.dedup();
    }
    Ok(out)
}

fn epoch_roots(
    base: &OrdMap<u64, Kappa>,
    candidate: &OrdMap<u64, Kappa>,
    meter: &mut WorkMeter,
) -> Result<Delta<Kappa>, StoreError> {
    let mut out = Delta::default();
    for item in base.diff(candidate) {
        examined(meter)?;
        match item {
            DiffItem::Add(_, root) => retain(&mut out.gained, root, meter)?,
            DiffItem::Remove(_, root) => retain(&mut out.lost, root, meter)?,
            DiffItem::Update {
                old: (_, before),
                new: (_, after),
            } => {
                retain(&mut out.lost, before, meter)?;
                retain(&mut out.gained, after, meter)?;
            }
        }
    }
    Ok(out)
}

/// What one publication attempt changes in every projection.
pub struct Changes {
    namespace: NamespaceId,
    incarnation: u64,
    revision: u64,
    content: Delta<Kappa>,
    epochs: Delta<Kappa>,
    names: Delta<String>,
    binding_sources: Delta<String>,
    binding_targets: Delta<Kappa>,
    assertions: Delta<Kappa>,
    assertion_asserters: Delta<Kappa>,
    assertion_subjects: Delta<String>,
    revocations: Delta<Kappa>,
    revocation_asserters: Delta<Kappa>,
    watermarks: Delta<Kappa>,
    watermark_asserters: Delta<Kappa>,
    handles: Delta<String>,
    handle_anchors: Delta<Kappa>,
    devices: Delta<Kappa>,
    prekeys: Delta<Kappa>,
}

impl Changes {
    /// The changes `candidate` makes to `base` of `namespace`, every diff
    /// item examined and every key retained charged to `meter` before it is
    /// cloned.
    pub fn between(
        namespace: NamespaceId,
        base: &NamespaceView,
        candidate: &NamespaceView,
        meter: &mut WorkMeter,
    ) -> Result<Self, StoreError> {
        fn name(view: &NamespaceView) -> Option<&String> {
            view.record.as_ref().map(|record| &record.name)
        }
        let mut names = Delta::default();
        let (before, after) = (name(base), name(candidate));
        if before != after {
            if let Some(before) = before {
                retain(&mut names.lost, before, meter)?;
            }
            if let Some(after) = after {
                retain(&mut names.gained, after, meter)?;
            }
        }
        let (b, c) = (&base.identity, &candidate.identity);
        Ok(Self {
            namespace,
            incarnation: candidate.incarnation,
            revision: candidate.revision,
            content: held(base, candidate, meter)?,
            epochs: epoch_roots(&base.epochs, &candidate.epochs, meter)?,
            names,
            binding_sources: delta(&b.bindings, &c.bindings, meter)?,
            binding_targets: delta(&b.binding_targets, &c.binding_targets, meter)?,
            assertions: delta(&b.assertions, &c.assertions, meter)?,
            assertion_asserters: delta(&b.assertion_asserters, &c.assertion_asserters, meter)?,
            assertion_subjects: delta(&b.assertion_subjects, &c.assertion_subjects, meter)?,
            revocations: delta(&b.revocations, &c.revocations, meter)?,
            revocation_asserters: delta(&b.revocation_asserters, &c.revocation_asserters, meter)?,
            watermarks: delta(&b.watermarks, &c.watermarks, meter)?,
            watermark_asserters: delta(&b.watermark_asserters, &c.watermark_asserters, meter)?,
            handles: delta(&b.handles, &c.handles, meter)?,
            handle_anchors: delta(&b.handle_anchors, &c.handle_anchors, meter)?,
            devices: delta(&b.devices, &c.devices, meter)?,
            prekeys: delta(&b.prekeys, &c.prekeys, meter)?,
        })
    }

    /// Keys this change registers and unregisters across every projection:
    /// the registration and removal work a publication admits before it
    /// signs.
    pub fn entries(&self) -> u64 {
        let keys = |gained: usize, lost: usize| (gained + lost) as u64;
        [
            keys(self.content.gained.len(), self.content.lost.len()),
            keys(self.epochs.gained.len(), self.epochs.lost.len()),
            keys(self.names.gained.len(), self.names.lost.len()),
            keys(
                self.binding_sources.gained.len(),
                self.binding_sources.lost.len(),
            ),
            keys(
                self.binding_targets.gained.len(),
                self.binding_targets.lost.len(),
            ),
            keys(self.assertions.gained.len(), self.assertions.lost.len()),
            keys(
                self.assertion_asserters.gained.len(),
                self.assertion_asserters.lost.len(),
            ),
            keys(
                self.assertion_subjects.gained.len(),
                self.assertion_subjects.lost.len(),
            ),
            keys(self.revocations.gained.len(), self.revocations.lost.len()),
            keys(
                self.revocation_asserters.gained.len(),
                self.revocation_asserters.lost.len(),
            ),
            keys(self.watermarks.gained.len(), self.watermarks.lost.len()),
            keys(
                self.watermark_asserters.gained.len(),
                self.watermark_asserters.lost.len(),
            ),
            keys(self.handles.gained.len(), self.handles.lost.len()),
            keys(
                self.handle_anchors.gained.len(),
                self.handle_anchors.lost.len(),
            ),
            keys(self.devices.gained.len(), self.devices.lost.len()),
            keys(self.prekeys.gained.len(), self.prekeys.lost.len()),
        ]
        .into_iter()
        .fold(0u64, u64::saturating_add)
    }

    /// Room for the `records` a signed root generates and for the root
    /// itself, charged to `meter` and reserved before the signature, so
    /// recording them after it allocates nothing. The registration and
    /// removal work of every key, generated ones included, is admitted
    /// here and charged key by key when it is done.
    pub fn reserve_generated(
        &mut self,
        records: usize,
        meter: &mut WorkMeter,
    ) -> Result<(), StoreError> {
        let generated = records.saturating_add(1);
        meter.admits(&[(
            Dimension::Entries,
            self.entries().saturating_add(generated as u64),
        )])?;
        meter.charge(
            Dimension::BytesAllocated,
            (generated.saturating_mul(size_of::<Kappa>())) as u64,
        )?;
        let refused = |error| StoreError::CapacityExceeded(format!("projection changes: {error}"));
        self.content.gained.try_reserve(records).map_err(refused)?;
        self.epochs.gained.try_reserve(1).map_err(refused)
    }

    /// Record `identity`, evidence generated from the signed root, as held
    /// by the candidate: a loss the candidate's other changes recorded is
    /// cancelled, and a gain recorded once unless `base` already held it.
    /// Within the room `reserve_generated` made, this never allocates.
    pub fn gain_generated(&mut self, base: &NamespaceView, identity: &Kappa) {
        if let Ok(at) = self.content.lost.binary_search(identity) {
            self.content.lost.remove(at);
        }
        if base.holds(identity) {
            return;
        }
        if let Err(at) = self.content.gained.binary_search(identity) {
            self.content.gained.insert(at, identity.clone());
        }
    }

    /// Record the signed root in the epoch projection, within the room
    /// `reserve_generated` made.
    pub fn gain_epoch(&mut self, root: &Kappa) {
        self.epochs.gained.push(root.clone());
    }

    const fn contribution(&self) -> Contribution {
        Contribution {
            namespace: self.namespace,
            incarnation: self.incarnation,
            revision: self.revision,
        }
    }
}

/// Register the keys of `gained`, which occupy positions `*start` onward
/// of the publication's registrations, from position `*next`, each charged
/// before it is registered; advance `*start` past them.
fn register_part<K: Ord + std::hash::Hash + Clone>(
    locator: &Locator<K>,
    gained: &[K],
    contribution: Contribution,
    start: &mut usize,
    next: &mut usize,
    meter: &mut WorkMeter,
) -> Result<(), StoreError> {
    let end = start.saturating_add(gained.len());
    while *next < end {
        let Some(key) = gained.get(*next - *start) else {
            return Err(StoreError::Internal(
                "registration position precedes its projection".into(),
            ));
        };
        meter.charge(Dimension::Entries, 1)?;
        locator.register(key, contribution);
        *next += 1;
    }
    *start = end;
    Ok(())
}

fn lose<K: Ord + std::hash::Hash + Clone>(
    locator: &Locator<K>,
    delta: &Delta<K>,
    contribution: Contribution,
) {
    for key in &delta.lost {
        locator.unregister(
            key,
            contribution.namespace,
            contribution.incarnation,
            contribution.revision,
        );
    }
}

macro_rules! each_projection {
    ($apply:ident, $self:ident, $changes:ident) => {{
        let contribution = $changes.contribution();
        $apply(&$self.content, &$changes.content, contribution);
        $apply(&$self.epochs, &$changes.epochs, contribution);
        $apply(&$self.names, &$changes.names, contribution);
        $apply(
            &$self.binding_sources,
            &$changes.binding_sources,
            contribution,
        );
        $apply(
            &$self.binding_targets,
            &$changes.binding_targets,
            contribution,
        );
        $apply(&$self.assertions, &$changes.assertions, contribution);
        $apply(
            &$self.assertion_asserters,
            &$changes.assertion_asserters,
            contribution,
        );
        $apply(
            &$self.assertion_subjects,
            &$changes.assertion_subjects,
            contribution,
        );
        $apply(&$self.revocations, &$changes.revocations, contribution);
        $apply(
            &$self.revocation_asserters,
            &$changes.revocation_asserters,
            contribution,
        );
        $apply(&$self.watermarks, &$changes.watermarks, contribution);
        $apply(
            &$self.watermark_asserters,
            &$changes.watermark_asserters,
            contribution,
        );
        $apply(&$self.handles, &$changes.handles, contribution);
        $apply(
            &$self.handle_anchors,
            &$changes.handle_anchors,
            contribution,
        );
        $apply(&$self.devices, &$changes.devices, contribution);
        $apply(&$self.prekeys, &$changes.prekeys, contribution);
    }};
}

macro_rules! register_each {
    ($self:ident, $changes:ident, $next:ident, $meter:ident, [$($projection:ident),* $(,)?]) => {{
        let contribution = $changes.contribution();
        let mut start = 0;
        $(
            register_part(
                &$self.$projection,
                &$changes.$projection.gained,
                contribution,
                &mut start,
                $next,
                $meter,
            )?;
        )*
    }};
}

impl Projections {
    /// Before the store: register every key the candidate gained from
    /// position `*next` of the publication's registrations, in projection
    /// order, each charged to `meter` before it is registered. `*next` is
    /// left at the first key not registered, so a refused call keeps every
    /// registration it made and a later one registers each key once.
    pub fn register_from(
        &self,
        changes: &Changes,
        next: &mut usize,
        meter: &mut WorkMeter,
    ) -> Result<(), StoreError> {
        register_each!(
            self,
            changes,
            next,
            meter,
            [
                content,
                epochs,
                names,
                binding_sources,
                binding_targets,
                assertions,
                assertion_asserters,
                assertion_subjects,
                revocations,
                revocation_asserters,
                watermarks,
                watermark_asserters,
                handles,
                handle_anchors,
                devices,
                prekeys,
            ]
        );
        Ok(())
    }

    /// After the store, under the namespace writer: unregister every key the
    /// candidate lost.
    pub fn unregister(&self, changes: &Changes) {
        each_projection!(lose, self, changes);
    }
}

/// A projection range bound starting after `after`, or at the start.
pub fn after<K>(after: Option<&K>) -> Bound<&K> {
    after.map_or(Bound::Unbounded, Bound::Excluded)
}

#[cfg(test)]
mod tests {
    use std::ops::Bound;
    use std::sync::Arc;

    use kappa_types::capacity::CapacityPool;
    use kappa_types::work::WorkLimit;

    use super::super::segments::Segments;
    use super::super::view::{Admission, Held, Representation};
    use super::*;

    fn inline(bytes: &[u8]) -> Result<Admission, StoreError> {
        let pool = Arc::new(CapacityPool::new("test retention", 1 << 20));
        let charge = pool
            .reserve(bytes.len() as u64)
            .map_err(|error| StoreError::CapacityExceeded(error.to_string()))?;
        Ok(Admission {
            representation: Representation::Inline {
                bytes: Held::new(bytes.to_vec(), charge),
                segments: Segments::of(bytes),
            },
            size: bytes.len() as u64,
        })
    }

    /// Registration stopped by its allowance keeps the contributions it
    /// made and its position; resuming registers each remaining key once,
    /// under the publication's own contribution.
    #[test]
    fn registration_resumes_from_its_position() -> Result<(), StoreError> {
        let base = NamespaceView::default();
        let mut candidate = NamespaceView {
            revision: 1,
            ..NamespaceView::default()
        };
        let keys: Vec<Kappa> = (0u8..5).map(|seed| Kappa::sha256(&[seed])).collect();
        for key in &keys {
            candidate
                .evidence
                .insert(key.clone(), inline(key.to_string().as_bytes())?);
        }
        let changes = Changes::between([3; 16], &base, &candidate, &mut WorkMeter::unbounded())?;
        let projections = Projections::default();
        let mut next = 0;
        let mut short = WorkMeter::new(WorkLimit::unbounded().with(Dimension::Entries, 2));
        assert!(
            projections
                .register_from(&changes, &mut next, &mut short)
                .is_err()
        );
        assert_eq!(next, 2, "two registrations made and recorded");
        let registered = |key: &Kappa| {
            projections
                .content
                .observe_from(key, Bound::Unbounded, 4)
                .candidates
        };
        let made: usize = keys.iter().map(|key| registered(key).len()).sum();
        assert_eq!(made, 2);
        let mut fresh = WorkMeter::unbounded();
        projections.register_from(&changes, &mut next, &mut fresh)?;
        assert_eq!(next, keys.len());
        assert_eq!(
            fresh.used().get(Dimension::Entries),
            3,
            "only the rest is done"
        );
        for key in &keys {
            assert_eq!(
                registered(key),
                vec![Contribution {
                    namespace: [3; 16],
                    incarnation: 0,
                    revision: 1,
                }]
            );
        }
        projections.register_from(&changes, &mut next, &mut fresh)?;
        assert_eq!(
            fresh.used().get(Dimension::Entries),
            3,
            "a complete registration does nothing"
        );
        Ok(())
    }

    /// Evidence the signed root generates may restore an identity the
    /// candidate's other changes dropped: the precomputed loss is
    /// cancelled, and no gain is recorded for what the base already held.
    #[test]
    fn generated_evidence_cancels_a_precomputed_loss() -> Result<(), StoreError> {
        let identity = Kappa::sha256(b"restored");
        let mut base = NamespaceView::default();
        base.evidence.insert(identity.clone(), inline(b"restored")?);
        let candidate = NamespaceView::default();
        let mut meter = WorkMeter::unbounded();
        let mut changes = Changes::between([1; 16], &base, &candidate, &mut meter)?;
        assert_eq!(changes.content.lost, vec![identity.clone()]);
        changes.reserve_generated(1, &mut meter)?;
        changes.gain_generated(&base, &identity);
        assert!(changes.content.lost.is_empty(), "the loss is cancelled");
        assert!(
            changes.content.gained.is_empty(),
            "the base already held it"
        );

        let fresh = Kappa::sha256(b"fresh");
        changes.gain_generated(&base, &fresh);
        changes.gain_generated(&base, &fresh);
        assert_eq!(changes.content.gained, vec![fresh], "recorded once");
        Ok(())
    }

    /// An identity changed in both holdings is one membership change, and a
    /// move between them is none.
    #[test]
    fn membership_is_the_union_of_admission_and_evidence() -> Result<(), StoreError> {
        let moved = Kappa::sha256(b"moved");
        let both = Kappa::sha256(b"both");
        let mut base = NamespaceView::default();
        base.admitted.insert(moved.clone(), inline(b"moved")?);
        let mut candidate = NamespaceView::default();
        candidate.evidence.insert(moved, inline(b"moved")?);
        candidate.admitted.insert(both.clone(), inline(b"both")?);
        candidate.evidence.insert(both.clone(), inline(b"both")?);
        let changes = Changes::between([1; 16], &base, &candidate, &mut WorkMeter::unbounded())?;
        assert!(changes.content.lost.is_empty(), "a move is no loss");
        assert_eq!(changes.content.gained, vec![both]);
        Ok(())
    }
}
