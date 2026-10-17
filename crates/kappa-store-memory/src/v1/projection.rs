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
//! - [`Projections::register`] inserts each gained key after every check
//!   that can refuse the publication has passed, immediately before the
//!   view store, which cannot fail; a registration therefore always
//!   becomes the published view's, and an attempt that is refused has
//!   registered nothing;
//! - after the view store, still under the namespace writer,
//!   [`Projections::unregister`] removes each lost key.
//!
//! Registration and removal take only the locators' shard locks and
//! cannot fail; they report nothing an operation could fail on.

use std::ops::Bound;

use imbl::OrdMap;
use imbl::ordmap::DiffItem;
use kappa_types::kappa::Kappa;

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

fn delta<K: Ord + Clone, V: PartialEq>(base: &OrdMap<K, V>, candidate: &OrdMap<K, V>) -> Delta<K> {
    let mut out = Delta::default();
    for item in base.diff(candidate) {
        match item {
            DiffItem::Add(key, _) => out.gained.push(key.clone()),
            DiffItem::Remove(key, _) => out.lost.push(key.clone()),
            DiffItem::Update { .. } => {}
        }
    }
    out
}

fn epoch_roots(base: &OrdMap<u64, Kappa>, candidate: &OrdMap<u64, Kappa>) -> Delta<Kappa> {
    let mut out = Delta::default();
    for item in base.diff(candidate) {
        match item {
            DiffItem::Add(_, root) => out.gained.push(root.clone()),
            DiffItem::Remove(_, root) => out.lost.push(root.clone()),
            DiffItem::Update {
                old: (_, before),
                new: (_, after),
            } => {
                out.lost.push(before.clone());
                out.gained.push(after.clone());
            }
        }
    }
    out
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
    /// The changes `candidate` makes to `base` of `namespace`.
    pub fn between(
        namespace: NamespaceId,
        base: &NamespaceView,
        candidate: &NamespaceView,
    ) -> Self {
        let name = |view: &NamespaceView| view.record.as_ref().map(|record| record.name.clone());
        let mut names = Delta::default();
        let (before, after) = (name(base), name(candidate));
        if before != after {
            names.lost.extend(before);
            names.gained.extend(after);
        }
        let (b, c) = (&base.identity, &candidate.identity);
        Self {
            namespace,
            incarnation: candidate.incarnation,
            revision: candidate.revision,
            content: delta(&base.admitted, &candidate.admitted),
            epochs: epoch_roots(&base.epochs, &candidate.epochs),
            names,
            binding_sources: delta(&b.bindings, &c.bindings),
            binding_targets: delta(&b.binding_targets, &c.binding_targets),
            assertions: delta(&b.assertions, &c.assertions),
            assertion_asserters: delta(&b.assertion_asserters, &c.assertion_asserters),
            assertion_subjects: delta(&b.assertion_subjects, &c.assertion_subjects),
            revocations: delta(&b.revocations, &c.revocations),
            revocation_asserters: delta(&b.revocation_asserters, &c.revocation_asserters),
            watermarks: delta(&b.watermarks, &c.watermarks),
            watermark_asserters: delta(&b.watermark_asserters, &c.watermark_asserters),
            handles: delta(&b.handles, &c.handles),
            handle_anchors: delta(&b.handle_anchors, &c.handle_anchors),
            devices: delta(&b.devices, &c.devices),
            prekeys: delta(&b.prekeys, &c.prekeys),
        }
    }

    const fn contribution(&self) -> Contribution {
        Contribution {
            namespace: self.namespace,
            incarnation: self.incarnation,
            revision: self.revision,
        }
    }
}

fn gain<K: Ord + std::hash::Hash + Clone>(
    locator: &Locator<K>,
    delta: &Delta<K>,
    contribution: Contribution,
) {
    for key in &delta.gained {
        locator.register(key, contribution);
    }
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

impl Projections {
    /// Immediately before the store: register every key the candidate
    /// gained.
    pub fn register(&self, changes: &Changes) {
        each_projection!(gain, self, changes);
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
