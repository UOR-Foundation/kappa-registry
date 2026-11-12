//! Installation of prepared content under the store writer: the native
//! row mechanics every admission and every store-produced record uses.
//!
//! Preparation (hashing, chunking, allocation, durability) happens outside
//! any writer and produces a [`PreparedContent`]: a verified identity, a
//! validated [`BlobRecord`], and, for external content, the pin that kept
//! its allocation protected since creation. Installation is the only
//! write to `BLOB_INDEX` and `ALLOCATIONS` and runs inside the transaction
//! of the epoch execution that publishes the content. It refuses or
//! validates (a composite's components must each have a committed row of
//! the shape its level requires with the declared logical size, and none
//! may be the composite itself), writes the row, and for external content
//! writes the owner marker beside the allocation
//! (`allocation::write_owner_marker`, durable before the row can commit, so
//! reclamation always finds the namespace whose rows decide the
//! allocation) and the `ALLOCATIONS` entry.
//!
//! Logical admission is a transition (`content_admit`): its evidence is
//! the canonical `ContentAdmissionRecord`, recorded through the transition
//! boundary, which calls into these mechanics for the row. A record the
//! store produces (transition evidence, the ledger, roots and state
//! records the seal writes) is installed without admission
//! ([`install_internal_in_txn`]): the identities are installed exactly as
//! for published content, the holder under the lowest axis and an alias
//! row for every other verified identity, so the record resolves under the
//! identity its caller supplied and under every mandatory axis.
//!
//! Rows are encrypted, written and read through the `BLOB_INDEX` row codec
//! (`blob_rows`).

use std::collections::BTreeSet;
use std::sync::Arc;

use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;

use crate::PersistentStore;
use crate::allocation::{Owner, Pin, Protection, write_owner_marker};
use crate::blob_rows::{record_in_txn, write_row};
use crate::derived_index::claim_allocation;
use crate::referrers::{Referrer, establish};
use crate::representation::{BlobRecord, Kind, Representation, RepresentationLimits};
use crate::unsettled_index::DiscoveryKey;

/// Content ready to install: its verified identity, its record, and the
/// allocation protection the preparation holds.
pub struct PreparedContent {
    identity: Kappa,
    record: BlobRecord,
    pin: Option<Pin>,
    aliases: Vec<Kappa>,
    owner: Option<Arc<Protection>>,
}

impl PreparedContent {
    /// Inline or composite content, which owns no allocation.
    pub(crate) fn unallocated(identity: Kappa, record: BlobRecord) -> Result<Self, StoreError> {
        if matches!(record.representation(), Representation::External { .. }) {
            return Err(StoreError::Internal(
                "external content prepared without its allocation pin".into(),
            ));
        }
        Ok(Self {
            identity,
            record,
            pin: None,
            aliases: Vec::new(),
            owner: None,
        })
    }

    /// External content whose allocation `pin` protected since creation.
    /// The pin must name the record's allocation.
    pub(crate) fn allocated(
        identity: Kappa,
        record: BlobRecord,
        pin: Pin,
    ) -> Result<Self, StoreError> {
        match record.representation() {
            Representation::External { allocation, .. } if allocation == pin.allocation() => {
                Ok(Self {
                    identity,
                    record,
                    pin: Some(pin),
                    aliases: Vec::new(),
                    owner: None,
                })
            }
            Representation::External { .. } => Err(StoreError::Internal(
                "allocation pin names a different allocation than the record".into(),
            )),
            Representation::Inline { .. }
            | Representation::Alias { .. }
            | Representation::Manifest { .. }
            | Representation::Composite { .. } => Err(StoreError::Internal(
                "allocation pin supplied for unallocated content".into(),
            )),
        }
    }

    pub const fn identity(&self) -> &Kappa {
        &self.identity
    }

    pub(crate) const fn record(&self) -> &BlobRecord {
        &self.record
    }

    pub(crate) fn with_aliases(mut self, aliases: Vec<Kappa>) -> Self {
        self.aliases = aliases;
        self
    }

    pub fn aliases(&self) -> &[Kappa] {
        &self.aliases
    }

    /// The physical bytes the preparation measured for its allocation, the
    /// amount the unsettled budget charges; zero for unallocated content.
    pub(crate) fn allocated_bytes(&self) -> u64 {
        self.pin.as_ref().map_or(0, Pin::bytes)
    }

    pub(crate) fn owned_by(mut self, owner: &Arc<Protection>) -> Self {
        self.owner = Some(Arc::clone(owner));
        self
    }

    /// The identity, record, allocation pin and aliases, for the admission
    /// that installs them (`content_admit`).
    pub(crate) fn into_parts(self) -> (Kappa, BlobRecord, Option<Pin>, Vec<Kappa>) {
        (self.identity, self.record, self.pin, self.aliases)
    }

    /// Whether `store` prepared this content: only its own protection can
    /// install it.
    pub(crate) fn owned_by_store(&self, store: &PersistentStore) -> bool {
        self.owner
            .as_ref()
            .is_some_and(|owner| Arc::ptr_eq(owner, &store.protection))
    }
}

impl kappa_store::PreparedContent for PreparedContent {
    fn identity(&self) -> &Kappa {
        // Method-call syntax selects the inherent accessor over this trait.
        let inherent: &Self = self;
        inherent.identity()
    }
    fn aliases(&self) -> &[Kappa] {
        let inherent: &Self = self;
        inherent.aliases()
    }
    fn total_size(&self) -> u64 {
        self.record().total_size()
    }
    fn etag(&self) -> Option<&str> {
        None
    }
    fn as_any(self: Box<Self>) -> Box<dyn std::any::Any + Send> {
        self
    }
}

/// Outcome of one installation.
#[derive(Debug, PartialEq, Eq)]
pub enum Installed {
    /// The row was written in this transaction.
    New,
    /// A committed row already selects a representation for the identity;
    /// nothing was written. The caller's allocation, if any, has no
    /// `ALLOCATIONS` entry and becomes reclaimable when its pin drops.
    Existing,
}

/// Install a record the store produces, without admission (see the module
/// documentation). Such content is read in full and verified against its
/// identity; it has no range or stream path.
pub fn install_internal_in_txn(
    store: &PersistentStore,
    txn: &redb::WriteTransaction,
    ns: &NamespaceRef,
    prepared: PreparedContent,
    limits: RepresentationLimits,
) -> Result<(Installed, Option<Pin>), StoreError> {
    if !prepared.owned_by_store(store) {
        return Err(StoreError::Rejected(
            "prepared content belongs to another store".into(),
        ));
    }
    let install = Install {
        store,
        txn,
        ns,
        limits,
    };
    let PreparedContent {
        identity,
        record,
        pin,
        aliases,
        ..
    } = prepared;
    let (holder, aliases) = canonical_order(identity, aliases);
    let installed = if record_in_txn(store, txn, &holder)?.is_some() {
        Installed::Existing
    } else {
        install.row(&holder, &record, pin.is_some())?;
        Installed::New
    };
    for alias in &aliases {
        install.alias_row(&holder, record.total_size(), alias)?;
    }
    Ok((installed, pin))
}

/// One installation's transaction context.
pub(crate) struct Install<'a> {
    pub(crate) store: &'a PersistentStore,
    pub(crate) txn: &'a redb::WriteTransaction,
    pub(crate) ns: &'a NamespaceRef,
    pub(crate) limits: RepresentationLimits,
}

impl Install<'_> {
    /// Write the row of `identity` and record it on the namespace's
    /// controller: the publication registers every identity its
    /// transaction wrote a row for in the unsettled identity index before
    /// it commits, so the identity is discoverable from that commit on.
    fn write(&self, identity: &Kappa, record: &BlobRecord) -> Result<(), StoreError> {
        write_row(self.store, self.txn, identity, record)?;
        self.store
            .controller(self.ns)?
            .installed_rows
            .lock()
            .map_err(|_| StoreError::Internal("installed row set poisoned".into()))?
            .push(DiscoveryKey::Content(identity.clone()));
        Ok(())
    }

    /// Validate and write the new row of `identity`, establish the
    /// references it assembles from, and for external content its owner
    /// marker and allocation ownership.
    pub(crate) fn row(
        &self,
        identity: &Kappa,
        record: &BlobRecord,
        pinned: bool,
    ) -> Result<(), StoreError> {
        self.validate(identity, record, pinned)?;
        self.write(identity, record)?;
        for child in referenced(record) {
            establish(
                self.store,
                self.txn,
                self.ns,
                &child,
                &Referrer::representation(identity),
            )?;
        }
        self.install_external(identity, record)
    }

    /// Refuse a record whose representation cannot be installed: external
    /// content without its pin, an alias of itself or of a target of
    /// another shape or length, and a composite or manifest whose
    /// components are absent, itself, at the wrong level, or of another
    /// committed length.
    fn validate(
        &self,
        identity: &Kappa,
        record: &BlobRecord,
        pinned: bool,
    ) -> Result<(), StoreError> {
        match record.representation() {
            Representation::Inline { .. } => Ok(()),
            Representation::External { .. } => {
                if pinned {
                    Ok(())
                } else {
                    Err(StoreError::Internal(
                        "external content reached installation without its pin".into(),
                    ))
                }
            }
            Representation::Alias { target } => {
                if target == identity {
                    return Err(StoreError::Rejected("content alias names itself".into()));
                }
                let selected = record_in_txn(self.store, self.txn, target)?.ok_or_else(|| {
                    StoreError::NotFound(format!("alias target {target} has no representation"))
                })?;
                if matches!(selected.kind(), Kind::Alias | Kind::Manifest)
                    || selected.total_size() != record.total_size()
                {
                    return Err(StoreError::Rejected(
                        "alias target has incompatible shape or logical length".into(),
                    ));
                }
                Ok(())
            }
            Representation::Composite { components, .. }
            | Representation::Manifest { components, .. } => {
                if matches!(record.kind(), Kind::Manifest)
                    && record.manifest_identity()? != *identity
                {
                    return Err(StoreError::Rejected(
                        "manifest identity does not name its canonical descriptor".into(),
                    ));
                }
                let leaf_children = !matches!(
                    record.kind(),
                    Kind::Composite {
                        leaf_children: false
                    }
                );
                for component in components {
                    if component.identity == *identity {
                        return Err(StoreError::Rejected(
                            "composite names itself as a component".into(),
                        ));
                    }
                    let committed = record_in_txn(self.store, self.txn, &component.identity)?
                        .ok_or_else(|| {
                            StoreError::NotFound(format!(
                                "composite component {} has no committed representation",
                                component.identity
                            ))
                        })?;
                    if !self.component_level_holds(&committed, leaf_children, component.length)? {
                        return Err(StoreError::Rejected(format!(
                            "composite component {} has the wrong level for this composite",
                            component.identity
                        )));
                    }
                    if committed.total_size() != component.length {
                        return Err(StoreError::Rejected(format!(
                            "composite declares {} bytes for component {} whose committed size is {}",
                            component.length,
                            component.identity,
                            committed.total_size()
                        )));
                    }
                }
                Ok(())
            }
        }
    }

    /// Whether `committed` sits at the level a component of a composite
    /// with `leaf_children` requires: leaf content under a leaf composite
    /// (an alias counts when its target is leaf content of `length`
    /// bytes), a manifest node under a composite of manifests, and never a
    /// composite.
    fn component_level_holds(
        &self,
        committed: &BlobRecord,
        leaf_children: bool,
        length: u64,
    ) -> Result<bool, StoreError> {
        Ok(match committed.representation() {
            Representation::Inline { .. } | Representation::External { .. } => leaf_children,
            Representation::Manifest { .. } => !leaf_children,
            Representation::Composite { .. } => false,
            Representation::Alias { target } => {
                let target = record_in_txn(self.store, self.txn, target)?.ok_or_else(|| {
                    StoreError::NotFound("manifest alias target is absent".into())
                })?;
                leaf_children && target.kind() == Kind::Leaf && target.total_size() == length
            }
        })
    }

    /// For external content: the owner marker and the `ALLOCATIONS` entry.
    /// Other representations own no allocation.
    fn install_external(&self, identity: &Kappa, record: &BlobRecord) -> Result<(), StoreError> {
        let Representation::External { allocation, .. } = record.representation() else {
            return Ok(());
        };
        // The marker is written while the preparation's pin still protects
        // the allocation, so no reclaimer can be deciding it; if this
        // transaction aborts the marker names a namespace whose rows do
        // not select the allocation, which is exactly the reclaimable case.
        write_owner_marker(
            &self.store.blob_root,
            allocation,
            &Owner {
                instance: self.store.controller(self.ns)?.instance,
                identity: identity.clone(),
            },
            self.store.fsync,
        )?;
        // A fresh allocation is owned by no committed row: an existing entry
        // is a projection that diverged from `BLOB_INDEX`, refused there.
        claim_allocation(self.store, self.txn, self.ns, allocation, identity)
    }

    /// Install `alias` as the same verified bytes as `target` under another
    /// mandatory axis: one hop to the target's row, no composition. This is
    /// the only path that writes alias rows, so admitted and store-produced
    /// content index them identically: a new alias row establishes its
    /// representation referrer on `target`, and an existing row is accepted
    /// only when it already selects the same bytes. Callers pass identities
    /// in canonical order (`canonical_order`), so an alias never names a
    /// holder under a higher axis than its own. Returns whether the row is
    /// new.
    pub(crate) fn alias_row(
        &self,
        target: &Kappa,
        length: u64,
        alias: &Kappa,
    ) -> Result<bool, StoreError> {
        if alias == target {
            return Ok(false);
        }
        if alias.axis().discriminant() < target.axis().discriminant() {
            return Err(StoreError::Internal(format!(
                "alias {alias} would name a holder under a higher axis"
            )));
        }
        if let Some(existing) = record_in_txn(self.store, self.txn, alias)? {
            if existing.total_size() != length {
                return Err(StoreError::Conflict("digest alias length differs".into()));
            }
            if let Representation::Alias { target: selected } = existing.representation()
                && selected != target
            {
                return Err(StoreError::Conflict(format!(
                    "digest alias {alias} already names {selected}, not {target}"
                )));
            }
            return Ok(false);
        }
        let record = BlobRecord::alias(target.clone(), length, self.limits)?;
        self.write(alias, &record)?;
        establish(
            self.store,
            self.txn,
            self.ns,
            target,
            &Referrer::representation(alias),
        )?;
        Ok(true)
    }
}

/// Order verified identities of the same bytes canonically: the holder
/// is the identity with the lowest axis discriminant; the rest alias it.
/// Identities under one axis are the same identity, so ties are equal.
pub fn canonical_order(identity: Kappa, aliases: Vec<Kappa>) -> (Kappa, Vec<Kappa>) {
    let mut all: Vec<Kappa> = std::iter::once(identity).chain(aliases).collect();
    all.sort_by_key(|k| k.axis().discriminant());
    all.dedup();
    let holder = all.remove(0);
    (holder, all)
}

/// Identities whose rows a representation references, each once however
/// often the representation lists it (a composite of two equal parts
/// refers to that part once). The installer establishes, retirement
/// releases, and the referrer rebuild re-derives exactly these, so one
/// referrer entry exists per (identity, representation) pair.
pub fn referenced(record: &BlobRecord) -> Vec<Kappa> {
    match record.representation() {
        Representation::Alias { target } => vec![target.clone()],
        Representation::Composite { components, .. }
        | Representation::Manifest { components, .. } => components
            .iter()
            .map(|c| c.identity.clone())
            .collect::<BTreeSet<Kappa>>()
            .into_iter()
            .collect(),
        Representation::Inline { .. } | Representation::External { .. } => Vec::new(),
    }
}
