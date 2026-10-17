//! Installation of prepared content under the store writer.
//!
//! Preparation (hashing, chunking, allocation, durability) happens outside
//! any writer and produces a [`PreparedContent`]: a verified identity, a
//! validated [`BlobRecord`], and, for external content, the pin that kept
//! its allocation protected since creation. Installation is the only
//! write to `BLOB_INDEX` and `ALLOCATIONS`, runs inside the transaction of
//! the epoch execution that publishes the content, and does three things:
//!
//! 1. refuses or validates: an identity with a committed row is a
//!    duplicate (reported, nothing written, the caller abandons its
//!    allocation); a composite's components must each have a committed
//!    row of the shape its level requires with the declared logical size,
//!    and none may be the composite itself;
//! 2. writes the row and, for external content, the owner marker beside
//!    the allocation (`allocation::write_owner_marker`, durable before
//!    the row can commit, so reclamation always finds the namespace whose
//!    rows decide the allocation) and the `ALLOCATIONS` entry;
//! 3. records the `ContentPublish` mutation naming a `ContentCommitment`
//!    of (identity, chunk size, chunk root), itself installed as inline
//!    content in the same transaction, so the chunk root a reader checks
//!    is authenticated by the epoch the transaction seals.
//!
//! A record the store produces while sealing (an internal install) records
//! no mutation: neither the commitment nor digest-alias evidence. The
//! sealing ledger cannot commit itself, and a mutation recorded after the
//! seal is refused by `commit_epoch_transaction`. Its identities are still
//! installed exactly as for published content, whatever its representation:
//! the holder under the lowest axis and an alias row for every other
//! verified identity, so the record resolves under the identity its caller
//! supplied and under every mandatory axis.
//!
//! Rows are encrypted, written and read through the `BLOB_INDEX` row codec
//! (`blob_rows`).

use std::collections::BTreeSet;
use std::sync::Arc;

use kappa_store::canonical::canonical_bytes;
use kappa_store::clock::ClockMs;
use kappa_store::epoch::MutationOp;
use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::verified::VerifiedContent;
use kappa_types::content::ContentAlias;
use kappa_types::{Axis, ContentCommitment};

use crate::PersistentStore;
use crate::allocation::{Owner, Pin, Protection, write_owner_marker};
use crate::blob_rows::{record_in_txn, write_row};
use crate::referrers::{Referrer, establish};
use crate::representation::{BlobRecord, Kind, Representation, RepresentationLimits};
use crate::tables::ALLOCATIONS;
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

    pub(crate) fn owned_by(mut self, owner: &Arc<Protection>) -> Self {
        self.owner = Some(Arc::clone(owner));
        self
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

/// Install `prepared` for `ns` inside `txn`, recording the `ContentPublish`
/// commitment for external content. Returns the pin for external content
/// so the caller holds it until the transaction's outcome is known: a
/// committed row protects the allocation through `ALLOCATIONS`, an aborted
/// one leaves it unprotected and reclaimable.
pub fn install_in_txn(
    store: &PersistentStore,
    txn: &redb::WriteTransaction,
    ns: &NamespaceRef,
    prepared: PreparedContent,
    now: ClockMs,
    limits: RepresentationLimits,
) -> Result<(Installed, Option<Pin>), StoreError> {
    Install {
        store,
        txn,
        ns,
        now,
        limits,
    }
    .run(prepared, Evidence::Recorded)
}

/// Install a record the store produces while sealing. No mutation is
/// recorded (see the module documentation). Such content is read in full
/// and verified against its identity; it has no range or stream path.
pub fn install_internal_in_txn(
    store: &PersistentStore,
    txn: &redb::WriteTransaction,
    ns: &NamespaceRef,
    prepared: PreparedContent,
    limits: RepresentationLimits,
) -> Result<(Installed, Option<Pin>), StoreError> {
    Install {
        store,
        txn,
        ns,
        now: ClockMs::from_raw(0),
        limits,
    }
    .run(prepared, Evidence::Withheld)
}

/// Whether an installation records its evidence in the ledger.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Evidence {
    /// Commitment and alias mutations are recorded for the epoch to seal.
    Recorded,
    /// The installation runs inside the seal: no mutation may be recorded.
    Withheld,
}

/// One installation's transaction context.
struct Install<'a> {
    store: &'a PersistentStore,
    txn: &'a redb::WriteTransaction,
    ns: &'a NamespaceRef,
    now: ClockMs,
    limits: RepresentationLimits,
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

    fn run(
        &self,
        prepared: PreparedContent,
        evidence: Evidence,
    ) -> Result<(Installed, Option<Pin>), StoreError> {
        let PreparedContent {
            identity,
            record,
            pin,
            aliases,
            owner,
        } = prepared;
        if !owner
            .as_ref()
            .is_some_and(|owner| Arc::ptr_eq(owner, &self.store.protection))
        {
            return Err(StoreError::Rejected(
                "prepared content belongs to another store".into(),
            ));
        }
        // Canonical correspondence: among the verified identities of these
        // bytes, the representation is held by the one under the lowest
        // axis discriminant and every other identity aliases it, whichever
        // axis the request named. Equivalent ingestions under different
        // primary axes therefore converge on one alias topology, and replay
        // never meets two contradictory bindings for the same bytes.
        let (identity, aliases) = canonical_order(identity, aliases);
        let installed = if record_in_txn(self.store, self.txn, &identity)?.is_some() {
            Installed::Existing
        } else {
            self.validate(&identity, &record, pin.is_some())?;
            self.write(&identity, &record)?;
            // Every identity a representation assembles from is retained
            // by it.
            for child in referenced(&record) {
                establish(
                    self.store,
                    self.txn,
                    &child,
                    &Referrer::representation(&identity),
                )?;
            }
            self.install_external(&identity, &record, evidence)?;
            Installed::New
        };
        self.install_aliases(&identity, record.total_size(), &aliases, evidence)?;
        Ok((installed, pin))
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

    /// For external content: the owner marker, the `ALLOCATIONS` entry
    /// and, when evidence is recorded, the `ContentPublish` commitment.
    /// Other representations own no allocation and commit no chunk root.
    fn install_external(
        &self,
        identity: &Kappa,
        record: &BlobRecord,
        evidence: Evidence,
    ) -> Result<(), StoreError> {
        let Representation::External {
            allocation,
            chunk_size,
            chunk_root,
            ..
        } = record.representation()
        else {
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
        let mut allocations = self
            .txn
            .open_table(ALLOCATIONS)
            .map_err(crate::error::redb)?;
        let previous = allocations
            .insert(allocation.0.as_slice(), identity.key_bytes().as_slice())
            .map_err(crate::error::redb)?
            .is_some();
        drop(allocations);
        if previous {
            // A fresh allocation is owned by no committed row: an entry here
            // is a projection that diverged from `BLOB_INDEX`.
            return Err(self.store.index_diverged(
                "ALLOCATIONS",
                format!("allocation {} is already owned", allocation.hex()),
            ));
        }
        if evidence == Evidence::Withheld {
            return Ok(());
        }
        let commitment = ContentCommitment::new(identity.clone(), *chunk_size, *chunk_root)?;
        self.record_evidence(MutationOp::ContentPublish, canonical_bytes(&commitment))
    }

    /// Install `aliases` as the same verified bytes as `target` under the
    /// store's other mandatory axes: one hop to the target's row, no
    /// composition. This is the only path that writes alias rows, so the
    /// new and the already-installed content paths index them identically:
    /// a new alias row establishes its representation referrer on `target`,
    /// and an existing row is accepted only when it already selects the
    /// same bytes. Callers pass identities in canonical order
    /// (`canonical_order`), so an alias never names a holder under a higher
    /// axis than its own. The `ContentAlias` evidence of each alias is
    /// recorded only when `evidence` is recorded; the rows are installed
    /// either way.
    fn install_aliases(
        &self,
        target: &Kappa,
        length: u64,
        aliases: &[Kappa],
        evidence: Evidence,
    ) -> Result<(), StoreError> {
        for alias in aliases.iter().filter(|alias| *alias != target) {
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
            } else {
                let record = BlobRecord::alias(target.clone(), length, self.limits)?;
                self.write(alias, &record)?;
                establish(
                    self.store,
                    self.txn,
                    target,
                    &Referrer::representation(alias),
                )?;
            }
            if evidence == Evidence::Recorded {
                let binding = ContentAlias::new(alias.clone(), target.clone(), length)?;
                self.record_evidence(MutationOp::ContentAlias, canonical_bytes(&binding))?;
            }
        }
        Ok(())
    }

    /// Install evidence `bytes` as inline content (once per identity) and
    /// record `op` naming it in the epoch the transaction seals.
    fn record_evidence(&self, op: MutationOp, bytes: Vec<u8>) -> Result<(), StoreError> {
        let evidence = VerifiedContent::compute(Axis::Sha256, &bytes)?;
        if record_in_txn(self.store, self.txn, evidence.kappa())?.is_none() {
            let record = BlobRecord::inline(bytes, None, self.limits)?;
            self.write(evidence.kappa(), &record)?;
        }
        self.store.record_mutation_in_txn(
            self.txn,
            self.ns,
            op,
            evidence.kappa().clone(),
            self.now,
            None,
        )
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
