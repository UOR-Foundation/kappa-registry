//! Retirement of committed representations and reclamation of the
//! allocations no namespace owns.
//!
//! Retirement removes a row inside the epoch execution that publishes the
//! retirement, so it commits with its epoch. Physical reclamation is
//! decided per allocation, under its deletion claim, by durable evidence
//! scoped to the one namespace that could own it:
//!
//! 1. the claim excludes every pin, so no preparation holds the
//!    allocation, no execution is installing it, and no committed epoch
//!    is still parked on it (pins are parked until the epoch settles, or
//!    held in `unresolved_content` while a commit outcome is unknown);
//! 2. the registry's completed projection (`projection::Family::
//!    AllocationOwner`) naming an owner is sufficient to keep the
//!    allocation, never sufficient to delete it;
//! 3. the owner marker the installer wrote beside the payload
//!    (`allocation::Owner`) names the storage instance whose committed rows
//!    decide: no marker means no installation ever started (a preparation
//!    that was dropped); an installer that holds custody of a retained
//!    publication (`custody`) protects every allocation it installed, since
//!    resolution installs them again, and so does custody that cannot be
//!    inspected; otherwise the installing instance's storage is classified
//!    once (`namespace_snapshot::admit_instance`): storage gone or replaced
//!    by another instance releases the allocation only when the instance's
//!    retirement record is verified to release what it held
//!    (`release_verified`), and protects it otherwise; an instance that is
//!    fenced (unknown commit outcome) or whose storage cannot be read
//!    protects the allocation; otherwise its `BLOB_INDEX` row at the
//!    identity the marker names decides: an External row selecting this
//!    allocation owns it, settled or not, and its absence (the installing
//!    transaction aborted, or the row was retired and the retirement
//!    committed) releases it only from storage exactly identified as the
//!    installer's (`Identification::permits_destruction`). Storage of an
//!    unknown (legacy) instance cannot be proven to be the installer's: its
//!    row keeps the allocation, and nothing about it releases one.
//!
//! No decision waits on another namespace's settlement, so sustained
//! publication anywhere never stops reclamation elsewhere, and absence is
//! never concluded from a lagging index or from unreadable evidence. The
//! bounded inventory that reaches every allocation is `content_inventory`.

use redb::{ReadableMultimapTable, ReadableTable};

use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::transition::RecordTransition;
use kappa_store::work::Meter;
use kappa_types::content::{ContentAdmission, ContentRetirementRecord};

use crate::PersistentStore;
use crate::allocation::{Owner, read_owner_marker};
use crate::blob_rows::{decode_row, record_in_txn};
use crate::content_install::referenced;
use crate::derived_index::{Generation, release_allocation};
use crate::namespace_snapshot::InstanceAdmission;
use crate::projection::Family;
use crate::referrers::{Referrer, Source as ReferrerSource, release};
use crate::representation::{AllocationId, Representation};
use crate::retirement_record::RetirementRecord;
use crate::tables::{BLOB_INDEX, BLOB_META};
use crate::transition_apply::{RedbPayload, TxnWriter};

/// Outcome of [`retire_in_txn`].
#[derive(Debug, PartialEq, Eq)]
pub enum Retired {
    /// The row is gone; the allocation, for external content, is released
    /// from this namespace's ownership when the epoch settles.
    Row(Option<AllocationId>),
    /// A committed referrer still names the identity; nothing was written.
    Retained,
    /// No row exists; nothing was written.
    Absent,
}

/// The digest family of `identity`: its holder (the identity itself unless
/// its row is an alias) followed by every alias row of the holder, found
/// through the holder's representation referrers in `generation`. `None`
/// when the namespace has no row for `identity`.
fn family(
    store: &PersistentStore,
    txn: &redb::WriteTransaction,
    generation: Generation,
    identity: &Kappa,
) -> Result<Option<Vec<Kappa>>, StoreError> {
    let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
    let row = |kappa: &Kappa| -> Result<Option<crate::representation::BlobRecord>, StoreError> {
        let key = kappa.key_bytes();
        index
            .get(key.as_slice())
            .map_err(crate::error::redb)?
            .map(|guard| decode_row(store, &key, guard.value()))
            .transpose()
    };
    let Some(record) = row(identity)? else {
        return Ok(None);
    };
    let holder = match record.representation() {
        Representation::Alias { target } => target.clone(),
        _ => identity.clone(),
    };
    let referrers = txn
        .open_multimap_table(generation.referrers())
        .map_err(crate::error::redb)?;
    let mut members = vec![holder.clone()];
    for entry in referrers
        .get(holder.key_bytes().as_slice())
        .map_err(crate::error::redb)?
    {
        let referrer = Referrer::decode(entry.map_err(crate::error::redb)?.value())?;
        if let ReferrerSource::Representation { owner } = referrer.source()
            && row(owner)?.is_some_and(|row| matches!(row.representation(), Representation::Alias { target } if *target == holder))
        {
            members.push(owner.clone());
        }
    }
    Ok(Some(members))
}

/// The blob metadata keys `identity` holds in `txn`.
fn meta_keys(txn: &redb::WriteTransaction, identity: &Kappa) -> Result<Vec<String>, StoreError> {
    let mut prefix = identity.key_bytes();
    prefix.push(b':');
    let table = txn.open_table(BLOB_META).map_err(crate::error::redb)?;
    let end = PersistentStore::prefix_successor(&prefix);
    let range = match &end {
        Some(end) => table.range(prefix.as_slice()..end.as_slice()),
        None => table.range(prefix.as_slice()..),
    }
    .map_err(crate::error::redb)?;
    let mut keys = Vec::new();
    for entry in range {
        let (key, _) = entry.map_err(crate::error::redb)?;
        let suffix = &key.value()[prefix.len()..];
        keys.push(
            std::str::from_utf8(suffix)
                .map_err(|error| StoreError::Internal(format!("blob metadata key: {error}")))?
                .to_owned(),
        );
    }
    Ok(keys)
}

/// Retire `identity` and the other identities of the same bytes inside the
/// namespace's transaction `writer` writes, unless a committed reference
/// names one of them: any referrer but an alias of the family itself
/// retains the whole family. The referrer check and the removals run in
/// the same write transaction, so no reference committed by another writer
/// of this namespace can fall between them. Every member, aliases before
/// the holder, first has its blob metadata removed by its own transitions,
/// then its admission retired by a `ContentRetire` naming the exact
/// admission; the holder releases the namespace's claim on its allocation.
/// Refused (`Unavailable`) while the namespace's indexes are known
/// divergent: an absent referrer there does not establish that nothing
/// refers to the identity.
pub fn retire_in_txn(writer: &TxnWriter<'_>, identity: &Kappa) -> Result<Retired, StoreError> {
    let (store, txn, ns) = (writer.store, writer.txn, writer.ns);
    let generation = store.trusted_generation(txn, ns)?;
    let Some(members) = family(store, txn, generation, identity)? else {
        return Ok(Retired::Absent);
    };
    {
        let referrers = txn
            .open_multimap_table(generation.referrers())
            .map_err(crate::error::redb)?;
        for member in &members {
            for entry in referrers
                .get(member.key_bytes().as_slice())
                .map_err(crate::error::redb)?
            {
                let referrer = Referrer::decode(entry.map_err(crate::error::redb)?.value())?;
                let within = matches!(referrer.source(), ReferrerSource::Representation { owner } if members.contains(owner));
                if !within {
                    return Ok(Retired::Retained);
                }
            }
        }
    }
    let mut outcome = Retired::Absent;
    for member in members.iter().rev() {
        let Some(record) = record_in_txn(store, txn, member)? else {
            continue;
        };
        for key in meta_keys(txn, member)? {
            writer.admit_blob_meta(member, &key, None)?;
        }
        let retirement = ContentRetirementRecord::new(ContentAdmission::new(
            *ns.id(),
            *writer.incarnation(),
            member.clone(),
            record.total_size(),
        ));
        writer.apply(
            RecordTransition::ContentRetire(retirement),
            RedbPayload::NoResources,
        )?;
        outcome = Retired::Row(match record.representation() {
            Representation::External { allocation, .. } => Some(*allocation),
            _ => None,
        });
    }
    Ok(outcome)
}

impl TxnWriter<'_> {
    /// Remove exactly the admission `record` names: its row, the references
    /// its representation held and, for external content, the namespace's
    /// claim on the allocation. No other admission may still select it, and
    /// its blob metadata must already be removed by its own transitions.
    pub(crate) fn apply_retirement(
        &self,
        record: &ContentRetirementRecord,
    ) -> Result<(), StoreError> {
        let (store, txn, ns) = (self.store, self.txn, self.ns);
        let removed = record.removed();
        let identity = removed.identity();
        if !meta_keys(txn, identity)?.is_empty() {
            return Err(StoreError::Internal(format!(
                "retirement of {identity} before its blob metadata was removed"
            )));
        }
        let key = identity.key_bytes();
        let row = txn
            .open_table(BLOB_INDEX)
            .map_err(crate::error::redb)?
            .remove(key.as_slice())
            .map_err(crate::error::redb)?
            .map(|guard| decode_row(store, &key, guard.value()))
            .transpose()?
            .ok_or_else(|| {
                StoreError::Internal(format!(
                    "retirement of {identity}, which the namespace does not admit"
                ))
            })?;
        if row.total_size() != removed.logical_size() {
            return Err(StoreError::Internal(format!(
                "retirement of {identity} names {} bytes; the admission holds {}",
                removed.logical_size(),
                row.total_size()
            )));
        }
        for child in referenced(&row) {
            release(store, txn, ns, &child, &Referrer::representation(identity))?;
        }
        if let Representation::External { allocation, .. } = row.representation() {
            release_allocation(store, txn, ns, allocation, identity)?;
        }
        Ok(())
    }
}

/// Outcome of one allocation's reclamation.
#[derive(Debug, PartialEq, Eq)]
pub enum Reclaimed {
    /// The files were deleted; the bytes they held.
    Deleted(u64),
    /// A committed row of its installing namespace, or the settled
    /// projection, owns it.
    Owned,
    /// A reader or preparation pin, another claim, an unknown commit
    /// outcome of its installer, or evidence that could not be read
    /// protects it.
    Protected,
    /// Nothing is on disk for it: already reclaimed.
    Absent,
}

/// What the installing namespace's committed rows say about an allocation.
enum OwnerVerdict {
    Owned,
    Released,
    Protected,
}

impl PersistentStore {
    /// Whether the completed projection names an owner of `allocation`,
    /// every owner examined on `work`: a refusal decides nothing, so it is
    /// never taken for "no owner".
    fn allocation_owned(
        &self,
        allocation: &AllocationId,
        work: &mut dyn Meter,
    ) -> Result<bool, StoreError> {
        Ok(!self
            .projection()?
            .members(Family::AllocationOwner, allocation.0.as_slice(), work)?
            .is_empty())
    }

    /// Whether the installing instance's retirement `record`, verified,
    /// releases what the instance held. Anything short of that protects
    /// the allocation: release is destructive.
    fn owner_retired(
        &self,
        allocation: &AllocationId,
        owner: &Owner,
        record: &RetirementRecord,
    ) -> OwnerVerdict {
        match self.release_verified(&owner.instance, record) {
            Ok(true) => OwnerVerdict::Released,
            Ok(false) => {
                tracing::warn!(
                    allocation = %allocation.hex(),
                    instance = %owner.instance,
                    "owner storage is gone but its retirement record does not verify a release; allocation protected"
                );
                OwnerVerdict::Protected
            }
            Err(error) => {
                tracing::warn!(
                    allocation = %allocation.hex(),
                    instance = %owner.instance,
                    %error,
                    "owner retirement evidence unreadable; allocation protected"
                );
                OwnerVerdict::Protected
            }
        }
    }

    /// What the storage instance the owner marker names says about
    /// `allocation` now, read from that instance's own committed state.
    /// Evidence that cannot be read, and evidence of another instance,
    /// protect the allocation; neither is ever absence.
    fn owner_verdict(
        &self,
        allocation: &AllocationId,
        owner: &Owner,
        work: &mut dyn Meter,
    ) -> OwnerVerdict {
        let (snapshot, identification) = match self.admit_instance(&owner.instance) {
            InstanceAdmission::Held {
                snapshot,
                identification,
            } => (snapshot, identification),
            InstanceAdmission::Released(record) => {
                return self.owner_retired(allocation, owner, &record);
            }
            // The owner's storage was not examined: never absence. The
            // inventory decides the allocation on a later pass.
            InstanceAdmission::CapacityDeferred { .. } => return OwnerVerdict::Protected,
            // Missing or replaced storage without a recorded retirement is
            // unexplained absence, and unreadable evidence is unavailable:
            // both protect the allocation.
            InstanceAdmission::Unexplained(error) | InstanceAdmission::Unreadable(error) => {
                tracing::warn!(
                    allocation = %allocation.hex(),
                    instance = %owner.instance,
                    %error,
                    "owner storage unavailable; allocation protected"
                );
                return OwnerVerdict::Protected;
            }
        };
        if snapshot.controller().fenced() {
            // A commit whose outcome this node has not learned may have
            // installed the row; the fence is lifted by settlement.
            return OwnerVerdict::Protected;
        }
        let decided = (|| -> Result<OwnerVerdict, StoreError> {
            // Ownership is decided only from indexes not known divergent;
            // a fenced namespace's allocations stay protected until its
            // repair completes.
            let generation = match self.trusted_snapshot_generation(&snapshot) {
                Ok(generation) => generation,
                Err(StoreError::Unavailable(_)) => return Ok(OwnerVerdict::Protected),
                Err(error) => return Err(error),
            };
            let index = snapshot.table(BLOB_INDEX)?;
            let selected = match snapshot
                .view()
                .record_from_table(&index, &owner.identity, work)
            {
                Ok(record) => matches!(
                    record.representation(),
                    Representation::External { allocation: held, .. } if held == allocation
                ),
                Err(StoreError::NotFound(_)) => false,
                Err(error) => return Err(error),
            };
            let allocations = snapshot.table(generation.allocations())?;
            let claimed = allocations
                .get(allocation.0.as_slice())
                .map_err(crate::error::redb)?
                .map(|guard| guard.value().to_vec());
            // Correspondence between the row and the derived index must
            // hold in both directions before either is believed.
            let corresponds = claimed.as_ref().map_or(!selected, |key| {
                selected && *key == owner.identity.key_bytes()
            });
            if !corresponds {
                let error = self.index_diverged(
                    owner.instance.namespace(),
                    "ALLOCATIONS",
                    format!(
                        "allocation {} ownership disagrees with the committed row of {}",
                        allocation.hex(),
                        owner.identity
                    ),
                );
                return Err(error);
            }
            Ok(if selected {
                OwnerVerdict::Owned
            } else if identification.permits_destruction() {
                OwnerVerdict::Released
            } else {
                // The rows are of storage that cannot be proven to be the
                // installer's (an unknown instance on either side): a row
                // keeps the allocation, its absence releases nothing.
                OwnerVerdict::Protected
            })
        })();
        match decided {
            Ok(verdict) => verdict,
            Err(error) => {
                tracing::warn!(
                    allocation = %allocation.hex(),
                    instance = %owner.instance,
                    %error,
                    "owner evidence unreadable; allocation protected"
                );
                OwnerVerdict::Protected
            }
        }
    }

    /// Reclaim one allocation: claim it (refused while a reader or
    /// preparation pins it, or a committed epoch is parked on it); keep it
    /// when the settled projection names an owner; otherwise let the
    /// namespace its owner marker names decide from its committed rows
    /// (see the module documentation); then delete. No step waits on the
    /// settlement of any namespace. The projection's owners are read on
    /// `work`; a refusal releases the claim and deletes nothing.
    pub(crate) fn reclaim_allocation(
        &self,
        allocation: AllocationId,
        work: &mut dyn Meter,
    ) -> Result<Reclaimed, StoreError> {
        let Some(claim) = self.protection.claim(allocation)? else {
            return Ok(Reclaimed::Protected);
        };
        if self.allocation_owned(&allocation, work)? {
            drop(claim);
            return Ok(Reclaimed::Owned);
        }
        let owner = match read_owner_marker(&self.blob_root, &allocation) {
            Ok(owner) => owner,
            Err(error) => {
                drop(claim);
                tracing::warn!(
                    allocation = %allocation.hex(),
                    %error,
                    "owner marker unreadable; allocation protected"
                );
                return Ok(Reclaimed::Protected);
            }
        };
        if let Some(owner) = owner {
            // A retained publication of the installer will install the
            // allocation again when it is resolved (`custody`): whatever its
            // aborted transaction left, the allocation is protected while
            // the custody record is held, and an unreadable record protects
            // it too.
            match self.holds_custody(&owner.instance) {
                Ok(false) => {}
                Ok(true) => {
                    drop(claim);
                    return Ok(Reclaimed::Protected);
                }
                Err(error) => {
                    drop(claim);
                    tracing::warn!(
                        allocation = %allocation.hex(),
                        instance = %owner.instance,
                        %error,
                        "custody of the owner unreadable; allocation protected"
                    );
                    return Ok(Reclaimed::Protected);
                }
            }
            match self.owner_verdict(&allocation, &owner, work) {
                OwnerVerdict::Owned => {
                    drop(claim);
                    return Ok(Reclaimed::Owned);
                }
                OwnerVerdict::Protected => {
                    drop(claim);
                    return Ok(Reclaimed::Protected);
                }
                OwnerVerdict::Released => {}
            }
        }
        match claim.delete(&self.blob_root, self.fsync) {
            Ok(Some(bytes)) => Ok(Reclaimed::Deleted(bytes)),
            Ok(None) => Ok(Reclaimed::Absent),
            Err((claim, error)) => {
                drop(claim);
                Err(error)
            }
        }
    }
}
