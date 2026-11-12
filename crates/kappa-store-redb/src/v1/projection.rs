//! The registry's completed-generation projections: the one boundary through
//! which settled state is staged, completed and read.
//!
//! Every projected row is a version: written by one settlement attempt of
//! one storage instance's epoch (`ProjectionStage`), invisible until that
//! attempt is recorded as the epoch's completed attempt in the same short
//! registry transaction that advances the instance's `SETTLED` checkpoint
//! (`ProjectionStage::complete`). A reader ([`ProjectionRead`]) holds one
//! registry read transaction and selects, per logical key and storage
//! instance, the newest version whose attempt completed; a version staged
//! by an attempt that has not completed (in progress, restarted, abandoned)
//! is never selected and never hides a completed one. Superseded versions
//! and attempts that will never complete are removed by bounded maintenance
//! (`projection_compact`) without changing what any reader selects.
//!
//! Rows are partitioned by the storage instance that settled them: the
//! instance a catalog entry, an allocation owner, an epoch root, a namespace
//! record or an identity row came from. A family keyed by namespace has one
//! instance per namespace at a time; a membership family (an index entry, a
//! catalog owner) is the union of every instance's visible members. What a
//! family's rows mean, and which family a consumer reads, is decided by the
//! typed adapters beside this module; no consumer opens the version tables.
//!
//! Key framing is [`key`]'s, visibility [`visibility`]'s, selection the one
//! reduction of [`reduce`]. Every read runs on its caller's meter and
//! answers completely or is refused, never partially taken for absence;
//! output grows only through `work::reserve_charged`, before a take.
//!
//! Every value is a candidate or a cache, never authority: a locator is
//! confirmed against the owning instance's namespace database, and absence
//! from a projection is absence from settled state only.

use std::ops::ControlFlow;

use redb::{ReadOnlyTable, ReadTransaction};

use kappa_cursor::interval::Interval;
use kappa_store::StoreError;
use kappa_store::work::{Dimension, Meter, Work, reserve_charged};

use crate::PersistentStore;
use crate::redb_cursor::rows;
use crate::storage_instance::StorageInstance;
use crate::tables::{PROJECTION_COMPLETED, PROJECTION_INSTANCES, PROJECTION_VERSIONS, SETTLED};

#[path = "projection_key.rs"]
mod key;

/// The one ordered reduction of versions, shared by committed reads and
/// staging.
#[path = "projection_reduce.rs"]
pub(crate) mod reduce;

/// The one decision of whether a version is visible.
#[path = "projection_visibility.rs"]
pub(crate) mod visibility;

pub(crate) use key::zeroed;
pub use key::{
    END, MAX_LOG_KEY_BYTES, Version, VersionBounds, VersionKey, VersionRef, attempt_prefix,
    attempt_prefix_len, epoch_key, key_prefix, key_prefix_len, log_key, log_key_len, logical,
    logical_len, prefixed, prefixed_cost, split_logical, version_key, version_key_len,
};
use key::{MEMBER, contains_member, unescape};
use reduce::{Delivery, Reduction, reduce_groups, undelivered};
use visibility::visibility;

/// A projected family. The discriminant is the first byte of every version
/// key and is part of the stored format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Family {
    /// Content identity -> presence: the instance selects a representation.
    Catalog = 1,
    /// Allocation id, member content identity -> presence.
    AllocationOwner = 2,
    /// Content identity -> allocation id the instance's External row selects.
    AllocationByRow = 3,
    /// Epoch root identity -> presence: the instance published it.
    EpochRoot = 4,
    /// Namespace -> `[plane:16][generation:8 BE]`.
    Assignment = 5,
    /// Namespace -> dCBOR `NamespaceInfo`.
    NamespaceRecord = 6,
    /// Assertion identity -> dCBOR `IdentityAssertion`.
    Assertion = 10,
    /// Asserter, member assertion identity -> presence.
    AssertionByAsserter = 11,
    /// `subject\0facet`, member `[asserter][assertion]` -> presence.
    AssertionBySubject = 12,
    /// Revocation identity -> dCBOR `Revocation`.
    Revocation = 13,
    /// Asserter, member revocation identity -> presence.
    RevocationByAsserter = 14,
    /// Watermark identity -> dCBOR `Watermark`.
    Watermark = 15,
    /// Asserter, member watermark identity -> presence.
    WatermarkByAsserter = 16,
    /// Old anchor -> dCBOR `Succession`.
    Succession = 17,
    /// Anchor -> longest chain depth ending at it (8 BE).
    SuccessionDepth = 18,
    /// `[ns:16][source]` -> dCBOR `Vec<IdentityBinding>`.
    Binding = 19,
    /// Source, member namespace -> presence.
    BindingBySource = 20,
    /// Handle key -> dCBOR `HandleRecord`.
    Handle = 21,
    /// Anchor, member handle key -> presence.
    HandleByAnchor = 22,
    /// Session id -> admitted ciphertext (a cache; ownership is the claim).
    Session = 23,
    /// Credential id -> admitted ciphertext.
    Credential = 24,
    /// Credential id -> admitted grace ciphertext.
    CredentialGrace = 25,
    /// Trust key -> admitted ciphertext.
    Trust = 26,
    /// Anchor -> dCBOR `Vec<DeviceBinding>`.
    DeviceBinding = 27,
    /// Anchor -> dCBOR `Vec<PrekeyBinding>`.
    PrekeyBinding = 28,
    /// Anchor -> dCBOR `LocatorRecord`.
    LocatorRecord = 29,
    /// Anchor -> dCBOR `RevocationCommitment`.
    RevocationCommitment = 30,
}

/// One visible row: the instance that settled it, its value and the
/// completion sequence of the epoch that wrote it (later completions are
/// newer state).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Visible {
    pub instance: StorageInstance,
    pub value: Vec<u8>,
    pub completion: u64,
}

/// A visible member of a membership family: `(key, member, row)`.
pub type ScannedMember = (Vec<u8>, Vec<u8>, Visible);

/// How a committed read collects its visible groups into `found`, so no
/// delivery is taken before its output is secured: `prepare` inspects the
/// group's escaped logical key and whether it is a put, and secures every
/// fallible allocation and conversion its part of the item needs
/// (returning `None` to pass over the group); the reduction then secures
/// room in `found`, takes the delivery, and pushes `assemble` of the
/// prepared part and the group's row, moved out of the delivery.
struct Collect<'a, P, T> {
    prepare: &'a mut dyn FnMut(&[u8], bool, &mut dyn Meter) -> Result<Option<P>, StoreError>,
    assemble: fn(P, Visible) -> T,
    found: &'a mut Vec<T>,
}

/// Completed projection state, read in one registry read transaction.
pub struct ProjectionRead {
    versions: ReadOnlyTable<&'static [u8], &'static [u8]>,
    completed: ReadOnlyTable<&'static [u8], &'static [u8]>,
    settled: ReadOnlyTable<&'static [u8], &'static [u8]>,
    instances: ReadOnlyTable<&'static [u8], &'static [u8]>,
    bounds: VersionBounds,
    unit: Work,
    txn: ReadTransaction,
}

impl PersistentStore {
    /// A read of completed projection state.
    pub(crate) fn projection(&self) -> Result<ProjectionRead, StoreError> {
        ProjectionRead::new(
            self.registry.begin_read()?,
            self.settlement_limits.versions(),
            self.settlement_limits.selection_unit(),
        )
    }
}

/// The escaped logical key of `key` in `family`, with `trailer` appended,
/// its length (`logical_len`) charged to `work` before it is built.
fn logical_on(
    family: Family,
    key: &[u8],
    trailer: &[u8],
    work: &mut dyn Meter,
) -> Result<Vec<u8>, StoreError> {
    work.charge(
        Dimension::BytesAllocated,
        logical_len(key, None, trailer.len())?,
    )?;
    logical(family, key, None, trailer)
}

/// `escaped` unescaped, its copy charged to `work` before it is made.
fn unescape_on(escaped: &[u8], work: &mut dyn Meter) -> Result<Vec<u8>, StoreError> {
    work.charge(Dimension::BytesAllocated, escaped.len() as u64)?;
    unescape(escaped)
}

impl ProjectionRead {
    pub(crate) fn new(
        txn: ReadTransaction,
        bounds: VersionBounds,
        unit: Work,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            versions: txn
                .open_table(PROJECTION_VERSIONS)
                .map_err(crate::error::redb)?,
            completed: txn
                .open_table(PROJECTION_COMPLETED)
                .map_err(crate::error::redb)?,
            settled: txn.open_table(SETTLED).map_err(crate::error::redb)?,
            instances: txn
                .open_table(PROJECTION_INSTANCES)
                .map_err(crate::error::redb)?,
            bounds,
            unit,
            txn,
        })
    }

    /// The registry read transaction this read holds, for a reader that
    /// pairs projection state with another registry table in one snapshot.
    pub(crate) const fn transaction(&self) -> &ReadTransaction {
        &self.txn
    }

    /// The newest visible version of every (logical key, instance) group
    /// whose escaped logical key starts with `prefix`, each collected by
    /// `collect`. Complete or refused. A delivery is taken only after its
    /// output is secured; its row moves out of it (a tombstone's row holds
    /// no value).
    fn select<P, T>(
        &self,
        prefix: &[u8],
        work: &mut dyn Meter,
        collect: Collect<'_, P, T>,
    ) -> Result<(), StoreError> {
        let mut versions = {
            let mut unit =
                work.admit(&[(Dimension::BytesAllocated, prefixed_cost(prefix, None)?)])?;
            prefixed(&self.versions, prefix, None, &mut unit)?
        };
        let mut visible = |version: &VersionKey, unit: &mut dyn Meter| {
            visibility(
                &self.completed,
                &self.settled,
                &self.instances,
                version,
                unit,
            )
        };
        let Collect {
            prepare,
            assemble,
            found,
        } = collect;
        reduce_groups(
            &mut Reduction::default(),
            &mut versions,
            &self.bounds,
            &self.unit,
            work,
            &mut visible,
            &mut |offered, work| {
                let delivery = offered.as_ref().ok_or_else(undelivered)?;
                let put = matches!(delivery.version, Version::Put(_));
                let prepared = prepare(&delivery.logical, put, work)?;
                if prepared.is_some() {
                    reserve_charged(work, found)?;
                }
                let Delivery {
                    instance,
                    completion,
                    version,
                    ..
                } = offered.take().ok_or_else(undelivered)?;
                if let Some(prepared) = prepared {
                    let value = match version {
                        Version::Put(value) => value,
                        Version::Tombstone => Vec::new(),
                    };
                    let row = Visible {
                        instance,
                        value,
                        completion,
                    };
                    found.push(assemble(prepared, row));
                }
                Ok(ControlFlow::Continue(()))
            },
        )?
        .complete()
    }

    /// The visible value of `key` in `family` from each instance holding
    /// one.
    pub(crate) fn get(
        &self,
        family: Family,
        key: &[u8],
        work: &mut dyn Meter,
    ) -> Result<Vec<Visible>, StoreError> {
        let exact = logical_on(family, key, &END, work)?;
        let mut found = Vec::new();
        self.select(
            &exact,
            work,
            Collect {
                prepare: &mut |_, put, _| Ok(put.then_some(())),
                assemble: |(), row| row,
                found: &mut found,
            },
        )?;
        Ok(found)
    }

    /// The visible members of `key` in membership `family`, each with the
    /// instance contributing it.
    pub(crate) fn members(
        &self,
        family: Family,
        key: &[u8],
        work: &mut dyn Meter,
    ) -> Result<Vec<(Vec<u8>, Visible)>, StoreError> {
        let prefix = logical_on(family, key, &MEMBER, work)?;
        let skip = prefix.len();
        let mut found = Vec::new();
        self.select(
            &prefix,
            work,
            Collect {
                prepare: &mut |logical, put, work| {
                    if !put {
                        return Ok(None);
                    }
                    unescape_on(&logical[skip..], work).map(Some)
                },
                assemble: |member, row| (member, row),
                found: &mut found,
            },
        )?;
        Ok(found)
    }

    /// The visible members of every key of membership `family` beginning
    /// with `prefix` (unescaped), as `(key, member, row)`, in key and member
    /// order.
    pub(crate) fn member_scan(
        &self,
        family: Family,
        prefix: &[u8],
        work: &mut dyn Meter,
    ) -> Result<Vec<ScannedMember>, StoreError> {
        let escaped = logical_on(family, prefix, &[], work)?;
        let mut found = Vec::new();
        self.select(
            &escaped,
            work,
            Collect {
                prepare: &mut |logical, put, work| {
                    let body = &logical[1..];
                    let Some(split) = body.windows(2).position(|pair| pair == MEMBER) else {
                        return Ok(None);
                    };
                    if !put {
                        return Ok(None);
                    }
                    let key = unescape_on(&body[..split], work)?;
                    let member = unescape_on(&body[split + 2..], work)?;
                    Ok(Some((key, member)))
                },
                assemble: |(key, member), row| (key, member, row),
                found: &mut found,
            },
        )?;
        Ok(found)
    }

    /// The visible single-valued keys of `family` beginning with `prefix`
    /// (unescaped), with their values, in key order.
    pub(crate) fn scan(
        &self,
        family: Family,
        prefix: &[u8],
        work: &mut dyn Meter,
    ) -> Result<Vec<(Vec<u8>, Visible)>, StoreError> {
        let escaped = logical_on(family, prefix, &[], work)?;
        let mut found = Vec::new();
        self.select(
            &escaped,
            work,
            Collect {
                prepare: &mut |logical, put, work| {
                    if !put || contains_member(&logical[1..]) {
                        return Ok(None);
                    }
                    unescape_on(&logical[1..], work).map(Some)
                },
                assemble: |key, row| (key, row),
                found: &mut found,
            },
        )?;
        Ok(found)
    }

    /// The first single-valued key of `family` at or after `from`
    /// (unescaped) that some instance holds a visible put of. Keys holding
    /// only tombstones or unfinished versions are passed over; each version
    /// between `from` and the key returned is examined inside one admitted
    /// unit by the one reduction, and the end of the family's range inside
    /// another.
    pub(crate) fn next_key(
        &self,
        family: Family,
        from: &[u8],
        work: &mut dyn Meter,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let start = logical_on(family, from, &[], work)?;
        let family_prefix = [family as u8];
        // The family's interval and the copy of `start` its seek makes, then
        // redb's copy of the bounds, which are no longer than both.
        let construction = Interval::prefix_cost(&family_prefix)
            .and_then(|interval| interval.checked_add(Interval::position_cost(&start)))
            .ok_or_else(|| StoreError::Internal("projection range bound exceeds u64".into()))?;
        let mut versions = {
            let mut unit = work.admit(&[
                (Dimension::BytesAllocated, construction),
                (Dimension::BytesAllocated, construction),
            ])?;
            unit.account(Dimension::BytesAllocated, construction)?;
            let interval = Interval::prefix(&family_prefix).at_or_after(&start);
            rows(&self.versions, &interval, &mut unit)?
        };
        let mut visible = |version: &VersionKey, unit: &mut dyn Meter| {
            if contains_member(&version.logical[1..]) {
                return Ok(None);
            }
            visibility(
                &self.completed,
                &self.settled,
                &self.instances,
                version,
                unit,
            )
        };
        // The first logical key a group of which holds a visible put: its
        // groups are delivered in key order, so the first such delivery is
        // the answer, and the reduction stops there. Taking a delivery
        // allocates nothing: it moves the group's own buffers.
        let mut found: Option<Vec<u8>> = None;
        reduce_groups(
            &mut Reduction::default(),
            &mut versions,
            &self.bounds,
            &self.unit,
            work,
            &mut visible,
            &mut |offered, _| {
                let Delivery {
                    logical, version, ..
                } = offered.take().ok_or_else(undelivered)?;
                if matches!(version, Version::Put(_)) {
                    found = Some(logical);
                    return Ok(ControlFlow::Break(()));
                }
                Ok(ControlFlow::Continue(()))
            },
        )?
        .complete()?;
        found
            .map(|logical| unescape_on(&logical[1..], work))
            .transpose()
    }

    /// Versions held, an upper bound on any traversal's work.
    pub(crate) fn version_count(&self) -> Result<u64, StoreError> {
        use redb::ReadableTableMetadata;
        self.versions.len().map_err(crate::error::redb)
    }
}

#[cfg(test)]
#[path = "projection_tests.rs"]
mod tests;
