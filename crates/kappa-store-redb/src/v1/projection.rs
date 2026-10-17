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
//! Every value is a candidate or a cache, never authority: a locator is
//! confirmed against the owning instance's namespace database, and absence
//! from a projection is absence from settled state only.

use std::cell::RefCell;
use std::collections::BTreeMap;

use redb::{ReadOnlyTable, ReadTransaction, ReadableDatabase};

use kappa_store::StoreError;

use crate::PersistentStore;
use crate::storage_instance::StorageInstance;
use crate::tables::{PROJECTION_COMPLETED, PROJECTION_INSTANCES, PROJECTION_VERSIONS, SETTLED};

#[path = "projection_key.rs"]
mod key;

use key::{END, MEMBER, contains_member, unescape};
pub use key::{VersionKey, epoch_key, logical, prefixed, split_logical, version_key, visibility};

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

/// The version of a logical key one attempt wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Version {
    Put(Vec<u8>),
    Tombstone,
}

impl Version {
    pub(crate) fn encode(&self) -> Vec<u8> {
        match self {
            Self::Put(payload) => {
                let mut out = Vec::with_capacity(1 + payload.len());
                out.push(0);
                out.extend_from_slice(payload);
                out
            }
            Self::Tombstone => vec![1],
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        match bytes.split_first() {
            Some((0, payload)) => Ok(Self::Put(payload.to_vec())),
            Some((1, [])) => Ok(Self::Tombstone),
            _ => Err(StoreError::Internal("malformed projection version".into())),
        }
    }
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

/// One selected version: its escaped logical key, the visible row, and the
/// version itself (a tombstone's row holds no value).
type Selected = (Vec<u8>, Visible, Version);

/// A visible member of a membership family: `(key, member, row)`.
pub type ScannedMember = (Vec<u8>, Vec<u8>, Visible);

/// The newest visible version of one (logical key, instance) while a
/// selection runs: ordered by `(epoch, sequence)`.
struct Newest {
    order: (u64, u64),
    completion: u64,
    version: Version,
}

/// Completed projection state, read in one registry read transaction.
pub struct ProjectionRead {
    versions: ReadOnlyTable<&'static [u8], &'static [u8]>,
    completed: ReadOnlyTable<&'static [u8], &'static [u8]>,
    settled: ReadOnlyTable<&'static [u8], &'static [u8]>,
    instances: ReadOnlyTable<&'static [u8], &'static [u8]>,
    /// Visibility decided in this read, by (instance, epoch, attempt).
    known: RefCell<BTreeMap<(StorageInstance, u64, u32), Option<u64>>>,
    txn: ReadTransaction,
}

impl PersistentStore {
    /// A read of completed projection state.
    pub(crate) fn projection(&self) -> Result<ProjectionRead, StoreError> {
        let txn = self.registry.begin_read().map_err(crate::error::redb)?;
        ProjectionRead::new(txn)
    }
}

impl ProjectionRead {
    pub(crate) fn new(txn: ReadTransaction) -> Result<Self, StoreError> {
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
            known: RefCell::new(BTreeMap::new()),
            txn,
        })
    }

    /// The registry read transaction this read holds, for a reader that
    /// pairs projection state with another registry table in one snapshot.
    pub(crate) const fn transaction(&self) -> &ReadTransaction {
        &self.txn
    }

    /// The completion sequence of `version` when its attempt is the
    /// completed attempt of its epoch (`visibility`).
    fn completion(&self, version: &VersionKey) -> Result<Option<u64>, StoreError> {
        let coordinates = (version.instance, version.epoch, version.attempt);
        if let Some(known) = self.known.borrow().get(&coordinates) {
            return Ok(*known);
        }
        let decided = visibility(&self.completed, &self.settled, &self.instances, version)?;
        self.known.borrow_mut().insert(coordinates, decided);
        Ok(decided)
    }

    /// The newest visible version of every (logical key, instance) whose
    /// escaped logical key starts with `prefix`, in key order; tombstones
    /// included, for callers that must see removals.
    fn select(&self, prefix: &[u8]) -> Result<Vec<Selected>, StoreError> {
        let mut newest: BTreeMap<(Vec<u8>, StorageInstance), Newest> = BTreeMap::new();
        for entry in prefixed(&self.versions, prefix)? {
            let (key, value) = entry.map_err(crate::error::redb)?;
            let version = VersionKey::decode(key.value())?;
            let Some(completion) = self.completion(&version)? else {
                continue;
            };
            let order = (version.epoch, version.sequence);
            let slot = (version.logical, version.instance);
            if newest.get(&slot).is_some_and(|held| held.order >= order) {
                continue;
            }
            newest.insert(
                slot,
                Newest {
                    order,
                    completion,
                    version: Version::decode(value.value())?,
                },
            );
        }
        Ok(newest
            .into_iter()
            .map(
                |(
                    (logical, instance),
                    Newest {
                        completion,
                        version,
                        ..
                    },
                )| {
                    let value = match &version {
                        Version::Put(value) => value.clone(),
                        Version::Tombstone => Vec::new(),
                    };
                    (
                        logical,
                        Visible {
                            instance,
                            value,
                            completion,
                        },
                        version,
                    )
                },
            )
            .collect())
    }

    /// The visible value of `key` in `family` from each instance holding
    /// one.
    pub(crate) fn get(&self, family: Family, key: &[u8]) -> Result<Vec<Visible>, StoreError> {
        let mut exact = logical(family, key, None);
        exact.extend_from_slice(&END);
        Ok(self
            .select(&exact)?
            .into_iter()
            .filter(|(_, _, version)| matches!(version, Version::Put(_)))
            .map(|(_, visible, _)| visible)
            .collect())
    }

    /// The visible members of `key` in membership `family`, each with the
    /// instance contributing it.
    pub(crate) fn members(
        &self,
        family: Family,
        key: &[u8],
    ) -> Result<Vec<(Vec<u8>, Visible)>, StoreError> {
        let mut prefix = logical(family, key, None);
        prefix.extend_from_slice(&MEMBER);
        let skip = prefix.len();
        self.select(&prefix)?
            .into_iter()
            .filter(|(_, _, version)| matches!(version, Version::Put(_)))
            .map(|(logical, visible, _)| Ok((unescape(&logical[skip..])?, visible)))
            .collect()
    }

    /// The visible members of every key of membership `family` beginning
    /// with `prefix` (unescaped), as `(key, member, row)`, in key and member
    /// order.
    pub(crate) fn member_scan(
        &self,
        family: Family,
        prefix: &[u8],
    ) -> Result<Vec<ScannedMember>, StoreError> {
        let escaped = logical(family, prefix, None);
        self.select(&escaped)?
            .into_iter()
            .filter(|(_, _, version)| matches!(version, Version::Put(_)))
            .filter_map(|(logical, visible, _)| {
                let body = &logical[1..];
                let split = body.windows(2).position(|pair| pair == MEMBER)?;
                Some((|| {
                    Ok((
                        unescape(&body[..split])?,
                        unescape(&body[split + 2..])?,
                        visible,
                    ))
                })())
            })
            .collect()
    }

    /// The visible single-valued keys of `family` beginning with `prefix`
    /// (unescaped), with their values, in key order. Range work is bounded
    /// by the versions under the prefix, which compaction keeps to one per
    /// key and instance.
    pub(crate) fn scan(
        &self,
        family: Family,
        prefix: &[u8],
    ) -> Result<Vec<(Vec<u8>, Visible)>, StoreError> {
        let escaped = logical(family, prefix, None);
        self.select(&escaped)?
            .into_iter()
            .filter(|(logical, _, version)| {
                matches!(version, Version::Put(_)) && !contains_member(&logical[1..])
            })
            .map(|(logical, visible, _)| Ok((unescape(&logical[1..])?, visible)))
            .collect()
    }
}

impl ProjectionRead {
    /// The first single-valued key of `family` at or after `from`
    /// (unescaped) that some instance holds a visible put of. Keys holding
    /// only tombstones or unfinished versions are passed over; the work is
    /// the versions between `from` and the key returned.
    pub(crate) fn next_key(
        &self,
        family: Family,
        from: &[u8],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let start = logical(family, from, None);
        let end = [family as u8 + 1];
        let range = self
            .versions
            .range::<&[u8]>(start.as_slice()..end.as_slice())
            .map_err(crate::error::redb)?;
        let mut group: Option<Vec<u8>> = None;
        let mut newest: BTreeMap<StorageInstance, ((u64, u64), bool)> = BTreeMap::new();
        for entry in range {
            let (key, value) = entry.map_err(crate::error::redb)?;
            let version = VersionKey::decode(key.value())?;
            if contains_member(&version.logical[1..]) {
                continue;
            }
            if group.as_ref() != Some(&version.logical) {
                if let Some(done) = group.take()
                    && newest.values().any(|(_, put)| *put)
                {
                    return Ok(Some(unescape(&done[1..])?));
                }
                newest.clear();
                group = Some(version.logical.clone());
            }
            if self.completion(&version)?.is_none() {
                continue;
            }
            let order = (version.epoch, version.sequence);
            if newest
                .get(&version.instance)
                .is_some_and(|(held, _)| *held >= order)
            {
                continue;
            }
            let put = matches!(Version::decode(value.value())?, Version::Put(_));
            newest.insert(version.instance, (order, put));
        }
        match group {
            Some(done) if newest.values().any(|(_, put)| *put) => Ok(Some(unescape(&done[1..])?)),
            _ => Ok(None),
        }
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
