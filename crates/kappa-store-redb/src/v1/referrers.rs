//! Epoch-derived reverse-reference index over content.
//!
//! `REFERRERS` maps a content identity to every direct referrer the
//! committed epoch state holds. Each entry is written in the same write
//! transaction as the reference mutation it describes, so the index is a
//! projection of epoch state and can be rebuilt from it.
//!
//! Referrers are the committed reference sources, nothing else: a direct
//! tag (a symbolic tag names another tag, not content, and has no entry), a
//! retaining edge's target, the edge record that owns an edge's own
//! content, a namespace pin, and the namespace's current epoch head. Every
//! other epoch dependency (ledgers, predecessors, rotation evidence, the
//! objects a ledger names) is an `EpochRoot` edge the head's chain already
//! retains, so it is indexed as an edge target like any other.
//!
//! The index accelerates candidate selection for reclamation. It records
//! direct references, not rooted reachability: content with no entry may
//! still be protected by a preparation or reader pin, and content with
//! entries may be unreachable from every namespace root. Absence alone never
//! authorizes physical reclamation.
//!
//! Authoritative mutations use [`establish`] and [`release`], which assert
//! the index state the mutation implies and report divergence as an
//! internal error. The owning execution latches that error and refuses to
//! publish; a caller must never commit a transaction over it.
//! A divergence is recorded on the store (`PersistentStore::index_diverged`)
//! and repaired by maintenance (`MaintenanceStore::repair_indexes`).
//! Reconstruction (`PersistentStore::rebuild_referrers`, in
//! `referrers_rebuild.rs`) empties the index and re-derives every entry
//! with [`rebuild`], which is idempotent.

use kappa_cursor::FallibleCursor;
use kappa_store::{Kappa, NamespaceRef, StoreError};
use redb::ReadableTableMetadata;

use crate::PersistentStore;
use crate::namespace_snapshot::NamespaceSnapshot;
use crate::tables::REFERRERS;

#[cfg(test)]
#[path = "referrers_tests.rs"]
mod tests;

#[path = "referrers_rebuild.rs"]
mod reconstruction;

/// A committed reference to content, with the identity of its source.
///
/// The representation is private: every value is built by a constructor
/// that validates it, or decoded by [`Referrer::decode`], which enforces
/// the same encoding. There is no way to hold a `Referrer` that
/// `encode` writes and `decode` rejects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Referrer {
    namespace: [u8; 16],
    source: Source,
}

/// What the committed state holds that refers to the content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// A direct tag named `name` points at the content.
    Tag { name: String },
    /// The edge record `edge` owns the content that is the edge's own
    /// canonical bytes.
    EdgeRecord { edge: Kappa },
    /// The retaining edge `edge` has the content as its target.
    EdgeTarget { edge: Kappa },
    /// The namespace pins the content under `_pin/{content}`. The multimap
    /// key is the content, so the namespace alone identifies the pin.
    Pin,
    /// The content is the namespace's current epoch root, as `EPOCH_CURRENT`
    /// names it. Moves with that pointer at every seal.
    EpochHead,
    /// The representation of `owner` (a composite, a manifest node, or an
    /// alias) is assembled from the content. Established when the owner's
    /// representation is installed, released when it is retired.
    ///
    /// Representations are global content, not namespace state: the row is
    /// shared by every namespace that names the identity, and it may be
    /// retired by an execution in any namespace (maintenance included). The
    /// entry therefore carries [`CONTENT_SCOPE`] in place of a namespace, so
    /// the release names exactly the entry the installation wrote.
    Representation { owner: Kappa },
}

/// Namespace field of every representation referrer: no namespace owns a
/// representation dependency.
pub const CONTENT_SCOPE: [u8; 16] = [0; 16];

const KIND_TAG: u8 = 0;
const KIND_EDGE_RECORD: u8 = 1;
const KIND_EDGE_TARGET: u8 = 2;
const KIND_PIN: u8 = 3;
const KIND_EPOCH_HEAD: u8 = 4;
const KIND_REPRESENTATION: u8 = 5;

impl Referrer {
    pub(crate) fn tag(namespace: &NamespaceRef, name: &str) -> Result<Self, StoreError> {
        if name.is_empty() {
            return Err(StoreError::Rejected("tag referrer requires a name".into()));
        }
        Ok(Self {
            namespace: *namespace.id(),
            source: Source::Tag {
                name: name.to_string(),
            },
        })
    }

    pub(crate) fn edge_record(namespace: &NamespaceRef, edge: &Kappa) -> Self {
        Self {
            namespace: *namespace.id(),
            source: Source::EdgeRecord { edge: edge.clone() },
        }
    }

    pub(crate) fn edge_target(namespace: &NamespaceRef, edge: &Kappa) -> Self {
        Self {
            namespace: *namespace.id(),
            source: Source::EdgeTarget { edge: edge.clone() },
        }
    }

    pub(crate) const fn pin(namespace: &NamespaceRef) -> Self {
        Self {
            namespace: *namespace.id(),
            source: Source::Pin,
        }
    }

    pub(crate) const fn epoch_head(namespace: &NamespaceRef) -> Self {
        Self {
            namespace: *namespace.id(),
            source: Source::EpochHead,
        }
    }

    pub(crate) fn representation(owner: &Kappa) -> Self {
        Self {
            namespace: CONTENT_SCOPE,
            source: Source::Representation {
                owner: owner.clone(),
            },
        }
    }

    /// The namespace the reference belongs to; [`CONTENT_SCOPE`] for a
    /// representation dependency.
    pub const fn namespace(&self) -> &[u8; 16] {
        &self.namespace
    }

    pub const fn source(&self) -> &Source {
        &self.source
    }

    /// `[namespace:16][kind:1][identity]`, where the identity encoding is
    /// fixed by the kind.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let (kind, id): (u8, Vec<u8>) = match &self.source {
            Source::Tag { name } => (KIND_TAG, name.as_bytes().to_vec()),
            Source::EdgeRecord { edge } => (KIND_EDGE_RECORD, edge.key_bytes()),
            Source::EdgeTarget { edge } => (KIND_EDGE_TARGET, edge.key_bytes()),
            Source::Pin => (KIND_PIN, Vec::new()),
            Source::EpochHead => (KIND_EPOCH_HEAD, Vec::new()),
            Source::Representation { owner } => (KIND_REPRESENTATION, owner.key_bytes()),
        };
        let mut value = Vec::with_capacity(17 + id.len());
        value.extend_from_slice(&self.namespace);
        value.push(kind);
        value.extend_from_slice(&id);
        value
    }

    /// Decode an index entry; refuses every malformed encoding.
    pub fn decode(value: &[u8]) -> Result<Self, StoreError> {
        if value.len() < 17 {
            return Err(StoreError::Internal(
                "referrer entry shorter than its namespace and kind".into(),
            ));
        }
        let mut namespace = [0u8; 16];
        namespace.copy_from_slice(&value[..16]);
        let id = &value[17..];
        let source = match value[16] {
            KIND_TAG => {
                if id.is_empty() {
                    return Err(StoreError::Internal("tag referrer without a name".into()));
                }
                let name = std::str::from_utf8(id)
                    .map_err(|error| StoreError::Internal(format!("tag referrer name: {error}")))?;
                Source::Tag {
                    name: name.to_string(),
                }
            }
            KIND_EDGE_RECORD => Source::EdgeRecord {
                edge: Kappa::from_key_bytes(id)
                    .map_err(|error| StoreError::Internal(format!("edge referrer: {error}")))?,
            },
            KIND_EDGE_TARGET => Source::EdgeTarget {
                edge: Kappa::from_key_bytes(id)
                    .map_err(|error| StoreError::Internal(format!("edge referrer: {error}")))?,
            },
            KIND_REPRESENTATION => {
                if namespace != CONTENT_SCOPE {
                    return Err(StoreError::Internal(
                        "representation referrer carries a namespace".into(),
                    ));
                }
                Source::Representation {
                    owner: Kappa::from_key_bytes(id).map_err(|error| {
                        StoreError::Internal(format!("representation referrer: {error}"))
                    })?,
                }
            }
            KIND_PIN | KIND_EPOCH_HEAD => {
                if !id.is_empty() {
                    return Err(StoreError::Internal(
                        "namespace-only referrer carries an identity".into(),
                    ));
                }
                if value[16] == KIND_PIN {
                    Source::Pin
                } else {
                    Source::EpochHead
                }
            }
            kind => {
                return Err(StoreError::Internal(format!(
                    "unknown referrer kind {kind}"
                )));
            }
        };
        Ok(Self { namespace, source })
    }
}

/// Record a reference an authoritative mutation creates. The entry must
/// not already exist: a present entry means the index has diverged from
/// the committed state it projects, and the mutation must not commit over
/// that divergence.
pub fn establish(
    store: &PersistentStore,
    txn: &redb::WriteTransaction,
    content: &Kappa,
    referrer: &Referrer,
) -> Result<(), StoreError> {
    let key = content.key_bytes();
    let value = referrer.encode();
    let present = txn
        .open_multimap_table(REFERRERS)
        .map_err(crate::error::redb)?
        .insert(key.as_slice(), value.as_slice())
        .map_err(crate::error::redb)?;
    if present {
        return Err(store.index_diverged(
            "REFERRERS",
            format!("referrer index already held {referrer:?} for {content}"),
        ));
    }
    Ok(())
}

/// Remove a reference an authoritative mutation retires. The entry must
/// exist: an absent entry means the index has diverged.
pub fn release(
    store: &PersistentStore,
    txn: &redb::WriteTransaction,
    content: &Kappa,
    referrer: &Referrer,
) -> Result<(), StoreError> {
    let key = content.key_bytes();
    let value = referrer.encode();
    let existed = txn
        .open_multimap_table(REFERRERS)
        .map_err(crate::error::redb)?
        .remove(key.as_slice(), value.as_slice())
        .map_err(crate::error::redb)?;
    if !existed {
        return Err(store.index_diverged(
            "REFERRERS",
            format!("referrer index lacked {referrer:?} for {content}"),
        ));
    }
    Ok(())
}

/// Insert during reconstruction from epoch state. Idempotent: an entry
/// already present is the expected outcome of replaying a reference that
/// an earlier pass already indexed.
pub fn rebuild(
    txn: &redb::WriteTransaction,
    content: &Kappa,
    referrer: &Referrer,
) -> Result<(), StoreError> {
    let key = content.key_bytes();
    let value = referrer.encode();
    txn.open_multimap_table(REFERRERS)
        .map_err(crate::error::redb)?
        .insert(key.as_slice(), value.as_slice())
        .map_err(crate::error::redb)?;
    Ok(())
}

impl PersistentStore {
    /// The committed references to `content` as `ns`'s index holds them,
    /// over a read view retained for the cursor's lifetime: the inspection
    /// surface for what retains an identity in a namespace (operators, the
    /// collector's report, tests). The index is per namespace: a
    /// representation's referrers are those of the namespace that admitted
    /// it. Absence of entries never authorizes reclamation by itself; see
    /// the module documentation.
    pub fn referrers_of(
        &self,
        ns: &NamespaceRef,
        content: &Kappa,
    ) -> Result<ReferrerCursor, StoreError> {
        ReferrerCursor::new(self.namespace_snapshot(ns)?, content)
    }
}

/// Validated traversal of the referrers of one content identity over one
/// retained namespace snapshot. Only the current entry is held in memory.
///
/// Every entry is decoded as it is loaded, and must belong to the
/// snapshot's namespace or be a representation dependency
/// ([`CONTENT_SCOPE`]): an entry of another namespace in this namespace's
/// index is divergence. A navigation failure, a malformed entry or a foreign
/// one latches the cursor: later calls report the retained error, never
/// successful exhaustion. Memory is bounded; `seek` is linear in the entries
/// it skips.
pub struct ReferrerCursor {
    /// Owns its transaction guard and pages: redb's value iterator needs
    /// no table retained beside it. Dropped before the snapshot.
    values: redb::MultimapValue<'static, &'static [u8]>,
    /// The namespace whose index is traversed, held open for the cursor's
    /// life; every entry is checked against it.
    snapshot: NamespaceSnapshot,
    head: Option<(Vec<u8>, Referrer)>,
    failure: Option<std::sync::Arc<StoreError>>,
    remaining: u64,
}

impl ReferrerCursor {
    fn new(snapshot: NamespaceSnapshot, content: &Kappa) -> Result<Self, StoreError> {
        let table = snapshot.multimap(REFERRERS)?;
        let key = content.key_bytes();
        let values = table.get(key.as_slice()).map_err(crate::error::redb)?;
        // The multimap's total entry count is a conservative bound on one
        // key's entries; `cost` therefore overestimates for shared content.
        let remaining = table.len().map_err(crate::error::redb)?;
        drop(table);
        let mut cursor = Self {
            values,
            snapshot,
            head: None,
            failure: None,
            remaining,
        };
        cursor.load_next()?;
        Ok(cursor)
    }

    /// The current referrer, already validated when it was loaded.
    pub fn referrer(&self) -> Result<Option<&Referrer>, StoreError> {
        self.ensure_valid()?;
        Ok(self.head.as_ref().map(|(_, referrer)| referrer))
    }

    fn load_next(&mut self) -> Result<(), StoreError> {
        match self.values.next() {
            Some(Ok(value)) => {
                let encoded = value.value().to_vec();
                let namespace = self.snapshot.controller().id;
                match Referrer::decode(&encoded) {
                    Ok(referrer)
                        if *referrer.namespace() == namespace
                            || *referrer.namespace() == CONTENT_SCOPE =>
                    {
                        self.head = Some((encoded, referrer));
                    }
                    Ok(referrer) => {
                        return Err(self.fail(StoreError::Internal(format!(
                            "the referrer index of namespace {} holds an entry of namespace {}",
                            hex::encode(namespace),
                            hex::encode(referrer.namespace())
                        ))));
                    }
                    Err(error) => return Err(self.fail(error)),
                }
            }
            Some(Err(error)) => return Err(self.fail(crate::error::redb(error))),
            None => {
                self.head = None;
                self.remaining = 0;
            }
        }
        Ok(())
    }

    fn fail(&mut self, error: StoreError) -> StoreError {
        self.head = None;
        let error = std::sync::Arc::new(error);
        let result = crate::redb_cursor::RedbCursor::retained_error(&error);
        self.failure = Some(error);
        result
    }

    fn ensure_valid(&self) -> Result<(), StoreError> {
        self.failure.as_ref().map_or_else(
            || Ok(()),
            |error| Err(crate::redb_cursor::RedbCursor::retained_error(error)),
        )
    }
}

impl FallibleCursor for ReferrerCursor {
    type Error = StoreError;

    fn key(&self) -> Result<Option<&[u8]>, StoreError> {
        self.ensure_valid()?;
        Ok(self.head.as_ref().map(|(encoded, _)| encoded.as_slice()))
    }

    fn advance(&mut self) -> Result<Option<&[u8]>, StoreError> {
        self.ensure_valid()?;
        if self.head.is_some() {
            self.remaining = self.remaining.saturating_sub(1);
            self.load_next()?;
        }
        self.key()
    }

    /// Entries of one key are visited in the multimap's value order, so a
    /// seek advances until the current entry is at or past `target`.
    fn seek(&mut self, target: &[u8]) -> Result<Option<&[u8]>, StoreError> {
        self.ensure_valid()?;
        while self
            .head
            .as_ref()
            .is_some_and(|(encoded, _)| encoded.as_slice() < target)
        {
            self.remaining = self.remaining.saturating_sub(1);
            self.load_next()?;
        }
        self.key()
    }

    fn size_hint(&self) -> u64 {
        self.remaining
    }

    fn cost(&self) -> u64 {
        self.remaining
    }
}
