//! The published view of one namespace: everything its epochs admit, as
//! one immutable value.
//!
//! A namespace publishes by replacing its view with one pointer store, so
//! a reader holding a view sees one revision of the namespace and nothing
//! else. The view decides every fact about the namespace: its tags, edges,
//! sequences, metadata, ledger, epochs and receipts, the representation it
//! selected for each identity it admitted, the blob metadata it admitted,
//! its directory record, and the identity and authorization rows it wrote.
//! Registry-wide lookups find namespaces through projections
//! (`projection`), and every answer is decided here.
//!
//! A representation holds the allocations it selects, so a retained view
//! keeps every file it can serve, and the segment digests every read of
//! them is checked against (`segments`). Aliases and composites name other
//! identities admitted in the same view; a reader resolves them and holds
//! the allocations of every component it may open.
//!
//! Every map is a persistent B+tree: an execution clones the view and
//! writes into the clone, copying only the paths it changes. Keys are full
//! identities and names; no truncated hash decides authority here.

use std::sync::Arc;

use imbl::{OrdMap, OrdSet, Vector};
use kappa_store::traits::namespace::NamespaceInfo;
use kappa_succinct::IncrementalDigest;
use kappa_types::clock::ClockMs;
use kappa_types::epoch::{EpochMutation, MutationOp};
use kappa_types::error::StoreError;
use kappa_types::identity::{
    DeviceBinding, HandleRecord, IdentityAssertion, IdentityBinding, LocatorRecord, PrekeyBinding,
    Revocation, RevocationCommitment, Succession, TrustPosition, Watermark,
};
use kappa_types::kappa::Kappa;
use kappa_types::tag::TagEntry;

use super::allocation::Allocation;
use super::edge::EdgeState;
use super::segments::Segments;

pub type NamespaceId = [u8; 16];

/// How a namespace selected the bytes of an identity it admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Representation {
    /// The identity's own allocation.
    File(Allocation),
    /// Another identity this namespace admitted holds the bytes.
    Alias(Kappa),
    /// The concatenation of identities this namespace admitted, each with
    /// its declared length.
    Composite(Arc<[(Kappa, u64)]>),
    /// Compressed bytes in `storage` under `algorithm`, decoding to the
    /// admission's `size` bytes of the identity, with the segment digests
    /// of the decoded bytes.
    Compressed {
        storage: Allocation,
        algorithm: String,
        decoded: Segments,
    },
}

/// One admitted identity: its representation and logical size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    pub representation: Representation,
    pub size: u64,
}

/// A row with the namespace revision that last wrote it. A dependency on
/// a present row records the revision, so a row rewritten to an equal
/// value is still a change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row<T> {
    pub value: T,
    pub revision: u64,
}

/// A session row: anchor, deadline as encoded `ClockMs`, metadata.
pub type SessionRecord = (Kappa, i64, Vec<u8>);

/// A credential row: anchor, current secret hash, and the previous hash
/// with its grace deadline as encoded `ClockMs`.
pub type CredentialRecord = (Kappa, Vec<u8>, Option<(Vec<u8>, i64)>);

/// Authorization rows this namespace owns. Each key is an exclusive claim
/// (`claims`): one namespace holds a session, a credential or the trust
/// position at a time.
#[derive(Clone, Default)]
pub struct Authorization {
    /// Session identifier (`identity_scope::session_id` of the token) to
    /// its row; the token itself is never stored.
    pub sessions: OrdMap<String, Row<SessionRecord>>,
    pub credentials: OrdMap<String, Row<CredentialRecord>>,
    pub trust: Option<Row<TrustPosition>>,
}

/// Identity records this namespace's epochs admitted, with the indexes
/// its reads use.
#[derive(Clone, Default)]
pub struct IdentityRows {
    /// Binding source to the bindings this namespace holds for it, newest
    /// verification first.
    pub bindings: OrdMap<String, Vec<IdentityBinding>>,
    /// Binding target to the sources naming it.
    pub binding_targets: OrdMap<Kappa, OrdSet<String>>,
    pub assertions: OrdMap<Kappa, IdentityAssertion>,
    pub assertion_asserters: OrdMap<Kappa, OrdSet<Kappa>>,
    /// `"subject\0facet"` to the assertions under it.
    pub assertion_subjects: OrdMap<String, OrdSet<Kappa>>,
    pub revocations: OrdMap<Kappa, Revocation>,
    pub revocation_asserters: OrdMap<Kappa, OrdSet<Kappa>>,
    pub watermarks: OrdMap<Kappa, Watermark>,
    pub watermark_asserters: OrdMap<Kappa, OrdSet<Kappa>>,
    /// Old anchor to its succession record.
    pub successions: OrdMap<Kappa, Succession>,
    /// `protocol:handle` to its record.
    pub handles: OrdMap<String, HandleRecord>,
    pub handle_anchors: OrdMap<Kappa, OrdSet<String>>,
    pub devices: OrdMap<Kappa, Vec<DeviceBinding>>,
    pub prekeys: OrdMap<Kappa, Vec<PrekeyBinding>>,
    pub locators: OrdMap<Kappa, LocatorRecord>,
    pub commitments: OrdMap<Kappa, RevocationCommitment>,
}

/// One revision of one namespace.
#[derive(Clone, Default)]
pub struct NamespaceView {
    /// Distinguishes this namespace's lifetime from an earlier one under
    /// the same id; assigned when the slot is created.
    pub incarnation: u64,
    /// Publications of this namespace so far; 0 before the first.
    pub revision: u64,
    pub record: Option<NamespaceInfo>,
    /// Aliases this namespace holds, as `(name, protocol)` with an empty
    /// protocol for a global alias: the claims it owns in the directory.
    pub aliases: OrdSet<(String, String)>,
    pub tags: OrdMap<String, TagEntry>,
    pub digest: IncrementalDigest,
    pub edges: EdgeState,
    pub sequences: OrdMap<String, u64>,
    pub meta: OrdMap<String, Vec<u8>>,
    /// Mutations since the current epoch; empty in every published view.
    pub ledger: Vector<EpochMutation>,
    /// Current epoch root.
    pub epoch: Option<Kappa>,
    /// Epoch number to root, for every epoch this namespace sealed.
    pub epochs: OrdMap<u64, Kappa>,
    /// Timestamp of the latest epoch sealed.
    pub latest_epoch_ms: Option<i64>,
    /// Operation identity to (epoch root, receipt identity).
    pub operations: OrdMap<[u8; 32], (Kappa, Kappa)>,
    pub admitted: OrdMap<Kappa, Admission>,
    /// Identity to the aliases and composites of this view selecting it.
    pub selected_by: OrdMap<Kappa, OrdSet<Kappa>>,
    /// Identity to the direct tags and epoch head of this view naming it.
    pub references: OrdMap<Kappa, u64>,
    pub blob_meta: OrdMap<(Kappa, String), Vec<u8>>,
    pub authorization: Authorization,
    pub identity: IdentityRows,
}

impl NamespaceView {
    /// The view of a namespace slot before its first publication.
    pub fn empty(incarnation: u64) -> Self {
        Self {
            incarnation,
            ..Self::default()
        }
    }

    /// Append a mutation to the ledger the next epoch seals.
    pub fn record(&mut self, op: MutationOp, kappa: Kappa, now: ClockMs, context: Option<String>) {
        self.ledger.push_back(EpochMutation {
            op,
            kappa,
            timestamp_ms: now.as_i64(),
            context,
        });
    }

    /// The revision the candidate derived from this view publishes as. A
    /// revision is never reused, so an exhausted namespace admits no
    /// further publication.
    pub fn next_revision(&self) -> Result<u64, StoreError> {
        self.revision.checked_add(1).ok_or_else(|| {
            StoreError::CapacityExceeded("namespace publication revisions exhausted".into())
        })
    }

    /// One more direct tag or head naming `identity`.
    pub fn reference(&mut self, identity: &Kappa) {
        let count = self.references.entry(identity.clone()).or_insert(0);
        *count = count.saturating_add(1);
    }

    /// One fewer direct tag or head naming `identity`. Returns whether the
    /// view held the reference; a release it did not hold is a writer
    /// fault the caller reports.
    pub fn release(&mut self, identity: &Kappa) -> bool {
        match self.references.get_mut(identity) {
            Some(count) if *count > 1 => {
                *count -= 1;
                true
            }
            Some(_) => {
                self.references.remove(identity);
                true
            }
            None => false,
        }
    }

    /// Record that `owner`'s representation selects `identity`.
    pub fn select(&mut self, identity: &Kappa, owner: &Kappa) {
        self.selected_by
            .entry(identity.clone())
            .or_default()
            .insert(owner.clone());
    }

    /// Forget that `owner`'s representation selects `identity`.
    pub fn unselect(&mut self, identity: &Kappa, owner: &Kappa) {
        if let Some(owners) = self.selected_by.get_mut(identity) {
            owners.remove(owner);
            if owners.is_empty() {
                self.selected_by.remove(identity);
            }
        }
    }
}
