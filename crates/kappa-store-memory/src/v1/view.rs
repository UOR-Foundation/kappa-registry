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
use kappa_types::capacity::Reservation;
use kappa_types::epoch::EpochMutation;
use kappa_types::error::StoreError;
use kappa_types::identity::{
    DeviceBinding, HandleRecord, IdentityAssertion, IdentityBinding, LocatorRecord, PrekeyBinding,
    Revocation, RevocationCommitment, Succession, TrustPosition, Watermark,
};
use kappa_types::kappa::Kappa;
use kappa_types::merkle::StreamingTree;
use kappa_types::namespace::LogicalIncarnation;
use kappa_types::namespace_state::NamespaceState;
use kappa_types::state_index::{self, Change, Node, NodeSource};
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
    /// Bytes held in the process's memory with their segment digests:
    /// publication evidence generated from a signed root, moved here from
    /// the record that generated it together with its retention charge.
    Inline {
        bytes: Arc<Held>,
        segments: Segments,
    },
}

/// Bytes held in the process's memory and the retention charge accounting
/// for them, owned together: every view and reader holding the bytes holds
/// the charge, so it is released only with the last of them.
#[derive(Debug)]
pub struct Held {
    bytes: Vec<u8>,
    /// Held for its lifetime; dropping it releases the charge.
    _charge: Reservation,
}

impl Held {
    pub fn new(bytes: Vec<u8>, charge: Reservation) -> Arc<Self> {
        Arc::new(Self {
            bytes,
            _charge: charge,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Held bytes are equal only to themselves: two records holding equal bytes
/// hold distinct charges.
impl PartialEq for Held {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl Eq for Held {}

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
    /// The namespace's logical content admissions: what its authenticated
    /// state indexes under the content family, and what retirement removes.
    pub admitted: OrdMap<Kappa, Admission>,
    /// Transition and publication evidence the namespace retains: every
    /// record its ledgers, roots and state commitments name. Held apart from
    /// logical admission, so storing evidence never admits content and
    /// retiring content never releases evidence history still names.
    pub evidence: OrdMap<Kappa, Admission>,
    /// Identity to the aliases and composites of this view selecting it.
    pub selected_by: OrdMap<Kappa, OrdSet<Kappa>>,
    /// Identity to the direct tags and epoch head of this view naming it.
    pub references: OrdMap<Kappa, u64>,
    pub blob_meta: OrdMap<(Kappa, String), Vec<u8>>,
    pub authorization: Authorization,
    pub identity: IdentityRows,

    // -- Authenticated state machinery --
    /// The nodes of the authenticated current-state index, keyed by their
    /// hash: every node of every root this namespace sealed, so a proof
    /// against any of its published roots is served from its current view.
    /// Views share the map structurally; a candidate writes into a clone
    /// that shares every node it does not add.
    pub state_nodes: OrdMap<[u8; 32], Node>,
    /// Root of the authenticated index after the last sealed epoch.
    /// `state_index::EMPTY` before genesis.
    pub state_index_root: [u8; 32],
    /// Index changes this candidate's transitions derived, in execution
    /// order. The seal reduces them to the last value per path.
    pub pending_state_changes: Vec<Change>,
    /// The RFC 9162 log builder carrying the peaks of the last sealed
    /// epoch. Sealing extends it by the epoch's mutations.
    pub history: StreamingTree,
    /// Emitted history nodes retained alongside the append continuation.
    pub history_nodes: OrdMap<u64, [u8; 32]>,
    /// The namespace-state record the last sealed epoch committed. `None`
    /// before genesis. The next seal's `StateInput::predecessor` uses it.
    pub committed_state: Option<NamespaceState>,
}

/// `NodeSource` over the view's retained index nodes.
impl NodeSource for NamespaceView {
    fn node(&self, hash: &[u8; 32]) -> Result<Node, StoreError> {
        self.state_nodes.get(hash).copied().ok_or_else(|| {
            StoreError::Internal(format!(
                "state index node {} is not retained by this view",
                hex::encode(hash)
            ))
        })
    }
}

impl NamespaceView {
    /// The logical incarnation of this namespace instance: the one accessor
    /// every transition domain, receipt, authority record and activation
    /// domain of the namespace takes its incarnation from. Its
    /// representation is the counter in big-endian in bytes 8..16.
    pub fn logical_incarnation(&self) -> LogicalIncarnation {
        let mut bytes = [0u8; 16];
        bytes[8..].copy_from_slice(&self.incarnation.to_be_bytes());
        LogicalIncarnation::from_bytes(bytes)
    }

    /// The representation of [`Self::logical_incarnation`], for the
    /// records that carry it.
    pub fn incarnation_bytes(&self) -> [u8; 16] {
        *self.logical_incarnation().as_bytes()
    }

    /// The bytes this view holds for `identity`: its logical admission, or
    /// the evidence it retains under that identity.
    pub fn held(&self, identity: &Kappa) -> Option<&Admission> {
        self.admitted
            .get(identity)
            .or_else(|| self.evidence.get(identity))
    }

    /// Whether this view can serve the bytes of `identity`.
    pub fn holds(&self, identity: &Kappa) -> bool {
        self.held(identity).is_some()
    }

    /// The view of a namespace slot before its first publication.
    pub fn empty(incarnation: u64) -> Self {
        Self {
            incarnation,
            state_index_root: state_index::EMPTY,
            ..Self::default()
        }
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
