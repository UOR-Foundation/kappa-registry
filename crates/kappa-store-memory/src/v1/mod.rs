//! `InMemoryStore`: reference implementation of all store sub-traits.
//!
//! Each namespace is a slot holding its published view (`view`) behind its
//! own pointer and its own writer gate (`writers`). An execution holds its
//! namespace's gate, writes a private clone of the namespace's view, and
//! publishes it with one pointer store into that slot. Publication of one
//! namespace waits on no other namespace: there is no store-wide
//! installation lock and no store-wide generation.
//!
//! What spans namespaces is coordinated by the constraint it belongs to:
//!
//! - registry-wide lookups find namespaces through projections
//!   (`projection`), registered before the view store and confirmed
//!   against the published views;
//! - keys only one namespace may hold are claims (`claims`);
//! - the succession graph admits links against every namespace's links
//!   (`succession_graph`);
//! - authorization rows other executions depend on are ordered by stripes
//!   held across validation and the view store (`dependency`);
//! - authority rotation is ordered against every publication by the
//!   activation gate, held shared from seal to store;
//! - physical files are allocation instances shared by identity and owned
//!   by the views and readers holding them (`allocation`).
//!
//! The availability contract is the process lifetime.

mod allocation;
pub mod availability;
mod blob;
mod blob_read;
mod blob_stream;
mod cache_layout;
mod claims;
mod content;
mod content_apply;
mod content_install;
mod dependency;
mod edge;
mod epoch;
mod epoch_read;
mod execution;
mod execution_reads;
mod execution_writes;
mod identity;
mod identity_authorization_write;
mod identity_local;
mod identity_read;
mod identity_write;
mod locate;
mod locator;
mod maintenance;
mod namespace;
mod namespace_write;
mod operation;
mod projection;
mod segments;
mod sequence;
mod succession_graph;
mod tag;
mod view;
mod writers;

#[cfg(test)]
mod tests;

/// Shared test-fixture construction for every crate that needs an
/// in-memory store.
///
/// Available under `cfg(test)` for unit tests within this crate and
/// under `feature = "test-util"` for integration tests and downstream
/// crates. The crate's own integration tests enable `test-util` via
/// a self-dev-dependency.
#[cfg(any(test, feature = "test-util"))]
pub mod test_support;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use arc_swap::ArcSwap;
use dashmap::DashMap;

use kappa_store::EpochAuthority;
use kappa_store::traits::StoreToken;
use kappa_types::capacity::CapacityPool;
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::namespace::NamespaceRef;
use kappa_types::work::{WorkLimit, WorkMeter};

use allocation::AllocationTable;
use claims::{Claims, Holder};
use dependency::Stripes;
use locator::Contribution;
use projection::Projections;
use succession_graph::SuccessionGraph;
use view::{NamespaceId, NamespaceView};
use writers::Gate;

pub use content::MemoryPrepared;
pub use execution::MemoryExecution;

/// Configuration for the in-memory store.
///
/// The signing authority is supplied whole by the caller and cannot be
/// split or replaced piecewise: the store signs every epoch with the
/// authority's signer under the anchor that signer derives.
#[non_exhaustive]
pub struct MemoryStoreConfig {
    pub blob_root: PathBuf,
    authority: kappa_crypto::SigningAuthority,
    resource_owner: Option<Arc<dyn Send + Sync>>,
    maintenance_handles: u64,
    maintenance_bytes: u64,
    publication_work: WorkLimit,
    read_work: WorkLimit,
    publication_retention: u64,
    encoding_storage: u64,
    decoded_storage: u64,
}

/// Directory handles suspended maintenance may hold open by default: four
/// full inventory walks of the cache layout.
pub const DEFAULT_MAINTENANCE_HANDLES: u64 = 4 * (cache_layout::DIRECTORY_DEPTH as u64 + 1);
/// Bytes of path buffers suspended maintenance may hold by default: four
/// walks' deferred-path allowances.
pub const DEFAULT_MAINTENANCE_BYTES: u64 = 4 * maintenance::DEFERRED_PATH_ALLOWANCE;

impl MemoryStoreConfig {
    /// Configuration with established signing authority and the bytes of
    /// publication evidence the store may retain in memory.
    ///
    /// `publication_retention` bounds every record a signed root generates
    /// (its encoding and its edges, held inline with their segment digests
    /// and rows) from the moment its publication's coordinate is consumed
    /// until the last view holding the record is dropped. It is required and
    /// has no default: a store refuses to open without a positive bound
    /// (`InMemoryStore::new`), and a publication whose retention does not
    /// fit is refused before its coordinate is consumed.
    pub const fn new(
        blob_root: PathBuf,
        authority: kappa_crypto::SigningAuthority,
        publication_retention: u64,
    ) -> Self {
        Self {
            blob_root,
            authority,
            resource_owner: None,
            maintenance_handles: DEFAULT_MAINTENANCE_HANDLES,
            maintenance_bytes: DEFAULT_MAINTENANCE_BYTES,
            publication_work: WorkLimit::unbounded(),
            read_work: WorkLimit::unbounded(),
            publication_retention,
            encoding_storage: kappa_types::canonical::DEFAULT_ENCODING_STORAGE,
            decoded_storage: kappa_types::canonical::DEFAULT_DECODED_STORAGE,
        }
    }

    /// Bound the work one read operation may do: evidence examined,
    /// decoded, allocated and hashed, signatures verified. Every read builds
    /// one meter at this ceiling where it enters the store
    /// ([`InMemoryStore::read_meter`]) and threads it through every read it
    /// nests.
    #[must_use]
    pub const fn read_work(mut self, limit: WorkLimit) -> Self {
        self.read_work = limit;
        self
    }

    /// Bound the bytes of canonical encodings the store's operations may
    /// hold live at once: prepared normalization scratch and encoded records
    /// awaiting their storage. Positive; default
    /// `canonical::DEFAULT_ENCODING_STORAGE`.
    #[must_use]
    pub const fn encoding_storage(mut self, bytes: u64) -> Self {
        self.encoding_storage = bytes;
        self
    }

    /// Bound decoder arenas and typed values retained by read operations.
    #[must_use]
    pub const fn decoded_storage(mut self, bytes: u64) -> Self {
        self.decoded_storage = bytes;
        self
    }

    /// Bound the work one publication's seal may do: index nodes examined,
    /// ledger and evidence bytes encoded, allocated and hashed, signatures.
    /// Every publication also carries its execution's deadline as the
    /// admission deadline of that work.
    #[must_use]
    pub const fn publication_work(mut self, limit: WorkLimit) -> Self {
        self.publication_work = limit;
        self
    }

    /// Bound what suspended maintenance continuations may retain: open
    /// directory handles, and bytes of path buffers.
    #[must_use]
    pub const fn maintenance_capacity(mut self, handles: u64, bytes: u64) -> Self {
        self.maintenance_handles = handles;
        self.maintenance_bytes = bytes;
        self
    }

    /// Retain `owner` for the store's lifetime. Every handle to the store,
    /// concrete or `Arc<dyn KappaStore>`, keeps it alive; the caller uses
    /// this for the filesystem scope that contains `blob_root`.
    #[must_use]
    pub fn retaining(mut self, owner: Arc<dyn Send + Sync>) -> Self {
        self.resource_owner = Some(owner);
        self
    }
}

/// One namespace: its published view, its writer gate, and its signing
/// coordinate. A slot lives as long as the store, so its gate is the
/// namespace's only gate.
pub struct Slot {
    pub(crate) view: ArcSwap<NamespaceView>,
    pub(crate) gate: Arc<Gate>,
    /// The highest epoch number of this slot whose signing coordinate is
    /// consumed. Outside every candidate view, so no abort or failed
    /// publication restores it: a seal reserves `head + 1` only while this
    /// equals the head's number, and a coordinate consumed by a seal that
    /// did not publish fences the slot against every later seal.
    pub(crate) signed: AtomicU64,
    /// The publication whose signing coordinate is consumed and which is not
    /// published, with every obligation it owns (`execution::Pending`). Held
    /// in place, so taking custody of a publication allocates nothing; its
    /// presence fences the slot until resolution
    /// (`ExecutionStore::resolve_publication`) publishes it.
    pub(crate) pending: Mutex<Option<execution::Pending>>,
}

/// No epoch was sealed yet.
const NO_EPOCH: i64 = i64::MIN;

/// The next value of `counter`, never reusing one: an exhausted counter
/// refuses instead of wrapping.
fn next(counter: &AtomicU64, what: &str) -> Result<u64, StoreError> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| StoreError::CapacityExceeded(format!("{what} exhausted")))
}

pub struct InMemoryStore {
    /// Current signing authority and its admitted succession history.
    /// Replaced only whole, under the exclusive `activation` gate, by
    /// `rotate_authority`; every publication seals and stores under the
    /// shared gate, so no publication signs with an authority a completed
    /// rotation retired and no rotation passes an epoch that is about to be
    /// stored.
    pub(crate) authority: ArcSwap<EpochAuthority>,
    pub(crate) activation: RwLock<()>,
    /// Set, under the exclusive activation gate, while an activation's
    /// governing epoch is retained unpublished: the incoming authority may
    /// still be installed, so no epoch is sealed under the outgoing one
    /// until the activation is resolved.
    pub(crate) activation_unresolved: AtomicBool,
    /// The latest timestamp of any epoch any namespace sealed: the lineage
    /// summary an authority transition is checked against. Raised under the
    /// shared activation gate by every publication, read under the
    /// exclusive gate by rotation.
    pub(crate) latest_epoch_ms: AtomicI64,

    pub(crate) slots: DashMap<NamespaceId, Arc<Slot>>,
    pub(crate) projections: Projections,
    pub(crate) claims: Claims,
    pub(crate) successions: SuccessionGraph,
    pub(crate) stripes: Stripes,
    pub(crate) allocations: AllocationTable,

    incarnations: AtomicU64,
    attempts: AtomicU64,
    /// Where the bounded session expiry resumes (`identity_local`).
    pub(crate) session_eviction_cursor: Mutex<Option<(NamespaceId, String)>>,
    /// This store instance's identity in the maintenance continuations it
    /// returns.
    pub(crate) instance: StoreToken,
    /// Directory handles and path-buffer bytes maintenance continuations
    /// retain while suspended (`maintenance`).
    pub(crate) maintenance_handles: Arc<CapacityPool>,
    pub(crate) maintenance_bytes: Arc<CapacityPool>,
    /// What one publication's seal may do (`MemoryStoreConfig::publication_work`).
    pub(crate) publication_work: WorkLimit,
    /// The ceiling of one read operation (`MemoryStoreConfig::read_work`).
    pub(crate) read_work: WorkLimit,
    /// Bytes of generated publication evidence held in memory
    /// (`MemoryStoreConfig::new`). A publication reserves its records' bound
    /// before its coordinate is consumed; each installed record carries its
    /// share into every view holding it.
    pub(crate) publication_retention: Arc<CapacityPool>,
    /// Bytes of canonical encodings operations hold live
    /// (`MemoryStoreConfig::encoding_storage`).
    pub(crate) encoding_storage: Arc<CapacityPool>,
    pub(crate) decoded_storage: Arc<CapacityPool>,

    /// Opaque owner of the filesystem scope containing the blob root,
    /// retained for the store's lifetime (see
    /// [`MemoryStoreConfig::retaining`]). Declared last so it drops after
    /// every other field, the allocation table included. Maintenance walks
    /// clone it so their open listings keep the scope alive.
    resource_owner: Option<Arc<dyn Send + Sync>>,
}

impl InMemoryStore {
    pub fn new(config: MemoryStoreConfig) -> Result<Self, StoreError> {
        if config.publication_retention == 0 {
            return Err(StoreError::Rejected(
                "publication retention capacity must be positive".into(),
            ));
        }
        if config.encoding_storage == 0 {
            return Err(StoreError::Rejected(
                "encoding storage capacity must be positive".into(),
            ));
        }
        if config.decoded_storage == 0 {
            return Err(StoreError::Rejected(
                "decoded storage capacity must be positive".into(),
            ));
        }
        std::fs::create_dir_all(&config.blob_root)?;
        Ok(Self {
            authority: ArcSwap::from_pointee(EpochAuthority::new(config.authority)?),
            activation: RwLock::new(()),
            activation_unresolved: AtomicBool::new(false),
            latest_epoch_ms: AtomicI64::new(NO_EPOCH),
            slots: DashMap::new(),
            projections: Projections::default(),
            claims: Claims::default(),
            successions: SuccessionGraph::default(),
            stripes: Stripes::default(),
            allocations: AllocationTable::new(config.blob_root, config.resource_owner.clone()),
            incarnations: AtomicU64::new(1),
            attempts: AtomicU64::new(1),
            session_eviction_cursor: Mutex::new(None),
            instance: StoreToken::new(),
            maintenance_handles: Arc::new(CapacityPool::new(
                "maintenance directory handles",
                config.maintenance_handles,
            )),
            maintenance_bytes: Arc::new(CapacityPool::new(
                "maintenance path buffers",
                config.maintenance_bytes,
            )),
            publication_work: config.publication_work,
            read_work: config.read_work,
            publication_retention: Arc::new(CapacityPool::new(
                "retained publication evidence",
                config.publication_retention,
            )),
            encoding_storage: Arc::new(CapacityPool::new(
                "canonical encodings",
                config.encoding_storage,
            )),
            decoded_storage: Arc::new(CapacityPool::new("decoded records", config.decoded_storage)),
            resource_owner: config.resource_owner,
        })
    }

    /// The anchor new epochs are signed under.
    pub fn node_anchor(&self) -> Kappa {
        self.authority.load().anchor().clone()
    }

    /// The meter of one read operation, at the configured ceiling: built
    /// once where a read enters the store and threaded through every read
    /// it nests, so the whole operation answers within it or is refused.
    pub(crate) const fn read_meter(&self) -> WorkMeter {
        WorkMeter::new(self.read_work)
    }

    /// The slot of `namespace`, created with a fresh incarnation on first
    /// use.
    pub(crate) fn slot(&self, namespace: &NamespaceId) -> Result<Arc<Slot>, StoreError> {
        if let Some(slot) = self.slots.get(namespace) {
            return Ok(Arc::clone(&slot));
        }
        let entry = self.slots.entry(*namespace);
        if let dashmap::Entry::Occupied(slot) = &entry {
            return Ok(Arc::clone(slot.get()));
        }
        let incarnation = next(&self.incarnations, "namespace incarnations")?;
        Ok(Arc::clone(&entry.or_insert_with(|| {
            Arc::new(Slot {
                view: ArcSwap::from_pointee(NamespaceView::empty(incarnation)),
                gate: Arc::new(Gate::default()),
                signed: AtomicU64::new(0),
                pending: Mutex::new(None),
            })
        })))
    }

    /// The published view of `namespace`; an empty view for a namespace
    /// that never published, without creating its slot.
    pub(crate) fn view(&self, namespace: &NamespaceId) -> Arc<NamespaceView> {
        self.slots.get(namespace).map_or_else(
            || Arc::new(NamespaceView::default()),
            |slot| slot.view.load_full(),
        )
    }

    /// The published view a candidate names, when it has reached the
    /// candidate's revision in the candidate's incarnation: the view in
    /// which a projection entry or claim is decided.
    pub(crate) fn confirm(&self, candidate: Contribution) -> Option<Arc<NamespaceView>> {
        let view = self.slots.get(&candidate.namespace)?.view.load_full();
        (view.incarnation == candidate.incarnation && view.revision >= candidate.revision)
            .then_some(view)
    }

    /// The published view of a claim holder, in the holder's incarnation.
    pub(crate) fn holder_view(&self, holder: Holder) -> Option<Arc<NamespaceView>> {
        let view = self.slots.get(&holder.namespace)?.view.load_full();
        (view.incarnation == holder.incarnation).then_some(view)
    }

    /// A namespace reference for `namespace` named by its published record.
    pub(crate) fn reference(namespace: &NamespaceId, view: &NamespaceView) -> NamespaceRef {
        view.record.as_ref().map_or_else(
            || NamespaceRef::resolved(*namespace, hex::encode(namespace), None),
            |record| {
                NamespaceRef::resolved(*namespace, record.name.clone(), record.protocol.clone())
            },
        )
    }

    /// A publication attempt identity, unique for the store's lifetime.
    pub(crate) fn attempt(&self) -> Result<u64, StoreError> {
        next(&self.attempts, "publication attempts")
    }

    /// The latest epoch timestamp sealed by any namespace, if any.
    pub(crate) fn latest_epoch(&self) -> Option<i64> {
        let latest = self.latest_epoch_ms.load(Ordering::Acquire);
        (latest != NO_EPOCH).then_some(latest)
    }
}
