use std::path::PathBuf;
use std::sync::Arc;

use kappa_store::work::{Dimension, WorkLimit};

/// Bytes a default recovery step may read, decode, allocate and hash.
const STEP_BYTES: u64 = 256 * 1024 * 1024;

/// The default recovery step: finite on every dimension.
const DEFAULT_RECOVERY_STEP: WorkLimit = WorkLimit::unbounded()
    .with(Dimension::Entries, 65_536)
    .with(Dimension::BytesRead, STEP_BYTES)
    .with(Dimension::BytesDecoded, STEP_BYTES)
    .with(Dimension::BytesAllocated, STEP_BYTES)
    .with(Dimension::BytesHashed, STEP_BYTES)
    .with(Dimension::Signatures, 8192)
    .with(Dimension::Handles, 4096)
    .with(Dimension::Candidates, 4096);

/// The default ceiling of one read operation, with the same finite
/// dimensional allowances as a recovery step.
const DEFAULT_READ_WORK: WorkLimit = DEFAULT_RECOVERY_STEP;

/// Configuration for `PersistentStore` construction.
///
/// `PersistentStoreConfig::new(blob_root, db_path, authority)` sets the
/// defaults; override the public fields before `PersistentStore::new`. The
/// signing authority is supplied whole by the composition root and cannot be
/// split or replaced piecewise: the store signs and admits every epoch with
/// the authority's signer under the anchor that signer derives.
#[non_exhaustive]
pub struct PersistentStoreConfig {
    /// Root directory of content allocations (`objects/{hex[0..2]}/{hex}`).
    pub blob_root: PathBuf,
    /// Path to the redb database file.
    pub db_path: PathBuf,
    /// Whether to fsync content files and their directories before they
    /// are indexed, and staged upload writes. Default true. Committed
    /// database writes use redb's durable transaction policy.
    pub fsync: bool,
    /// Complete encoded representation limit for inline placement.
    pub inline_limit: u64,
    pub max_components: usize,
    pub preparation_entries: usize,
    pub preparation_bytes: u64,
    pub durability_batch_entries: usize,
    pub durability_batch_bytes: u64,
    /// Inventory entries examined by the one bounded step that runs at
    /// open; the maintenance inventory resumes after it. Default 4096.
    pub open_inventory_entries: usize,
    /// Maintenance passes that may be suspended at once holding a storage
    /// handle (an open directory stream) in their continuation. A pass
    /// that cannot reserve one refuses to start; a dropped continuation
    /// releases its reservation with its handle. Default 16.
    pub max_suspended_traversals: u64,
    /// What one recovery step may do, on every work dimension: the step
    /// at open, and the defaults of a settlement step a caller bounds on
    /// fewer dimensions (`settlement_recovery`). It must admit one whole
    /// epoch unit (`SettlementLimits::epoch_unit`) on every dimension,
    /// and carry no deadline: a deadline is a step's, set by its caller.
    /// Default: 65536 entries, 8192 signatures, 4096 handles and candidates,
    /// 256 MiB read, decoded, allocated and hashed.
    pub recovery_step: WorkLimit,
    /// What one publication's seal may do, on every work dimension, with an
    /// execution's deadline as its admission deadline; the seal and every
    /// resolution of a retained publication are admitted against it.
    /// Default unbounded, as the in-memory backend's.
    pub publication_work: WorkLimit,
    /// The ceiling of one read operation, on every work dimension: each
    /// read the store serves runs on one meter built from it at its
    /// boundary, threaded through every nested read, and is answered
    /// completely or refused (`StoreError::WorkRefused`), never answered
    /// with a partial result taken for absence. It must admit one
    /// projection version at the settlement record limit
    /// (`SettlementLimits::selection_unit`) and carry no deadline: a
    /// deadline is a request's. Default: the recovery step's allowances
    /// with 65536 entries.
    pub read_work: WorkLimit,
    /// Bytes of canonical encodings the store's operations may hold live at
    /// once: prepared normalization scratch and encoded records awaiting
    /// their storage, each released when its bytes are. Positive; default
    /// `canonical::DEFAULT_ENCODING_STORAGE` (64 MiB).
    pub encoding_storage: u64,
    /// Raw record destinations retained by readers. None derives capacity
    /// from the final cursor count, record limit and chunk scratch bound.
    pub settlement_read_bytes: Option<u64>,
    /// Decoder arenas and constructed records retained by readers.
    pub settlement_decoded_bytes: u64,
    /// Largest custody record of a retained publication (`custody`): a
    /// seal whose record would exceed it is refused before its coordinate
    /// is consumed, and a larger record is refused before it is read.
    /// Default 64 MiB.
    pub custody_record_bytes: u64,
    /// Largest ledger element, referenced record or row settlement reads;
    /// a larger one is refused before it is copied or decoded and leaves
    /// its epoch an unresolved recovery obligation. At least the epoch
    /// root limit (8 MiB) and above `inline_limit`. Default 8 MiB.
    pub settlement_record_bytes: u64,
    /// Bytes of projection versions settlement may hold staged and not yet
    /// compacted (`projection_stage`); a step that would exceed it waits
    /// for compaction. At least what one recovery step reads. Default
    /// 1 GiB.
    pub settlement_staging_bytes: u64,
    /// Epochs settlement and recovery may hold partly read at once, each
    /// owning one namespace activity grant until it completes. At least
    /// one and below `max_active_namespaces`. Default 16.
    pub max_epoch_cursors: usize,
    /// Bytes of retained preparation the pending elements of every epoch
    /// cursor may hold at once: the keys settlement builds for an element
    /// before applying it, kept across deferred steps and released with the
    /// element. At least one element's bound under the settlement record
    /// limit (`settlement::element_preparation_bytes`). Default: that bound
    /// for every cursor of the defaults (16 cursors at 8 MiB records).
    pub settlement_preparation_bytes: u64,
    /// This node's identity in control-plane memberships. Default: the
    /// host name, or `node` when it cannot be read.
    pub node_id: String,
    /// Namespace databases kept open while idle; see
    /// `storage::DEFAULT_MAX_IDLE_HANDLES`.
    pub max_idle_namespaces: usize,
    /// Namespace controllers that may be active at once; see
    /// `storage::DEFAULT_MAX_ACTIVE_HANDLES`.
    pub max_active_namespaces: usize,
    /// Committed epochs one namespace may hold unsettled before its
    /// admission refuses further executions. Default 256.
    pub max_unsettled_epochs: usize,
    /// Allocations every namespace together may hold unsettled (parked
    /// between commit and settlement). Default 65536.
    pub max_unsettled_entries: u64,
    /// Bytes of allocations held unsettled across every namespace.
    /// Default 4 GiB.
    pub max_unsettled_bytes: u64,
    /// Identities every namespace together may hold committed but not yet
    /// settled, each discoverable by identity alone through the unsettled
    /// identity index (`unsettled_index`). A publication that would exceed
    /// it is refused before it commits. Default 262144.
    pub max_unsettled_identities: u64,
    /// Optional 32-byte key for authenticated blob-chunk and table-value
    /// encryption. None means plaintext storage.
    pub encryption_key: Option<[u8; 32]>,
    /// Optional `StorageBackend` factory. None uses redb's default
    /// `FileBackend`. Some provides a custom backend (raw block device,
    /// S3-backed, RADOS omap). The factory is called once during
    /// `PersistentStore::new`.
    pub backend: Option<Box<dyn Fn() -> Box<dyn redb::StorageBackend> + Send>>,
    /// Optional `StorageBackend` factory for namespace databases, called
    /// with the namespace identity each time its database is opened;
    /// `None` from the factory opens the file backend at the namespace's
    /// path. Tests inject faults into one namespace's commits with it.
    pub namespace_backend: Option<crate::storage::NamespaceBackend>,
    pub(crate) authority: kappa_crypto::SigningAuthority,
    pub(crate) alternates: Vec<kappa_crypto::SigningAuthority>,
    pub(crate) require_history: bool,
    pub(crate) resource_owner: Option<Arc<dyn Send + Sync>>,
}

impl PersistentStoreConfig {
    pub fn new(
        blob_root: PathBuf,
        db_path: PathBuf,
        authority: kappa_crypto::SigningAuthority,
    ) -> Self {
        Self {
            blob_root,
            db_path,
            fsync: true,
            inline_limit: 16 * 1024,
            max_components: 4096,
            preparation_entries: 256,
            preparation_bytes: 4 * 1024 * 1024 * 1024,
            durability_batch_entries: 64,
            durability_batch_bytes: 256 * 1024 * 1024,
            open_inventory_entries: 4096,
            max_suspended_traversals: 16,
            recovery_step: DEFAULT_RECOVERY_STEP,
            publication_work: WorkLimit::unbounded(),
            read_work: DEFAULT_READ_WORK,
            encoding_storage: kappa_store::canonical::DEFAULT_ENCODING_STORAGE,
            settlement_read_bytes: None,
            settlement_decoded_bytes: kappa_store::canonical::DEFAULT_DECODED_STORAGE,
            custody_record_bytes: 64 * 1024 * 1024,
            settlement_record_bytes: 8 * 1024 * 1024,
            settlement_staging_bytes: 1024 * 1024 * 1024,
            max_epoch_cursors: 16,
            settlement_preparation_bytes: crate::settlement::default_preparation_bytes(
                16,
                8 * 1024 * 1024,
            ),
            node_id: std::env::var("HOSTNAME").unwrap_or_else(|_| "node".to_string()),
            max_idle_namespaces: crate::storage::DEFAULT_MAX_IDLE_HANDLES,
            max_active_namespaces: crate::storage::DEFAULT_MAX_ACTIVE_HANDLES,
            max_unsettled_epochs: 256,
            max_unsettled_entries: 65_536,
            max_unsettled_bytes: 4 * 1024 * 1024 * 1024,
            max_unsettled_identities: 262_144,
            encryption_key: None,
            backend: None,
            namespace_backend: None,
            authority,
            alternates: Vec::new(),
            require_history: false,
            resource_owner: None,
        }
    }

    /// Further authorities the persisted history may end at: every other
    /// intact key the node holds, such as a successor staged by a rotation
    /// that committed before the process stopped. Opening a store with
    /// history selects the one authority whose key is the history's last;
    /// the history alone decides, so a crash anywhere between the store's
    /// durable rotation and the key store's settlement resolves to the
    /// authority that actually signs. Read the outcome from
    /// [`crate::PersistentStore::node_anchor`]. A store without history
    /// records the configured authority as its origin.
    #[must_use]
    pub fn with_alternates(mut self, alternates: Vec<kappa_crypto::SigningAuthority>) -> Self {
        self.alternates = alternates;
        self
    }

    /// Refuse to open a store without authority history instead of
    /// recording the configured authority as its origin. For a caller that
    /// holds several keys and no independent record of which one is
    /// current: only committed history may choose among them.
    #[must_use]
    pub const fn requiring_history(mut self) -> Self {
        self.require_history = true;
        self
    }

    /// Retain `owner` for as long as any resource of the store needs the
    /// filesystem scope it represents: the store itself, and every encrypted
    /// blob reader, whose later reads consult erasure state under
    /// `blob_root`. Callers pass the owner of the directory containing
    /// `blob_root` and `db_path`.
    #[must_use]
    pub fn retaining(mut self, owner: Arc<dyn Send + Sync>) -> Self {
        self.resource_owner = Some(owner);
        self
    }
}
