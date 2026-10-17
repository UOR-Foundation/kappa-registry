use std::path::PathBuf;
use std::sync::Arc;

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
    /// Durable recovery records (retirements, creation intents, pending
    /// markers) and known obligations the one recovery step at open visits;
    /// maintenance steps resume after it (`settlement_recovery`). Default
    /// 4096.
    pub recovery_step_entries: u64,
    /// Ledger elements, seal records and edges one recovery or settlement
    /// step examines across every epoch it reads (`settlement_ledger`).
    /// Default 4096.
    pub recovery_step_mutations: u64,
    /// Bytes one recovery or settlement step reads, decodes or copies.
    /// At least twice the reservation of one mutation
    /// (`SettlementLimits::minimum_step_bytes`), so each half of a split
    /// step admits one. Default 256 MiB.
    pub recovery_step_bytes: u64,
    /// Largest ledger element, referenced record or row settlement reads;
    /// a larger one is refused before it is copied or decoded and leaves
    /// its epoch an unresolved recovery obligation. At least the epoch
    /// root limit (8 MiB) and above `inline_limit`. Default 8 MiB.
    pub settlement_record_bytes: u64,
    /// Bytes of projection versions settlement may hold staged and not yet
    /// compacted (`projection_stage`); a step that would exceed it waits
    /// for compaction. At least `recovery_step_bytes`. Default 1 GiB.
    pub settlement_staging_bytes: u64,
    /// Epochs settlement and recovery may hold partly read at once, each
    /// owning one namespace activity grant until it completes. At least
    /// one and below `max_active_namespaces`. Default 16.
    pub max_epoch_cursors: usize,
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
    /// Whether to load all credentials into an in-memory `DashMap`
    /// at startup for O(1) lookup on every authenticated request.
    /// Disable on memory-constrained devices. Default false.
    pub enable_credential_cache: bool,
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
            recovery_step_entries: 4096,
            recovery_step_mutations: 4096,
            recovery_step_bytes: 256 * 1024 * 1024,
            settlement_record_bytes: 8 * 1024 * 1024,
            settlement_staging_bytes: 1024 * 1024 * 1024,
            max_epoch_cursors: 16,
            node_id: std::env::var("HOSTNAME").unwrap_or_else(|_| "node".to_string()),
            max_idle_namespaces: crate::storage::DEFAULT_MAX_IDLE_HANDLES,
            max_active_namespaces: crate::storage::DEFAULT_MAX_ACTIVE_HANDLES,
            max_unsettled_epochs: 256,
            max_unsettled_entries: 65_536,
            max_unsettled_bytes: 4 * 1024 * 1024 * 1024,
            max_unsettled_identities: 262_144,
            encryption_key: None,
            enable_credential_cache: false,
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
