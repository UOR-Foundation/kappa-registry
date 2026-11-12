#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod test_hooks;

/// Fixture configuration for tests in this crate and downstream crates.
#[cfg(any(test, feature = "test-util"))]
pub mod test_support;

mod allocation;
mod authority;
mod backend;
pub mod blob;
mod blob_cipher;
mod blob_encryption;
mod blob_rows;
mod chunk_integrity;
mod commitments;
pub mod config;
mod content_admit;
mod content_install;
mod content_inventory;
mod content_prepare;
mod content_read;
mod content_reclaim;
mod content_stream;
pub mod control_plane;
pub mod credentials;
mod custody;
mod custody_inventory;
mod custody_resolve;
mod derived_index;
mod durability;
pub mod edge;
mod edge_write;
pub mod encrypted;
pub mod epoch;
mod epoch_blob;
mod epoch_cache;
mod epoch_execution;
mod epoch_seal;
mod error;
pub mod frame_reader;
pub mod identity;
mod identity_anchor;
mod identity_anchor_write;
mod identity_local;
mod identity_query;
mod identity_records;
mod identity_write;
mod index_repair;
mod instance_record;
pub mod namespace;
mod namespace_snapshot;
mod namespace_write;
mod operation;
mod projection;
mod projection_compact;
mod projection_cursor;
mod projection_stage;
pub mod redb_cursor;
mod referrers;
mod registry;
mod representation;
mod representation_codec;
mod retirement_record;
pub mod sequence;
mod settlement;
mod settlement_identity;
mod state_nodes;
pub mod storage;
mod storage_instance;
mod storage_retirement;
mod store_access;
mod store_open;
pub mod tables;
pub mod tag;
mod tag_state;
mod tag_write;
mod time_state;
mod transition_apply;
mod unsettled;
mod unsettled_index;

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::Ordering;

use dashmap::DashMap;

use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::work::{Dimension, WorkLimit, WorkMeter};

pub use config::PersistentStoreConfig;
pub use content_install::PreparedContent;
pub use control_plane::{
    Agreement, AssignmentRecord, ConflictPolicy, ControlPlane, ControlPlaneId, ControlPlanes,
    Decision, Guarantees, LatestWriterWins, LeaseAgreement, LocalAgreement, Membership,
    NoConflicts, NodeId, Proposal, ProtocolBinding,
};
pub use epoch_execution::EpochExecution;
pub use referrers::{CONTENT_SCOPE, Referrer, ReferrerCursor, Source as ReferrerSource};
pub use storage::{Active, NamespaceController, NamespaceStorage, Opening};

/// Blob chunk size in bytes: one AEAD frame, so an encrypted chunk carries
/// exactly one authentication tag and range reads stay positional.
pub const BLOB_CHUNK_SIZE: usize = 64 * 1024;

pub struct PersistentStore {
    pub(crate) protection: std::sync::Arc<allocation::Protection>,
    pub(crate) content_durability: durability::Durability,
    pub(crate) representation_limits: representation::RepresentationLimits,
    pub(crate) blob_encryptor: Option<std::sync::Arc<blob_encryption::BlobEncryption>>,
    pub(crate) time_authority_owned: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The registry: projections settled from namespace epochs, the
    /// directory, the registry-wide authority and node-local state, behind
    /// the one writer slot every registry write transaction holds
    /// (`registry::Registry`). No ordinary publication writes to it.
    pub(crate) registry: std::sync::Arc<registry::Registry>,
    /// The namespace databases, each owned by its controller.
    pub(crate) namespaces: storage::NamespaceStorage,
    /// The control planes this node participates in.
    pub(crate) planes: std::sync::Arc<control_plane::ControlPlanes>,
    pub(crate) fsync: bool,
    pub(crate) chunk_size: usize,
    /// Root of content allocations: `objects/{hex[0..2]}/{hex}` and their
    /// `.chunks` sidecars (see `allocation`).
    pub(crate) blob_root: PathBuf,
    /// Commitments admitted through authenticated epoch state, cached once
    /// per process (see `content_read::ReadView::resolve_commitment`).
    pub(crate) commitments: std::sync::Arc<DashMap<Kappa, kappa_store::ContentCommitment>>,
    pub(crate) epoch_cache: epoch_cache::EpochCache,
    pub(crate) table_encryptor: Option<std::sync::Arc<encrypted::TableEncryptor>>,
    /// Current signing authority and its admitted succession history,
    /// recovered at open from the governing activation evidence the
    /// `AUTHORITY_HISTORY` projection names. Replaced only whole, by
    /// `rotate_authority`, and only after the governing epoch committed, so
    /// no reader ever observes an uncommitted authority.
    pub(crate) authority: std::sync::Arc<arc_swap::ArcSwap<kappa_store::EpochAuthority>>,
    /// Signing capability of an unresolved activation, never used by ordinary seals.
    /// Transferred from the activation hold before its gate is released.
    pub(crate) retained_authority: arc_swap::ArcSwapOption<kappa_store::EpochAuthority>,
    /// Orders authority installation against epoch signing. Rotation holds
    /// it exclusively from inside its registry write transaction until the
    /// committed authority is installed; sealing holds it shared while it
    /// signs and while it commits, so no epoch is signed under an authority
    /// a rotation has already retired and no rotation validates against a
    /// `latest_epoch_ms` that a signed, uncommitted epoch will raise.
    pub(crate) activation: std::sync::RwLock<()>,
    /// Set, under the exclusive activation gate, when a rotation's durable
    /// commit failed: whether its transition is persisted is unknown, so
    /// neither the outgoing nor the incoming authority may sign.
    pub(crate) authority_unresolved: std::sync::atomic::AtomicBool,
    /// Latest timestamp of any epoch this store has signed or recovered,
    /// raised when the epoch is signed (under the shared activation gate,
    /// before its commit), so a rotation that takes the gate exclusively
    /// afterwards observes every epoch that may commit under the outgoing
    /// authority. A transition must take effect after it.
    pub(crate) latest_epoch_ms: std::sync::atomic::AtomicI64,
    /// Greatest causal time any recovered or committed namespace
    /// transaction carries (`time_state`); `i64::MIN` until one is known.
    pub(crate) committed_floor_ms: std::sync::atomic::AtomicI64,
    /// The identity every maintenance continuation of this open store is
    /// scoped to; a continuation another store returned is refused before
    /// any work.
    pub(crate) maintenance_scope: kappa_store::traits::maintenance::StoreToken,
    /// Storage handles suspended maintenance passes hold in their
    /// continuations (`content_inventory`), each charged here for as long
    /// as its continuation lives.
    pub(crate) suspended_traversals: std::sync::Arc<kappa_store::capacity::CapacityPool>,
    /// Bytes of canonical encodings operations hold live
    /// (`PersistentStoreConfig::encoding_storage`).
    pub(crate) encoding_storage: std::sync::Arc<kappa_store::capacity::CapacityPool>,
    pub(crate) record_storage: content_read::RecordStorage,
    /// Bytes of retained settlement preparation pending elements hold
    /// (`PersistentStoreConfig::settlement_preparation_bytes`).
    pub(crate) settlement_preparation: std::sync::Arc<kappa_store::capacity::CapacityPool>,
    /// Recovery's state across steps (`settlement_recovery`): the cycle
    /// over the durable records, the queue of known obligations, and the
    /// startup closing charge until the enumeration at open finishes.
    pub(crate) recovery: Mutex<settlement::Recovery>,
    /// Epochs partly read by settlement and recovery, each owning its
    /// namespace's activity grant (`settlement_cursors`).
    pub(crate) epoch_cursors: Mutex<settlement::EpochCursors>,
    /// Limits of every settlement read (`settlement_work`).
    pub(crate) settlement_limits: settlement::SettlementLimits,
    /// What one recovery step may do (`PersistentStoreConfig::recovery_step`):
    /// the step at open, and the dimensions a test step leaves unbounded.
    pub(crate) step_limit: WorkLimit,
    /// What one publication's seal may do
    /// (`PersistentStoreConfig::publication_work`).
    pub(crate) publication_work: WorkLimit,
    /// The ceiling of one read operation
    /// (`PersistentStoreConfig::read_work`); see [`Self::read_meter`].
    pub(crate) read_work: WorkLimit,
    /// Largest custody record (`PersistentStoreConfig::custody_record_bytes`).
    pub(crate) custody_record_bytes: u64,
    /// Exact progress retained when durable custody writes fail. This owner
    /// outlives the transaction and prevents losing returned signature bytes
    /// on the same handle while persistence is retried.
    pub(crate) live_custody: Mutex<
        std::collections::BTreeMap<storage_instance::StorageInstance, custody::CustodyRecord>,
    >,
    /// Restart ownership of unpublished candidates, independent of the
    /// committed-epoch settlement obligations of the same instance.
    pub(crate) custody_debt:
        Mutex<std::collections::BTreeMap<storage_instance::StorageInstance, unsettled::Charge>>,
    /// Bytes of projection versions settlement may hold not yet compacted.
    pub(crate) staging_capacity: u64,
    /// Where the next compaction step starts, as the last committed step
    /// left it (`projection_compact::CompactionCursor`).
    pub(crate) compaction_cursor: Mutex<projection_compact::CompactionCursor>,
    /// The session identifier the previous bounded eviction stopped at
    /// (`identity_local::evict_sessions`); `None` starts from the first.
    pub(crate) session_eviction_cursor: Mutex<Option<String>>,
    /// Node-wide bound on parked publication ownership (`unsettled`);
    /// shared with every `Charge` reserved against it.
    pub(crate) unsettled: std::sync::Arc<unsettled::UnsettledBudget>,
    /// Identities committed but not yet settled, by registering namespace
    /// (`unsettled_index`): the identity-directed locator that covers the
    /// catalog's lag.
    pub(crate) unsettled_index: std::sync::Arc<unsettled_index::UnsettledIndex>,
    /// Storage instances recovery found holding pre-restart unsettled
    /// ownership, each with what accounts for it and registers its
    /// identities, and whether the enumeration at open is still running
    /// (`settlement::RecoveryObligations`). An instance holding one admits
    /// no execution until settlement discharges it; one not yet registered
    /// leaves identity discovery incomplete (`store_access::Coverage`).
    pub(crate) recovery_obligations: Mutex<settlement::RecoveryObligations>,
    /// Committed epochs one namespace may hold unsettled before its
    /// admission refuses further executions.
    pub(crate) max_unsettled_epochs: usize,
    /// Namespaces whose derived indexes a mutation found diverged from the
    /// committed state they project, with the revision of each record
    /// (`index_repair::Divergence`). A recorded namespace's indexes are
    /// fenced until a repair started after the record completes.
    pub(crate) divergence: Mutex<index_repair::Divergence>,
    #[cfg(test)]
    pub(crate) hooks: test_hooks::TestHooks,
    /// Owner of the filesystem scope holding `blob_root` and the databases
    /// (see [`PersistentStoreConfig::retaining`]). Declared last so it drops
    /// after every database handle and every other field.
    _resource_owner: Option<std::sync::Arc<dyn Send + Sync>>,
}

impl PersistentStore {
    pub fn new(mut config: PersistentStoreConfig) -> Result<Self, StoreError> {
        // Configuration and every bound derived from it are validated before
        // anything is opened; the projection bound the registry was
        // established under is decided before anything else is built over
        // the registry, and an open it refuses, or whose recording fails,
        // returns no store.
        if config.encoding_storage == 0 {
            return Err(StoreError::Rejected(
                "encoding storage capacity must be positive".into(),
            ));
        }
        let settlement_limits =
            settlement::SettlementLimits::new(config.settlement_record_bytes, config.inline_limit)?;
        let element = settlement::element_preparation_bytes(config.settlement_record_bytes)
            .ok_or_else(|| {
                StoreError::Rejected(
                    "settlement record limit makes one element's preparation unrepresentable"
                        .into(),
                )
            })?;
        if config.settlement_preparation_bytes < element {
            return Err(StoreError::Rejected(format!(
                "settlement preparation capacity {} is below one element's bound {element}",
                config.settlement_preparation_bytes
            )));
        }
        Self::validate_settlement(&config, settlement_limits)?;
        let record_storage = content_read::RecordStorage::new(&config)?;
        let registry = Self::open_registry(&config)?;
        Self::establish_version_bounds(&registry, settlement_limits)?;
        allocation::precreate_shards(&config.blob_root)?;
        let representation_limits = representation::RepresentationLimits {
            inline_limit: config.inline_limit,
            max_components: config.max_components,
        }
        .validate()?;
        let content_durability = Self::content_durability(&config)?;
        let configured = config.authority.clone();
        let alternates = std::mem::take(&mut config.alternates);
        let require_history = config.require_history;
        let store_open::Encryptors {
            blob: blob_encryptor,
            table: table_encryptor,
        } = Self::encryptors(&mut config)?;
        let node = control_plane::NodeId(config.node_id.clone());
        let planes = std::sync::Arc::new(control_plane::ControlPlanes::new(node));
        let namespaces =
            Self::namespace_storage(&mut config, &planes, table_encryptor.clone(), &registry);

        let unsettled = std::sync::Arc::new(unsettled::UnsettledBudget::new(
            config.max_unsettled_entries,
            config.max_unsettled_bytes,
        ));
        // The ownership present at open is unknown until recovery has
        // enumerated it: the pool is closed from before the store exists.
        let recovery =
            settlement::Recovery::starting(unsettled.unmeasured(unsettled::Closure::Startup)?);
        let step_limit = config.recovery_step;
        let store = Self {
            protection: std::sync::Arc::new(allocation::Protection::default()),
            content_durability,
            representation_limits,
            blob_encryptor,
            time_authority_owned: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            registry,
            namespaces,
            planes,
            fsync: config.fsync,
            chunk_size: BLOB_CHUNK_SIZE,
            blob_root: config.blob_root.clone(),
            commitments: std::sync::Arc::new(DashMap::new()),
            epoch_cache: epoch_cache::EpochCache::new(&record_storage.decoded)?,
            table_encryptor,
            authority: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
                kappa_store::EpochAuthority::new(config.authority)?,
            )),
            activation: std::sync::RwLock::new(()),
            retained_authority: arc_swap::ArcSwapOption::empty(),
            authority_unresolved: std::sync::atomic::AtomicBool::new(false),
            latest_epoch_ms: std::sync::atomic::AtomicI64::new(i64::MIN),
            committed_floor_ms: std::sync::atomic::AtomicI64::new(i64::MIN),
            maintenance_scope: kappa_store::traits::maintenance::StoreToken::new(),
            suspended_traversals: std::sync::Arc::new(kappa_store::capacity::CapacityPool::new(
                "suspended maintenance traversals",
                config.max_suspended_traversals,
            )),
            encoding_storage: std::sync::Arc::new(kappa_store::capacity::CapacityPool::new(
                "canonical encodings",
                config.encoding_storage,
            )),
            record_storage,
            settlement_preparation: std::sync::Arc::new(kappa_store::capacity::CapacityPool::new(
                "retained settlement preparation",
                config.settlement_preparation_bytes,
            )),
            recovery: Mutex::new(recovery),
            epoch_cursors: Mutex::new(settlement::EpochCursors::new(config.max_epoch_cursors)),
            settlement_limits,
            step_limit,
            publication_work: config.publication_work,
            read_work: config.read_work,
            custody_record_bytes: config.custody_record_bytes,
            live_custody: Mutex::new(std::collections::BTreeMap::new()),
            custody_debt: Mutex::new(std::collections::BTreeMap::new()),
            staging_capacity: config.settlement_staging_bytes,
            compaction_cursor: Mutex::new(projection_compact::CompactionCursor::default()),
            session_eviction_cursor: Mutex::new(None),
            unsettled,
            unsettled_index: std::sync::Arc::new(unsettled_index::UnsettledIndex::new(
                config.max_unsettled_identities,
            )),
            recovery_obligations: Mutex::new(settlement::RecoveryObligations::default()),
            max_unsettled_epochs: config.max_unsettled_epochs,
            divergence: Mutex::new(index_repair::Divergence::default()),
            #[cfg(test)]
            hooks: test_hooks::TestHooks::default(),
            _resource_owner: config.resource_owner,
        };

        store.recover_at_open(
            configured,
            alternates,
            require_history,
            config.open_inventory_entries,
        )?;
        Ok(store)
    }

    /// Refuse a settlement configuration under which a step could never
    /// make progress, before the store serves anything: a recovery step that
    /// does not admit, on every dimension, each mandatory indivisible unit
    /// at its maximum (an epoch, a directory resolution, a namespace record
    /// decision, a compaction unit), or that carries a deadline, staging
    /// smaller than one step's reads, or cursors that could take every
    /// namespace activity grant.
    fn validate_settlement(
        config: &PersistentStoreConfig,
        limits: settlement::SettlementLimits,
    ) -> Result<(), StoreError> {
        let refuse = |detail: String| Err(StoreError::Rejected(detail));
        let step = config.recovery_step;
        if step.deadline().is_some() {
            return refuse(
                "recovery_step carries a deadline; a step's deadline is its caller's".into(),
            );
        }
        // Every mandatory indivisible unit at its maximum: a step that
        // cannot admit one would leave the durable work behind it waiting
        // forever, so the store refuses to open under it instead.
        let mandatory: [(&str, Vec<(Dimension, u64)>); 4] = [
            ("one epoch unit", limits.epoch_unit().as_bound().to_vec()),
            (
                "one directory resolution",
                namespace_write::RESOLUTION_UNIT.to_vec(),
            ),
            (
                "one namespace record decision",
                namespace_write::record_unit(limits.record_bytes()).to_vec(),
            ),
            (
                "one compaction unit",
                projection_compact::compaction_unit().as_bound().to_vec(),
            ),
        ];
        for (what, unit) in mandatory {
            if let Err(refused) = WorkMeter::new(step).admits(&unit) {
                return refuse(format!("recovery_step does not admit {what}: {refused}"));
            }
        }
        // Every projection read examines versions one admitted unit at a
        // time: a ceiling that cannot admit one would refuse every read.
        if config.read_work.deadline().is_some() {
            return refuse(
                "read_work carries a deadline; a read's deadline is its request's".into(),
            );
        }
        if let Err(refused) =
            WorkMeter::new(config.read_work).admits(&limits.selection_unit().as_bound())
        {
            return refuse(format!(
                "read_work does not admit one projection version: {refused}"
            ));
        }
        let step_reads = step.limit(Dimension::BytesRead);
        if config.settlement_staging_bytes < step_reads {
            return refuse(format!(
                "settlement_staging_bytes {} is below one step's reads {step_reads}",
                config.settlement_staging_bytes
            ));
        }
        if config.max_epoch_cursors == 0 || config.max_epoch_cursors >= config.max_active_namespaces
        {
            return refuse(format!(
                "max_epoch_cursors {} must be at least one and below max_active_namespaces {}",
                config.max_epoch_cursors, config.max_active_namespaces
            ));
        }
        Ok(())
    }

    /// The meter of one read operation, at the configured ceiling: built
    /// once where a read enters the store and threaded through every read
    /// it nests, so the whole operation answers within it or is refused.
    pub(crate) const fn read_meter(&self) -> WorkMeter {
        WorkMeter::new(self.read_work)
    }

    pub(crate) fn encode_seq_value(&self, db_key: &str, value: u64) -> Result<Vec<u8>, StoreError> {
        let bytes = value.to_be_bytes();
        self.encrypt_bytes(db_key, &bytes)
    }

    pub(crate) fn decode_seq_value(&self, db_key: &str, raw: &[u8]) -> Result<u64, StoreError> {
        let bytes = self.decrypt_bytes(db_key, raw)?;
        if bytes.len() != 8 {
            return Err(StoreError::Internal(format!(
                "sequence value {} bytes, expected 8",
                bytes.len()
            )));
        }
        let arr: [u8; 8] = bytes
            .try_into()
            .map_err(|_| StoreError::Internal("sequence value conversion".into()))?;
        Ok(u64::from_be_bytes(arr))
    }

    /// Seal `plaintext` under the table key in the context `db_key`.
    /// Content chunks are sealed under the blob encryption domain by the
    /// content pipeline (`content_prepare`, `content_stream`), and rows of
    /// content are admitted under that domain by their codec (`blob_rows`).
    pub(crate) fn encrypt_bytes(
        &self,
        db_key: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        self.table_encryptor.as_ref().map_or_else(
            || Ok(plaintext.to_vec()),
            |enc| {
                enc.encrypt_value(db_key, plaintext)
                    .map_err(|e| StoreError::Internal(format!("encrypt: {e}")))
            },
        )
    }

    /// Open what [`Self::encrypt_bytes`] sealed in the context `db_key`.
    pub(crate) fn decrypt_bytes(&self, db_key: &str, stored: &[u8]) -> Result<Vec<u8>, StoreError> {
        self.table_encryptor.as_ref().map_or_else(
            || Ok(stored.to_vec()),
            |enc| {
                enc.decrypt_value(db_key, stored)
                    .map_err(|e| StoreError::Internal(format!("decrypt: {e}")))
            },
        )
    }

    /// Compute the exclusive upper bound for a prefix scan.
    /// Returns None if the prefix is all 0xFF bytes (no upper bound exists).
    pub(crate) fn prefix_successor(prefix: &[u8]) -> Option<Vec<u8>> {
        let mut successor = prefix.to_vec();
        while let Some(last) = successor.last_mut() {
            if *last < 0xFF {
                *last += 1;
                return Some(successor);
            }
            successor.pop();
        }
        None
    }

    /// The anchor new epochs are signed under.
    pub fn node_anchor(&self) -> Kappa {
        self.authority.load().anchor().clone()
    }

    /// Every anchor the committed authority history retired, oldest first.
    pub fn retired_authorities(&self) -> Vec<Kappa> {
        self.authority.load().retired().cloned().collect()
    }

    /// The control planes this node participates in; a plane is registered
    /// here before any namespace can be assigned to it on this node.
    pub const fn control_planes(&self) -> &std::sync::Arc<control_plane::ControlPlanes> {
        &self.planes
    }

    /// Whether a rotation's commit outcome is unknown to this handle, in
    /// which case it seals nothing until the store is reopened.
    pub fn authority_unresolved(&self) -> bool {
        self.authority_unresolved.load(Ordering::SeqCst)
    }
}

// Versioning is `kappa_store::version_ops`: writers take the execution that
// publishes them, readers take the published store. No VersionStore trait.
// Staged resources are `kappa_store::resource` over the same execution
// contract; this backend holds no session state.
