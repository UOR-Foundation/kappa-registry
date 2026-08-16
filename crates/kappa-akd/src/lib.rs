//! AKD adapter for kappa-registry.
//!
//! Two components:
//! 1. AkdStoreAdapter: implements akd::storage::Database using DashMap
//!    with checkpoint persistence via postcard into kappa blobs.
//! 2. AkdManager: wraps akd::Directory to provide publish/lookup/audit/absence
//!    operations callable from HTTP handlers.

use std::collections::HashMap;
use std::sync::Arc;

use akd::append_only_zks::AzksParallelismConfig;
use akd::directory::Directory;
use akd::ecvrf::HardCodedAkdVRF;
use akd::errors::{AkdError, StorageError};
use akd::storage::manager::StorageManager;
use akd::storage::types::{
    DbRecord, KeyData, StorageType, ValueState, ValueStateKey, ValueStateRetrievalFlag,
};
use akd::storage::{Database, DbSetState, Storable};
use akd::{AkdLabel, AkdValue, EpochHash};
use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use kappa_core::store::KappaStore;
use kappa_core::types::NamespaceRef;

type Epoch = u64;
type UserValueMap = HashMap<Epoch, ValueState>;

/// Shared mutable state for the AKD storage adapter.
///
/// Wrapped in `Arc` and shared between the `AkdStoreAdapter` clone passed
/// to `StorageManager` (which the `Directory` uses for tree operations) and
/// the `AkdManager` (which calls `checkpoint()` after each publish).
///
/// All fields are DashMap -- concurrent reads and writes to different shards
/// proceed without blocking. The `checkpoint()` method iterates both maps
/// to serialize state. DashMap iteration is NOT atomic: concurrent mutation
/// during iteration produces an inconsistent snapshot. Checkpoint must be
/// called while the Directory mutex is held (no concurrent publishes).
struct AkdState {
    db: DashMap<Vec<u8>, DbRecord>,
    user_info: DashMap<Vec<u8>, UserValueMap>,
}

impl AkdState {
    fn new() -> Self {
        Self {
            db: DashMap::new(),
            user_info: DashMap::new(),
        }
    }

    fn from_checkpoint(checkpoint: AkdCheckpoint) -> Self {
        let db = DashMap::new();
        for (k, v) in checkpoint.db {
            db.insert(k, v);
        }
        let user_info = DashMap::new();
        for (k, v) in checkpoint.user_info {
            user_info.insert(k, v);
        }
        Self { db, user_info }
    }
}

/// AKD storage adapter backed by in-memory DashMaps with checkpoint
/// persistence to kappa blob storage.
///
/// Cloneable: all clones share the same underlying `AkdState` via Arc.
/// The `store` and `namespace` fields are per-instance config (also
/// cheaply cloneable via Arc and String::clone).
pub struct AkdStoreAdapter {
    state: Arc<AkdState>,
    store: Arc<dyn KappaStore>,
    namespace: String,
}

impl Clone for AkdStoreAdapter {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            store: self.store.clone(),
            namespace: self.namespace.clone(),
        }
    }
}

impl AkdStoreAdapter {
    pub fn new(store: Arc<dyn KappaStore>, namespace: String) -> Self {
        Self {
            state: Arc::new(AkdState::new()),
            store,
            namespace,
        }
    }

    /// Checkpoint the adapter's state as a single blob + tag.
    ///
    /// MUST be called while the AkdManager's directory mutex is held
    /// to prevent concurrent publishes from mutating the DashMaps
    /// during iteration. The AkdManager.publish() method enforces this.
    pub fn checkpoint(&self) -> Result<(), kappa_core::StoreError> {
        let db_entries: Vec<(Vec<u8>, DbRecord)> = self
            .state
            .db
            .iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect();
        let user_entries: Vec<(Vec<u8>, UserValueMap)> = self
            .state
            .user_info
            .iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect();

        let checkpoint = AkdCheckpoint {
            db: db_entries,
            user_info: user_entries,
        };

        let bytes = postcard::to_allocvec(&checkpoint).map_err(|e| {
            kappa_core::StoreError::Rejected(format!("checkpoint serialize: {}", e))
        })?;
        let kappa = kappa_core::store::blob_put_computed(&*self.store, &bytes)?;
        self.store
            .tag_set(&NamespaceRef::from(self.namespace.as_str()), "_akd/checkpoint", &kappa)?;
        Ok(())
    }

    /// Recover adapter state from a previously checkpointed blob.
    pub fn recover(
        store: Arc<dyn KappaStore>,
        namespace: String,
    ) -> Result<Self, kappa_core::StoreError> {
        let entry = store.tag_get(&NamespaceRef::from(namespace.as_str()), "_akd/checkpoint")?;
        let bytes = store.blob_get(&entry.kappa)?;
        let checkpoint: AkdCheckpoint = postcard::from_bytes(&bytes).map_err(|e| {
            kappa_core::StoreError::Rejected(format!("checkpoint deserialize: {}", e))
        })?;

        Ok(Self {
            state: Arc::new(AkdState::from_checkpoint(checkpoint)),
            store,
            namespace,
        })
    }

    async fn get_internal<St: Storable>(
        &self,
        id: &St::StorageKey,
    ) -> Result<DbRecord, StorageError> {
        let bin_id = St::get_full_binary_key_id(id);
        if St::data_type() == StorageType::ValueState {
            if let Ok(ValueStateKey(username, epoch)) = ValueState::key_from_full_binary(&bin_id) {
                if let Some(state) = self.state.user_info.get(&username) {
                    if let Some(found) = state.get(&epoch) {
                        return Ok(DbRecord::ValueState(found.clone()));
                    }
                }
                return Err(StorageError::NotFound(format!("ValueState {:?}", id)));
            }
        }
        if let Some(result) = self.state.db.get(&bin_id) {
            Ok(result.clone())
        } else {
            Err(StorageError::NotFound(format!(
                "{:?} {:?}",
                St::data_type(),
                id
            )))
        }
    }
}

#[derive(Serialize, Deserialize)]
struct AkdCheckpoint {
    db: Vec<(Vec<u8>, DbRecord)>,
    user_info: Vec<(Vec<u8>, UserValueMap)>,
}

#[async_trait]
impl Database for AkdStoreAdapter {
    async fn set(&self, record: DbRecord) -> Result<(), StorageError> {
        self.batch_set(vec![record], DbSetState::General).await
    }

    async fn batch_set(
        &self,
        records: Vec<DbRecord>,
        _state: DbSetState,
    ) -> Result<(), StorageError> {
        for record in records.into_iter() {
            if let DbRecord::ValueState(value_state) = record {
                let username = value_state.username.to_vec();
                match self.state.user_info.get_mut(&username) {
                    Some(mut states) => {
                        states.insert(value_state.epoch, value_state);
                    }
                    None => {
                        let mut new_map = HashMap::new();
                        new_map.insert(value_state.epoch, value_state);
                        self.state.user_info.insert(username, new_map);
                    }
                }
            } else {
                self.state.db.insert(record.get_full_binary_id(), record);
            }
        }
        Ok(())
    }

    async fn get<St: Storable>(&self, id: &St::StorageKey) -> Result<DbRecord, StorageError> {
        self.get_internal::<St>(id).await
    }

    async fn batch_get<St: Storable>(
        &self,
        ids: &[St::StorageKey],
    ) -> Result<Vec<DbRecord>, StorageError> {
        let mut records = Vec::new();
        for key in ids.iter() {
            if let Ok(result) = self.get_internal::<St>(key).await {
                records.push(result);
            }
        }
        Ok(records)
    }

    async fn get_user_data(&self, username: &AkdLabel) -> Result<KeyData, StorageError> {
        if let Some(result) = self.state.user_info.get(&username.0) {
            let mut results: Vec<ValueState> = result.values().cloned().collect();
            results.sort_by_key(|a| a.epoch);
            Ok(KeyData { states: results })
        } else {
            Err(StorageError::NotFound(format!("ValueState {:?}", username)))
        }
    }

    async fn get_user_state(
        &self,
        username: &AkdLabel,
        flag: ValueStateRetrievalFlag,
    ) -> Result<ValueState, StorageError> {
        let intermediate = self.get_user_data(username).await?.states;
        match flag {
            ValueStateRetrievalFlag::MaxEpoch => {
                if let Some(value) = intermediate.iter().max_by(|a, b| a.epoch.cmp(&b.epoch)) {
                    return Ok(value.clone());
                }
            }
            ValueStateRetrievalFlag::MinEpoch => {
                if let Some(value) = intermediate.iter().min_by(|a, b| a.epoch.cmp(&b.epoch)) {
                    return Ok(value.clone());
                }
            }
            _ => {
                let mut tracked_epoch = 0u64;
                let mut tracker = None;
                for kvp in intermediate.iter() {
                    match flag {
                        ValueStateRetrievalFlag::SpecificVersion(version)
                            if version == kvp.version =>
                        {
                            return Ok(kvp.clone());
                        }
                        ValueStateRetrievalFlag::LeqEpoch(epoch) if epoch == kvp.epoch => {
                            return Ok(kvp.clone());
                        }
                        ValueStateRetrievalFlag::LeqEpoch(epoch) if kvp.epoch < epoch => {
                            if tracked_epoch == 0 || kvp.epoch > tracked_epoch {
                                tracked_epoch = kvp.epoch;
                                tracker = Some(kvp.clone());
                            }
                        }
                        ValueStateRetrievalFlag::SpecificEpoch(epoch) if epoch == kvp.epoch => {
                            return Ok(kvp.clone());
                        }
                        _ => continue,
                    }
                }
                if let Some(r) = tracker {
                    return Ok(r);
                }
            }
        }
        Err(StorageError::NotFound(format!("ValueState {:?}", username)))
    }

    async fn get_user_state_versions(
        &self,
        keys: &[AkdLabel],
        flag: ValueStateRetrievalFlag,
    ) -> Result<HashMap<AkdLabel, (u64, AkdValue)>, StorageError> {
        let mut map = HashMap::new();
        for username in keys.iter() {
            if let Ok(result) = self.get_user_state(username, flag).await {
                map.insert(
                    AkdLabel(result.username.to_vec()),
                    (result.version, AkdValue(result.value.to_vec())),
                );
            }
        }
        Ok(map)
    }
}

// =============================================================================
// AkdManager: wraps akd::Directory for the identity module
// =============================================================================

/// AKD configuration. WhatsAppV1Configuration is the production config
/// from Meta's key transparency deployment.
type Config = akd::WhatsAppV1Configuration;

/// Manages an AKD Directory instance for identity assertion proofs.
///
/// Thread-safe via Mutex around the Directory (which requires &mut self
/// for publish). All operations are async.
///
/// Lifecycle:
/// 1. new() creates the Directory with a fresh or recovered AkdStoreAdapter
/// 2. publish() adds label-value pairs and advances the epoch
/// 3. lookup() generates a lookup proof for a label
/// 4. audit() generates an append-only proof between two epochs
/// 5. get_public_key() returns the VRF public key for client verification
pub struct AkdManager {
    directory: Mutex<Directory<Config, AkdStoreAdapter, HardCodedAkdVRF>>,
    /// Shared reference to the adapter for checkpoint persistence.
    /// This is a clone of the adapter passed to the Directory's StorageManager.
    /// Both point to the same Arc<AkdState> so checkpoint() sees the
    /// Directory's mutations.
    adapter: AkdStoreAdapter,
}

/// Error type for AKD operations.
#[derive(Debug)]
pub enum AkdManagerError {
    Akd(AkdError),
    Store(kappa_core::StoreError),
    Serialization(String),
}

impl std::fmt::Display for AkdManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Akd(e) => write!(f, "AKD error: {e}"),
            Self::Store(e) => write!(f, "store error: {e}"),
            Self::Serialization(e) => write!(f, "serialization error: {e}"),
        }
    }
}

impl From<AkdError> for AkdManagerError {
    fn from(e: AkdError) -> Self {
        Self::Akd(e)
    }
}

impl From<kappa_core::StoreError> for AkdManagerError {
    fn from(e: kappa_core::StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<akd::verify::VerificationError> for AkdManagerError {
    fn from(e: akd::verify::VerificationError) -> Self {
        Self::Serialization(format!("verification error: {e}"))
    }
}

/// Result of a lookup proof.
pub struct LookupResult {
    pub epoch: u64,
    pub version: u64,
    pub value: Vec<u8>,
    pub proof_json: serde_json::Value,
}

/// Result of an audit proof.
pub struct AuditResult {
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub proof_json: serde_json::Value,
}

impl AkdManager {
    /// Create a new AkdManager with a fresh AKD directory.
    ///
    /// Attempts to recover from a checkpoint first. If no checkpoint exists,
    /// creates a new empty directory.
    pub async fn new(store: Arc<dyn KappaStore>, namespace: String) -> Result<Self, AkdManagerError> {
        let adapter = match AkdStoreAdapter::recover(store.clone(), namespace.clone()) {
            Ok(a) => {
                tracing::info!("AKD directory recovered from checkpoint");
                a
            }
            Err(_) => {
                tracing::info!("AKD directory starting fresh (no checkpoint)");
                AkdStoreAdapter::new(store, namespace)
            }
        };

        // Clone the adapter before passing to StorageManager. Both clones
        // share the same Arc<AkdState>, so the Directory's mutations are
        // visible to our checkpoint() calls.
        let adapter_for_checkpoint = adapter.clone();

        let storage = StorageManager::new_no_cache(adapter);
        let vrf = HardCodedAkdVRF {};
        let directory = Directory::<Config, _, _>::new(
            storage,
            vrf,
            AzksParallelismConfig::default(),
        )
        .await?;

        Ok(Self {
            directory: Mutex::new(directory),
            adapter: adapter_for_checkpoint,
        })
    }

    /// Publish a batch of label-value pairs, advancing the epoch.
    ///
    /// Each publish creates a new epoch in the AKD tree. The epoch hash
    /// is the root of the Merkle tree at that epoch.
    pub async fn publish(
        &self,
        entries: Vec<(AkdLabel, AkdValue)>,
    ) -> Result<EpochHash, AkdManagerError> {
        let dir = self.directory.lock().await;
        let epoch_hash = dir.publish(entries).await?;

        // Checkpoint while the directory mutex is held. The DashMap
        // iteration in checkpoint() is safe because no concurrent
        // publish can mutate the maps while we hold the lock.
        //
        // Checkpoint failure fails the publish. Without a durable
        // checkpoint, a process restart loses this epoch's tree state.
        // Lookup proofs would fail. Absence proofs would be wrong.
        // The publish and checkpoint are one atomic unit of durability.
        self.adapter.checkpoint().map_err(AkdManagerError::Store)?;

        Ok(epoch_hash)
    }

    /// Generate a lookup proof for a label at the current epoch.
    pub async fn lookup(&self, label: AkdLabel) -> Result<LookupResult, AkdManagerError> {
        let dir = self.directory.lock().await;
        let (proof, epoch_hash) = dir.lookup(label).await?;
        let public_key = dir.get_public_key().await?;

        // Verify the proof ourselves before returning it
        let verify_result = akd::client::lookup_verify::<Config>(
            public_key.as_bytes(),
            epoch_hash.hash(),
            epoch_hash.epoch(),
            AkdLabel(proof.value.0.clone()),
            proof.clone(),
        )?;

        // Serialize the proof as JSON for the HTTP response.
        // The proof struct implements serde::Serialize (via serde_serialization feature).
        let proof_json = serde_json::to_value(&proof)
            .map_err(|e| AkdManagerError::Serialization(e.to_string()))?;

        Ok(LookupResult {
            epoch: verify_result.epoch,
            version: verify_result.version,
            value: verify_result.value.0,
            proof_json,
        })
    }

    /// Generate an append-only audit proof between two epochs.
    pub async fn audit(
        &self,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<AuditResult, AkdManagerError> {
        let dir = self.directory.lock().await;
        let proof: akd::AppendOnlyProof = dir.audit(start_epoch, end_epoch).await?;

        let proof_json = serde_json::to_value(&proof)
            .map_err(|e| AkdManagerError::Serialization(e.to_string()))?;

        Ok(AuditResult {
            start_epoch,
            end_epoch,
            proof_json,
        })
    }

    /// Get the VRF public key for client-side proof verification.
    pub async fn get_public_key(&self) -> Result<Vec<u8>, AkdManagerError> {
        let dir = self.directory.lock().await;
        let pk = dir.get_public_key().await?;
        Ok(pk.as_bytes().to_vec())
    }

    /// Get the current epoch hash.
    pub async fn get_epoch_hash(&self) -> Result<EpochHash, AkdManagerError> {
        let dir = self.directory.lock().await;
        let eh = dir.get_epoch_hash().await?;
        Ok(eh)
    }
}
