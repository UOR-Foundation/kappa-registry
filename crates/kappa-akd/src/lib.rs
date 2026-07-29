//! AKD adapter for kappa-registry.
//!
//! Mirrors akd's AsyncInMemoryDatabase: two DashMaps for db records
//! and user value states. Checkpoint persistence via postcard
//! serialization into a single content-addressed blob.

use std::collections::HashMap;
use std::sync::Arc;

use akd::errors::StorageError;
use akd::storage::types::{
    DbRecord, KeyData, StorageType, ValueState, ValueStateKey, ValueStateRetrievalFlag,
};
use akd::storage::{Database, DbSetState, Storable};
use akd::{AkdLabel, AkdValue};
use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use kappa_core::store::KappaStore;

type Epoch = u64;
type UserValueMap = HashMap<Epoch, ValueState>;

pub struct AkdStoreAdapter {
    db: DashMap<Vec<u8>, DbRecord>,
    user_info: DashMap<Vec<u8>, UserValueMap>,
    store: Arc<dyn KappaStore>,
    namespace: String,
}

impl AkdStoreAdapter {
    pub fn new(store: Arc<dyn KappaStore>, namespace: String) -> Self {
        Self {
            db: DashMap::new(),
            user_info: DashMap::new(),
            store,
            namespace,
        }
    }

    /// Checkpoint the adapter's state as a single blob + tag.
    ///
    /// SAFETY: Must not be called concurrently with `batch_set` or any
    /// Database trait method that mutates `self.db` or `self.user_info`.
    /// DashMap iteration is not atomic -- concurrent mutation during
    /// iteration produces an inconsistent snapshot. Call this between
    /// akd StorageManager transaction commits, never during one.
    pub fn checkpoint(&self) -> Result<(), kappa_core::StoreError> {
        let db_entries: Vec<(Vec<u8>, DbRecord)> = self
            .db
            .iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect();
        let user_entries: Vec<(Vec<u8>, UserValueMap)> = self
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
            .tag_set(&self.namespace, "_akd/checkpoint", &kappa)?;
        Ok(())
    }

    /// Recover adapter state from a previously checkpointed blob.
    pub fn recover(
        store: Arc<dyn KappaStore>,
        namespace: String,
    ) -> Result<Self, kappa_core::StoreError> {
        let entry = store.tag_get(&namespace, "_akd/checkpoint")?;
        let bytes = store.blob_get(&entry.kappa)?;
        let checkpoint: AkdCheckpoint = postcard::from_bytes(&bytes).map_err(|e| {
            kappa_core::StoreError::Rejected(format!("checkpoint deserialize: {}", e))
        })?;

        let db = DashMap::new();
        for (k, v) in checkpoint.db {
            db.insert(k, v);
        }
        let user_info = DashMap::new();
        for (k, v) in checkpoint.user_info {
            user_info.insert(k, v);
        }

        Ok(Self {
            db,
            user_info,
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
                if let Some(state) = self.user_info.get(&username) {
                    if let Some(found) = state.get(&epoch) {
                        return Ok(DbRecord::ValueState(found.clone()));
                    }
                }
                return Err(StorageError::NotFound(format!("ValueState {:?}", id)));
            }
        }
        if let Some(result) = self.db.get(&bin_id) {
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
                match self.user_info.get_mut(&username) {
                    Some(mut states) => {
                        states.insert(value_state.epoch, value_state);
                    }
                    None => {
                        let mut new_map = HashMap::new();
                        new_map.insert(value_state.epoch, value_state);
                        self.user_info.insert(username, new_map);
                    }
                }
            } else {
                self.db.insert(record.get_full_binary_id(), record);
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
        if let Some(result) = self.user_info.get(&username.0) {
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
