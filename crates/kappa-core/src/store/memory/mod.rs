//! InMemoryStore: the primary store implementation.
//!
//! Tags, edges, sequences, metadata, and epoch state live in hash maps.
//! Blobs live on the filesystem, content-addressed by kappa-label.

mod edge;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use dashmap::DashMap;

use crate::clock::Clock;
use crate::epoch::{self, EpochRoot, EpochRootFields};
use crate::store::KappaStore;
use crate::types::*;

#[non_exhaustive]
pub struct MemoryStoreConfig {
    pub blob_root: PathBuf,
    pub upload_timeout_secs: Option<u64>,
}

impl MemoryStoreConfig {
    pub fn new(blob_root: PathBuf) -> Self {
        Self {
            blob_root,
            upload_timeout_secs: None,
        }
    }
}

pub struct InMemoryStore {
    blob_root: PathBuf,
    clock: Arc<dyn Clock>,
    upload_timeout_secs: Option<u64>,
    tags: RwLock<HashMap<([u8; 16], u64), TagEntry>>,
    meta: DashMap<(u64, u64), Vec<u8>>,
    /// Namespace-scoped metadata index: (ns_uuid, key_hash, value_hash) -> Vec<kappa>
    ns_meta: DashMap<([u8; 16], u64, u64), Vec<String>>,
    pub(crate) edges: RwLock<HashMap<([u8; 16], u64), Edge>>,
    pub(crate) fwd_index: RwLock<HashMap<([u8; 16], u64), Vec<String>>>,
    pub(crate) rev_index: RwLock<HashMap<([u8; 16], u64), Vec<String>>>,
    pub(crate) rel_index: RwLock<HashMap<([u8; 16], u64), Vec<String>>>,
    pub(crate) asr_index: RwLock<HashMap<([u8; 16], u64), Vec<String>>>,
    sequences: Mutex<HashMap<([u8; 16], u64), u64>>,
    epoch_roots: RwLock<HashMap<String, EpochRoot>>,
    current_epochs: RwLock<HashMap<[u8; 16], String>>,
    uploads: Mutex<HashMap<String, UploadSession>>,
    /// Compression records: uncompressed_hash -> (kappa, algorithm, compressed_bytes, uncompressed_size)
    compression_records: DashMap<String, (String, String, Vec<u8>, u64)>,
    /// Identity bindings: source -> Vec<IdentityBinding>
    identity_bindings: DashMap<String, Vec<crate::identity::IdentityBinding>>,
    /// Identity successions: old_anchor -> new_anchor
    identity_successions: DashMap<String, String>,
    /// Assertion inbound index: "{subject}\0{facet}" -> Vec<assertion_kappa>
    assertion_inbound: DashMap<String, Vec<String>>,
    /// Namespace aliases: "{protocol}:{name}" or "{name}" -> uuid
    ns_aliases: DashMap<String, [u8; 16]>,
    /// Namespace records: uuid -> NamespaceRecord
    ns_records: DashMap<[u8; 16], crate::store::NamespaceRecord>,
}

struct UploadSession {
    namespace: String,
    data: Vec<u8>,
    max_size: u64,
    created_at: std::time::Instant,
    part_digests: Vec<(u32, [u8; 16], u64)>, // (part_number, md5, size)
}

impl InMemoryStore {
    pub fn new(config: MemoryStoreConfig, clock: Arc<dyn Clock>) -> Result<Self, StoreError> {
        std::fs::create_dir_all(&config.blob_root)?;
        Ok(InMemoryStore {
            blob_root: config.blob_root,
            clock,
            upload_timeout_secs: config.upload_timeout_secs,
            tags: RwLock::new(HashMap::new()),
            meta: DashMap::new(),
            ns_meta: DashMap::new(),
            edges: RwLock::new(HashMap::new()),
            fwd_index: RwLock::new(HashMap::new()),
            rev_index: RwLock::new(HashMap::new()),
            rel_index: RwLock::new(HashMap::new()),
            asr_index: RwLock::new(HashMap::new()),
            sequences: Mutex::new(HashMap::new()),
            epoch_roots: RwLock::new(HashMap::new()),
            current_epochs: RwLock::new(HashMap::new()),
            uploads: Mutex::new(HashMap::new()),
            compression_records: DashMap::new(),
            identity_bindings: DashMap::new(),
            identity_successions: DashMap::new(),
            assertion_inbound: DashMap::new(),
            ns_aliases: DashMap::new(),
            ns_records: DashMap::new(),
        })
    }

    fn blob_path(&self, kappa: &str) -> Result<PathBuf, StoreError> {
        crate::kappa::blob_path_for(&self.blob_root, kappa)
    }

    fn ensure_namespace(&self, ns: &NamespaceRef) {
        let uuid = *ns.uuid();
        if !self.ns_records.contains_key(&uuid) {
            let name = ns.display_name().unwrap_or("").to_string();
            self.ns_records.insert(uuid, crate::store::NamespaceRecord {
                uuid_hex: ns.uuid_hex(),
                owner: String::new(),
                created_at_ms: 0,
                protocol: None,
                aliases: if name.is_empty() { vec![] } else { vec![name.clone()] },
                tombstoned: false,
            });
            if !name.is_empty() {
                self.ns_aliases.insert(name, uuid);
            }
        }
    }

    fn collect_sorted_tags(&self, ns: &NamespaceRef) -> Vec<TagEntry> {
        let uuid = *ns.uuid();
        let tags = self.tags.read().unwrap();
        let mut entries: Vec<TagEntry> = tags
            .iter()
            .filter(|((u, _), _)| *u == uuid)
            .map(|(_, e)| e.clone())
            .collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries
    }
}

impl KappaStore for InMemoryStore {
    fn blob_put_verified(&self, verified: &crate::verified::VerifiedContent) -> Result<bool, StoreError> {
        let kappa = verified.kappa();
        let content = verified.content();
        tracing::debug!(kappa = kappa, size = content.len(), "blob_put_verified");
        let path = self.blob_path(kappa)?;
        if path.exists() {
            return Ok(false);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, content)?;
        std::fs::rename(&tmp, &path)?;
        Ok(true)
    }

    fn blob_get(&self, kappa: &str) -> Result<Vec<u8>, StoreError> {
        tracing::debug!(kappa = kappa, "blob_get");
        let path = self.blob_path(kappa)?;
        std::fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound(kappa.to_string())
            } else {
                StoreError::Io(e)
            }
        })
    }

    fn blob_exists(&self, kappa: &str) -> Result<bool, StoreError> {
        tracing::trace!(kappa = kappa, "blob_exists");
        Ok(self.blob_path(kappa)?.exists())
    }

    fn blob_delete(&self, kappa: &str) -> Result<(), StoreError> {
        tracing::debug!(kappa = kappa, "blob_delete");
        let path = self.blob_path(kappa)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    fn blob_size(&self, kappa: &str) -> Result<u64, StoreError> {
        tracing::trace!(kappa = kappa, "blob_size");
        let path = self.blob_path(kappa)?;
        let metadata = std::fs::metadata(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound(kappa.to_string())
            } else {
                StoreError::Io(e)
            }
        })?;
        Ok(metadata.len())
    }

    fn blob_get_range(&self, kappa: &str, offset: u64, length: u64) -> Result<Vec<u8>, StoreError> {
        use std::io::{Read, Seek, SeekFrom};
        tracing::debug!(
            kappa = kappa,
            offset = offset,
            length = length,
            "blob_get_range"
        );
        let path = self.blob_path(kappa)?;
        let mut file = std::fs::File::open(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound(kappa.to_string())
            } else {
                StoreError::Io(e)
            }
        })?;
        file.seek(SeekFrom::Start(offset)).map_err(StoreError::Io)?;
        let mut buf = vec![0u8; length as usize];
        let n = file.read(&mut buf).map_err(StoreError::Io)?;
        buf.truncate(n);
        Ok(buf)
    }

    fn blob_list(&self) -> Result<Vec<String>, StoreError> {
        tracing::trace!("blob_list");
        let mut kappas = Vec::new();
        let Ok(algo_entries) = std::fs::read_dir(&self.blob_root) else {
            return Ok(kappas);
        };
        for algo_entry in algo_entries {
            let algo_entry = algo_entry?;
            if !algo_entry.file_type()?.is_dir() {
                continue;
            }
            let algo = algo_entry.file_name().to_string_lossy().to_string();
            for shard1 in std::fs::read_dir(algo_entry.path())? {
                let shard1 = shard1?;
                if !shard1.file_type()?.is_dir() {
                    continue;
                }
                for shard2 in std::fs::read_dir(shard1.path())? {
                    let shard2 = shard2?;
                    if !shard2.file_type()?.is_dir() {
                        continue;
                    }
                    for blob in std::fs::read_dir(shard2.path())? {
                        let blob = blob?;
                        let name = blob.file_name().to_string_lossy().to_string();
                        if name.ends_with(".tmp") {
                            continue;
                        }
                        kappas.push(format!("{}:{}", algo, name));
                    }
                }
            }
        }
        kappas.sort();
        Ok(kappas)
    }

    // -- Blob metadata --------------------------------------------------------

    fn blob_put_meta(&self, kappa: &str, key: &str, value: &[u8]) -> Result<(), StoreError> {
        tracing::debug!(kappa = kappa, key = key, "blob_put_meta");
        let k = (item_hash(kappa), item_hash(key));
        self.meta.insert(k, value.to_vec());
        Ok(())
    }

    fn blob_get_meta(&self, kappa: &str, key: &str) -> Result<Vec<u8>, StoreError> {
        tracing::trace!(kappa = kappa, key = key, "blob_get_meta");
        let k = (item_hash(kappa), item_hash(key));
        self.meta
            .get(&k)
            .map(|v| v.value().clone())
            .ok_or_else(|| StoreError::NotFound(format!("meta {}:{}", kappa, key)))
    }

    fn blob_delete_meta(&self, kappa: &str, key: &str) -> Result<(), StoreError> {
        tracing::debug!(kappa = kappa, key = key, "blob_delete_meta");
        let k = (item_hash(kappa), item_hash(key));
        self.meta.remove(&k);
        Ok(())
    }

    // -- Namespace-scoped metadata --------------------------------------------

    fn meta_set(&self, ns: &NamespaceRef, kappa: &str, key: &str, value: &str) -> Result<(), StoreError> {
        tracing::debug!(ns = %ns, kappa = kappa, key = key, value = value, "meta_set");
        self.ensure_namespace(ns);
        let idx_key = (*ns.uuid(), item_hash(key), item_hash(value));
        self.ns_meta
            .entry(idx_key)
            .or_default()
            .push(kappa.to_string());
        Ok(())
    }

    fn meta_query(&self, ns: &NamespaceRef, key: &str, value: &str) -> Result<Vec<String>, StoreError> {
        tracing::trace!(ns = %ns, key = key, value = value, "meta_query");
        let uuid = *ns.uuid();
        if value.is_empty() {
            let key_hash = item_hash(key);
            let mut results = Vec::new();
            for entry in self.ns_meta.iter() {
                let (u, kh, _vh) = *entry.key();
                if u == uuid && kh == key_hash {
                    results.extend(entry.value().iter().cloned());
                }
            }
            results.sort();
            results.dedup();
            Ok(results)
        } else {
            let idx_key = (uuid, item_hash(key), item_hash(value));
            match self.ns_meta.get(&idx_key) {
                Some(kappas) => {
                    let mut results = kappas.value().clone();
                    results.sort();
                    results.dedup();
                    Ok(results)
                }
                None => Ok(Vec::new()),
            }
        }
    }

    // -- Tag ------------------------------------------------------------------

    fn tag_set(&self, ns: &NamespaceRef, name: &str, kappa: &str) -> Result<u64, StoreError> {
        tracing::debug!(ns = %ns, tag = name, kappa = kappa, "tag_set");
        self.ensure_namespace(ns);
        let key = (*ns.uuid(), item_hash(name));
        let mut tags = self.tags.write().unwrap();
        let version = tags.get(&key).map(|e| e.version + 1).unwrap_or(1);
        tags.insert(
            key,
            TagEntry {
                name: name.to_string(),
                kappa: kappa.to_string(),
                version,
            },
        );
        Ok(version)
    }

    fn tag_get(&self, ns: &NamespaceRef, name: &str) -> Result<TagEntry, StoreError> {
        tracing::trace!(ns = %ns, tag = name, "tag_get");
        let tags = self.tags.read().unwrap();
        tags.get(&(*ns.uuid(), item_hash(name)))
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("{}/{}", ns, name)))
    }

    fn tag_delete(&self, ns: &NamespaceRef, name: &str) -> Result<(), StoreError> {
        tracing::debug!(ns = %ns, tag = name, "tag_delete");
        self.tags
            .write()
            .unwrap()
            .remove(&(*ns.uuid(), item_hash(name)));
        Ok(())
    }

    fn tag_list(&self, ns: &NamespaceRef) -> Result<Vec<TagEntry>, StoreError> {
        tracing::trace!(ns = %ns, "tag_list");
        Ok(self.collect_sorted_tags(ns))
    }

    fn tag_prefix(&self, ns: &NamespaceRef, prefix: &str) -> Result<Vec<TagEntry>, StoreError> {
        tracing::trace!(ns = %ns, prefix = prefix, "tag_prefix");
        let uuid = *ns.uuid();
        let tags = self.tags.read().unwrap();
        let mut result: Vec<TagEntry> = tags
            .iter()
            .filter(|((u, _), e)| *u == uuid && e.name.starts_with(prefix))
            .map(|(_, e)| e.clone())
            .collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    fn tag_set_batch(&self, ns: &NamespaceRef, updates: &[TagUpdate]) -> Result<(), StoreError> {
        tracing::debug!(ns = %ns, count = updates.len(), "tag_set_batch");
        self.ensure_namespace(ns);
        let uuid = *ns.uuid();
        let mut tags = self.tags.write().unwrap();

        for update in updates {
            if let Some(expected) = update.expected_version {
                let current = tags
                    .get(&(uuid, item_hash(&update.name)))
                    .map(|e| e.version)
                    .unwrap_or(0);
                if expected != current {
                    return Err(StoreError::Conflict(format!(
                        "tag {}: expected version {} but current is {}",
                        update.name, expected, current
                    )));
                }
            }
        }

        for update in updates {
            let key = (uuid, item_hash(&update.name));
            let version = tags.get(&key).map(|e| e.version + 1).unwrap_or(1);
            tags.insert(
                key,
                TagEntry {
                    name: update.name.clone(),
                    kappa: update.kappa.clone(),
                    version,
                },
            );
        }
        Ok(())
    }

    // -- Edge -----------------------------------------------------------------

    fn edge_put(&self, ns: &NamespaceRef, edge_record: &Edge) -> Result<(), StoreError> {
        tracing::debug!(
            ns = ns.as_str(),
            source = %edge_record.source,
            target = %edge_record.target,
            "edge_put"
        );
        edge::edge_put(self, ns, edge_record)
    }

    fn edge_query(&self, ns: &NamespaceRef, query: &EdgeQuery) -> Result<Vec<Edge>, StoreError> {
        tracing::trace!(ns = ns.as_str(), anchor = %query.anchor, "edge_query");
        edge::edge_query(self, ns, query)
    }

    fn edge_delete(
        &self,
        ns: &NamespaceRef,
        source: &str,
        target: &str,
        relation: EdgeRelation,
    ) -> Result<(), StoreError> {
        tracing::debug!(
            ns = ns.as_str(),
            source = source,
            target = target,
            relation = relation.as_str(),
            "edge_delete"
        );
        edge::edge_delete(self, ns, source, target, relation)
    }

    // -- Sequence -------------------------------------------------------------

    fn sequence_next(&self, ns: &NamespaceRef, name: &str) -> Result<u64, StoreError> {
        tracing::debug!(ns = %ns, seq = name, "sequence_next");
        self.ensure_namespace(ns);
        let key = (*ns.uuid(), item_hash(name));
        let mut seqs = self.sequences.lock().unwrap();
        let counter = seqs.entry(key).or_insert(0);
        *counter += 1;
        Ok(*counter)
    }

    fn sequence_current(&self, ns: &NamespaceRef, name: &str) -> Result<u64, StoreError> {
        tracing::trace!(ns = %ns, seq = name, "sequence_current");
        let seqs = self.sequences.lock().unwrap();
        Ok(seqs
            .get(&(*ns.uuid(), item_hash(name)))
            .copied()
            .unwrap_or(0))
    }

    // -- Epoch ----------------------------------------------------------------

    fn epoch_advance(&self, ns: &NamespaceRef, mutations: Vec<EpochMutation>) -> Result<String, StoreError> {
        tracing::debug!(ns = %ns, mutation_count = mutations.len(), "epoch_advance");
        self.ensure_namespace(ns);
        let uuid = *ns.uuid();
        let epoch_number = {
            let mut seqs = self.sequences.lock().unwrap();
            let key = (uuid, item_hash("_epoch"));
            let counter = seqs.entry(key).or_insert(0);
            *counter += 1;
            *counter
        };

        let prev_root_kappa = self.epoch_current(ns)?;
        let sorted_tags = self.collect_sorted_tags(ns);
        let state_root = epoch::state_merkle_root(&sorted_tags);
        let mutations_root = epoch::mutations_merkle_root(&mutations);
        let timestamp_ms = self.clock.now_ms();

        let epoch_root = EpochRoot::build(EpochRootFields {
            namespace: ns.to_string(),
            epoch_number,
            prev_root_kappa,
            state_root,
            mutations_root,
            timestamp_ms,
            signer_anchor: String::new(),
        });

        let kappa = epoch_root.kappa();

        // Persist the epoch root as a content-addressed blob so it
        // survives process restart and participates in GC/federation.
        // Format: 7 length-prefixed Merkle leaves (+ signature if present).
        self.ingest_compute(crate::kappa::Axis::Sha256, &epoch_root.to_leaf_bytes())?;

        self.epoch_roots
            .write()
            .unwrap()
            .insert(kappa.clone(), epoch_root);
        self.current_epochs
            .write()
            .unwrap()
            .insert(uuid, kappa.clone());

        // Persist the current epoch pointer as a tag so epoch_current
        // survives process restart without scanning all blobs.
        self.tag_set(ns, "_epoch/current", &kappa)?;

        Ok(kappa)
    }

    fn epoch_current(&self, ns: &NamespaceRef) -> Result<Option<String>, StoreError> {
        tracing::trace!(ns = %ns, "epoch_current");
        let uuid = *ns.uuid();
        // Check in-memory cache first
        if let Some(k) = self
            .current_epochs
            .read()
            .unwrap()
            .get(&uuid)
            .cloned()
        {
            return Ok(Some(k));
        }
        // Fall back to persisted tag (post-restart recovery)
        match self.tag_get(ns, "_epoch/current") {
            Ok(entry) => {
                self.current_epochs
                    .write()
                    .unwrap()
                    .insert(uuid, entry.kappa.clone());
                Ok(Some(entry.kappa))
            }
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn epoch_get(&self, kappa: &str) -> Result<EpochRoot, StoreError> {
        tracing::trace!(kappa = kappa, "epoch_get");
        // Check in-memory cache first
        if let Some(root) = self.epoch_roots.read().unwrap().get(kappa) {
            return Ok(root.clone());
        }
        // Fall back to blob (post-restart recovery)
        let blob = self.blob_get(kappa)?;
        let root = EpochRoot::from_leaf_bytes(&blob)
            .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
        self.epoch_roots
            .write()
            .unwrap()
            .insert(kappa.to_string(), root.clone());
        Ok(root)
    }

    // -- Namespace ------------------------------------------------------------

    fn namespace_create(
        &self,
        name: &str,
        owner: &str,
        protocol: Option<&str>,
    ) -> Result<NamespaceRef, StoreError> {
        let alias_key = alias_key(name, protocol);
        if self.ns_aliases.contains_key(&alias_key) {
            return Err(StoreError::Conflict(format!("namespace alias already exists: {}", alias_key)));
        }
        let ns = NamespaceRef::generate(name);
        let uuid = *ns.uuid();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.ns_aliases.insert(alias_key, uuid);
        self.ns_records.insert(uuid, crate::store::NamespaceRecord {
            uuid_hex: ns.uuid_hex(),
            owner: owner.to_string(),
            created_at_ms: now_ms,
            protocol: protocol.map(|s| s.to_string()),
            aliases: vec![name.to_string()],
            tombstoned: false,
        });
        Ok(ns)
    }

    fn namespace_resolve(
        &self,
        name: &str,
        protocol: Option<&str>,
    ) -> Result<NamespaceRef, StoreError> {
        let key = alias_key(name, protocol);
        let uuid = self.ns_aliases.get(&key)
            .map(|r| *r.value())
            .ok_or_else(|| StoreError::NotFound(format!("namespace alias: {}", key)))?;
        Ok(NamespaceRef::with_name(uuid, name.to_string()))
    }

    fn namespace_resolve_or_create(
        &self,
        name: &str,
        owner: &str,
        protocol: Option<&str>,
    ) -> Result<NamespaceRef, StoreError> {
        match self.namespace_resolve(name, protocol) {
            Ok(ns) => Ok(ns),
            Err(StoreError::NotFound(_)) => {
                match self.namespace_create(name, owner, protocol) {
                    Ok(ns) => Ok(ns),
                    Err(StoreError::Conflict(_)) => self.namespace_resolve(name, protocol),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    fn namespace_list(
        &self,
        protocol: Option<&str>,
    ) -> Result<Vec<crate::store::NamespaceRecord>, StoreError> {
        tracing::trace!("namespace_list");
        let mut result: Vec<crate::store::NamespaceRecord> = self.ns_records.iter()
            .map(|r| r.value().clone())
            .filter(|r| {
                if let Some(p) = protocol {
                    r.protocol.as_deref() == Some(p)
                } else {
                    true
                }
            })
            .collect();
        result.sort_by(|a, b| a.aliases.first().cmp(&b.aliases.first()));
        Ok(result)
    }

    fn namespace_exists(
        &self,
        name: &str,
        protocol: Option<&str>,
    ) -> Result<bool, StoreError> {
        let key = alias_key(name, protocol);
        Ok(self.ns_aliases.contains_key(&key))
    }

    fn namespace_rename(
        &self,
        old_name: &str,
        new_name: &str,
        actor: &str,
        protocol: Option<&str>,
    ) -> Result<(), StoreError> {
        let old_key = alias_key(old_name, protocol);
        let new_key = alias_key(new_name, protocol);
        let uuid = self.ns_aliases.get(&old_key)
            .map(|r| *r.value())
            .ok_or_else(|| StoreError::NotFound(format!("namespace alias: {}", old_key)))?;
        if self.ns_aliases.contains_key(&new_key) {
            return Err(StoreError::Conflict(format!("target alias already exists: {}", new_key)));
        }
        if let Some(mut record) = self.ns_records.get_mut(&uuid) {
            if record.owner != actor {
                return Err(StoreError::Rejected(format!(
                    "only owner {} can rename, actor is {}", record.owner, actor
                )));
            }
            record.aliases.retain(|a| a != old_name);
            record.aliases.push(new_name.to_string());
        }
        self.ns_aliases.remove(&old_key);
        self.ns_aliases.insert(new_key, uuid);
        Ok(())
    }

    fn namespace_add_alias(
        &self,
        uuid: &[u8; 16],
        alias: &str,
        actor: &str,
        protocol: Option<&str>,
    ) -> Result<(), StoreError> {
        let key = alias_key(alias, protocol);
        if self.ns_aliases.contains_key(&key) {
            return Err(StoreError::Conflict(format!("alias already exists: {}", key)));
        }
        let mut record = self.ns_records.get_mut(uuid)
            .ok_or_else(|| StoreError::NotFound(format!("namespace record: {}", hex::encode(uuid))))?;
        if record.owner != actor {
            return Err(StoreError::Rejected(format!(
                "only owner {} can add alias, actor is {}", record.owner, actor
            )));
        }
        if !record.aliases.contains(&alias.to_string()) {
            record.aliases.push(alias.to_string());
        }
        drop(record);
        self.ns_aliases.insert(key, *uuid);
        Ok(())
    }

    fn namespace_transfer(
        &self,
        uuid: &[u8; 16],
        new_owner: &str,
        actor: &str,
    ) -> Result<(), StoreError> {
        let mut record = self.ns_records.get_mut(uuid)
            .ok_or_else(|| StoreError::NotFound(format!("namespace record: {}", hex::encode(uuid))))?;
        if record.owner != actor {
            let resolved = self.identity_succession_resolve(&record.owner)?;
            if resolved != actor {
                return Err(StoreError::Rejected(format!(
                    "only owner {} (or successor) can transfer, actor is {}", record.owner, actor
                )));
            }
        }
        record.owner = new_owner.to_string();
        Ok(())
    }

    fn namespace_info(
        &self,
        name: &str,
        protocol: Option<&str>,
    ) -> Result<crate::store::NamespaceRecord, StoreError> {
        let key = alias_key(name, protocol);
        let uuid = self.ns_aliases.get(&key)
            .map(|r| *r.value())
            .ok_or_else(|| StoreError::NotFound(format!("namespace alias: {}", key)))?;
        self.ns_records.get(&uuid)
            .map(|r| r.value().clone())
            .ok_or_else(|| StoreError::NotFound(format!("namespace record: {}", hex::encode(uuid))))
    }

    fn namespace_delete(
        &self,
        name: &str,
        actor: &str,
        protocol: Option<&str>,
    ) -> Result<(), StoreError> {
        let key = alias_key(name, protocol);
        let uuid = self.ns_aliases.get(&key)
            .map(|r| *r.value())
            .ok_or_else(|| StoreError::NotFound(format!("namespace alias: {}", key)))?;
        {
            let record = self.ns_records.get(&uuid)
                .ok_or_else(|| StoreError::NotFound(format!("namespace record: {}", hex::encode(uuid))))?;
            if record.owner != actor {
                return Err(StoreError::Rejected(format!(
                    "only owner {} can delete, actor is {}", record.owner, actor
                )));
            }
        }
        // Remove all aliases
        if let Some(mut record) = self.ns_records.get_mut(&uuid) {
            for alias_name in record.aliases.clone() {
                self.ns_aliases.remove(&alias_name);
                if let Some(ref proto) = record.protocol {
                    let scoped = format!("{}:{}", proto, alias_name);
                    self.ns_aliases.remove(&scoped);
                }
            }
            record.tombstoned = true;
        }
        Ok(())
    }

    // -- Streaming upload (in-memory) -----------------------------------------

    fn upload_begin(&self, namespace: &NamespaceRef, max_size: u64) -> Result<String, StoreError> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut uploads = self.uploads.lock().unwrap();
        uploads.insert(id.clone(), UploadSession {
            namespace: namespace.to_string(),
            data: Vec::new(),
            max_size,
            created_at: std::time::Instant::now(),
            part_digests: Vec::new(),
        });
        Ok(id)
    }

    fn upload_put_part(
        &self,
        upload_id: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<u64, StoreError> {
        let mut uploads = self.uploads.lock().unwrap();
        // Inline expiration check before proceeding
        if let Some(timeout) = self.upload_timeout_secs {
            if let Some(session) = uploads.get(upload_id) {
                if session.created_at.elapsed() > std::time::Duration::from_secs(timeout) {
                    uploads.remove(upload_id);
                    return Err(StoreError::NotFound(format!("upload {} expired", upload_id)));
                }
            }
        }
        let session = uploads.get_mut(upload_id)
            .ok_or_else(|| StoreError::NotFound(format!("upload {}", upload_id)))?;
        if offset != session.data.len() as u64 {
            return Err(StoreError::Conflict(format!(
                "out-of-order: expected offset {}, got {}",
                session.data.len(), offset
            )));
        }
        let new_len = session.data.len() + data.len();
        if session.max_size > 0 && new_len as u64 > session.max_size {
            return Err(StoreError::Rejected(format!(
                "upload exceeds max size {}",
                session.max_size
            )));
        }
        // Compute per-part MD5 for ETag validation on CompleteMultipartUpload
        use md5::Digest;
        let md5_hash = md5::Md5::digest(data);
        let mut md5_bytes = [0u8; 16];
        md5_bytes.copy_from_slice(&md5_hash);
        let part_number = session.part_digests.len() as u32 + 1;
        session.part_digests.push((part_number, md5_bytes, data.len() as u64));

        session.data.extend_from_slice(data);
        Ok(session.data.len() as u64)
    }

    fn upload_complete(
        &self,
        upload_id: &str,
        claimed_digest: Option<&str>,
    ) -> Result<crate::store::IngestResult, StoreError> {
        let content = {
            let mut uploads = self.uploads.lock().unwrap();
            let session = uploads.remove(upload_id)
                .ok_or_else(|| StoreError::NotFound(format!("upload {}", upload_id)))?;
            if let Some(timeout) = self.upload_timeout_secs {
                if session.created_at.elapsed() > std::time::Duration::from_secs(timeout) {
                    return Err(StoreError::NotFound(format!("upload {} expired", upload_id)));
                }
            }
            session.data
        };

        // Type-enforced verification: produce a StreamingVerificationProof
        // from the content, then consume it via ingest_verified. For
        // InMemoryStore the content is in memory so we use the in-memory
        // hash. The proof ensures no unverified kappa reaches storage.
        let proof = {
            let mut cursor = std::io::Cursor::new(&content);
            let axis = match claimed_digest {
                Some(d) => d.split_once(':').map(|(a, _)| a).unwrap_or("sha256"),
                None => "sha256",
            };
            crate::kappa::streaming_compute_kappa(axis, &mut cursor)
                .map_err(|e| StoreError::Rejected(e.to_string()))?
        };

        // Verify claimed digest matches proof if caller provided one
        if let Some(claimed) = claimed_digest {
            if proof.kappa() != claimed {
                return Err(StoreError::Rejected(format!(
                    "digest mismatch: expected {}, computed {}",
                    claimed, proof.kappa()
                )));
            }
        }

        // Consume the proof: extract the verified kappa and store
        let verified_kappa = proof.kappa().to_string();
        drop(proof); // proof consumed
        self.ingest_verified(&verified_kappa, &content)
    }

    fn upload_abort(&self, upload_id: &str) -> Result<(), StoreError> {
        let mut uploads = self.uploads.lock().unwrap();
        uploads.remove(upload_id);
        Ok(())
    }

    fn upload_bytes_received(&self, upload_id: &str) -> Option<u64> {
        let mut uploads = self.uploads.lock().unwrap();
        if let Some(timeout) = self.upload_timeout_secs {
            if let Some(s) = uploads.get(upload_id) {
                if s.created_at.elapsed() > std::time::Duration::from_secs(timeout) {
                    uploads.remove(upload_id);
                    return None;
                }
            }
        }
        uploads.get(upload_id).map(|s| s.data.len() as u64)
    }

    fn upload_namespace(&self, upload_id: &str) -> Option<String> {
        let mut uploads = self.uploads.lock().unwrap();
        if let Some(timeout) = self.upload_timeout_secs {
            if let Some(s) = uploads.get(upload_id) {
                if s.created_at.elapsed() > std::time::Duration::from_secs(timeout) {
                    uploads.remove(upload_id);
                    return None;
                }
            }
        }
        uploads.get(upload_id).map(|s| s.namespace.clone())
    }

    fn upload_part_info(&self, upload_id: &str) -> Vec<(u32, String, u64)> {
        let uploads = self.uploads.lock().unwrap();
        match uploads.get(upload_id) {
            Some(session) => session.part_digests.iter().map(|(pn, md5, size)| {
                (*pn, format!("\"{}\"", hex::encode(md5)), *size)
            }).collect(),
            None => Vec::new(),
        }
    }

    fn upload_evict_expired(&self, timeout_secs: u64) -> usize {
        let mut uploads = self.uploads.lock().unwrap();
        let before = uploads.len();
        uploads.retain(|_, s| s.created_at.elapsed() <= std::time::Duration::from_secs(timeout_secs));
        before - uploads.len()
    }

    // -- Compression-transparent blob storage ---------------------------------

    fn ingest_compressed(
        &self,
        uncompressed_hash: &str,
        compressed_content: &[u8],
        compression: &str,
        uncompressed_size: u64,
    ) -> Result<crate::store::IngestResult, StoreError> {
        let kappa = crate::kappa::kappa_from_bytes(compressed_content);
        // Store compressed bytes on disk at kappa path
        let path = self.blob_path(&kappa)?;
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, compressed_content)?;
            std::fs::rename(&tmp, &path)?;
        }
        // Store compression record
        self.compression_records.insert(
            uncompressed_hash.to_string(),
            (kappa.clone(), compression.to_string(), compressed_content.to_vec(), uncompressed_size),
        );
        Ok(crate::store::IngestResult::new(kappa, true))
    }

    fn blob_open_compressed(
        &self,
        uncompressed_hash: &str,
    ) -> Result<Box<dyn crate::store::BlobReader>, StoreError> {
        let entry = self.compression_records.get(uncompressed_hash)
            .ok_or_else(|| StoreError::NotFound(uncompressed_hash.to_string()))?;
        let compressed_bytes = entry.value().2.clone();
        Ok(Box::new(std::io::Cursor::new(compressed_bytes)))
    }

    fn blob_open_decompressed(
        &self,
        uncompressed_hash: &str,
    ) -> Result<Box<dyn crate::store::BlobReader>, StoreError> {
        let entry = self.compression_records.get(uncompressed_hash)
            .ok_or_else(|| StoreError::NotFound(uncompressed_hash.to_string()))?;
        let (_, ref algo, ref compressed, _) = *entry.value();
        let decompressed = decompress_bytes(compressed, algo)?;
        Ok(Box::new(std::io::Cursor::new(decompressed)))
    }

    // -- Assertion inbound index ----------------------------------------------

    fn assertion_index_put(
        &self,
        subject: &str,
        facet: &str,
        assertion_kappa: &str,
    ) -> Result<(), StoreError> {
        let key = format!("{}\x00{}", subject, facet);
        self.assertion_inbound
            .entry(key)
            .or_default()
            .push(assertion_kappa.to_string());
        Ok(())
    }

    fn assertion_index_query_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<String>, StoreError> {
        let prefix = format!("{}\x00", subject);
        let mut results = Vec::new();
        for entry in self.assertion_inbound.iter() {
            if entry.key().starts_with(&prefix) {
                results.extend(entry.value().iter().cloned());
            }
        }
        results.sort();
        results.dedup();
        Ok(results)
    }

    // -- Identity binding -----------------------------------------------------

    fn identity_binding_put(
        &self,
        _ns: &NamespaceRef,
        binding: &crate::identity::IdentityBinding,
    ) -> Result<String, StoreError> {
        let kappa = crate::kappa::kappa_from_value(binding);
        // Append with supersession:
        // - Same source+target, same metadata: skip (exact duplicate)
        // - Same source+target, different metadata: update in place
        //   (verified_at, trust_level, method may change on re-verification)
        // - Same source, different target: append (new binding supersedes
        //   old but old remains as historical record, sorted by verified_at)
        // - New source: insert
        //
        // This mirrors the assertion/watermark pattern: newer evidence
        // supersedes older evidence without deleting it. The latest
        // binding (highest verified_at_ms) is the current authority.
        // Historical bindings are queryable for audit.
        let mut bindings = self.identity_bindings
            .entry(binding.source.clone())
            .or_default();
        if let Some(existing) = bindings.iter_mut().find(|b| b.target == binding.target) {
            // Same source+target: update metadata if anything changed
            if existing.method != binding.method
                || existing.trust_level != binding.trust_level
                || existing.verified_at_ms != binding.verified_at_ms
            {
                *existing = binding.clone();
            }
            // else exact duplicate, skip
        } else {
            // Different target or first binding: append
            bindings.push(binding.clone());
        }
        // Sort by verified_at_ms descending so latest is first
        bindings.sort_by(|a, b| b.verified_at_ms.cmp(&a.verified_at_ms));
        Ok(kappa)
    }

    fn identity_binding_get(
        &self,
        subject: &str,
    ) -> Result<Vec<crate::identity::IdentityBinding>, StoreError> {
        match self.identity_bindings.get(subject) {
            Some(bindings) => Ok(bindings.value().clone()),
            None => Ok(Vec::new()),
        }
    }

    fn identity_binding_delete(
        &self,
        _ns: &NamespaceRef,
        subject: &str,
        target: &str,
    ) -> Result<(), StoreError> {
        if let Some(mut bindings) = self.identity_bindings.get_mut(subject) {
            bindings.retain(|b| b.target != target);
            if bindings.is_empty() {
                drop(bindings);
                self.identity_bindings.remove(subject);
            }
        }
        Ok(())
    }

    fn identity_binding_list_by_asserter(
        &self,
        asserter: &str,
    ) -> Result<Vec<crate::identity::IdentityBinding>, StoreError> {
        let mut results = Vec::new();
        for entry in self.identity_bindings.iter() {
            for binding in entry.value() {
                if binding.target == asserter {
                    results.push(binding.clone());
                }
            }
        }
        Ok(results)
    }

    // -- Identity succession --------------------------------------------------

    fn identity_succession_put(
        &self,
        succession: &crate::identity::IdentitySuccession,
    ) -> Result<String, StoreError> {
        if succession.old_anchor == succession.new_anchor {
            return Err(StoreError::Rejected("cannot succeed to self".into()));
        }
        let kappa = crate::kappa::kappa_from_value(succession);
        self.identity_successions.insert(
            succession.old_anchor.clone(),
            succession.new_anchor.clone(),
        );

        // Create watermark voiding old anchor's assertions.
        // KeyCompromise: void everything (timestamp 0).
        // Other reasons: void assertions before effective_at.
        let watermark_ts = if succession.reason == "key-compromise" {
            0u64
        } else {
            succession.effective_at_ms
        };
        let now_ms = self.clock.now_ms();
        let watermark = crate::identity::watermark::Watermark {
            asserter: succession.old_anchor.clone(),
            invalidate_before_ms: watermark_ts,
            reason: format!("{} succession", succession.reason),
            set_at_ms: now_ms,
        };
        let wm_bytes = crate::canonical::canonical_bytes(&watermark);
        let wm_kappa = crate::kappa::kappa_from_bytes(&wm_bytes);
        let _ = self.ingest_verified(&wm_kappa, &wm_bytes);
        // Tag under the asserter's anchor namespace so resolve_handler finds it
        let anchor_ns = NamespaceRef::deterministic(&succession.old_anchor);
        self.ensure_namespace(&anchor_ns);
        let wm_tag = format!("watermark/{}", wm_kappa);
        let _ = self.tag_set(&anchor_ns, &wm_tag, &wm_kappa);

        Ok(kappa)
    }

    fn identity_succession_resolve(
        &self,
        anchor: &str,
    ) -> Result<String, StoreError> {
        let mut current = anchor.to_string();
        let mut visited = std::collections::HashSet::new();
        visited.insert(current.clone());
        loop {
            match self.identity_successions.get(&current) {
                Some(next) => {
                    let next_val = next.value().clone();
                    if visited.contains(&next_val) {
                        return Err(StoreError::Rejected(format!(
                            "succession cycle detected at {next_val}"
                        )));
                    }
                    if visited.len() >= 10 {
                        return Err(StoreError::Rejected(
                            "succession chain exceeds 10 hops".into()
                        ));
                    }
                    visited.insert(next_val.clone());
                    current = next_val;
                }
                None => return Ok(current),
            }
        }
    }

    fn identity_succession_chain(
        &self,
        anchor: &str,
    ) -> Result<Vec<String>, StoreError> {
        let mut chain = vec![anchor.to_string()];
        let mut current = anchor.to_string();
        let mut visited = std::collections::HashSet::new();
        visited.insert(current.clone());
        loop {
            match self.identity_successions.get(&current) {
                Some(next) => {
                    let next_val = next.value().clone();
                    if visited.contains(&next_val) {
                        return Err(StoreError::Rejected(format!(
                            "succession cycle detected at {next_val}"
                        )));
                    }
                    if visited.len() >= 10 {
                        return Err(StoreError::Rejected(
                            "succession chain exceeds 10 hops".into()
                        ));
                    }
                    visited.insert(next_val.clone());
                    chain.push(next_val.clone());
                    current = next_val;
                }
                None => return Ok(chain),
            }
        }
    }
}

fn alias_key(name: &str, protocol: Option<&str>) -> String {
    match protocol {
        Some(p) => format!("{}:{}", p, name),
        None => name.to_string(),
    }
}

fn decompress_bytes(data: &[u8], algorithm: &str) -> Result<Vec<u8>, StoreError> {
    match algorithm {
        "none" => Ok(data.to_vec()),
        "zstd" => zstd::decode_all(std::io::Cursor::new(data))
            .map_err(|e| StoreError::Io(std::io::Error::other(format!("zstd: {e}")))),
        "xz" | "lzma" => {
            use std::io::Read;
            let mut decoder = xz2::read::XzDecoder::new(data);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out)
                .map_err(|e| StoreError::Io(std::io::Error::other(format!("xz: {e}"))))?;
            Ok(out)
        }
        "bzip2" => {
            use std::io::Read;
            let mut decoder = bzip2::read::BzDecoder::new(data);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out)
                .map_err(|e| StoreError::Io(std::io::Error::other(format!("bzip2: {e}"))))?;
            Ok(out)
        }
        other => Err(StoreError::Rejected(format!("unsupported compression: {other}"))),
    }
}
