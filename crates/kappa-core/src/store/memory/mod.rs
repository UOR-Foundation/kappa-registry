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
    tags: RwLock<HashMap<(u64, u64), TagEntry>>,
    meta: DashMap<(u64, u64), Vec<u8>>,
    /// Namespace-scoped metadata index: (ns_hash, key_hash, value_hash) -> Vec<kappa>
    ns_meta: DashMap<(u64, u64, u64), Vec<String>>,
    pub(crate) edges: RwLock<HashMap<(u64, u64), Edge>>,
    pub(crate) fwd_index: RwLock<HashMap<(u64, u64), Vec<String>>>,
    pub(crate) rev_index: RwLock<HashMap<(u64, u64), Vec<String>>>,
    pub(crate) rel_index: RwLock<HashMap<(u64, u64), Vec<String>>>,
    pub(crate) asr_index: RwLock<HashMap<(u64, u64), Vec<String>>>,
    sequences: Mutex<HashMap<(u64, u64), u64>>,
    namespaces: RwLock<std::collections::HashSet<String>>,
    epoch_roots: RwLock<HashMap<String, EpochRoot>>,
    current_epochs: RwLock<HashMap<u64, String>>,
    uploads: Mutex<HashMap<String, UploadSession>>,
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
            namespaces: RwLock::new(std::collections::HashSet::new()),
            epoch_roots: RwLock::new(HashMap::new()),
            current_epochs: RwLock::new(HashMap::new()),
            uploads: Mutex::new(HashMap::new()),
        })
    }

    fn blob_path(&self, kappa: &str) -> Result<PathBuf, StoreError> {
        crate::kappa::blob_path_for(&self.blob_root, kappa)
    }

    fn ensure_namespace(&self, ns: &NamespaceRef) {
        self.namespaces.write().unwrap().insert(ns.as_str().to_string());
    }

    fn collect_sorted_tags(&self, ns: &NamespaceRef) -> Vec<TagEntry> {
        let ns_hash = namespace_hash(ns.as_str());
        let tags = self.tags.read().unwrap();
        let mut entries: Vec<TagEntry> = tags
            .iter()
            .filter(|((nh, _), _)| *nh == ns_hash)
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
        tracing::debug!(ns = ns.as_str(), kappa = kappa, key = key, value = value, "meta_set");
        self.ensure_namespace(ns);
        let idx_key = (namespace_hash(ns.as_str()), item_hash(key), item_hash(value));
        self.ns_meta
            .entry(idx_key)
            .or_default()
            .push(kappa.to_string());
        Ok(())
    }

    fn meta_query(&self, ns: &NamespaceRef, key: &str, value: &str) -> Result<Vec<String>, StoreError> {
        tracing::trace!(ns = ns.as_str(), key = key, value = value, "meta_query");
        if value.is_empty() {
            let ns_hash = namespace_hash(ns.as_str());
            let key_hash = item_hash(key);
            let mut results = Vec::new();
            for entry in self.ns_meta.iter() {
                let (nh, kh, _vh) = *entry.key();
                if nh == ns_hash && kh == key_hash {
                    results.extend(entry.value().iter().cloned());
                }
            }
            results.sort();
            results.dedup();
            Ok(results)
        } else {
            let idx_key = (namespace_hash(ns.as_str()), item_hash(key), item_hash(value));
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
        tracing::debug!(ns = ns.as_str(), tag = name, kappa = kappa, "tag_set");
        self.ensure_namespace(ns);
        let key = (namespace_hash(ns.as_str()), item_hash(name));
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
        tracing::trace!(ns = ns.as_str(), tag = name, "tag_get");
        let tags = self.tags.read().unwrap();
        tags.get(&(namespace_hash(ns.as_str()), item_hash(name)))
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("{}/{}", ns.as_str(), name)))
    }

    fn tag_delete(&self, ns: &NamespaceRef, name: &str) -> Result<(), StoreError> {
        tracing::debug!(ns = ns.as_str(), tag = name, "tag_delete");
        self.tags
            .write()
            .unwrap()
            .remove(&(namespace_hash(ns.as_str()), item_hash(name)));
        Ok(())
    }

    fn tag_list(&self, ns: &NamespaceRef) -> Result<Vec<TagEntry>, StoreError> {
        tracing::trace!(ns = ns.as_str(), "tag_list");
        Ok(self.collect_sorted_tags(ns))
    }

    fn tag_prefix(&self, ns: &NamespaceRef, prefix: &str) -> Result<Vec<TagEntry>, StoreError> {
        tracing::trace!(ns = ns.as_str(), prefix = prefix, "tag_prefix");
        let ns_hash = namespace_hash(ns.as_str());
        let tags = self.tags.read().unwrap();
        let mut result: Vec<TagEntry> = tags
            .iter()
            .filter(|((nh, _), e)| *nh == ns_hash && e.name.starts_with(prefix))
            .map(|(_, e)| e.clone())
            .collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    fn tag_set_batch(&self, ns: &NamespaceRef, updates: &[TagUpdate]) -> Result<(), StoreError> {
        tracing::debug!(ns = ns.as_str(), count = updates.len(), "tag_set_batch");
        self.ensure_namespace(ns);
        let ns_hash = namespace_hash(ns.as_str());
        let mut tags = self.tags.write().unwrap();

        for update in updates {
            if let Some(expected) = update.expected_version {
                let current = tags
                    .get(&(ns_hash, item_hash(&update.name)))
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
            let key = (ns_hash, item_hash(&update.name));
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
        tracing::debug!(ns = ns.as_str(), seq = name, "sequence_next");
        self.ensure_namespace(ns);
        let key = (namespace_hash(ns.as_str()), item_hash(name));
        let mut seqs = self.sequences.lock().unwrap();
        let counter = seqs.entry(key).or_insert(0);
        *counter += 1;
        Ok(*counter)
    }

    fn sequence_current(&self, ns: &NamespaceRef, name: &str) -> Result<u64, StoreError> {
        tracing::trace!(ns = ns.as_str(), seq = name, "sequence_current");
        let seqs = self.sequences.lock().unwrap();
        Ok(seqs
            .get(&(namespace_hash(ns.as_str()), item_hash(name)))
            .copied()
            .unwrap_or(0))
    }

    // -- Epoch ----------------------------------------------------------------

    fn epoch_advance(&self, ns: &NamespaceRef, mutations: Vec<EpochMutation>) -> Result<String, StoreError> {
        tracing::debug!(ns = ns.as_str(), mutation_count = mutations.len(), "epoch_advance");
        self.ensure_namespace(ns);
        let ns_hash = namespace_hash(ns.as_str());
        let epoch_number = {
            let mut seqs = self.sequences.lock().unwrap();
            let key = (ns_hash, item_hash("_epoch"));
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
            namespace: ns.as_str().to_string(),
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
            .insert(ns_hash, kappa.clone());

        // Persist the current epoch pointer as a tag so epoch_current
        // survives process restart without scanning all blobs.
        self.tag_set(ns, "_epoch/current", &kappa)?;

        Ok(kappa)
    }

    fn epoch_current(&self, ns: &NamespaceRef) -> Result<Option<String>, StoreError> {
        tracing::trace!(ns = ns.as_str(), "epoch_current");
        // Check in-memory cache first
        if let Some(k) = self
            .current_epochs
            .read()
            .unwrap()
            .get(&namespace_hash(ns.as_str()))
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
                    .insert(namespace_hash(ns.as_str()), entry.kappa.clone());
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

    fn namespace_list(&self) -> Result<Vec<String>, StoreError> {
        tracing::trace!("namespace_list");
        let nss = self.namespaces.read().unwrap();
        let mut result: Vec<String> = nss.iter().cloned().collect();
        result.sort();
        Ok(result)
    }

    fn namespace_exists(&self, ns: &NamespaceRef) -> Result<bool, StoreError> {
        tracing::trace!(ns = ns.as_str(), "namespace_exists");
        Ok(self.namespaces.read().unwrap().contains(ns.as_str()))
    }

    // -- Streaming upload (in-memory) -----------------------------------------

    fn upload_begin(&self, namespace: &NamespaceRef, max_size: u64) -> Result<String, StoreError> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut uploads = self.uploads.lock().unwrap();
        uploads.insert(id.clone(), UploadSession {
            namespace: namespace.as_str().to_string(),
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
}
