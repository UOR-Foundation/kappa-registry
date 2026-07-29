//! InMemoryStore: the primary store implementation.
//!
//! Tags, edges, sequences, and epoch state live in hash maps.
//! Blobs live on the filesystem, content-addressed by kappa-label.
//!
//! no_std-clean modules (future kappa-core-types extraction):
//!   types, canonical, kappa, merkle, crypto traits + frost/ed25519/ecdsa
//!
//! std-required modules (stay in kappa-core):
//!   store (filesystem, RwLock), clock (SystemTime),
//!   crypto/keystore (filesystem), crypto/kms (filesystem),
//!   crypto/prf (filesystem for key material)

mod edge;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use crate::clock::Clock;
use crate::epoch::{self, EpochRoot, EpochRootFields};
use crate::kappa::kappa_from_bytes;
use crate::store::KappaStore;
use crate::types::*;

pub struct MemoryStoreConfig {
    pub blob_root: PathBuf,
}

pub struct InMemoryStore {
    blob_root: PathBuf,
    clock: Arc<dyn Clock>,
    tags: RwLock<HashMap<(u64, u64), TagEntry>>,
    pub(crate) edges: RwLock<HashMap<(u64, u64), Edge>>,
    pub(crate) fwd_index: RwLock<HashMap<(u64, u64), Vec<String>>>,
    pub(crate) rev_index: RwLock<HashMap<(u64, u64), Vec<String>>>,
    pub(crate) rel_index: RwLock<HashMap<(u64, u64), Vec<String>>>,
    pub(crate) asr_index: RwLock<HashMap<(u64, u64), Vec<String>>>,
    sequences: Mutex<HashMap<(u64, u64), u64>>,
    namespaces: RwLock<std::collections::HashSet<String>>,
    epoch_roots: RwLock<HashMap<String, EpochRoot>>,
    current_epochs: RwLock<HashMap<u64, String>>,
}

impl InMemoryStore {
    pub fn new(config: MemoryStoreConfig, clock: Arc<dyn Clock>) -> Result<Self, StoreError> {
        std::fs::create_dir_all(&config.blob_root)?;
        Ok(InMemoryStore {
            blob_root: config.blob_root,
            clock,
            tags: RwLock::new(HashMap::new()),
            edges: RwLock::new(HashMap::new()),
            fwd_index: RwLock::new(HashMap::new()),
            rev_index: RwLock::new(HashMap::new()),
            rel_index: RwLock::new(HashMap::new()),
            asr_index: RwLock::new(HashMap::new()),
            sequences: Mutex::new(HashMap::new()),
            namespaces: RwLock::new(std::collections::HashSet::new()),
            epoch_roots: RwLock::new(HashMap::new()),
            current_epochs: RwLock::new(HashMap::new()),
        })
    }

    fn blob_path(&self, kappa: &str) -> Result<PathBuf, StoreError> {
        let (algo, digest) = crate::kappa::split_kappa(kappa)
            .ok_or_else(|| StoreError::Rejected(format!("invalid kappa-label: {}", kappa)))?;
        if digest.len() < 4 {
            return Err(StoreError::Rejected(format!("kappa digest too short: {}", kappa)));
        }
        Ok(self.blob_root.join(algo).join(&digest[..2]).join(&digest[2..4]).join(digest))
    }

    fn ensure_namespace(&self, ns: &str) {
        self.namespaces.write().unwrap().insert(ns.to_string());
    }

    fn collect_sorted_tags(&self, ns: &str) -> Vec<TagEntry> {
        let ns_hash = namespace_hash(ns);
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
    /// Durability: survives clean shutdown. No fsync -- recovery from
    /// epoch chain replay if power loss occurs between write and
    /// next checkpoint.
    fn blob_put(&self, content: &[u8]) -> Result<String, StoreError> {
        let kappa = kappa_from_bytes(content);
        let path = self.blob_path(&kappa)?;
        if path.exists() {
            return Ok(kappa);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, content)?;
        std::fs::rename(&tmp, &path)?;
        Ok(kappa)
    }

    fn blob_get(&self, kappa: &str) -> Result<Vec<u8>, StoreError> {
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
        Ok(self.blob_path(kappa)?.exists())
    }

    fn blob_delete(&self, kappa: &str) -> Result<(), StoreError> {
        let path = self.blob_path(kappa)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    fn blob_get_range(&self, kappa: &str, offset: u64, length: u64) -> Result<Vec<u8>, StoreError> {
        let data = self.blob_get(kappa)?;
        let start = offset as usize;
        if start >= data.len() {
            return Ok(Vec::new());
        }
        let end = std::cmp::min(start + length as usize, data.len());
        Ok(data[start..end].to_vec())
    }

    fn tag_set(&self, ns: &str, name: &str, kappa: &str) -> Result<u64, StoreError> {
        self.ensure_namespace(ns);
        let key = (namespace_hash(ns), item_hash(name));
        let mut tags = self.tags.write().unwrap();
        let version = tags.get(&key).map(|e| e.version + 1).unwrap_or(1);
        tags.insert(key, TagEntry {
            name: name.to_string(),
            kappa: kappa.to_string(),
            version,
        });
        Ok(version)
    }

    fn tag_get(&self, ns: &str, name: &str) -> Result<TagEntry, StoreError> {
        let tags = self.tags.read().unwrap();
        tags.get(&(namespace_hash(ns), item_hash(name)))
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("{}/{}", ns, name)))
    }

    fn tag_delete(&self, ns: &str, name: &str) -> Result<(), StoreError> {
        self.tags.write().unwrap().remove(&(namespace_hash(ns), item_hash(name)));
        Ok(())
    }

    fn tag_list(&self, ns: &str) -> Result<Vec<TagEntry>, StoreError> {
        Ok(self.collect_sorted_tags(ns))
    }

    fn tag_prefix(&self, ns: &str, prefix: &str) -> Result<Vec<TagEntry>, StoreError> {
        let ns_hash = namespace_hash(ns);
        let tags = self.tags.read().unwrap();
        let mut result: Vec<TagEntry> = tags
            .iter()
            .filter(|((nh, _), e)| *nh == ns_hash && e.name.starts_with(prefix))
            .map(|(_, e)| e.clone())
            .collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    fn tag_set_batch(&self, ns: &str, updates: &[TagUpdate]) -> Result<(), StoreError> {
        self.ensure_namespace(ns);
        let ns_hash = namespace_hash(ns);
        let mut tags = self.tags.write().unwrap();

        for update in updates {
            if let Some(expected) = update.expected_version {
                let current = tags.get(&(ns_hash, item_hash(&update.name)))
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
            tags.insert(key, TagEntry {
                name: update.name.clone(),
                kappa: update.kappa.clone(),
                version,
            });
        }
        Ok(())
    }

    fn edge_put(&self, ns: &str, edge_record: &Edge) -> Result<String, StoreError> {
        edge::edge_put(self, ns, edge_record)
    }

    fn edge_query(&self, ns: &str, query: &EdgeQuery) -> Result<Vec<Edge>, StoreError> {
        edge::edge_query(self, ns, query)
    }

    fn edge_delete(&self, ns: &str, edge_kappa: &str) -> Result<(), StoreError> {
        edge::edge_delete(self, ns, edge_kappa)
    }

    fn sequence_next(&self, ns: &str, name: &str) -> Result<u64, StoreError> {
        self.ensure_namespace(ns);
        let key = (namespace_hash(ns), item_hash(name));
        let mut seqs = self.sequences.lock().unwrap();
        let counter = seqs.entry(key).or_insert(0);
        *counter += 1;
        Ok(*counter)
    }

    fn sequence_current(&self, ns: &str, name: &str) -> Result<u64, StoreError> {
        let seqs = self.sequences.lock().unwrap();
        Ok(seqs.get(&(namespace_hash(ns), item_hash(name))).copied().unwrap_or(0))
    }

    fn epoch_advance(&self, ns: &str, mutations: Vec<EpochMutation>) -> Result<String, StoreError> {
        self.ensure_namespace(ns);
        let ns_hash = namespace_hash(ns);
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
            namespace: ns.to_string(),
            epoch_number,
            prev_root_kappa,
            state_root,
            mutations_root,
            timestamp_ms,
            signer_anchor: String::new(),
        });

        let kappa = epoch_root.kappa();
        self.epoch_roots.write().unwrap().insert(kappa.clone(), epoch_root);
        self.current_epochs.write().unwrap().insert(ns_hash, kappa.clone());
        Ok(kappa)
    }

    fn epoch_current(&self, ns: &str) -> Result<Option<String>, StoreError> {
        Ok(self.current_epochs.read().unwrap().get(&namespace_hash(ns)).cloned())
    }

    fn epoch_get(&self, kappa: &str) -> Result<EpochRoot, StoreError> {
        self.epoch_roots.read().unwrap()
            .get(kappa)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(kappa.to_string()))
    }

    fn namespace_list(&self) -> Result<Vec<String>, StoreError> {
        let nss = self.namespaces.read().unwrap();
        let mut result: Vec<String> = nss.iter().cloned().collect();
        result.sort();
        Ok(result)
    }

    fn namespace_exists(&self, ns: &str) -> Result<bool, StoreError> {
        Ok(self.namespaces.read().unwrap().contains(ns))
    }
}
