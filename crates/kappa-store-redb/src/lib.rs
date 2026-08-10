//! Persistent KappaStore backed by redb B+tree tables and filesystem blobs.
//!
//! All structured state (tags, edges, sequences, metadata, namespaces,
//! epoch pointers) is stored in redb tables and survives process restart.
//! Blobs remain on the filesystem, content-addressed by kappa-label.
//!
//! redb provides ACID transactions with Durability::Immediate by default
//! (fsync on commit). This means committed data survives kill -9.
//!
//! The store is organized as modules:
//!   blob.rs      -- filesystem blob ops + redb blob metadata + ns_meta
//!   tag.rs       -- redb tag CRUD with B+tree range scans
//!   edge.rs      -- redb edge tables with 4 multimap indexes
//!   epoch.rs     -- epoch chain with blob persistence + redb pointer
//!   namespace.rs -- redb namespace + sequence tables
//!   tables.rs    -- redb table constant definitions

mod blob;
pub mod credentials;
mod edge;
pub mod encrypted;
mod epoch;
pub mod frame_reader;
mod namespace;
mod tables;
mod tag;
mod versions;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use redb::{Database, ReadableDatabase};

struct DiskUploadSession {
    namespace: String,
    staging_path: PathBuf,
    offset: u64,
    max_size: u64,
    created_at: std::time::Instant,
    /// Per-part digests computed during upload_put_part.
    part_digests: Vec<PartDigests>,
    /// Running MD5 hasher for the current part.
    current_md5: md5::Md5,
    /// Running CRC32C for the current part.
    current_crc32c: crc_fast::Digest,
    /// Running CRC64-NVME for the current part.
    current_crc64nvme: crc_fast::Digest,
}

/// Per-part digest metadata computed during upload.
#[derive(Debug, Clone)]
struct PartDigests {
    part_number: u32,
    offset: u64,
    size: u64,
    md5: [u8; 16],
    crc32c: u64,
    crc64nvme: u64,
}

use md5::Digest as Md5Digest;

use kappa_core::clock::Clock;
use kappa_core::epoch::EpochRoot;
use kappa_core::store::KappaStore;
use kappa_core::types::*;

pub struct PersistentStore {
    blob_root: PathBuf,
    clock: Arc<dyn Clock>,
    db: Database,
    fsync: bool,
    epoch_cache: RwLock<HashMap<String, EpochRoot>>,
    upload_sessions: std::sync::Mutex<HashMap<String, DiskUploadSession>>,
    staging_root: PathBuf,
    /// Optional encryption key for blob-at-rest and redb value encryption.
    /// When Some, blobs are AEAD-encrypted before writing to disk, and
    /// blob paths use HMAC(key, kappa) instead of plaintext hex.
    /// When None, blobs are stored in plaintext (default).
    encryption_key: Option<[u8; 32]>,
    /// Cached BlobEncryptor for the current encryption key.
    /// Constructed once at store creation, reused for all operations.
    blob_encryptor: Option<kappa_core::crypto::aead::BlobEncryptor>,
    /// Cached TableEncryptor for redb value encryption.
    table_encryptor: Option<encrypted::TableEncryptor>,
    /// Upload session timeout in seconds. Sessions older than this are
    /// rejected on access (inline check) and cleaned up by background
    /// eviction. None = no timeout (infinite).
    upload_timeout_secs: Option<u64>,
}

/// Configuration for PersistentStore construction.
///
/// Use `PersistentStoreConfig::new(blob_root, db_path)` to create with
/// sensible defaults. Override fields as needed before passing to
/// `PersistentStore::new`.
#[non_exhaustive]
pub struct PersistentStoreConfig {
    pub blob_root: PathBuf,
    pub db_path: PathBuf,
    pub fsync: bool,
    pub encryption_key: Option<[u8; 32]>,
    pub upload_timeout_secs: Option<u64>,
}

impl PersistentStoreConfig {
    pub fn new(blob_root: PathBuf, db_path: PathBuf) -> Self {
        Self {
            blob_root,
            db_path,
            fsync: true,
            encryption_key: None,
            upload_timeout_secs: None,
        }
    }
}

impl PersistentStore {
    pub fn new(
        config: PersistentStoreConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, StoreError> {
        let blob_root = config.blob_root;
        let db_path = config.db_path;
        let fsync = config.fsync;
        let encryption_key = config.encryption_key;
        let upload_timeout_secs = config.upload_timeout_secs;

        std::fs::create_dir_all(&blob_root).map_err(StoreError::Io)?;
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(StoreError::Io)?;
        }
        let db = Database::create(&db_path).map_err(Self::redb_err)?;

        // Create all tables on first open
        let txn = db.begin_write().map_err(Self::redb_err)?;
        {
            txn.open_table(tables::TAGS).map_err(Self::redb_err)?;
            txn.open_table(tables::EDGES).map_err(Self::redb_err)?;
            txn.open_multimap_table(tables::EDGE_FWD)
                .map_err(Self::redb_err)?;
            txn.open_multimap_table(tables::EDGE_REV)
                .map_err(Self::redb_err)?;
            txn.open_multimap_table(tables::EDGE_REL)
                .map_err(Self::redb_err)?;
            txn.open_multimap_table(tables::EDGE_ASR)
                .map_err(Self::redb_err)?;
            txn.open_table(tables::SEQUENCES).map_err(Self::redb_err)?;
            txn.open_table(tables::BLOB_META).map_err(Self::redb_err)?;
            txn.open_multimap_table(tables::NS_META)
                .map_err(Self::redb_err)?;
            txn.open_table(tables::NAMESPACES).map_err(Self::redb_err)?;
            txn.open_table(tables::EPOCH_CURRENT)
                .map_err(Self::redb_err)?;
            txn.open_multimap_table(tables::ASSERTION_INBOUND)
                .map_err(Self::redb_err)?;
            txn.open_table(tables::BINDING_RECORDS)
                .map_err(Self::redb_err)?;
            txn.open_table(tables::CREDENTIALS)
                .map_err(Self::redb_err)?;
            txn.open_table(tables::VERSIONS)
                .map_err(Self::redb_err)?;
        }
        txn.commit().map_err(Self::redb_err)?;

        let blob_encryptor = match &encryption_key {
            Some(key) => {
                // Create a FileKms with the encryption key as root secret
                let erased_dir = blob_root.join("_erased");
                let kms = kappa_core::crypto::kms::FileKms::new(*key, erased_dir)
                    .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
                Some(
                    kappa_core::crypto::aead::BlobEncryptor::new(&kms, "_default")
                        .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?,
                )
            }
            None => None,
        };
        let table_encryptor = match &encryption_key {
            Some(key) => Some(
                encrypted::TableEncryptor::new(key)
                    .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?,
            ),
            None => None,
        };

        let staging_root = blob_root.parent()
            .unwrap_or(&blob_root)
            .join("staging");
        let _ = std::fs::create_dir_all(&staging_root);
        // Startup cleanup: remove orphaned staging files from prior crashes
        if let Ok(entries) = std::fs::read_dir(&staging_root) {
            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }

        Ok(Self {
            blob_root,
            clock,
            db,
            fsync,
            epoch_cache: RwLock::new(HashMap::new()),
            upload_sessions: std::sync::Mutex::new(HashMap::new()),
            staging_root,
            encryption_key,
            blob_encryptor,
            table_encryptor,
            upload_timeout_secs,
        })
    }

    pub(crate) fn redb_err(e: impl std::fmt::Display) -> StoreError {
        StoreError::Io(std::io::Error::other(e.to_string()))
    }

    /// Index an assertion by subject+facet for cross-namespace resolution.
    pub fn assertion_index_put(
        &self,
        subject: &str,
        facet: &str,
        assertion_kappa: &str,
    ) -> Result<(), StoreError> {
        let key = format!("{}\x00{}", subject, facet);
        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        {
            let mut table = txn
                .open_multimap_table(tables::ASSERTION_INBOUND)
                .map_err(Self::redb_err)?;
            table
                .insert(&*key, assertion_kappa)
                .map_err(Self::redb_err)?;
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(())
    }

    /// Query assertions by subject+facet from the cross-namespace index.
    pub fn assertion_index_query(
        &self,
        subject: &str,
        facet: &str,
    ) -> Result<Vec<String>, StoreError> {
        let key = format!("{}\x00{}", subject, facet);
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn
            .open_multimap_table(tables::ASSERTION_INBOUND)
            .map_err(Self::redb_err)?;
        let mut results = Vec::new();
        if let Ok(values) = table.get(&*key) {
            for v in values.flatten() {
                results.push(v.value().to_string());
            }
        }
        Ok(results)
    }

    /// Query all assertions for a subject (any facet) from the cross-namespace index.
    pub fn assertion_index_query_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<String>, StoreError> {
        let prefix = format!("{}\x00", subject);
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn
            .open_multimap_table(tables::ASSERTION_INBOUND)
            .map_err(Self::redb_err)?;
        let mut results = Vec::new();
        let range = match Self::prefix_successor(prefix.as_bytes()) {
            Some(end) => {
                let end_str = String::from_utf8_lossy(&end).to_string();
                table.range::<&str>(prefix.as_str()..end_str.as_str())
            }
            None => table.range::<&str>(prefix.as_str()..),
        };
        if let Ok(iter) = range {
            for entry in iter.flatten() {
                let (_key, values) = entry;
                for v in values.flatten() {
                    results.push(v.value().to_string());
                }
            }
        }
        results.sort();
        results.dedup();
        Ok(results)
    }

    /// Compute the successor key for prefix range scans.
    /// Handles 0xFF carry: increments the rightmost non-0xFF byte
    /// and truncates everything after it. Returns None if all bytes
    /// are 0xFF (range extends to end of keyspace).
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
}

/// Compute composite S3 ETag from per-part MD5s: md5(md5(p1)||md5(p2)||...)-N
/// Serialize part digests to JSON and store as a blob. Create a
/// ChunkManifest edge from the object kappa to the manifest kappa.
/// This makes part information queryable after upload completion
/// via GetObjectAttributes.
fn persist_part_manifest(
    store: &PersistentStore,
    object_kappa: &str,
    parts: &[PartDigests],
) {
    if parts.is_empty() { return; }
    let manifest_json = serde_json::json!({
        "parts": parts.iter().map(|p| serde_json::json!({
            "part_number": p.part_number,
            "offset": p.offset,
            "size": p.size,
            "md5": hex::encode(p.md5),
            "crc32c": p.crc32c,
            "crc64nvme": p.crc64nvme,
        })).collect::<Vec<_>>(),
        "total_parts": parts.len(),
    });
    let manifest_bytes = serde_json::to_vec(&manifest_json).unwrap_or_default();
    // Store manifest blob
    use kappa_core::store::KappaStore;
    if let Ok(manifest_result) = store.ingest_compute(kappa_core::kappa::Axis::Sha256, &manifest_bytes) {
        // Create ChunkManifest edge from object to manifest
        let _ = store.edge_put_impl("_manifests", &kappa_core::types::Edge {
            source: object_kappa.to_string(),
            target: manifest_result.kappa,
            relation: kappa_core::types::EdgeRelation::ChunkManifest,
            asserter: "_system".to_string(),
            value_kappa: None,
            metadata: None,
        });
    }
}

fn compute_composite_etag(parts: &[PartDigests]) -> Option<String> {
    if parts.is_empty() {
        return None;
    }
    let mut hasher = md5::Md5::new();
    for part in parts {
        Md5Digest::update(&mut hasher, &part.md5);
    }
    let combined = hasher.finalize();
    Some(format!("\"{}-{}\"", hex::encode(combined), parts.len()))
}

// -- KappaStore trait implementation -------------------------------------------
// Each method delegates to the _impl method in the corresponding module.

impl KappaStore for PersistentStore {
    fn ingest_verified(
        &self,
        claimed: &str,
        content: &[u8],
    ) -> Result<kappa_core::store::IngestResult, StoreError> {
        let verified = kappa_core::verified::VerifiedContent::verify(claimed, content.to_vec())
            .map_err(|e| StoreError::Rejected(e.to_string()))?;
        let client_axis = verified.axis();
        let kappa = verified.kappa().to_string();
        let newly_stored = self.blob_put_impl(&verified)?;

        let mut additional_kappas = Vec::new();
        for axis in self.mandatory_axes() {
            if axis == client_axis { continue; }
            let additional = kappa_core::verified::VerifiedContent::compute(axis, content.to_vec())
                .map_err(|e| StoreError::Rejected(e.to_string()))?;
            let additional_kappa = additional.kappa().to_string();

            if self.encryption_key.is_some() {
                // Encrypted: store under additional address via blob_put_impl
                // (creates its own binding record pointing to its own ciphertext)
                self.blob_put_impl(&additional)?;
            } else {
                // Unencrypted: hard-link to primary path
                let primary_path = kappa_core::kappa::blob_path_for(&self.blob_root, &kappa)?;
                let alt_path = kappa_core::kappa::blob_path_for(&self.blob_root, &additional_kappa)?;
                if !alt_path.exists() {
                    if let Some(parent) = alt_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::hard_link(&primary_path, &alt_path);
                }
            }
            additional_kappas.push(additional_kappa);
        }

        Ok(kappa_core::store::IngestResult::new(kappa, newly_stored)
            .with_additional(additional_kappas))
    }

    fn ingest_compute(
        &self,
        axis: kappa_core::kappa::Axis,
        content: &[u8],
    ) -> Result<kappa_core::store::IngestResult, StoreError> {
        let verified = kappa_core::verified::VerifiedContent::compute(axis, content.to_vec())
            .map_err(|e| StoreError::Rejected(e.to_string()))?;
        let kappa = verified.kappa().to_string();
        let newly_stored = self.blob_put_impl(&verified)?;

        let mut additional_kappas = Vec::new();
        for mandatory in self.mandatory_axes() {
            if mandatory == axis { continue; }
            let additional = kappa_core::verified::VerifiedContent::compute(mandatory, content.to_vec())
                .map_err(|e| StoreError::Rejected(e.to_string()))?;
            let additional_kappa = additional.kappa().to_string();

            if self.encryption_key.is_some() {
                self.blob_put_impl(&additional)?;
            } else {
                let primary_path = kappa_core::kappa::blob_path_for(&self.blob_root, &kappa)?;
                let alt_path = kappa_core::kappa::blob_path_for(&self.blob_root, &additional_kappa)?;
                if !alt_path.exists() {
                    if let Some(parent) = alt_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::hard_link(&primary_path, &alt_path);
                }
            }
            additional_kappas.push(additional_kappa);
        }

        Ok(kappa_core::store::IngestResult::new(kappa, newly_stored)
            .with_additional(additional_kappas))
    }

    fn blob_put_verified(&self, content: &kappa_core::verified::VerifiedContent) -> Result<bool, StoreError> {
        self.blob_put_impl(content)
    }
    fn blob_get(&self, kappa: &str) -> Result<Vec<u8>, StoreError> {
        self.blob_get_impl(kappa)
    }
    fn blob_exists(&self, kappa: &str) -> Result<bool, StoreError> {
        self.blob_exists_impl(kappa)
    }
    fn blob_delete(&self, kappa: &str) -> Result<(), StoreError> {
        self.blob_delete_impl(kappa)
    }
    fn blob_size(&self, kappa: &str) -> Result<u64, StoreError> {
        self.blob_size_impl(kappa)
    }
    fn blob_get_range(
        &self,
        kappa: &str,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, StoreError> {
        self.blob_get_range_impl(kappa, offset, length)
    }
    fn blob_list(&self) -> Result<Vec<String>, StoreError> {
        self.blob_list_impl()
    }
    fn blob_put_meta(
        &self,
        kappa: &str,
        key: &str,
        value: &[u8],
    ) -> Result<(), StoreError> {
        self.blob_put_meta_impl(kappa, key, value)
    }
    fn blob_get_meta(&self, kappa: &str, key: &str) -> Result<Vec<u8>, StoreError> {
        self.blob_get_meta_impl(kappa, key)
    }
    fn blob_delete_meta(&self, kappa: &str, key: &str) -> Result<(), StoreError> {
        self.blob_delete_meta_impl(kappa, key)
    }
    fn meta_set(
        &self,
        ns: &str,
        kappa: &str,
        key: &str,
        value: &str,
    ) -> Result<(), StoreError> {
        self.meta_set_impl(ns, kappa, key, value)
    }
    fn meta_query(
        &self,
        ns: &str,
        key: &str,
        value: &str,
    ) -> Result<Vec<String>, StoreError> {
        self.meta_query_impl(ns, key, value)
    }
    fn tag_set(&self, ns: &str, name: &str, kappa: &str) -> Result<u64, StoreError> {
        self.tag_set_impl(ns, name, kappa)
    }
    fn tag_get(&self, ns: &str, name: &str) -> Result<TagEntry, StoreError> {
        self.tag_get_impl(ns, name)
    }
    fn tag_delete(&self, ns: &str, name: &str) -> Result<(), StoreError> {
        self.tag_delete_impl(ns, name)
    }
    fn tag_list(&self, ns: &str) -> Result<Vec<TagEntry>, StoreError> {
        self.tag_list_impl(ns)
    }
    fn tag_prefix(&self, ns: &str, prefix: &str) -> Result<Vec<TagEntry>, StoreError> {
        self.tag_prefix_impl(ns, prefix)
    }
    fn tag_set_batch(&self, ns: &str, updates: &[TagUpdate]) -> Result<(), StoreError> {
        self.tag_set_batch_impl(ns, updates)
    }
    fn edge_put(&self, ns: &str, edge: &Edge) -> Result<(), StoreError> {
        self.edge_put_impl(ns, edge)
    }
    fn edge_query(&self, ns: &str, query: &EdgeQuery) -> Result<Vec<Edge>, StoreError> {
        self.edge_query_impl(ns, query)
    }
    fn edge_delete(
        &self,
        ns: &str,
        source: &str,
        target: &str,
        relation: EdgeRelation,
    ) -> Result<(), StoreError> {
        self.edge_delete_impl(ns, source, target, relation)
    }
    fn edge_put_batch(&self, ns: &str, edges: &[Edge]) -> Result<(), StoreError> {
        self.edge_put_batch_impl(ns, edges)
    }
    fn sequence_next(&self, ns: &str, name: &str) -> Result<u64, StoreError> {
        self.sequence_next_impl(ns, name)
    }
    fn sequence_current(&self, ns: &str, name: &str) -> Result<u64, StoreError> {
        self.sequence_current_impl(ns, name)
    }
    fn epoch_advance(
        &self,
        ns: &str,
        mutations: Vec<EpochMutation>,
    ) -> Result<String, StoreError> {
        self.epoch_advance_impl(ns, mutations)
    }
    fn epoch_current(&self, ns: &str) -> Result<Option<String>, StoreError> {
        self.epoch_current_impl(ns)
    }
    fn epoch_get(&self, kappa: &str) -> Result<EpochRoot, StoreError> {
        self.epoch_get_impl(kappa)
    }
    fn blob_open(&self, kappa: &str) -> Result<Box<dyn kappa_core::store::BlobReader>, StoreError> {
        self.blob_open_impl(kappa)
    }
    fn namespace_list(&self) -> Result<Vec<String>, StoreError> {
        self.namespace_list_impl()
    }
    fn namespace_exists(&self, ns: &str) -> Result<bool, StoreError> {
        self.namespace_exists_impl(ns)
    }
    fn assertion_index_put(
        &self,
        subject: &str,
        facet: &str,
        assertion_kappa: &str,
    ) -> Result<(), StoreError> {
        PersistentStore::assertion_index_put(self, subject, facet, assertion_kappa)
    }
    fn assertion_index_query_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<String>, StoreError> {
        PersistentStore::assertion_index_query_subject(self, subject)
    }

    // -- Versioning (redb VERSIONS table) -------------------------------------

    fn version_put(
        &self,
        ns: &str,
        key: &str,
        kappa: &str,
        etag: Option<&str>,
    ) -> Result<String, StoreError> {
        self.version_put_impl(ns, key, kappa, etag)
    }
    fn version_get(
        &self,
        ns: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<VersionEntry, StoreError> {
        self.version_get_impl(ns, key, version_id)
    }
    fn version_delete(
        &self,
        ns: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<DeleteResult, StoreError> {
        self.version_delete_impl(ns, key, version_id)
    }
    fn version_list(
        &self,
        ns: &str,
        key: &str,
        max: usize,
    ) -> Result<Vec<VersionEntry>, StoreError> {
        self.version_list_impl(ns, key, max)
    }

    // -- Streaming upload (disk-backed) ---------------------------------------

    fn upload_begin(&self, namespace: &str, max_size: u64) -> Result<String, StoreError> {
        let id = uuid::Uuid::new_v4().to_string();
        let staging_path = self.staging_root.join(&id);
        {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .create(true).write(true).mode(0o600)
                    .open(&staging_path).map_err(StoreError::Io)?;
            }
            #[cfg(not(unix))]
            {
                std::fs::OpenOptions::new()
                    .create(true).write(true)
                    .open(&staging_path).map_err(StoreError::Io)?;
            }
        }
        let mut sessions = self.upload_sessions.lock().unwrap();
        sessions.insert(id.clone(), DiskUploadSession {
            namespace: namespace.to_string(),
            staging_path,
            offset: 0,
            max_size,
            created_at: std::time::Instant::now(),
            part_digests: Vec::new(),
            current_md5: md5::Md5::new(),
            current_crc32c: crc_fast::Digest::new(crc_fast::CrcAlgorithm::Crc32Iscsi),
            current_crc64nvme: crc_fast::Digest::new(crc_fast::CrcAlgorithm::Crc64Nvme),
        });
        Ok(id)
    }

    fn upload_put_part(
        &self,
        upload_id: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<u64, StoreError> {
        let mut sessions = self.upload_sessions.lock().unwrap();
        let session = sessions.get_mut(upload_id)
            .ok_or_else(|| StoreError::NotFound(format!("upload {}", upload_id)))?;
        // Inline expiration check: reject writes to expired sessions
        // without waiting for the background eviction task.
        if let Some(timeout) = self.upload_timeout_secs {
            if session.created_at.elapsed() > std::time::Duration::from_secs(timeout) {
                let staging = session.staging_path.clone();
                sessions.remove(upload_id);
                let _ = std::fs::remove_file(&staging);
                return Err(StoreError::NotFound(format!("upload {} expired", upload_id)));
            }
        }
        if offset != session.offset {
            return Err(StoreError::Conflict(format!(
                "out-of-order: expected offset {}, got {}",
                session.offset, offset
            )));
        }
        let new_total = session.offset + data.len() as u64;
        if session.max_size > 0 && new_total > session.max_size {
            return Err(StoreError::Rejected(format!(
                "upload exceeds max size {}", session.max_size
            )));
        }
        // Append to staging file
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&session.staging_path)
            .map_err(StoreError::Io)?;
        file.write_all(data).map_err(StoreError::Io)?;

        // Feed all attestation digesters for this part.
        Md5Digest::update(&mut session.current_md5, data);
        session.current_crc32c.update(data);
        session.current_crc64nvme.update(data);

        // Finalize per-part digests and reset for next part.
        let part_number = session.part_digests.len() as u32 + 1;
        let part_size = data.len() as u64;
        let md5_result = session.current_md5.finalize_reset();
        let mut md5_bytes = [0u8; 16];
        md5_bytes.copy_from_slice(&md5_result);
        let crc32c_val = session.current_crc32c.finalize_reset();
        let crc64nvme_val = session.current_crc64nvme.finalize_reset();
        session.part_digests.push(PartDigests {
            part_number,
            offset: session.offset,
            size: part_size,
            md5: md5_bytes,
            crc32c: crc32c_val,
            crc64nvme: crc64nvme_val,
        });

        session.offset = new_total;
        Ok(new_total)
    }

    fn upload_complete(
        &self,
        upload_id: &str,
        claimed_digest: Option<&str>,
    ) -> Result<kappa_core::store::IngestResult, StoreError> {
        let (staging_path, part_digests) = {
            let mut sessions = self.upload_sessions.lock().unwrap();
            let session = sessions.remove(upload_id)
                .ok_or_else(|| StoreError::NotFound(format!("upload {}", upload_id)))?;
            if let Some(timeout) = self.upload_timeout_secs {
                if session.created_at.elapsed() > std::time::Duration::from_secs(timeout) {
                    let _ = std::fs::remove_file(&session.staging_path);
                    return Err(StoreError::NotFound(format!("upload {} expired", upload_id)));
                }
            }
            (session.staging_path, session.part_digests)
        };

        // Type-enforced streaming verification.
        //
        // Step 1: Determine axes to compute. Client axis (from claimed_digest)
        // plus all mandatory axes, in one streaming pass.
        let algo = match claimed_digest {
            Some(claimed) => claimed.split_once(':')
                .map(|(a, _)| a.to_string())
                .unwrap_or_else(|| "sha256".to_string()),
            None => "sha256".to_string(),
        };
        let mut axes: Vec<&str> = vec![&algo];
        for mandatory in &self.mandatory_axes() {
            let a = mandatory.as_str();
            if !axes.contains(&a) {
                axes.push(a);
            }
        }

        // Step 2: Produce StreamingVerificationProof via streaming_compute_multi.
        // This is the ONLY way to get a proof -- the compiler enforces that
        // no unverified kappa can bypass this step.
        let proof = {
            let mut file = std::fs::File::open(&staging_path).map_err(StoreError::Io)?;
            kappa_core::kappa::streaming_compute_multi(&axes, &mut file)
                .map_err(|e| StoreError::Rejected(e.to_string()))?
        };

        // Step 3: If caller claimed a digest, verify against the proof.
        if let Some(claimed) = claimed_digest {
            if proof.kappa() != claimed {
                let _ = std::fs::remove_file(&staging_path);
                return Err(StoreError::Rejected(format!(
                    "digest mismatch: expected {}, computed {}",
                    claimed, proof.kappa()
                )));
            }
        }

        // Step 4: Consume the proof -- extract verified kappas.
        // After this point, the proof is gone. The finalize step below
        // uses the extracted strings. A developer cannot skip steps 1-3
        // because the strings only exist after the proof is consumed.
        let (final_digest, additional_pairs) = proof.into_parts();
        let additional_kappas: Vec<String> = additional_pairs.into_iter()
            .map(|(_, k)| k).collect();

        // sigma (hash of plaintext) verified. Now store the content.
        if let Some(enc) = &self.blob_encryptor {
            // Encrypted path: streaming framed encryption.
            // Read plaintext staging file in 64 KiB frames, encrypt each
            // frame, write framed ciphertext to a temp file. Hash the
            // ciphertext file for kappa. Rename to kappa path. Insert
            // binding record. Delete plaintext staging file.
            // Maximum memory: ~128 KiB (one plaintext frame + one ciphertext frame).

            let ct_tmp = staging_path.with_extension("ct.tmp");
            let (base_nonce, plaintext_size) = {
                let mut pt_file = std::fs::File::open(&staging_path).map_err(StoreError::Io)?;
                let mut ct_file = std::fs::File::create(&ct_tmp).map_err(StoreError::Io)?;
                enc.encrypt_streaming(&final_digest, &mut pt_file, &mut ct_file)
                    .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?
            };

            // Hash the ciphertext file to get kappa (storage address).
            // The proof attests the ciphertext hash. Consume it for the
            // kappa string -- this is an internal storage address, not
            // client-facing verification.
            let kappa = {
                let mut ct_file = std::fs::File::open(&ct_tmp).map_err(StoreError::Io)?;
                let ct_proof = kappa_core::kappa::streaming_compute_kappa("sha256", &mut ct_file)
                    .map_err(|e| StoreError::Rejected(e.to_string()))?;
                ct_proof.into_parts().0
            };

            // Rename ciphertext file to kappa path
            let blob_path = self.kappa_path(&kappa)?;
            let newly_stored = if blob_path.exists() {
                let _ = std::fs::remove_file(&ct_tmp);
                false
            } else {
                if let Some(parent) = blob_path.parent() {
                    std::fs::create_dir_all(parent).map_err(StoreError::Io)?;
                }
                std::fs::rename(&ct_tmp, &blob_path).map_err(StoreError::Io)?;
                if self.fsync {
                    if let Some(p) = blob_path.parent() {
                        if let Ok(d) = std::fs::File::open(p) { let _ = d.sync_all(); }
                    }
                }
                true
            };

            // Insert binding records: client sigma + all additional sigmas -> same kappa
            {
                use crate::blob::encode_binding;
                let txn = self.db.begin_write().map_err(Self::redb_err)?;
                {
                    let mut table = txn.open_table(tables::BINDING_RECORDS).map_err(Self::redb_err)?;
                    let rec = encode_binding(&kappa, &base_nonce, plaintext_size);
                    table.insert(final_digest.as_str(), rec.as_slice()).map_err(Self::redb_err)?;
                    for additional_sigma in &additional_kappas {
                        table.insert(additional_sigma.as_str(), rec.as_slice()).map_err(Self::redb_err)?;
                    }
                }
                txn.commit().map_err(Self::redb_err)?;
            }

            let _ = std::fs::remove_file(&staging_path);

            let mut result = kappa_core::store::IngestResult::new(kappa, newly_stored)
                .with_additional(additional_kappas);
            // Combine per-part CRCs via crc_fast::checksum_combine.
            // The first part's CRC is the seed. Each subsequent part's CRC
            // is combined with the running value using the part's byte count.
            // Result: the CRC of the full concatenated content, computed from
            // per-part CRCs without re-reading any data.
            let combined_crc32c: Option<u32> = if part_digests.is_empty() {
                None
            } else {
                let mut running = part_digests[0].crc32c;
                for pd in &part_digests[1..] {
                    running = crc_fast::checksum_combine(
                        crc_fast::CrcAlgorithm::Crc32Iscsi,
                        running, pd.crc32c, pd.size,
                    );
                }
                Some(running as u32)
            };
            let combined_crc64nvme: Option<u64> = if part_digests.is_empty() {
                None
            } else {
                let mut running = part_digests[0].crc64nvme;
                for pd in &part_digests[1..] {
                    running = crc_fast::checksum_combine(
                        crc_fast::CrcAlgorithm::Crc64Nvme,
                        running, pd.crc64nvme, pd.size,
                    );
                }
                Some(running)
            };

            if let Some(etag) = compute_composite_etag(&part_digests) {
                result = result.with_etag(etag);
            }
            // Store combined checksums as blob metadata
            if let Some(crc32c) = combined_crc32c {
                let _ = self.blob_put_meta_impl(
                    &result.kappa, "_s3_checksum_crc32c",
                    crc32c.to_be_bytes().as_slice(),
                );
            }
            if let Some(crc64nvme) = combined_crc64nvme {
                let _ = self.blob_put_meta_impl(
                    &result.kappa, "_s3_checksum_crc64nvme",
                    crc64nvme.to_be_bytes().as_slice(),
                );
            }
            persist_part_manifest(self, &result.kappa, &part_digests);
            Ok(result)
        } else {
            // Unencrypted path: sigma == kappa. Atomic rename.
            let blob_path = kappa_core::kappa::blob_path_for(&self.blob_root, &final_digest)?;
            let newly_stored = if blob_path.exists() {
                let _ = std::fs::remove_file(&staging_path);
                false
            } else {
                if let Some(parent) = blob_path.parent() {
                    std::fs::create_dir_all(parent).map_err(StoreError::Io)?;
                }
                std::fs::rename(&staging_path, &blob_path).map_err(StoreError::Io)?;
                if self.fsync {
                    if let Some(p) = blob_path.parent() {
                        if let Ok(d) = std::fs::File::open(p) { let _ = d.sync_all(); }
                    }
                }
                true
            };

            // Hard-link additional addresses to the same file.
            // Same content, multiple addresses, one copy on disk.
            for additional in &additional_kappas {
                let alt_path = kappa_core::kappa::blob_path_for(&self.blob_root, additional)?;
                if !alt_path.exists() {
                    if let Some(parent) = alt_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::hard_link(&blob_path, &alt_path);
                }
            }

            let mut result = kappa_core::store::IngestResult::new(
                final_digest.clone(), newly_stored,
            ).with_additional(additional_kappas);
            // Combine per-part CRCs via crc_fast::checksum_combine.
            // The first part's CRC is the seed. Each subsequent part's CRC
            // is combined with the running value using the part's byte count.
            // Result: the CRC of the full concatenated content, computed from
            // per-part CRCs without re-reading any data.
            let combined_crc32c: Option<u32> = if part_digests.is_empty() {
                None
            } else {
                let mut running = part_digests[0].crc32c;
                for pd in &part_digests[1..] {
                    running = crc_fast::checksum_combine(
                        crc_fast::CrcAlgorithm::Crc32Iscsi,
                        running, pd.crc32c, pd.size,
                    );
                }
                Some(running as u32)
            };
            let combined_crc64nvme: Option<u64> = if part_digests.is_empty() {
                None
            } else {
                let mut running = part_digests[0].crc64nvme;
                for pd in &part_digests[1..] {
                    running = crc_fast::checksum_combine(
                        crc_fast::CrcAlgorithm::Crc64Nvme,
                        running, pd.crc64nvme, pd.size,
                    );
                }
                Some(running)
            };

            if let Some(etag) = compute_composite_etag(&part_digests) {
                result = result.with_etag(etag);
            }
            if let Some(crc32c) = combined_crc32c {
                let _ = self.blob_put_meta_impl(
                    &result.kappa, "_s3_checksum_crc32c",
                    crc32c.to_be_bytes().as_slice(),
                );
            }
            if let Some(crc64nvme) = combined_crc64nvme {
                let _ = self.blob_put_meta_impl(
                    &result.kappa, "_s3_checksum_crc64nvme",
                    crc64nvme.to_be_bytes().as_slice(),
                );
            }
            persist_part_manifest(self, &result.kappa, &part_digests);
            Ok(result)
        }
    }

    fn upload_abort(&self, upload_id: &str) -> Result<(), StoreError> {
        let mut sessions = self.upload_sessions.lock().unwrap();
        if let Some(session) = sessions.remove(upload_id) {
            let _ = std::fs::remove_file(&session.staging_path);
        }
        Ok(())
    }

    fn upload_bytes_received(&self, upload_id: &str) -> Option<u64> {
        let mut sessions = self.upload_sessions.lock().unwrap();
        if let Some(timeout) = self.upload_timeout_secs {
            if let Some(s) = sessions.get(upload_id) {
                if s.created_at.elapsed() > std::time::Duration::from_secs(timeout) {
                    let staging = s.staging_path.clone();
                    sessions.remove(upload_id);
                    let _ = std::fs::remove_file(&staging);
                    return None;
                }
            }
        }
        sessions.get(upload_id).map(|s| s.offset)
    }

    fn upload_namespace(&self, upload_id: &str) -> Option<String> {
        let mut sessions = self.upload_sessions.lock().unwrap();
        if let Some(timeout) = self.upload_timeout_secs {
            if let Some(s) = sessions.get(upload_id) {
                if s.created_at.elapsed() > std::time::Duration::from_secs(timeout) {
                    let staging = s.staging_path.clone();
                    sessions.remove(upload_id);
                    let _ = std::fs::remove_file(&staging);
                    return None;
                }
            }
        }
        sessions.get(upload_id).map(|s| s.namespace.clone())
    }

    fn upload_part_info(&self, upload_id: &str) -> Vec<(u32, String, u64)> {
        let sessions = self.upload_sessions.lock().unwrap();
        match sessions.get(upload_id) {
            Some(session) => session.part_digests.iter().map(|pd| {
                (pd.part_number, format!("\"{}\"", hex::encode(pd.md5)), pd.size)
            }).collect(),
            None => Vec::new(),
        }
    }

    fn upload_evict_expired(&self, timeout_secs: u64) -> usize {
        let mut sessions = self.upload_sessions.lock().unwrap();
        let before = sessions.len();
        let expired: Vec<String> = sessions.iter()
            .filter(|(_, s)| s.created_at.elapsed() > std::time::Duration::from_secs(timeout_secs))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &expired {
            if let Some(s) = sessions.remove(id) {
                let _ = std::fs::remove_file(&s.staging_path);
            }
        }
        before - sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_core::clock::ntp_lamport::NtpLamportClock;
    use kappa_core::kappa::kappa_from_bytes;
    use kappa_core::store::blob_put_computed;

    fn new_store() -> (PersistentStore, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = PersistentStoreConfig::new(
            tmp.path().join("blobs"), tmp.path().join("state.redb"),
        );
        config.fsync = false;
        let clock = Arc::new(NtpLamportClock::new());
        let store = PersistentStore::new(config, clock).unwrap();
        (store, tmp)
    }

    fn reopen(tmp: &std::path::Path) -> PersistentStore {
        let mut config = PersistentStoreConfig::new(
            tmp.join("blobs"), tmp.join("state.redb"),
        );
        config.fsync = false;
        let clock = Arc::new(NtpLamportClock::new());
        PersistentStore::new(config, clock).unwrap()
    }

    // -- Blob -----------------------------------------------------------------

    #[test]
    fn blob_roundtrip() {
        let (s, _d) = new_store();
        let k = kappa_from_bytes(b"hello");
        assert!(s.ingest_verified(&k,b"hello").unwrap().newly_stored);
        assert_eq!(s.blob_get(&k).unwrap(), b"hello");
        assert!(!s.ingest_verified(&k,b"hello").unwrap().newly_stored); // idempotent
    }

    #[test]
    fn blob_meta_roundtrip() {
        let (s, _d) = new_store();
        let k = kappa_from_bytes(b"meta");
        s.ingest_verified(&k,b"meta").unwrap();
        s.blob_put_meta(&k, "ct", b"text/plain").unwrap();
        assert_eq!(s.blob_get_meta(&k, "ct").unwrap(), b"text/plain");
        s.blob_delete_meta(&k, "ct").unwrap();
        assert!(s.blob_get_meta(&k, "ct").is_err());
    }

    // -- Tag ------------------------------------------------------------------

    #[test]
    fn tag_set_get() {
        let (s, _d) = new_store();
        assert_eq!(s.tag_set("ns", "latest", "sha256:aaa").unwrap(), 1);
        let e = s.tag_get("ns", "latest").unwrap();
        assert_eq!(e.kappa, "sha256:aaa");
        assert_eq!(e.version, 1);
    }

    #[test]
    fn tag_list_sorted() {
        let (s, _d) = new_store();
        s.tag_set("ns", "c", "k3").unwrap();
        s.tag_set("ns", "a", "k1").unwrap();
        s.tag_set("ns", "b", "k2").unwrap();
        let list = s.tag_list("ns").unwrap();
        let names: Vec<&str> = list.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn tag_survives_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let s = reopen(tmp.path());
            let k = blob_put_computed(&s, b"persist").unwrap();
            s.tag_set("ns", "t1", &k).unwrap();
        }
        {
            let s = reopen(tmp.path());
            let e = s.tag_get("ns", "t1").unwrap();
            assert_eq!(e.version, 1);
        }
    }

    // -- Edge -----------------------------------------------------------------

    #[test]
    fn edge_put_query() {
        let (s, _d) = new_store();
        let edge = Edge {
            source: "sha256:src".into(),
            target: "sha256:tgt".into(),
            relation: EdgeRelation::Owns,
            asserter: "a".into(),
            value_kappa: None,
            metadata: None,
        };
        s.edge_put("ns", &edge).unwrap();
        let r = s
            .edge_query(
                "ns",
                &EdgeQuery {
                    anchor: "sha256:src".into(),
                    direction: Direction::Outbound,
                    relation: None,
                    asserter: None,
                },
            )
            .unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].target, "sha256:tgt");
    }

    #[test]
    fn edge_survives_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let s = reopen(tmp.path());
            s.edge_put(
                "ns",
                &Edge {
                    source: "s".into(),
                    target: "t".into(),
                    relation: EdgeRelation::DerivedFrom,
                    asserter: "a".into(),
                    value_kappa: None,
                    metadata: None,
                },
            )
            .unwrap();
        }
        {
            let s = reopen(tmp.path());
            let r = s
                .edge_query(
                    "ns",
                    &EdgeQuery {
                        anchor: "s".into(),
                        direction: Direction::Outbound,
                        relation: None,
                        asserter: None,
                    },
                )
                .unwrap();
            assert_eq!(r.len(), 1);
        }
    }

    // -- Sequence -------------------------------------------------------------

    #[test]
    fn sequence_survives_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let s = reopen(tmp.path());
            for _ in 0..5 {
                s.sequence_next("ns", "c").unwrap();
            }
        }
        {
            let s = reopen(tmp.path());
            assert_eq!(s.sequence_current("ns", "c").unwrap(), 5);
            assert_eq!(s.sequence_next("ns", "c").unwrap(), 6);
        }
    }

    // -- Namespace ------------------------------------------------------------

    #[test]
    fn namespace_survives_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let s = reopen(tmp.path());
            s.tag_set("test-ns", "t", "k").unwrap();
        }
        {
            let s = reopen(tmp.path());
            assert!(s.namespace_exists("test-ns").unwrap());
            assert!(s.namespace_list().unwrap().contains(&"test-ns".to_string()));
        }
    }

    // -- Epoch ----------------------------------------------------------------

    #[test]
    fn epoch_survives_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let epoch_k;
        {
            let s = reopen(tmp.path());
            epoch_k = s.epoch_advance("ns", vec![]).unwrap();
        }
        {
            let s = reopen(tmp.path());
            assert_eq!(s.epoch_current("ns").unwrap(), Some(epoch_k.clone()));
            let root = s.epoch_get(&epoch_k).unwrap();
            assert_eq!(root.epoch_number, 1);
        }
    }

    // -- Meta query -----------------------------------------------------------

    #[test]
    fn meta_query_survives_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let s = reopen(tmp.path());
            let k = blob_put_computed(&s, b"mq").unwrap();
            s.meta_set("ns", &k, "object-type", "manifest").unwrap();
        }
        {
            let s = reopen(tmp.path());
            let r = s.meta_query("ns", "object-type", "manifest").unwrap();
            assert_eq!(r.len(), 1);
        }
    }

    // -- blob_open --------------------------------------------------------------

    #[test]
    fn blob_open_returns_file_for_existing() {
        let (s, _d) = new_store();
        let k = kappa_from_bytes(b"open-test");
        s.ingest_verified(&k,b"open-test").unwrap();
        let mut file = s.blob_open(&k).unwrap();
        let mut buf = Vec::new();
        use std::io::Read;
        file.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"open-test");
    }

    #[test]
    fn blob_open_not_found_for_missing() {
        let (s, _d) = new_store();
        let result = s.blob_open("sha256:0000000000000000000000000000000000000000000000000000000000000000");
        assert!(result.is_err());
    }

    #[test]
    fn blob_open_content_matches_blob_get() {
        let (s, _d) = new_store();
        let content: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let k = kappa_from_bytes(&content);
        s.ingest_verified(&k,&content).unwrap();

        let get_result = s.blob_get(&k).unwrap();
        let mut file = s.blob_open(&k).unwrap();
        let mut open_result = Vec::new();
        use std::io::Read;
        file.read_to_end(&mut open_result).unwrap();
        assert_eq!(get_result, open_result);
    }

    #[test]
    fn blob_open_file_at_start() {
        let (s, _d) = new_store();
        let k = kappa_from_bytes(b"position-test");
        s.ingest_verified(&k,b"position-test").unwrap();
        let mut file = s.blob_open(&k).unwrap();
        use std::io::Seek;
        let pos = file.stream_position().unwrap();
        assert_eq!(pos, 0, "file should be positioned at start");
    }

    // -- Prefix successor -----------------------------------------------------

    #[test]
    fn prefix_successor_normal() {
        let s = PersistentStore::prefix_successor(b"abc");
        assert_eq!(s, Some(b"abd".to_vec()));
    }

    #[test]
    fn prefix_successor_trailing_ff() {
        let s = PersistentStore::prefix_successor(b"ab\xff");
        assert_eq!(s, Some(b"ac".to_vec()));
    }

    #[test]
    fn prefix_successor_all_ff() {
        let s = PersistentStore::prefix_successor(b"\xff\xff");
        assert_eq!(s, None);
    }

    // -- Streaming upload lifecycle -------------------------------------------

    #[test]
    fn upload_lifecycle_begin_put_complete() {
        let (s, _d) = new_store();
        let content = b"streaming upload test content";
        let digest = kappa_from_bytes(content);

        let id = s.upload_begin("test-ns", 0).unwrap();
        assert!(s.upload_bytes_received(&id).is_some());
        assert_eq!(s.upload_bytes_received(&id).unwrap(), 0);

        // Write in two parts
        let total = s.upload_put_part(&id, 0, &content[..10]).unwrap();
        assert_eq!(total, 10);
        let total = s.upload_put_part(&id, 10, &content[10..]).unwrap();
        assert_eq!(total, content.len() as u64);

        // Complete with correct digest
        let result = s.upload_complete(&id, Some(digest.as_str())).unwrap();
        assert_eq!(result.kappa, digest);
        assert!(result.newly_stored);

        // Blob is now retrievable
        assert_eq!(s.blob_get(&digest).unwrap(), content);

        // Upload ID is gone
        assert!(s.upload_bytes_received(&id).is_none());
    }

    #[test]
    fn upload_abort_cleans_up() {
        let (s, _d) = new_store();
        let id = s.upload_begin("test-ns", 0).unwrap();
        s.upload_put_part(&id, 0, b"some data").unwrap();
        s.upload_abort(&id).unwrap();
        assert!(s.upload_bytes_received(&id).is_none());
        // Staging file should be gone
        let staging = s.staging_root.join(&id);
        assert!(!staging.exists());
    }

    #[test]
    fn upload_wrong_digest_rejected() {
        let (s, _d) = new_store();
        let id = s.upload_begin("test-ns", 0).unwrap();
        s.upload_put_part(&id, 0, b"real content").unwrap();
        let wrong = format!("sha256:{}", "0".repeat(64));
        let result = s.upload_complete(&id, Some(wrong.as_str()));
        assert!(result.is_err());
    }

    #[test]
    fn upload_out_of_order_rejected() {
        let (s, _d) = new_store();
        let id = s.upload_begin("test-ns", 0).unwrap();
        s.upload_put_part(&id, 0, b"first").unwrap();
        // Skip offset 5, try to write at 10
        let result = s.upload_put_part(&id, 10, b"wrong");
        assert!(result.is_err());
    }

    #[test]
    fn upload_size_limit_enforced() {
        let (s, _d) = new_store();
        let id = s.upload_begin("test-ns", 10).unwrap(); // max 10 bytes
        s.upload_put_part(&id, 0, b"12345").unwrap();
        let result = s.upload_put_part(&id, 5, b"678901"); // 11 bytes total
        assert!(result.is_err());
    }

    #[test]
    fn upload_evict_expired() {
        let (s, _d) = new_store();
        let _id = s.upload_begin("test-ns", 0).unwrap();
        // With timeout 0, everything is expired
        std::thread::sleep(std::time::Duration::from_millis(50));
        let evicted = s.upload_evict_expired(0);
        assert_eq!(evicted, 1);
    }

    // -- Encrypted upload lifecycle -------------------------------------------

    fn new_encrypted_store() -> (PersistentStore, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let blob_root = tmp.path().join("blobs");
        let db_path = tmp.path().join("state.redb");
        let clock = Arc::new(NtpLamportClock::new());
        let mut config = PersistentStoreConfig::new(blob_root, db_path);
        config.fsync = false;
        config.encryption_key = Some([0x42u8; 32]);
        let store = PersistentStore::new(config, clock).unwrap();
        (store, tmp)
    }

    #[test]
    fn upload_lifecycle_encrypted() {
        let (s, _d) = new_encrypted_store();
        let content = b"encrypted streaming upload test content here";
        let digest = kappa_from_bytes(content);

        // Begin + put parts
        let id = s.upload_begin("test-ns", 0).unwrap();
        s.upload_put_part(&id, 0, &content[..20]).unwrap();
        s.upload_put_part(&id, 20, &content[20..]).unwrap();

        // Complete with correct digest
        let result = s.upload_complete(&id, Some(digest.as_str())).unwrap();
        assert!(result.newly_stored);

        // blob_get returns original plaintext
        assert_eq!(s.blob_get(&digest).unwrap(), content);

        // blob_exists confirms binding record exists
        assert!(s.blob_exists(&digest).unwrap());

        // blob_size returns plaintext size
        assert_eq!(s.blob_size(&digest).unwrap(), content.len() as u64);

        // Staging file is gone
        let staging = s.staging_root.join(&id);
        assert!(!staging.exists());

        // Raw file on disk is NOT plaintext (it's framed AEAD ciphertext)
        // The kappa in the result is hash(ciphertext), not hash(plaintext)
        let kappa = &result.kappa;
        assert_ne!(kappa, &digest, "kappa should differ from sigma under encryption");
        let blob_path = s.kappa_path(kappa).unwrap();
        let raw_disk = std::fs::read(&blob_path).unwrap();
        assert_ne!(raw_disk, content, "raw file must be ciphertext, not plaintext");
        // First 16 bytes should be the AEAD tag of frame 0
        assert!(raw_disk.len() > 16, "ciphertext should include tag overhead");
    }

    #[test]
    fn upload_encrypted_wrong_digest_rejected() {
        let (s, _d) = new_encrypted_store();
        let id = s.upload_begin("test-ns", 0).unwrap();
        s.upload_put_part(&id, 0, b"real content").unwrap();
        let wrong = format!("sha256:{}", "0".repeat(64));
        let result = s.upload_complete(&id, Some(wrong.as_str()));
        assert!(result.is_err());
    }
}
