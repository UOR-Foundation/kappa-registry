//! Store trait and implementations.

pub mod memory;

use crate::epoch::EpochRoot;
use crate::kappa::Axis;
use crate::verified::VerifiedContent;
pub use crate::types::{
    DeleteResult, Edge, EdgeQuery, EdgeRelation, EpochMutation, StoreError, TagEntry, TagUpdate,
    VersionEntry,
};

/// Trait object for streaming blob reads. Implemented by std::fs::File
/// (unencrypted path, zero-copy) and FrameDecryptingReader (encrypted
/// path, one frame in memory at a time).
pub trait BlobReader: std::io::Read + std::io::Seek + Send {}

impl BlobReader for std::fs::File {}
impl BlobReader for std::io::Cursor<Vec<u8>> {}

/// Result of an ingest operation.
#[non_exhaustive]
pub struct IngestResult {
    /// The content address (kappa-label) of the stored content.
    pub kappa: String,
    /// True if the blob was newly stored, false if it already existed.
    pub newly_stored: bool,
    /// Additional addresses computed by mandatory axes (e.g. sha256).
    pub additional_kappas: Vec<String>,
    /// Composite ETag for multipart uploads (MD5-of-MD5s with part count).
    /// None for single-PUT objects.
    pub etag: Option<String>,
}

impl IngestResult {
    pub fn new(kappa: String, newly_stored: bool) -> Self {
        Self {
            kappa,
            newly_stored,
            additional_kappas: Vec::new(),
            etag: None,
        }
    }

    pub fn with_additional(mut self, additional: Vec<String>) -> Self {
        self.additional_kappas = additional;
        self
    }

    pub fn with_etag(mut self, etag: String) -> Self {
        self.etag = Some(etag);
        self
    }
}

/// Content-addressed key-value store.
///
/// Two ingest methods handle all writes:
/// - `ingest_verified`: client provides a claimed digest, store verifies.
/// - `ingest_compute`: store computes the digest under a given axis.
///
/// Both construct `VerifiedContent` internally and delegate to
/// `blob_put_verified`. Handlers never import `VerifiedContent`.
/// When store internals change (encryption, transforms, multi-digest),
/// only the default implementations change. Zero handler cascade.
pub trait KappaStore: Send + Sync {
    // -- Configuration (1) ----------------------------------------------------

    /// Axes computed on every ingest regardless of client axis.
    /// SHA-256 is always in this set. Implementations may extend it
    /// (e.g. via KAPPA_MANDATORY_AXES env var) but never remove SHA-256.
    fn mandatory_axes(&self) -> Vec<Axis> {
        vec![Axis::Sha256]
    }

    // -- Ingest: verified content storage (3) ---------------------------------

    /// Store bytes with a caller-claimed digest. The store verifies the
    /// claim, then computes every mandatory axis that differs from the
    /// client's axis and stores the content under all addresses.
    ///
    /// Both InMemoryStore and PersistentStore inherit this default.
    /// PersistentStore may override for hard-link/binding-record
    /// optimization, but the observable behavior is identical.
    fn ingest_verified(
        &self,
        claimed: &str,
        content: &[u8],
    ) -> Result<IngestResult, StoreError> {
        let verified = VerifiedContent::verify(claimed, content.to_vec())
            .map_err(|e| StoreError::Rejected(e.to_string()))?;
        let client_axis = verified.axis();
        let kappa = verified.kappa().to_string();
        let newly_stored = self.blob_put_verified(&verified)?;

        let mut additional_kappas = Vec::new();
        for axis in self.mandatory_axes() {
            if axis == client_axis { continue; }
            let additional = VerifiedContent::compute(axis, content.to_vec())
                .map_err(|e| StoreError::Rejected(e.to_string()))?;
            let additional_kappa = additional.kappa().to_string();
            self.blob_put_verified(&additional)?;
            additional_kappas.push(additional_kappa);
        }

        Ok(IngestResult::new(kappa, newly_stored).with_additional(additional_kappas))
    }

    /// Store bytes and compute the digest under the given axis, plus
    /// all mandatory axes that differ.
    fn ingest_compute(
        &self,
        axis: Axis,
        content: &[u8],
    ) -> Result<IngestResult, StoreError> {
        let verified = VerifiedContent::compute(axis, content.to_vec())
            .map_err(|e| StoreError::Rejected(e.to_string()))?;
        let kappa = verified.kappa().to_string();
        let newly_stored = self.blob_put_verified(&verified)?;

        let mut additional_kappas = Vec::new();
        for mandatory in self.mandatory_axes() {
            if mandatory == axis { continue; }
            let additional = VerifiedContent::compute(mandatory, content.to_vec())
                .map_err(|e| StoreError::Rejected(e.to_string()))?;
            let additional_kappa = additional.kappa().to_string();
            self.blob_put_verified(&additional)?;
            additional_kappas.push(additional_kappa);
        }

        Ok(IngestResult::new(kappa, newly_stored).with_additional(additional_kappas))
    }

    /// Low-level verified put. Implementations override this.
    /// Called by ingest_verified and ingest_compute for each address.
    /// Handlers never call this directly.
    fn blob_put_verified(
        &self,
        content: &VerifiedContent,
    ) -> Result<bool, StoreError>;

    // -- Blob read operations (6) ---------------------------------------------

    /// Retrieve bytes at the given kappa address.
    fn blob_get(&self, kappa: &str) -> Result<Vec<u8>, StoreError>;

    /// Check existence without reading content.
    fn blob_exists(&self, kappa: &str) -> Result<bool, StoreError>;

    /// Remove bytes at the given kappa address.
    fn blob_delete(&self, kappa: &str) -> Result<(), StoreError>;

    /// Byte length without reading content.
    fn blob_size(&self, kappa: &str) -> Result<u64, StoreError>;

    /// Read a byte range.
    fn blob_get_range(&self, kappa: &str, offset: u64, length: u64) -> Result<Vec<u8>, StoreError>;

    /// Enumerate all stored kappa-labels.
    fn blob_list(&self) -> Result<Vec<String>, StoreError>;

    // -- Blob metadata: per-blob key-value pairs (3) --------------------------

    fn blob_put_meta(&self, kappa: &str, key: &str, value: &[u8]) -> Result<(), StoreError>;
    fn blob_get_meta(&self, kappa: &str, key: &str) -> Result<Vec<u8>, StoreError>;
    fn blob_delete_meta(&self, kappa: &str, key: &str) -> Result<(), StoreError>;

    // -- Namespace-scoped metadata (2) ----------------------------------------

    fn meta_set(&self, ns: &str, kappa: &str, key: &str, value: &str) -> Result<(), StoreError>;
    fn meta_query(&self, ns: &str, key: &str, value: &str) -> Result<Vec<String>, StoreError>;

    // -- Tag: namespace-scoped name-to-kappa bindings (6) ---------------------

    fn tag_set(&self, ns: &str, name: &str, kappa: &str) -> Result<u64, StoreError>;
    fn tag_get(&self, ns: &str, name: &str) -> Result<TagEntry, StoreError>;
    fn tag_delete(&self, ns: &str, name: &str) -> Result<(), StoreError>;
    fn tag_list(&self, ns: &str) -> Result<Vec<TagEntry>, StoreError>;
    fn tag_prefix(&self, ns: &str, prefix: &str) -> Result<Vec<TagEntry>, StoreError>;
    fn tag_set_batch(&self, ns: &str, updates: &[TagUpdate]) -> Result<(), StoreError>;

    // -- Edge: typed relationships between kappas (4) -------------------------

    fn edge_put(&self, ns: &str, edge: &Edge) -> Result<(), StoreError>;
    fn edge_query(&self, ns: &str, query: &EdgeQuery) -> Result<Vec<Edge>, StoreError>;
    fn edge_delete(
        &self,
        ns: &str,
        source: &str,
        target: &str,
        relation: EdgeRelation,
    ) -> Result<(), StoreError>;

    /// Store multiple edges in a single transaction. Default loops
    /// edge_put. PersistentStore overrides with a single redb write
    /// transaction for all edges, amortizing commit overhead.
    fn edge_put_batch(&self, ns: &str, edges: &[Edge]) -> Result<(), StoreError> {
        for edge in edges {
            self.edge_put(ns, edge)?;
        }
        Ok(())
    }

    // -- Sequence: monotonic counters (2) -------------------------------------

    fn sequence_next(&self, ns: &str, name: &str) -> Result<u64, StoreError>;
    fn sequence_current(&self, ns: &str, name: &str) -> Result<u64, StoreError>;

    // -- Epoch: signed state chain (3) ----------------------------------------

    fn epoch_advance(&self, ns: &str, mutations: Vec<EpochMutation>) -> Result<String, StoreError>;
    fn epoch_current(&self, ns: &str) -> Result<Option<String>, StoreError>;
    fn epoch_get(&self, kappa: &str) -> Result<EpochRoot, StoreError>;

    // -- Streaming upload (4) --------------------------------------------------

    /// Begin a streaming upload. Returns an opaque upload ID.
    /// The store creates a staging area for incoming parts.
    /// `namespace` is stored with the session for policy enforcement
    /// at completion (e.g. SHA-1 policy per namespace).
    /// `max_size` is the maximum total content size (0 = unlimited).
    fn upload_begin(&self, namespace: &str, max_size: u64) -> Result<String, StoreError>;

    /// Append a part to a streaming upload.
    /// `offset` must equal the number of bytes previously appended
    /// (sequential writes only, no gaps, no overlaps).
    /// Returns the new total byte count.
    fn upload_put_part(
        &self,
        upload_id: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<u64, StoreError>;

    /// Complete a streaming upload.
    ///
    /// When `claimed_digest` is Some: the store performs streaming hash
    /// verification over the staging file, producing a
    /// `StreamingVerificationProof` internally. If the computed hash
    /// does not match the claimed digest, returns `StoreError::Rejected`.
    /// The proof is consumed by the internal finalize step -- the compiler
    /// enforces that no unverified kappa reaches storage.
    ///
    /// When `claimed_digest` is None: the store computes SHA-256 of the
    /// staged content server-side. This is the S3 CompleteMultipartUpload
    /// path where the server computes the digest, not the client.
    ///
    /// The staged file is consumed -- the upload ID is invalid after this call.
    fn upload_complete(
        &self,
        upload_id: &str,
        claimed_digest: Option<&str>,
    ) -> Result<IngestResult, StoreError>;

    /// Abort a streaming upload. Removes the staging file.
    fn upload_abort(&self, upload_id: &str) -> Result<(), StoreError>;

    /// Bytes received so far for an upload. None if ID not found.
    fn upload_bytes_received(&self, upload_id: &str) -> Option<u64>;

    /// Namespace associated with an upload. None if ID not found.
    fn upload_namespace(&self, upload_id: &str) -> Option<String>;

    /// Per-part metadata for an in-progress upload.
    /// Returns (part_number, md5_hex, size) for each uploaded part.
    /// Empty vec if upload not found.
    fn upload_part_info(&self, upload_id: &str) -> Vec<(u32, String, u64)> {
        let _ = upload_id;
        Vec::new()
    }

    /// Evict uploads older than `timeout_secs`. Returns count evicted.
    fn upload_evict_expired(&self, timeout_secs: u64) -> usize;

    // -- Blob reader for streaming (1) ----------------------------------------

    fn blob_open(&self, kappa: &str) -> Result<Box<dyn BlobReader>, StoreError> {
        let content = self.blob_get(kappa)?;
        Ok(Box::new(std::io::Cursor::new(content)))
    }

    // -- Verified read (1) ----------------------------------------------------

    fn blob_get_verified(&self, kappa: &str) -> Result<Vec<u8>, StoreError> {
        let content = self.blob_get(kappa)?;
        match crate::kappa::verify_kappa(kappa, &content) {
            Ok(true) => Ok(content),
            Ok(false) => Err(StoreError::Rejected(format!(
                "integrity failure: content at {} does not match its address",
                kappa
            ))),
            Err(e) => Err(StoreError::Rejected(format!(
                "integrity check failed for {}: {}",
                kappa, e
            ))),
        }
    }

    // -- Namespace (2) --------------------------------------------------------

    fn namespace_list(&self) -> Result<Vec<String>, StoreError>;
    fn namespace_exists(&self, ns: &str) -> Result<bool, StoreError>;

    // -- Versioning (5, optional) -------------------------------------------------

    /// Put a new version of an object. Returns the assigned version_id.
    /// Behavior depends on the namespace's versioning state:
    /// - Unversioned: overwrites via tag_set. No version table entry.
    /// - Enabled: UUID version_id, inserted into version table.
    /// - Suspended: version_id = "null", replaces previous null entry.
    fn version_put(
        &self,
        _ns: &str,
        _key: &str,
        _kappa: &str,
        _etag: Option<&str>,
    ) -> Result<String, StoreError> {
        Err(StoreError::Rejected("versioning not implemented".into()))
    }

    /// Get a version. None = latest non-delete-marker. Some = specific version.
    fn version_get(
        &self,
        _ns: &str,
        _key: &str,
        _version_id: Option<&str>,
    ) -> Result<VersionEntry, StoreError> {
        Err(StoreError::Rejected("versioning not implemented".into()))
    }

    /// Delete a version. None = insert delete marker. Some = permanent remove.
    fn version_delete(
        &self,
        _ns: &str,
        _key: &str,
        _version_id: Option<&str>,
    ) -> Result<DeleteResult, StoreError> {
        Err(StoreError::Rejected("versioning not implemented".into()))
    }

    /// List versions of a key, newest first.
    fn version_list(
        &self,
        _ns: &str,
        _key: &str,
        _max: usize,
    ) -> Result<Vec<VersionEntry>, StoreError> {
        Ok(Vec::new())
    }

    // -- Cross-namespace assertion index (2, optional) -------------------------

    fn assertion_index_put(
        &self,
        _subject: &str,
        _facet: &str,
        _assertion_kappa: &str,
    ) -> Result<(), StoreError> {
        Ok(())
    }

    fn assertion_index_query_subject(
        &self,
        _subject: &str,
    ) -> Result<Vec<String>, StoreError> {
        Ok(Vec::new())
    }
}

/// Convenience: compute sha256 and store. Returns the kappa.
pub fn blob_put_computed(store: &dyn KappaStore, content: &[u8]) -> Result<String, StoreError> {
    let result = store.ingest_compute(Axis::Sha256, content)?;
    Ok(result.kappa)
}
