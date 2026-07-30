//! Store trait and implementations.

pub mod memory;

use crate::epoch::EpochRoot;
use crate::kappa::kappa_from_bytes;
pub use crate::types::{
    Edge, EdgeQuery, EdgeRelation, EpochMutation, StoreError, TagEntry, TagUpdate,
};

/// Content-addressed key-value store.
///
/// The key is the kappa-label. The caller provides it. The store does
/// not compute digests, does not verify them, does not know what
/// algorithm produced the key. It stores bytes at an address and
/// retrieves them by that address.
pub trait KappaStore: Send + Sync {
    // -- Blob: content-addressed byte storage (7) -----------------------------

    /// Store bytes at the given kappa address.
    ///
    /// The caller computed the digest. The store does not verify it.
    /// Returns true if newly stored, false if already existed (idempotent).
    fn blob_put(&self, kappa: &str, content: &[u8]) -> Result<bool, StoreError>;

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

    // -- Blob metadata: per-blob key-value pairs (4) --------------------------

    /// Store a metadata value for a blob. Keyed by (kappa, key).
    /// Content-type, object-type, and any future per-blob metadata live here.
    fn blob_put_meta(&self, kappa: &str, key: &str, value: &[u8]) -> Result<(), StoreError>;

    /// Retrieve a metadata value for a blob.
    fn blob_get_meta(&self, kappa: &str, key: &str) -> Result<Vec<u8>, StoreError>;

    /// Delete a metadata value for a blob.
    fn blob_delete_meta(&self, kappa: &str, key: &str) -> Result<(), StoreError>;

    // -- Namespace-scoped metadata: indexed key-value on blobs (2) ------------

    /// Associate a metadata key-value pair with a blob within a namespace.
    /// This is queryable via meta_query. Used for object-type and any
    /// metadata that needs to be discoverable by key/value search within
    /// a namespace scope.
    fn meta_set(&self, ns: &str, kappa: &str, key: &str, value: &str) -> Result<(), StoreError>;

    /// Query blobs by metadata key-value pair within a namespace.
    /// Returns all kappas in this namespace that have the given key
    /// set to the given value (or any value if value is empty).
    fn meta_query(&self, ns: &str, key: &str, value: &str) -> Result<Vec<String>, StoreError>;

    // -- Tag: namespace-scoped name-to-kappa bindings (6) ---------------------

    /// Bind a name to a kappa in a namespace. Returns the new version number.
    fn tag_set(&self, ns: &str, name: &str, kappa: &str) -> Result<u64, StoreError>;

    /// Resolve a name to its TagEntry.
    fn tag_get(&self, ns: &str, name: &str) -> Result<TagEntry, StoreError>;

    /// Remove a name binding.
    fn tag_delete(&self, ns: &str, name: &str) -> Result<(), StoreError>;

    /// List all tags in a namespace, sorted by name.
    fn tag_list(&self, ns: &str) -> Result<Vec<TagEntry>, StoreError>;

    /// List tags matching a prefix in a namespace.
    fn tag_prefix(&self, ns: &str, prefix: &str) -> Result<Vec<TagEntry>, StoreError>;

    /// Atomic batch of tag updates with optional CAS per entry.
    fn tag_set_batch(&self, ns: &str, updates: &[TagUpdate]) -> Result<(), StoreError>;

    // -- Edge: typed relationships between kappas (3) -------------------------

    /// Store an edge.
    fn edge_put(&self, ns: &str, edge: &Edge) -> Result<(), StoreError>;

    /// Query edges by anchor, direction, relation, asserter.
    fn edge_query(&self, ns: &str, query: &EdgeQuery) -> Result<Vec<Edge>, StoreError>;

    /// Delete an edge by its constituent fields.
    fn edge_delete(
        &self,
        ns: &str,
        source: &str,
        target: &str,
        relation: EdgeRelation,
    ) -> Result<(), StoreError>;

    // -- Sequence: monotonic counters (2) -------------------------------------

    fn sequence_next(&self, ns: &str, name: &str) -> Result<u64, StoreError>;
    fn sequence_current(&self, ns: &str, name: &str) -> Result<u64, StoreError>;

    // -- Epoch: signed state chain (3) ----------------------------------------

    fn epoch_advance(&self, ns: &str, mutations: Vec<EpochMutation>) -> Result<String, StoreError>;
    fn epoch_current(&self, ns: &str) -> Result<Option<String>, StoreError>;
    fn epoch_get(&self, kappa: &str) -> Result<EpochRoot, StoreError>;

    // -- Blob file handle for streaming (1) ------------------------------------

    /// Open a blob file for streaming reads. Returns a file handle
    /// positioned at the start. The caller owns the read lifecycle.
    ///
    /// Use for HTTP response streaming where the blob could be any size.
    /// Use blob_get for small reads (metadata, edges, epochs) where
    /// allocation is acceptable.
    fn blob_open(&self, kappa: &str) -> Result<std::fs::File, StoreError> {
        let content = self.blob_get(kappa)?;
        let mut tmp = tempfile::NamedTempFile::new().map_err(StoreError::Io)?;
        use std::io::Write;
        tmp.write_all(&content).map_err(StoreError::Io)?;
        use std::io::Seek;
        tmp.as_file_mut()
            .seek(std::io::SeekFrom::Start(0))
            .map_err(StoreError::Io)?;
        Ok(tmp.into_file())
    }

    // -- Namespace (2) --------------------------------------------------------

    fn namespace_list(&self) -> Result<Vec<String>, StoreError>;
    fn namespace_exists(&self, ns: &str) -> Result<bool, StoreError>;
}

/// Convenience function for internal code that wants auto-sha256 storage.
///
/// Computes the sha256 kappa of content, stores the blob, returns the kappa.
/// OCI handler code NEVER calls this because the client chooses the algorithm.
pub fn blob_put_computed(store: &dyn KappaStore, content: &[u8]) -> Result<String, StoreError> {
    let kappa = kappa_from_bytes(content);
    store.blob_put(&kappa, content)?;
    Ok(kappa)
}
