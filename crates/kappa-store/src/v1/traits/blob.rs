use kappa_cursor::FallibleCursor;

use kappa_types::axis::Axis;
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::namespace::NamespaceRef;
use kappa_types::verified::VerifiedContent;

/// Trait object for streaming blob reads.
pub trait BlobReader: std::io::Read + std::io::Seek + Send {}
impl<T: std::io::Read + std::io::Seek + Send> BlobReader for T {}

/// Content-addressed immutable blob reads.
///
/// Blobs are globally content-addressed. A read that names no namespace
/// resolves the identity through the registry's catalog to a namespace
/// that admitted a representation for it; the `_in` forms read exactly
/// the named namespace's admitted representation and report absence when
/// that namespace admitted none, however many others did. Handlers that
/// serve a namespace-scoped request use the `_in` forms, so a namespace
/// never serves content it did not admit.
///
/// There is no write entry point here. Content enters a store only through
/// an execution (`ExecutionWrites::content_install` after
/// `ContentPreparation::prepare_content`, or `ExecutionWrites::blob_put`
/// for records the execution produces) and leaves only through
/// `ExecutionWrites::content_retire`, so every representation a reader can
/// select was installed by a published epoch.
pub trait BlobStore: Send + Sync {
    /// Retrieve blob bytes.
    fn blob_get(&self, kappa: &Kappa) -> Result<Vec<u8>, StoreError>;

    /// Retrieve a byte range. Backends with chunked storage read
    /// only the overlapping chunks, not the full blob.
    fn blob_get_range(
        &self,
        kappa: &Kappa,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, StoreError>;

    /// Open a blob for streaming read. Backends with chunked storage
    /// return a reader that loads one chunk at a time. Memory: `O(chunk_size)`.
    fn blob_open(&self, kappa: &Kappa) -> Result<Box<dyn BlobReader>, StoreError>;

    /// Check existence without reading content.
    fn blob_exists(&self, kappa: &Kappa) -> Result<bool, StoreError>;

    /// `blob_get` bound to the representation `ns` admitted.
    fn blob_get_in(&self, ns: &NamespaceRef, kappa: &Kappa) -> Result<Vec<u8>, StoreError>;

    /// `blob_open` bound to the representation `ns` admitted.
    fn blob_open_in(
        &self,
        ns: &NamespaceRef,
        kappa: &Kappa,
    ) -> Result<Box<dyn BlobReader>, StoreError>;

    /// `blob_exists` bound to the representation `ns` admitted.
    fn blob_exists_in(&self, ns: &NamespaceRef, kappa: &Kappa) -> Result<bool, StoreError>;

    /// `blob_size` bound to the representation `ns` admitted.
    fn blob_size_in(&self, ns: &NamespaceRef, kappa: &Kappa) -> Result<u64, StoreError>;

    /// `blob_get_range` bound to the representation `ns` admitted.
    fn blob_get_range_in(
        &self,
        ns: &NamespaceRef,
        kappa: &Kappa,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, StoreError>;

    /// `blob_meta_get` bound to the metadata `ns` admitted.
    fn blob_meta_get_in(
        &self,
        ns: &NamespaceRef,
        kappa: &Kappa,
        key: &str,
    ) -> Result<Vec<u8>, StoreError>;

    /// The namespaces whose admitted epochs select a representation for
    /// `kappa`, as the backend's settled projection holds them. Empty when
    /// none does. A locator for work that must act inside each owning
    /// namespace (retirement); the namespace's own state is the evidence.
    fn blob_owners(&self, kappa: &Kappa) -> Result<Vec<NamespaceRef>, StoreError>;

    /// `blob_get_verified` bound to the representation `ns` admitted.
    fn blob_get_verified_in(
        &self,
        ns: &NamespaceRef,
        kappa: &Kappa,
    ) -> Result<Vec<u8>, StoreError> {
        let data = self.blob_get_in(ns, kappa)?;
        VerifiedContent::verify(kappa, &data)
            .map_err(|e| StoreError::Internal(format!("integrity check failed: {e}")))?;
        Ok(data)
    }

    /// Logical size without reading content.
    fn blob_size(&self, kappa: &Kappa) -> Result<u64, StoreError>;

    /// List blobs with optional `key_bytes` prefix filter, paginated.
    /// The prefix is binary (axis discriminant + partial digest bytes),
    /// not a wire-format string. Use `Axis::discriminant()` to filter
    /// by algorithm.
    fn blob_list(
        &self,
        prefix: Option<&[u8]>,
        page: &kappa_types::page::PageRequest,
    ) -> Result<kappa_types::page::Page<Kappa>, StoreError>;

    /// Cursor over all blob kappas, sorted by `key_bytes()`.
    ///
    /// Default: materializes `blob_list` into a `SliceCursor`.
    /// Backends with a trie index override for streaming.
    fn blob_cursor(&self) -> Result<Box<dyn FallibleCursor<Error = StoreError> + '_>, StoreError> {
        let mut request = kappa_types::page::PageRequest::first(256);
        let mut continuations = std::collections::HashSet::new();
        let mut key_bytes = Vec::new();
        loop {
            let page = self.blob_list(None, &request)?;
            if page.items.len() > request.limit {
                return Err(StoreError::Rejected(
                    "blob page exceeds requested bound".into(),
                ));
            }
            let empty = page.items.is_empty();
            key_bytes.extend(page.items.into_iter().map(|identity| identity.key_bytes()));
            match page.next_after {
                Some(next) => {
                    if empty || !continuations.insert(next.clone()) {
                        return Err(StoreError::Rejected(
                            "blob continuation did not progress".into(),
                        ));
                    }
                    request.after = Some(next);
                }
                None => break,
            }
        }
        Ok(Box::new(kappa_cursor::InfallibleCursor::new(
            kappa_cursor::SliceCursor::from_owned(key_bytes),
        )))
    }

    /// Identities the committed representation of `kappa` is assembled
    /// from: the components of a composite or manifest node, the holder of
    /// an alias. Empty for a self-contained representation. The collector
    /// marks through these so a dependency is never offered for
    /// retirement while something reachable selects it.
    fn blob_components(&self, kappa: &Kappa) -> Result<Vec<Kappa>, StoreError>;

    /// Get per-blob metadata by key.
    fn blob_meta_get(&self, kappa: &Kappa, key: &str) -> Result<Vec<u8>, StoreError>;

    /// Raw compressed bytes and algorithm name of a compressed
    /// representation.
    fn blob_get_compressed(&self, kappa: &Kappa) -> Result<(Vec<u8>, String), StoreError>;

    /// Get decompressed bytes.
    fn blob_get_decompressed(&self, kappa: &Kappa) -> Result<Vec<u8>, StoreError>;

    /// Mandatory secondary axes. Default: SHA-256.
    fn mandatory_axes(&self) -> Vec<Axis> {
        vec![Axis::Sha256]
    }

    /// Retrieve and verify integrity.
    fn blob_get_verified(&self, kappa: &Kappa) -> Result<Vec<u8>, StoreError> {
        let data = self.blob_get(kappa)?;
        VerifiedContent::verify(kappa, &data)
            .map_err(|e| StoreError::Internal(format!("integrity check failed: {e}")))?;
        Ok(data)
    }
}
