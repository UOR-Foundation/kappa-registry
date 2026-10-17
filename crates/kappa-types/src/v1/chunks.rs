//! Chunk-level blob retrieval for content-defined chunking.
//!
//! The `ChunkSource` trait abstracts retrieval of individual chunks
//! from a blob that has been split via content-defined chunking
//! (e.g., `FastCDC`, Rabin fingerprint). Each chunk is addressed
//! by its own kappa. Reconstruction reassembles chunks in order
//! from a `ChunkManifest` edge listing.

/// Errors from chunk operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChunkError {
    #[error("chunk not found: {0}")]
    NotFound(String),
    #[error("chunk source not available")]
    NotAvailable,
    #[error("chunk io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Retrieve individual chunks by their kappa address.
pub trait ChunkSource: Send + Sync {
    /// Retrieve a chunk's bytes by its kappa.
    ///
    /// # Errors
    ///
    /// Returns `ChunkError::NotFound` if the chunk does not exist.
    /// Returns `ChunkError::NotAvailable` if the source is not configured.
    fn chunk_get(&self, kappa: &str) -> Result<Vec<u8>, ChunkError>;

    /// Check whether a chunk exists without reading it.
    fn chunk_exists(&self, kappa: &str) -> bool;

    /// Retrieve multiple chunks in one call. Default calls `chunk_get`
    /// per kappa. Implementations may batch for efficiency.
    fn chunk_get_batch(&self, kappas: &[&str]) -> Vec<Result<Vec<u8>, ChunkError>> {
        kappas.iter().map(|k| self.chunk_get(k)).collect()
    }
}

/// No-op chunk source for deployments without content-defined chunking.
pub struct NoOpChunkSource;

impl ChunkSource for NoOpChunkSource {
    fn chunk_get(&self, _kappa: &str) -> Result<Vec<u8>, ChunkError> {
        Err(ChunkError::NotAvailable)
    }

    fn chunk_exists(&self, _kappa: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_chunk_get_returns_not_available() {
        let cs = NoOpChunkSource;
        assert!(matches!(
            cs.chunk_get("sha256:abc"),
            Err(ChunkError::NotAvailable)
        ));
    }

    #[test]
    fn noop_chunk_exists_returns_false() {
        let cs = NoOpChunkSource;
        assert!(!cs.chunk_exists("sha256:abc"));
    }

    #[test]
    fn noop_batch_returns_not_available_for_each() {
        let cs = NoOpChunkSource;
        let results = cs.chunk_get_batch(&["sha256:a", "sha256:b"]);
        assert_eq!(results.len(), 2);
        for r in results {
            assert!(matches!(r, Err(ChunkError::NotAvailable)));
        }
    }
}
