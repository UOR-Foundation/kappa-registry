//! ChunkSource trait (seam S8): chunk-level blob retrieval.

#[derive(Debug, thiserror::Error)]
pub enum ChunkError {
    #[error("chunk not found: {0}")]
    NotFound(String),
    #[error("chunk not available")]
    NotAvailable,
    #[error("chunk io error: {0}")]
    Io(#[from] std::io::Error),
}

pub trait ChunkSource: Send + Sync {
    fn chunk_get(&self, kappa: &str) -> Result<Vec<u8>, ChunkError>;
    fn chunk_exists(&self, kappa: &str) -> bool;
}

pub struct NoOpChunkSource;

impl ChunkSource for NoOpChunkSource {
    fn chunk_get(&self, _kappa: &str) -> Result<Vec<u8>, ChunkError> {
        Err(ChunkError::NotAvailable)
    }

    fn chunk_exists(&self, _kappa: &str) -> bool {
        false
    }
}
