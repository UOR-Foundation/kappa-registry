//! OffloadVerifier trait (seam S11): provable offload receipts.

#[derive(Debug, thiserror::Error)]
pub enum OffloadError {
    #[error("offload verification failed: {0}")]
    VerificationFailed(String),
    #[error("offload receipt invalid: {0}")]
    InvalidReceipt(String),
    #[error("offload not configured")]
    NotConfigured,
}

#[derive(Debug, Clone)]
pub struct OffloadReceipt {
    pub source_kappa: String,
    pub destination: String,
    pub destination_signature: Vec<u8>,
    pub timestamp_ms: u64,
}

pub trait OffloadVerifier: Send + Sync {
    fn verify_offload(&self, receipt: &OffloadReceipt) -> Result<bool, OffloadError>;
}

pub struct NoOpOffloadVerifier;

impl OffloadVerifier for NoOpOffloadVerifier {
    fn verify_offload(&self, _receipt: &OffloadReceipt) -> Result<bool, OffloadError> {
        Err(OffloadError::NotConfigured)
    }
}
