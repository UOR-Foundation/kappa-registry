//! Provable offload receipts for tiered storage.
//!
//! When a blob is moved from hot storage to cold (glacier, tape,
//! remote archive), the destination signs a receipt proving it holds
//! the content. The receipt is stored as an `OffloadReceipt` edge.
//! On retrieval, the receipt is verified before trusting the
//! destination to return the correct bytes.

/// Errors from offload operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OffloadError {
    #[error("offload verification failed: {0}")]
    VerificationFailed(String),
    #[error("offload receipt invalid: {0}")]
    InvalidReceipt(String),
    #[error("offload not configured")]
    NotConfigured,
}

/// A signed receipt from the offload destination proving it holds the blob.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OffloadReceipt {
    /// The kappa of the blob that was offloaded.
    pub source_kappa: String,
    /// The destination identifier (URL, bucket, archive name).
    pub destination: String,
    /// The destination's cryptographic signature over the blob kappa.
    pub destination_signature: Vec<u8>,
    /// When the offload was confirmed, in epoch milliseconds.
    pub timestamp_ms: u64,
}

/// Verify offload receipts from storage destinations.
pub trait OffloadVerifier: Send + Sync {
    /// Verify that a receipt is valid: the destination signature
    /// covers the source kappa and the destination is trusted.
    ///
    /// # Errors
    ///
    /// Returns `OffloadError::VerificationFailed` if the signature is invalid.
    /// Returns `OffloadError::InvalidReceipt` if the receipt is malformed.
    /// Returns `OffloadError::NotConfigured` if no verifier is set up.
    fn verify_offload(&self, receipt: &OffloadReceipt) -> Result<bool, OffloadError>;

    /// Whether offload verification is available in this deployment.
    fn is_configured(&self) -> bool {
        true
    }
}

/// No-op verifier for deployments without tiered storage.
pub struct NoOpOffloadVerifier;

impl OffloadVerifier for NoOpOffloadVerifier {
    fn verify_offload(&self, _receipt: &OffloadReceipt) -> Result<bool, OffloadError> {
        Err(OffloadError::NotConfigured)
    }

    fn is_configured(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_verifier_returns_not_configured() {
        let v = NoOpOffloadVerifier;
        let receipt = OffloadReceipt {
            source_kappa: "sha256:abc".to_string(),
            destination: "s3://archive-bucket".to_string(),
            destination_signature: vec![1, 2, 3],
            timestamp_ms: 1000,
        };
        assert!(matches!(
            v.verify_offload(&receipt),
            Err(OffloadError::NotConfigured)
        ));
        assert!(!v.is_configured());
    }

    #[test]
    fn receipt_fields_preserved() {
        let receipt = OffloadReceipt {
            source_kappa: "sha256:deadbeef".to_string(),
            destination: "glacier://vault-1".to_string(),
            destination_signature: vec![10, 20, 30],
            timestamp_ms: 999_999,
        };
        assert_eq!(receipt.source_kappa, "sha256:deadbeef");
        assert_eq!(receipt.destination, "glacier://vault-1");
        assert_eq!(receipt.destination_signature, vec![10, 20, 30]);
        assert_eq!(receipt.timestamp_ms, 999_999);
    }

    #[test]
    fn receipt_serializes_to_json() -> Result<(), serde_json::Error> {
        let receipt = OffloadReceipt {
            source_kappa: "sha256:abc".to_string(),
            destination: "cold".to_string(),
            destination_signature: vec![],
            timestamp_ms: 0,
        };
        let json = serde_json::to_string(&receipt)?;
        assert!(json.contains("sha256:abc"));
        let parsed: OffloadReceipt = serde_json::from_str(&json)?;
        assert_eq!(parsed.source_kappa, receipt.source_kappa);
        Ok(())
    }
}
