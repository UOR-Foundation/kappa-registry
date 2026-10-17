//! External witness of epoch roots.
//!
//! An epoch witness is an external entity that attests to having
//! observed an epoch root at a point in time. The receipt is
//! stored as a `WitnessReceipt` edge in the epoch graph, providing
//! non-repudiable evidence of state at a given epoch.

/// Errors from witness operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WitnessError {
    #[error("witness unavailable: {0}")]
    Unavailable(String),
    #[error("witness rejected: {0}")]
    Rejected(String),
    #[error("witness verification failed: {0}")]
    VerificationFailed(String),
}

/// A signed attestation that an external entity observed an epoch root.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WitnessReceipt {
    /// The epoch root kappa that was witnessed.
    pub epoch_root_kappa: String,
    /// The witness's cryptographic signature over the epoch root bytes.
    pub witness_signature: Vec<u8>,
    /// The witness's identity (anchor, URL, or public key identifier).
    pub witness_identity: String,
    /// When the witness observed the epoch root, in epoch milliseconds.
    pub timestamp_ms: Option<u64>,
}

/// Submit epoch roots to an external witness and receive signed receipts.
pub trait EpochWitness: Send + Sync {
    /// Submit an epoch root for witnessing.
    ///
    /// The witness signs the epoch root bytes and returns a receipt.
    /// The caller stores the receipt as a `WitnessReceipt` edge.
    ///
    /// # Errors
    ///
    /// Returns `WitnessError::Unavailable` if the witness is unreachable.
    /// Returns `WitnessError::Rejected` if the witness refuses the root.
    fn witness(
        &self,
        epoch_root_kappa: &str,
        epoch_root_bytes: &[u8],
    ) -> Result<WitnessReceipt, WitnessError>;

    /// Verify a previously received witness receipt against the epoch root.
    ///
    /// Default implementation accepts all receipts. Override with
    /// signature verification for production witnesses.
    fn verify(
        &self,
        receipt: &WitnessReceipt,
        _epoch_root_bytes: &[u8],
    ) -> Result<bool, WitnessError> {
        if receipt.witness_signature.is_empty() {
            return Ok(false);
        }
        Ok(true)
    }
}

/// Single-node no-op witness. Returns unsigned receipts.
pub struct NoOpWitness;

impl EpochWitness for NoOpWitness {
    fn witness(
        &self,
        epoch_root_kappa: &str,
        _epoch_root_bytes: &[u8],
    ) -> Result<WitnessReceipt, WitnessError> {
        Ok(WitnessReceipt {
            epoch_root_kappa: epoch_root_kappa.to_string(),
            witness_signature: Vec::new(),
            witness_identity: "none".to_string(),
            timestamp_ms: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_witness_returns_receipt() -> Result<(), WitnessError> {
        let w = NoOpWitness;
        let receipt = w.witness("sha256:abc", b"root bytes")?;
        assert_eq!(receipt.epoch_root_kappa, "sha256:abc");
        assert_eq!(receipt.witness_identity, "none");
        assert!(receipt.timestamp_ms.is_none());
        assert!(receipt.witness_signature.is_empty());
        Ok(())
    }

    #[test]
    fn noop_verify_rejects_empty_signature() -> Result<(), WitnessError> {
        let w = NoOpWitness;
        let receipt = w.witness("sha256:abc", b"root")?;
        let valid = w.verify(&receipt, b"root")?;
        assert!(!valid, "empty signature should not verify");
        Ok(())
    }

    #[test]
    fn verify_accepts_nonempty_signature_by_default() -> Result<(), WitnessError> {
        let w = NoOpWitness;
        let receipt = WitnessReceipt {
            epoch_root_kappa: "sha256:abc".to_string(),
            witness_signature: vec![1, 2, 3],
            witness_identity: "test-witness".to_string(),
            timestamp_ms: Some(1000),
        };
        let valid = w.verify(&receipt, b"root")?;
        assert!(valid, "nonempty signature passes default verify");
        Ok(())
    }
}
