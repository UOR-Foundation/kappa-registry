//! EpochWitness trait (seam S5): external witness of epoch roots.

#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    #[error("witness unavailable: {0}")]
    Unavailable(String),
    #[error("witness rejected: {0}")]
    Rejected(String),
}

#[derive(Debug, Clone)]
pub struct WitnessReceipt {
    pub epoch_root_kappa: String,
    pub witness_signature: Vec<u8>,
    pub witness_identity: String,
    pub timestamp_ms: Option<u64>,
}

pub trait EpochWitness: Send + Sync {
    fn witness(
        &self,
        epoch_root_kappa: &str,
        epoch_root_bytes: &[u8],
    ) -> Result<WitnessReceipt, WitnessError>;
}

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
    fn noop_witness_returns_receipt_with_no_timestamp() {
        let w = NoOpWitness;
        let receipt = w.witness("sha256:abc", b"root bytes").unwrap();
        assert_eq!(receipt.epoch_root_kappa, "sha256:abc");
        assert_eq!(receipt.witness_identity, "none");
        assert!(receipt.timestamp_ms.is_none());
    }
}
