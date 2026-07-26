//! Epoch-chained namespace roots.
//!
//! Each asserter's namespace has an epoch chain. The chain is the
//! authority record. Each epoch root commits to the previous root,
//! the current AKD tree state, and the epoch number. Epoch advance
//! is atomic with assertion/tag storage.
//!
//! `epoch/current` is excluded from state_root computation to prevent
//! infinite recursion (the epoch pointer changing would change the
//! state root, which would change the epoch pointer).

use serde::{Deserialize, Serialize};

use crate::kappa::KappaLabel;

/// A signed epoch root in the namespace chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochRoot {
    /// The namespace this epoch belongs to.
    pub namespace: String,
    /// Monotonically increasing epoch counter (per-asserter Lamport).
    pub epoch: u64,
    /// Kappa of the previous epoch root (None for genesis).
    pub prev_epoch_root: Option<String>,
    /// Hash of current tag/assertion state (excludes epoch/current tag).
    pub state_root: String,
    /// AKD tree root hash at this epoch (if AKD is active).
    pub azks_root: Option<String>,
    /// Mutations applied in this epoch.
    pub mutations: Vec<EpochMutation>,
    /// Signing algorithm used.
    pub algorithm: Option<String>,
    /// Signer's public key.
    pub public_key: Option<Vec<u8>>,
    /// Signature over canonical form (excludes signature field).
    pub signature: Option<Vec<u8>>,
}

/// A single mutation recorded in an epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochMutation {
    pub operation: MutationOp,
    pub name: String,
    pub value: Option<String>,
    pub prev_value: Option<String>,
}

/// The type of mutation that occurred.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MutationOp {
    TagSet,
    TagDelete,
    TagSetIf,
    TagSymbolic,
    TagBatchItem,
    AssertionPublish,
    RevocationPublish,
    AnchorGenesis,
}

impl EpochRoot {
    /// Canonical bytes for signing (excludes signature, algorithm, public_key).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        // namespace
        buf.extend_from_slice(&(self.namespace.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.namespace.as_bytes());
        // epoch
        buf.extend_from_slice(&self.epoch.to_be_bytes());
        // prev_epoch_root
        match &self.prev_epoch_root {
            Some(prev) => {
                buf.push(0x01);
                buf.extend_from_slice(&(prev.len() as u16).to_be_bytes());
                buf.extend_from_slice(prev.as_bytes());
            }
            None => buf.push(0x00),
        }
        // state_root
        buf.extend_from_slice(&(self.state_root.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.state_root.as_bytes());
        // azks_root
        match &self.azks_root {
            Some(azks) => {
                buf.push(0x01);
                buf.extend_from_slice(&(azks.len() as u16).to_be_bytes());
                buf.extend_from_slice(azks.as_bytes());
            }
            None => buf.push(0x00),
        }
        // mutation count (but not mutation details -- those are in the blob)
        buf.extend_from_slice(&(self.mutations.len() as u32).to_be_bytes());
        buf
    }

    /// Compute the kappa of this epoch root.
    pub fn kappa(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("EpochRoot serialization cannot fail");
        KappaLabel::sha256(&bytes).as_str().to_owned()
    }

    /// Check for equivocation: two epoch roots at the same epoch
    /// with different state roots.
    pub fn is_equivocation(&self, other: &EpochRoot) -> bool {
        self.namespace == other.namespace
            && self.epoch == other.epoch
            && self.state_root != other.state_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch(epoch: u64, state_root: &str) -> EpochRoot {
        EpochRoot {
            namespace: "test-ns".to_owned(),
            epoch,
            prev_epoch_root: None,
            state_root: state_root.to_owned(),
            azks_root: None,
            mutations: Vec::new(),
            algorithm: None,
            public_key: None,
            signature: None,
        }
    }

    #[test]
    fn canonical_bytes_deterministic() {
        let e = test_epoch(1, "sha256:root");
        assert_eq!(e.canonical_bytes(), e.canonical_bytes());
    }

    #[test]
    fn canonical_bytes_excludes_signature() {
        let mut e = test_epoch(1, "sha256:root");
        let b1 = e.canonical_bytes();
        e.signature = Some(vec![0xFF; 64]);
        e.algorithm = Some("ed25519".to_owned());
        e.public_key = Some(vec![0xAA; 32]);
        assert_eq!(b1, e.canonical_bytes());
    }

    #[test]
    fn kappa_deterministic() {
        let e = test_epoch(1, "sha256:root");
        assert_eq!(e.kappa(), e.kappa());
    }

    #[test]
    fn equivocation_detected() {
        let e1 = test_epoch(5, "sha256:root_a");
        let e2 = test_epoch(5, "sha256:root_b");
        assert!(e1.is_equivocation(&e2));
    }

    #[test]
    fn no_equivocation_different_epochs() {
        let e1 = test_epoch(5, "sha256:root_a");
        let e2 = test_epoch(6, "sha256:root_a");
        assert!(!e1.is_equivocation(&e2));
    }

    #[test]
    fn no_equivocation_same_root() {
        let e1 = test_epoch(5, "sha256:root_a");
        let e2 = test_epoch(5, "sha256:root_a");
        assert!(!e1.is_equivocation(&e2));
    }
}
