//! Node identity: bootstrap, self-assertion, and trust floor.
//!
//! I-1: Bootstrap never touches the network
//! I-2: Identity is derived, not granted (pure function of signing key)
//! I-3: Absence is not failure (no peers = Standalone, not Degraded)
//! I-5: Self-asserted claims carry basis "self-asserted"
//! I-8: Origin is idempotent (repeated bootstrap = same anchor)

use std::sync::RwLock;

use crate::crypto::anchor::NodeAnchor;
use crate::crypto::keystore::KeyStore;
use crate::crypto::{CryptoError, Signer};
use crate::identity::trust::TrustPosition;
use crate::store::{blob_put_computed, KappaStore};
use crate::types::StoreError;

/// A registry node's identity, established at bootstrap.
///
/// Owns the node's signing key so it can sign epoch roots,
/// identity assertions, and federation messages. The signer
/// is stored for the lifetime of the process -- it is not
/// dropped after bootstrap.
pub struct NodeIdentity {
    anchor: NodeAnchor,
    algorithm: String,
    signer: Box<dyn Signer>,
    position: RwLock<TrustPosition>,
}

impl NodeIdentity {
    /// Establish this node's identity. Never contacts the network (I-1).
    ///
    /// Idempotent: on existing state this loads and returns the same
    /// anchor. It will not mint a second identity (I-8).
    ///
    /// The signing key is retained in the returned NodeIdentity so
    /// handlers can call sign() for epoch root signatures, identity
    /// assertions, and federation messages.
    pub fn bootstrap(keys: &KeyStore, store: &dyn KappaStore) -> Result<Self, StoreError> {
        let signer = keys
            .load_or_generate_ed25519("default")
            .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;

        let anchor = NodeAnchor::from_key(
            signer.algorithm(),
            crate::crypto::Signer::public_key(&signer),
        );

        let ns = anchor.as_namespace();
        let anchor_kappa = blob_put_computed(store, anchor.as_str().as_bytes())?;
        store.tag_set(&ns, "node/anchor", &anchor_kappa)?;
        let algo_kappa = blob_put_computed(store, signer.algorithm().as_bytes())?;
        store.tag_set(&ns, "node/algorithm", &algo_kappa)?;
        let version_kappa = blob_put_computed(store, env!("CARGO_PKG_VERSION").as_bytes())?;
        store.tag_set(&ns, "node/version", &version_kappa)?;
        let position_kappa = blob_put_computed(store, b"unprobed")?;
        store.tag_set(&ns, "trust/position", &position_kappa)?;

        tracing::info!(
            anchor = anchor.as_str(),
            algorithm = signer.algorithm(),
            "node identity bootstrapped"
        );

        Ok(Self {
            anchor,
            algorithm: signer.algorithm().to_owned(),
            signer: Box::new(signer),
            position: RwLock::new(TrustPosition::Unprobed),
        })
    }

    pub fn anchor(&self) -> &NodeAnchor {
        &self.anchor
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Sign a message with this node's signing key.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.signer.sign(message)
    }

    /// The node's public key bytes.
    pub fn public_key(&self) -> &[u8] {
        self.signer.public_key()
    }

    pub fn position(&self) -> TrustPosition {
        self.position
            .read()
            .expect("position lock poisoned")
            .clone()
    }

    pub fn set_position(&self, pos: TrustPosition) {
        *self.position.write().expect("position lock poisoned") = pos;
    }

    /// Update trust position from a batch of probe results.
    ///
    /// Examines all probe results to determine the aggregate trust state:
    /// - All verified -> Federated { verified_peers: count }
    /// - Any equivocation -> Degraded { reason: Equivocation, ... }
    /// - Any invalid signature -> Degraded { reason: SignatureInvalid, ... }
    /// - All unreachable -> Standalone (absence is not failure, I-3)
    /// - No probes -> Unprobed
    pub fn update_from_probes(&self, results: &[super::probe::ProbeResult]) {
        use super::probe::ProbeResult;
        use super::trust::DegradeReason;

        if results.is_empty() {
            return;
        }

        let mut verified = 0u64;
        let mut unreachable = 0u64;
        let mut sig_invalid = 0u64;
        let mut equivocations = 0u64;
        let total = results.len() as u64;

        for result in results {
            match result {
                ProbeResult::Verified(_) => verified += 1,
                ProbeResult::Unreachable(_) => unreachable += 1,
                ProbeResult::SignatureInvalid(_) => sig_invalid += 1,
                ProbeResult::Equivocation { .. } => equivocations += 1,
            }
        }

        let position = if equivocations > 0 {
            TrustPosition::Degraded {
                reason: DegradeReason::Equivocation,
                reachable: verified + sig_invalid,
                verified,
            }
        } else if sig_invalid > 0 {
            TrustPosition::Degraded {
                reason: DegradeReason::SignatureInvalid,
                reachable: verified + sig_invalid,
                verified,
            }
        } else if verified > 0 {
            TrustPosition::Federated {
                verified_peers: verified,
            }
        } else if unreachable == total {
            TrustPosition::Standalone
        } else {
            TrustPosition::Unprobed
        };

        self.set_position(position);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_position_starts_unprobed() {
        let pos = TrustPosition::Unprobed;
        assert_eq!(pos.as_str(), "unprobed");
        assert!(!pos.is_faulted());
    }
}
