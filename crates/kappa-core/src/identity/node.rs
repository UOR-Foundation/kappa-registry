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
use crate::identity::trust::TrustPosition;
use crate::store::KappaStore;
use crate::types::StoreError;

/// A registry node's identity, established at bootstrap.
pub struct NodeIdentity {
    anchor: NodeAnchor,
    algorithm: String,
    position: RwLock<TrustPosition>,
}

impl NodeIdentity {
    /// Establish this node's identity. Never contacts the network (I-1).
    ///
    /// Idempotent: on existing state this loads and returns the same
    /// anchor. It will not mint a second identity (I-8).
    pub fn bootstrap(
        keys: &KeyStore,
        store: &dyn KappaStore,
    ) -> Result<Self, StoreError> {
        let signer = keys
            .load_or_generate_ed25519("default")
            .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;

        let anchor = NodeAnchor::from_key(
            signer.algorithm(),
            crate::crypto::Signer::public_key(&signer),
        );

        let ns = anchor.as_namespace();
        let _ = store.tag_set(&ns, "node/anchor", anchor.as_str());
        let _ = store.tag_set(&ns, "node/algorithm", signer.algorithm());
        let _ = store.tag_set(&ns, "node/version", env!("CARGO_PKG_VERSION"));
        let _ = store.tag_set(&ns, "trust/position", "unprobed");

        tracing::info!(
            anchor = anchor.as_str(),
            algorithm = signer.algorithm(),
            "node identity bootstrapped"
        );

        Ok(Self {
            anchor,
            algorithm: signer.algorithm().to_owned(),
            position: RwLock::new(TrustPosition::Unprobed),
        })
    }

    pub fn anchor(&self) -> &NodeAnchor {
        &self.anchor
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
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
