//! Node identity -- bootstrap, self-assertion, and trust floor.
//!
//! Invariants (testable, non-negotiable):
//! - I-1: Bootstrap never touches the network
//! - I-2: Identity is derived, not granted (pure function of signing key)
//! - I-3: Absence is not failure (no peers = Standalone, not Degraded)
//! - I-5: Self-asserted claims carry Basis::SelfAsserted
//! - I-8: Origin is idempotent (repeated bootstrap = same anchor)

use std::sync::RwLock;

use crate::crypto::anchor::anchor_from_key;
use crate::crypto::keystore::KeyStore;
use crate::identity::anchor::NodeAnchor;
use crate::store::StoreError;

use super::trust::TrustPosition;

/// A registry node's identity, established at bootstrap.
///
/// No `Default` impl -- a default identity is a nonsense value.
pub struct NodeIdentity {
    anchor: NodeAnchor,
    algorithm: String,
    position: RwLock<TrustPosition>,
}

impl NodeIdentity {
    /// Establish this node's identity. Never contacts the network.
    ///
    /// Idempotent: on existing state this loads and returns the same
    /// anchor. It will not mint a second identity.
    ///
    /// # Steps
    /// 1. Signing key: generates on first run, loads thereafter.
    ///    Fails hard on BLAKE3 integrity mismatch -- a corrupt or
    ///    tampered keystore must never be silently regenerated.
    /// 2. VRF key: namespace-lifetime, never rotates.
    /// 3. Self-assertions: node/anchor, node/algorithm, node/version,
    ///    trust/position=unprobed. All carry Basis::SelfAsserted.
    /// 4. Capability floor: this node may write its own reserved
    ///    namespaces. Written as a real, inspectable, revocable edge --
    ///    not a hardcoded bypass in authorize().
    pub fn bootstrap(
        keys: &KeyStore,
        store: &dyn crate::store::KappaStore,
        signing_algorithm: &str,
    ) -> Result<Self, StoreError> {
        // 1. Signing key
        let signer = keys
            .load_or_generate(signing_algorithm)
            .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;

        let anchor = anchor_from_key(signer.algorithm(), &signer.public_key_bytes());

        // 2. VRF key
        let vrf_dir = keys.keys_dir().to_path_buf();
        let _ = crate::crypto::vrf::VrfKeyMaterial::load_or_generate(&vrf_dir);

        // 3. Self-assertions as tags in the node's own namespace
        let ns = anchor.as_namespace();
        let _ = store.tag_set(&ns, "node/anchor", anchor.as_str());
        let _ = store.tag_set(&ns, "node/algorithm", signer.algorithm());
        let _ = store.tag_set(&ns, "node/version", env!("CARGO_PKG_VERSION"));
        let _ = store.tag_set(&ns, "trust/position", "unprobed");

        // 4. Capability floor: registry anchor can write reserved namespaces.
        // Written as edges so they're inspectable and revocable.
        let cap_meta = serde_json::json!({"ops": ["read", "write", "admin"]});
        for reserved in crate::auth::RESERVED_PREFIXES {
            let edge_kappa = format!("capability:{}:{}", anchor.as_str(), reserved);
            let _ = store.edge_put(
                reserved,
                anchor.as_str(),
                &edge_kappa,
                anchor.as_str(),
                "capability",
                anchor.as_str(),
                b"",
                cap_meta.clone(),
            );
        }

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

    /// Build the whoami response as a JSON value.
    pub fn whoami(&self, store: &dyn crate::store::KappaStore) -> serde_json::Value {
        let pos = self.position();
        let ns = self.anchor.as_namespace();

        let epoch = store.sequence_current(&ns, "identity_epoch").unwrap_or(0);

        let mut self_assertions = serde_json::Map::new();
        for facet in [
            "node/anchor",
            "node/algorithm",
            "node/version",
            "trust/position",
        ] {
            if let Ok(Some(val)) = store.tag_get(&ns, facet) {
                self_assertions.insert(facet.to_owned(), serde_json::Value::String(val));
            }
        }

        let mut result = serde_json::json!({
            "anchor": self.anchor.as_str(),
            "algorithm": self.algorithm,
            "trust_position": pos.as_str(),
            "epoch": epoch,
            "self_assertions": self_assertions,
        });

        match &pos {
            TrustPosition::Federated { verified_peers } => {
                result["verified_peers"] = serde_json::json!(verified_peers.get());
            }
            TrustPosition::Degraded {
                reason,
                reachable,
                verified,
            } => {
                result["degrade_reason"] = serde_json::json!({
                    "kind": reason.as_str(),
                    "detail": reason.detail(),
                });
                result["reachable_peers"] = serde_json::json!(reachable);
                result["verified_peers"] = serde_json::json!(verified);
            }
            _ => {}
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integration tests requiring FsStore + KeyStore are in tests/integration/.
    // Unit tests here verify type properties.

    #[test]
    fn trust_position_starts_unprobed() {
        // Cannot construct NodeIdentity without a store, but can test
        // that TrustPosition::Unprobed is the default semantic.
        let pos = TrustPosition::Unprobed;
        assert_eq!(pos.as_str(), "unprobed");
        assert!(!pos.is_faulted());
    }
}
