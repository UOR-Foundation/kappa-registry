//! Peer probing for trust position advancement.
//!
//! `PeerProbe` trait abstracts fetching a peer's epoch root.
//! `probe_peer` fetches the root, verifies the signature, detects
//! equivocation (same epoch number, different root hash), and returns
//! a `ProbeResult`.

use crate::crypto::{verifier_for, CryptoError};
use crate::epoch::EpochRoot;
use crate::identity::trust::PeerRecord;

/// Response from a peer's epoch root endpoint.
#[derive(Debug, Clone)]
pub struct PeerEpochResponse {
    /// The peer's node anchor (content-addressed identity).
    pub anchor: String,
    /// Signing algorithm (ed25519, p256, k256, frost-ed25519, etc).
    pub algorithm: String,
    /// The peer's current epoch number for this namespace.
    pub epoch_number: u64,
    /// The kappa-label of the peer's current epoch root.
    pub root_kappa: String,
    /// The signature over the epoch root.
    pub signature: Vec<u8>,
    /// The peer's public key bytes.
    pub public_key: Vec<u8>,
}

/// Errors from peer probing.
#[derive(Debug)]
pub enum ProbeError {
    /// Network or transport failure.
    Transport(String),
    /// Cryptographic verification failure.
    Verification(CryptoError),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(msg) => write!(f, "transport: {}", msg),
            Self::Verification(e) => write!(f, "verification: {}", e),
        }
    }
}

impl std::error::Error for ProbeError {}

/// Transport abstraction for fetching peer state.
pub trait PeerProbe: Send + Sync {
    /// Fetch the current epoch root from a peer for a given namespace.
    fn fetch_epoch_root(
        &self,
        endpoint: &str,
        namespace: &str,
    ) -> Result<PeerEpochResponse, ProbeError>;
}

/// Result of probing a peer.
#[derive(Debug)]
pub enum ProbeResult {
    /// Peer's epoch root signature verified, no equivocation.
    Verified(PeerRecord),
    /// Peer's signature did not verify.
    SignatureInvalid(String),
    /// Peer signed a different root at the same epoch number.
    Equivocation {
        peer: String,
        epoch: u64,
        local_root: String,
        remote_root: String,
    },
    /// Peer could not be reached.
    Unreachable(String),
}

/// Probe a peer: fetch epoch root, verify signature, check for equivocation.
///
/// The message signed by the peer is: "{namespace}\n{root_kappa}\n{epoch_number}".
/// This is the canonical signable representation of an epoch root claim.
///
/// If `local_epoch` is Some and the peer's epoch_number matches but the
/// root_kappa differs, that is equivocation -- a Byzantine fault.
pub fn probe_peer(
    transport: &dyn PeerProbe,
    endpoint: &str,
    namespace: &str,
    local_epoch: Option<&EpochRoot>,
) -> ProbeResult {
    let response = match transport.fetch_epoch_root(endpoint, namespace) {
        Ok(r) => r,
        Err(ProbeError::Transport(msg)) => return ProbeResult::Unreachable(msg),
        Err(ProbeError::Verification(e)) => {
            return ProbeResult::SignatureInvalid(e.to_string())
        }
    };

    // Verify signature
    let verifier = match verifier_for(&response.algorithm) {
        Ok(v) => v,
        Err(_) => {
            return ProbeResult::SignatureInvalid(format!(
                "unsupported algorithm: {}",
                response.algorithm
            ))
        }
    };

    let message = format!(
        "{}\n{}\n{}",
        namespace, response.root_kappa, response.epoch_number
    );
    match verifier.verify(
        &response.public_key,
        message.as_bytes(),
        &response.signature,
    ) {
        Ok(true) => {}
        Ok(false) => return ProbeResult::SignatureInvalid(response.anchor),
        Err(e) => return ProbeResult::SignatureInvalid(e.to_string()),
    }

    // Check equivocation: same epoch, different root
    if let Some(local) = local_epoch {
        if local.epoch_number == response.epoch_number
            && local.kappa() != response.root_kappa
        {
            return ProbeResult::Equivocation {
                peer: response.anchor,
                epoch: response.epoch_number,
                local_root: local.kappa(),
                remote_root: response.root_kappa,
            };
        }
    }

    ProbeResult::Verified(PeerRecord {
        endpoint: endpoint.to_string(),
        asserter_anchor: response.anchor,
        last_epoch: response.epoch_number,
        state_root: response.root_kappa,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTransport {
        response: Result<PeerEpochResponse, ProbeError>,
    }

    impl PeerProbe for MockTransport {
        fn fetch_epoch_root(
            &self,
            _endpoint: &str,
            _namespace: &str,
        ) -> Result<PeerEpochResponse, ProbeError> {
            match &self.response {
                Ok(r) => Ok(r.clone()),
                Err(ProbeError::Transport(msg)) => {
                    Err(ProbeError::Transport(msg.clone()))
                }
                Err(ProbeError::Verification(e)) => {
                    Err(ProbeError::Verification(CryptoError::SigningFailed(
                        e.to_string(),
                    )))
                }
            }
        }
    }

    fn signed_response(
        namespace: &str,
        epoch: u64,
        root_kappa: &str,
    ) -> PeerEpochResponse {
        use crate::crypto::Signer;
        let signer = crate::crypto::ed25519::Ed25519Signer::generate(
            &mut rand_core::UnwrapErr(getrandom::SysRng),
        );
        let message = format!("{}\n{}\n{}", namespace, root_kappa, epoch);
        let signature = signer.sign(message.as_bytes()).unwrap();
        PeerEpochResponse {
            anchor: "sha256:peer-anchor".into(),
            algorithm: "ed25519".into(),
            epoch_number: epoch,
            root_kappa: root_kappa.into(),
            signature,
            public_key: signer.public_key().to_vec(),
        }
    }

    #[test]
    fn probe_verified() {
        let resp = signed_response("ns", 5, "sha256:root-5");
        let transport = MockTransport {
            response: Ok(resp),
        };
        let result = probe_peer(&transport, "http://peer:8080", "ns", None);
        match result {
            ProbeResult::Verified(pr) => {
                assert_eq!(pr.last_epoch, 5);
                assert_eq!(pr.state_root, "sha256:root-5");
            }
            other => panic!("expected Verified, got {:?}", other),
        }
    }

    #[test]
    fn probe_unreachable() {
        let transport = MockTransport {
            response: Err(ProbeError::Transport("connection refused".into())),
        };
        let result = probe_peer(&transport, "http://dead:8080", "ns", None);
        assert!(matches!(result, ProbeResult::Unreachable(_)));
    }

    #[test]
    fn probe_invalid_signature() {
        let mut resp = signed_response("ns", 5, "sha256:root-5");
        resp.signature = vec![0u8; 64]; // corrupt
        let transport = MockTransport {
            response: Ok(resp),
        };
        let result = probe_peer(&transport, "http://peer:8080", "ns", None);
        assert!(matches!(result, ProbeResult::SignatureInvalid(_)));
    }

    #[test]
    fn probe_equivocation() {
        let resp = signed_response("ns", 5, "sha256:remote-root");
        let transport = MockTransport {
            response: Ok(resp),
        };

        let local = crate::epoch::EpochRoot::build(crate::epoch::EpochRootFields {
            namespace: "ns".into(),
            epoch_number: 5,
            prev_root_kappa: None,
            state_root: [0xAA; 32],
            mutations_root: [0xBB; 32],
            timestamp_ms: 1000,
            signer_anchor: "local".into(),
        });
        // local.kappa() != "sha256:remote-root", same epoch 5
        let result =
            probe_peer(&transport, "http://peer:8080", "ns", Some(&local));
        match result {
            ProbeResult::Equivocation {
                peer,
                epoch,
                local_root,
                remote_root,
            } => {
                assert_eq!(epoch, 5);
                assert_eq!(remote_root, "sha256:remote-root");
                assert_ne!(local_root, remote_root);
                assert_eq!(peer, "sha256:peer-anchor");
            }
            other => panic!("expected Equivocation, got {:?}", other),
        }
    }

    #[test]
    fn probe_unsupported_algorithm() {
        let mut resp = signed_response("ns", 5, "sha256:root");
        resp.algorithm = "rsa-4096".into();
        let transport = MockTransport {
            response: Ok(resp),
        };
        let result = probe_peer(&transport, "http://peer:8080", "ns", None);
        assert!(matches!(result, ProbeResult::SignatureInvalid(_)));
    }
}
