use std::collections::BTreeMap;

use frost_ed25519 as frost_ed;
mod entropy;

use super::{Commitment, CryptoError, Round1State, SignatureShare, ThresholdSigner, Verifier};

/// Backend-specific errors for FROST threshold operations.
/// Each variant carries the algorithm and operation context.
/// Converted to CryptoError at module boundary via From.
enum FrostError {
    Serialization {
        algorithm: &'static str,
        context: &'static str,
        reason: String,
    },
    Deserialization {
        algorithm: &'static str,
        context: &'static str,
        reason: String,
    },
    Signing {
        algorithm: &'static str,
        reason: String,
    },
    InvalidKey {
        algorithm: &'static str,
        reason: String,
    },
    InvalidSignature {
        algorithm: &'static str,
        reason: String,
    },
}

impl From<FrostError> for CryptoError {
    fn from(e: FrostError) -> Self {
        match e {
            FrostError::Serialization {
                algorithm,
                context,
                reason,
            } => CryptoError::Serialization {
                context: format!("frost-{} {}", algorithm, context),
                reason,
            },
            FrostError::Deserialization {
                algorithm,
                context,
                reason,
            } => CryptoError::Deserialization {
                context: format!("frost-{} {}", algorithm, context),
                reason,
            },
            FrostError::Signing { algorithm, reason } => CryptoError::SigningFailed {
                algorithm: format!("frost-{}", algorithm),
                reason,
            },
            FrostError::InvalidKey { algorithm, reason } => CryptoError::InvalidKey {
                reason: format!("frost-{} key: {}", algorithm, reason),
            },
            FrostError::InvalidSignature { algorithm, reason } => CryptoError::VerificationFailed {
                algorithm: format!("frost-{algorithm}"),
                reason,
            },
        }
    }
}

// -- FROST Ed25519 Signer -----------------------------------------------------

pub struct FrostEd25519Signer {
    key_package: frost_ed::keys::KeyPackage,
    group_public_key_bytes: Vec<u8>,
}

impl FrostEd25519Signer {
    pub fn new(key_package: frost_ed::keys::KeyPackage) -> Result<Self, CryptoError> {
        let group_public_key_bytes =
            key_package
                .verifying_key()
                .serialize()
                .map_err(|e| FrostError::Serialization {
                    algorithm: "ed25519",
                    context: "group public key",
                    reason: e.to_string(),
                })?;
        Ok(Self {
            key_package,
            group_public_key_bytes,
        })
    }

    pub fn identifier(&self) -> Vec<u8> {
        self.key_package.identifier().serialize()
    }
}

impl ThresholdSigner for FrostEd25519Signer {
    fn algorithm(&self) -> &'static str {
        "frost-ed25519"
    }
    fn group_public_key(&self) -> &[u8] {
        &self.group_public_key_bytes
    }

    fn precompute_round1(&mut self) -> Result<Round1State, CryptoError> {
        let mut rng = entropy::NonceEntropy::acquire()?;
        let (nonces, commitments) =
            frost_ed::round1::commit(self.key_package.signing_share(), &mut rng);
        let commitments_bytes = commitments
            .serialize()
            .map_err(|e| FrostError::Serialization {
                algorithm: "ed25519",
                context: "commitments",
                reason: e.to_string(),
            })?;
        Ok(Round1State::new(
            nonces,
            commitments_bytes,
            self.identifier(),
            self.group_public_key_bytes.clone(),
        ))
    }

    fn sign_share(
        &mut self,
        round1: Round1State,
        message: &[u8],
        commitments: &[Commitment],
    ) -> Result<SignatureShare, CryptoError> {
        let nonces = round1.consume(&self.identifier(), &self.group_public_key_bytes)?;

        let mut commitment_map = BTreeMap::new();
        for c in commitments {
            let id = frost_ed::Identifier::deserialize(c.signer_id()).map_err(|e| {
                FrostError::Deserialization {
                    algorithm: "ed25519",
                    context: "identifier",
                    reason: e.to_string(),
                }
            })?;
            let sc = frost_ed::round1::SigningCommitments::deserialize(c.data()).map_err(|e| {
                FrostError::Deserialization {
                    algorithm: "ed25519",
                    context: "signing commitments",
                    reason: e.to_string(),
                }
            })?;
            if commitment_map.insert(id, sc).is_some() {
                return Err(FrostError::Signing {
                    algorithm: "ed25519",
                    reason: "duplicate participant commitment".into(),
                }
                .into());
            }
        }

        let signing_package = frost_ed::SigningPackage::new(commitment_map, message);
        let share =
            frost_ed::round2::sign(&signing_package, &nonces, &self.key_package).map_err(|e| {
                FrostError::Signing {
                    algorithm: "ed25519",
                    reason: e.to_string(),
                }
            })?;

        Ok(SignatureShare::new(self.identifier(), share.serialize()))
    }
}

// -- FROST Ed25519 Coordinator ------------------------------------------------

pub struct FrostEd25519Coordinator {
    public_key_package: frost_ed::keys::PublicKeyPackage,
    group_public_key_bytes: Vec<u8>,
}

impl FrostEd25519Coordinator {
    pub fn new(public_key_package: frost_ed::keys::PublicKeyPackage) -> Result<Self, CryptoError> {
        let group_public_key_bytes =
            public_key_package
                .verifying_key()
                .serialize()
                .map_err(|e| FrostError::Serialization {
                    algorithm: "ed25519",
                    context: "group public key",
                    reason: e.to_string(),
                })?;
        Ok(Self {
            public_key_package,
            group_public_key_bytes,
        })
    }

    pub fn group_public_key(&self) -> &[u8] {
        &self.group_public_key_bytes
    }

    /// Aggregate signature shares into a final signature.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Deserialization` if any commitment or
    /// share cannot be parsed.
    ///
    /// Returns `CryptoError::SigningFailed` if aggregation fails
    /// (insufficient shares, invalid shares, etc).
    pub fn aggregate(
        &self,
        message: &[u8],
        commitments: &[Commitment],
        shares: &[SignatureShare],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut commitment_map = BTreeMap::new();
        for c in commitments {
            let id = frost_ed::Identifier::deserialize(c.signer_id()).map_err(|e| {
                FrostError::Deserialization {
                    algorithm: "ed25519",
                    context: "identifier",
                    reason: e.to_string(),
                }
            })?;
            let sc = frost_ed::round1::SigningCommitments::deserialize(c.data()).map_err(|e| {
                FrostError::Deserialization {
                    algorithm: "ed25519",
                    context: "signing commitments",
                    reason: e.to_string(),
                }
            })?;
            if commitment_map.insert(id, sc).is_some() {
                return Err(FrostError::Signing {
                    algorithm: "ed25519",
                    reason: "duplicate participant commitment".into(),
                }
                .into());
            }
        }

        let signing_package = frost_ed::SigningPackage::new(commitment_map, message);

        let mut share_map = BTreeMap::new();
        for s in shares {
            let id = frost_ed::Identifier::deserialize(s.signer_id()).map_err(|e| {
                FrostError::Deserialization {
                    algorithm: "ed25519",
                    context: "share identifier",
                    reason: e.to_string(),
                }
            })?;
            let ss = frost_ed::round2::SignatureShare::deserialize(s.data()).map_err(|e| {
                FrostError::Deserialization {
                    algorithm: "ed25519",
                    context: "signature share",
                    reason: e.to_string(),
                }
            })?;
            if share_map.insert(id, ss).is_some() {
                return Err(FrostError::Signing {
                    algorithm: "ed25519",
                    reason: "duplicate participant share".into(),
                }
                .into());
            }
        }

        let sig = frost_ed::aggregate(&signing_package, &share_map, &self.public_key_package)
            .map_err(|e| FrostError::Signing {
                algorithm: "ed25519",
                reason: e.to_string(),
            })?;

        self.public_key_package
            .verifying_key()
            .verify(message, &sig)
            .map_err(|e| FrostError::Signing {
                algorithm: "ed25519",
                reason: e.to_string(),
            })?;
        Ok(sig.serialize().map_err(|e| FrostError::Serialization {
            algorithm: "ed25519",
            context: "aggregated signature",
            reason: e.to_string(),
        })?)
    }
}

// -- FROST Schnorr Verifiers --------------------------------------------------

pub struct P256SchnorrVerifier;

impl Verifier for P256SchnorrVerifier {
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let vk = frost_p256::VerifyingKey::deserialize(public_key).map_err(|e| {
            FrostError::InvalidKey {
                algorithm: "p256",
                reason: e.to_string(),
            }
        })?;
        let sig = frost_p256::Signature::deserialize(signature).map_err(|e| {
            FrostError::InvalidSignature {
                algorithm: "p256",
                reason: e.to_string(),
            }
        })?;
        Ok(vk.verify(message, &sig).is_ok())
    }
}

pub struct K256SchnorrVerifier;

impl Verifier for K256SchnorrVerifier {
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let vk = frost_secp256k1::VerifyingKey::deserialize(public_key).map_err(|e| {
            FrostError::InvalidKey {
                algorithm: "secp256k1",
                reason: e.to_string(),
            }
        })?;
        let sig = frost_secp256k1::Signature::deserialize(signature).map_err(|e| {
            FrostError::InvalidSignature {
                algorithm: "secp256k1",
                reason: e.to_string(),
            }
        })?;
        Ok(vk.verify(message, &sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frost_ed25519_keygen_sign_verify() {
        let (shares, pubkey_package) = frost_ed::keys::generate_with_dealer(
            3,
            2,
            frost_ed::keys::IdentifierList::Default,
            rand_core_06::OsRng,
        )
        .expect("keygen");

        let mut signers: Vec<FrostEd25519Signer> = shares
            .into_values()
            .map(|share| {
                FrostEd25519Signer::new(share.try_into().expect("validate dealer share"))
                    .expect("signer")
            })
            .collect();

        // Round 1: each signer produces nonces + commitments
        let mut round1_states = Vec::new();
        let mut all_commitments = Vec::new();
        for signer in &mut signers[..2] {
            let r1 = signer.precompute_round1().expect("round1");
            all_commitments.push(Commitment::new(
                signer.identifier(),
                r1.commitments().to_vec(),
            ));
            round1_states.push(r1);
        }

        // Round 2: each signer produces a share
        let message = b"frost test message";
        let mut all_shares = Vec::new();
        for (signer, r1) in signers[..2].iter_mut().zip(round1_states) {
            let share = signer
                .sign_share(r1, message, &all_commitments)
                .expect("sign_share");
            all_shares.push(share);
        }

        // Coordinator aggregates
        let coordinator = FrostEd25519Coordinator::new(pubkey_package).expect("coordinator");
        let signature = coordinator
            .aggregate(message, &all_commitments, &all_shares)
            .expect("aggregate");

        // Verify with the Ed25519 verifier (FROST-Ed25519 produces standard Ed25519 signatures)
        let verifier = crate::ed25519::Ed25519Verifier;
        let valid = verifier
            .verify(coordinator.group_public_key(), message, &signature)
            .expect("verify");
        assert!(valid, "aggregated FROST signature must verify");
    }

    #[test]
    fn frost_ed25519_wrong_message_rejected() {
        let (shares, pubkey_package) = frost_ed::keys::generate_with_dealer(
            3,
            2,
            frost_ed::keys::IdentifierList::Default,
            rand_core_06::OsRng,
        )
        .expect("keygen");

        let mut signers: Vec<FrostEd25519Signer> = shares
            .into_values()
            .map(|share| {
                FrostEd25519Signer::new(share.try_into().expect("validate dealer share"))
                    .expect("signer")
            })
            .collect();

        let mut round1_states = Vec::new();
        let mut all_commitments = Vec::new();
        for signer in &mut signers[..2] {
            let r1 = signer.precompute_round1().expect("round1");
            all_commitments.push(Commitment::new(
                signer.identifier(),
                r1.commitments().to_vec(),
            ));
            round1_states.push(r1);
        }

        let mut all_shares = Vec::new();
        for (signer, r1) in signers[..2].iter_mut().zip(round1_states) {
            let share = signer
                .sign_share(r1, b"original", &all_commitments)
                .expect("sign_share");
            all_shares.push(share);
        }

        let coordinator = FrostEd25519Coordinator::new(pubkey_package).expect("coordinator");
        let signature = coordinator
            .aggregate(b"original", &all_commitments, &all_shares)
            .expect("aggregate");

        let verifier = crate::ed25519::Ed25519Verifier;
        let valid = verifier
            .verify(coordinator.group_public_key(), b"tampered", &signature)
            .expect("verify");
        assert!(!valid, "wrong message must not verify");
    }

    #[test]
    fn p256_schnorr_verifier_rejects_malformed_key() {
        let verifier = P256SchnorrVerifier;
        let result = verifier.verify(&[0u8; 10], b"msg", &[0u8; 64]);
        assert!(matches!(result, Err(CryptoError::InvalidKey { .. })));
    }

    #[test]
    fn k256_schnorr_verifier_rejects_malformed_key() {
        let verifier = K256SchnorrVerifier;
        let result = verifier.verify(&[0u8; 10], b"msg", &[0u8; 64]);
        assert!(matches!(result, Err(CryptoError::InvalidKey { .. })));
    }
}
