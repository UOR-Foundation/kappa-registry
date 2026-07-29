//! FROST threshold signing (RFC 9591, NCC-audited v3.0.0).
//!
//! FrostEd25519Signer implements ThresholdSigner (per-signer operations).
//! FrostEd25519Coordinator implements aggregation (coordinator operation).
//! Round1State is consumed by sign_share() -- nonces are used exactly
//! once and destroyed by move semantics.

use frost_ed25519 as frost_ed;

use super::{Commitment, CryptoError, Round1State, SignatureShare, ThresholdSigner};

// -- FROST Ed25519 Signer --------------------------------------------------

pub struct FrostEd25519Signer {
    key_package: frost_ed::keys::KeyPackage,
    group_public_key_bytes: Vec<u8>,
}

impl FrostEd25519Signer {
    pub fn new(key_package: frost_ed::keys::KeyPackage) -> Result<Self, CryptoError> {
        let group_public_key_bytes = key_package
            .verifying_key()
            .serialize()
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        Ok(Self { key_package, group_public_key_bytes })
    }

    pub fn identifier(&self) -> Vec<u8> {
        self.key_package.identifier().serialize()
    }
}

impl ThresholdSigner for FrostEd25519Signer {
    fn algorithm(&self) -> &'static str { "frost-ed25519" }

    fn group_public_key(&self) -> &[u8] { &self.group_public_key_bytes }

    fn precompute_round1(&mut self) -> Result<Round1State, CryptoError> {
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let (nonces, commitments) = frost_ed::round1::commit(
            self.key_package.signing_share(),
            &mut rng,
        );
        let nonce_bytes = nonces.serialize()
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        let commit_bytes = commitments.serialize()
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        Ok(Round1State {
            nonces: nonce_bytes,
            commitments: commit_bytes,
        })
    }

    fn sign_share(
        &mut self,
        round1: Round1State,
        message: &[u8],
        commitments: &[Commitment],
    ) -> Result<SignatureShare, CryptoError> {
        let nonces = frost_ed::round1::SigningNonces::deserialize(&round1.nonces)
            .map_err(|e| CryptoError::Deserialization(e.to_string()))?;

        let mut commitment_map = std::collections::BTreeMap::new();
        for c in commitments {
            let id = frost_ed::Identifier::deserialize(&c.signer_id)
                .map_err(|e| CryptoError::Deserialization(e.to_string()))?;
            let sc = frost_ed::round1::SigningCommitments::deserialize(&c.data)
                .map_err(|e| CryptoError::Deserialization(e.to_string()))?;
            commitment_map.insert(id, sc);
        }

        let signing_package = frost_ed::SigningPackage::new(commitment_map, message);
        let share = frost_ed::round2::sign(&signing_package, &nonces, &self.key_package)
            .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;

        Ok(SignatureShare {
            signer_id: self.identifier(),
            data: share.serialize(),
        })
    }
}

// -- FROST Ed25519 Coordinator ---------------------------------------------

pub struct FrostEd25519Coordinator {
    public_key_package: frost_ed::keys::PublicKeyPackage,
    group_public_key_bytes: Vec<u8>,
}

impl FrostEd25519Coordinator {
    pub fn new(
        public_key_package: frost_ed::keys::PublicKeyPackage,
    ) -> Result<Self, CryptoError> {
        let group_public_key_bytes = public_key_package
            .verifying_key()
            .serialize()
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        Ok(Self { public_key_package, group_public_key_bytes })
    }

    pub fn group_public_key(&self) -> &[u8] {
        &self.group_public_key_bytes
    }

    pub fn aggregate(
        &self,
        message: &[u8],
        commitments: &[Commitment],
        shares: &[SignatureShare],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut commitment_map = std::collections::BTreeMap::new();
        for c in commitments {
            let id = frost_ed::Identifier::deserialize(&c.signer_id)
                .map_err(|e| CryptoError::Deserialization(e.to_string()))?;
            let sc = frost_ed::round1::SigningCommitments::deserialize(&c.data)
                .map_err(|e| CryptoError::Deserialization(e.to_string()))?;
            commitment_map.insert(id, sc);
        }

        let signing_package = frost_ed::SigningPackage::new(commitment_map, message);

        let mut share_map = std::collections::BTreeMap::new();
        for s in shares {
            let id = frost_ed::Identifier::deserialize(&s.signer_id)
                .map_err(|e| CryptoError::Deserialization(e.to_string()))?;
            let ss = frost_ed::round2::SignatureShare::deserialize(&s.data)
                .map_err(|e| CryptoError::Deserialization(e.to_string()))?;
            share_map.insert(id, ss);
        }

        let sig = frost_ed::aggregate(
            &signing_package,
            &share_map,
            &self.public_key_package,
        )
        .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;

        sig.serialize()
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ed25519::Ed25519Verifier;
    use super::super::Verifier;

    fn keygen_2_of_3() -> (
        frost_ed::keys::PublicKeyPackage,
        Vec<frost_ed::keys::KeyPackage>,
    ) {
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let (shares, pubkey_package) = frost_ed::keys::generate_with_dealer(
            3, 2,
            frost_ed::keys::IdentifierList::Default,
            &mut rng,
        )
        .unwrap();

        let key_packages: Vec<frost_ed::keys::KeyPackage> = shares
            .into_values()
            .map(|s| frost_ed::keys::KeyPackage::try_from(s).unwrap())
            .collect();

        (pubkey_package, key_packages)
    }

    #[test]
    fn frost_ed25519_sign_verify() {
        let (pubkey_pkg, key_packages) = keygen_2_of_3();
        let message = b"frost threshold test";

        let mut signers: Vec<FrostEd25519Signer> = key_packages
            .into_iter()
            .map(|kp| FrostEd25519Signer::new(kp).unwrap())
            .collect();

        let mut round1_states = Vec::new();
        let mut all_commitments = Vec::new();

        for signer in signers.iter_mut() {
            let r1 = signer.precompute_round1().unwrap();
            all_commitments.push(Commitment {
                signer_id: signer.identifier(),
                data: r1.commitments.clone(),
            });
            round1_states.push(r1);
        }

        // 2 of 3 sign
        let mut shares = Vec::new();
        for i in 0..2 {
            let r1 = std::mem::replace(
                &mut round1_states[i],
                Round1State { nonces: vec![], commitments: vec![] },
            );
            let share = signers[i]
                .sign_share(r1, message, &all_commitments)
                .unwrap();
            shares.push(share);
        }

        // Coordinator aggregates
        let coordinator = FrostEd25519Coordinator::new(pubkey_pkg).unwrap();
        let group_sig = coordinator
            .aggregate(message, &all_commitments, &shares)
            .unwrap();

        // Verify with standard Ed25519Verifier
        let verifier = Ed25519Verifier;
        assert!(verifier
            .verify(coordinator.group_public_key(), message, &group_sig)
            .unwrap());
    }

    #[test]
    fn frost_ed25519_wrong_message_fails() {
        let (pubkey_pkg, key_packages) = keygen_2_of_3();

        let mut signers: Vec<FrostEd25519Signer> = key_packages
            .into_iter()
            .map(|kp| FrostEd25519Signer::new(kp).unwrap())
            .collect();

        let mut round1_states = Vec::new();
        let mut all_commitments = Vec::new();

        for signer in signers.iter_mut() {
            let r1 = signer.precompute_round1().unwrap();
            all_commitments.push(Commitment {
                signer_id: signer.identifier(),
                data: r1.commitments.clone(),
            });
            round1_states.push(r1);
        }

        let mut shares = Vec::new();
        for i in 0..2 {
            let r1 = std::mem::replace(
                &mut round1_states[i],
                Round1State { nonces: vec![], commitments: vec![] },
            );
            let share = signers[i]
                .sign_share(r1, b"signed message", &all_commitments)
                .unwrap();
            shares.push(share);
        }

        let coordinator = FrostEd25519Coordinator::new(pubkey_pkg).unwrap();
        let group_sig = coordinator
            .aggregate(b"signed message", &all_commitments, &shares)
            .unwrap();

        let verifier = Ed25519Verifier;
        assert!(!verifier
            .verify(coordinator.group_public_key(), b"different message", &group_sig)
            .unwrap());
    }
}
