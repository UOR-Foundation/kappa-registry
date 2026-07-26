//! FROST threshold signing library integration (P11 extension).
//!
//! Wraps frost-ed25519, frost-p256, frost-secp256k1 for:
//! - Trusted-dealer key generation (generate_shares)
//! - Social recovery via split/reconstruct
//!
//! All three algorithms that the registry supports (Ed25519, P-256, K-256)
//! are implemented. did:plc constrains rotation keys to secp256k1 and P-256
//! only, so omitting those would make threshold rotation for any
//! did:plc-compatible identity structurally impossible.
//!
//! No HTTP endpoints. FROST HTTP endpoints (recovery/split) are
//! intentionally omitted because transmitting private keys over HTTP
//! has no correct form.

use super::CryptoError;

/// A serialized share bundle for distribution to a guardian or signer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShareBundle {
    pub identifier: Vec<u8>,
    pub signing_share: Vec<u8>,
    pub verifying_share: Vec<u8>,
    pub min_signers: u16,
    pub algorithm: String,
}

/// Generate threshold key shares using trusted dealer.
///
/// Returns `(shares, group_public_key_bytes)`.
///
/// # Errors
///
/// Returns `CryptoError::UnsupportedAlgorithm` for unknown algorithms
/// or if FROST key generation fails internally.
pub fn generate_shares(
    algorithm: &str,
    min_signers: u16,
    max_signers: u16,
) -> Result<(Vec<ShareBundle>, Vec<u8>), CryptoError> {
    match algorithm {
        "ed25519" => {
            generate_typed::<frost_ed25519::Ed25519Sha512>(algorithm, min_signers, max_signers)
        }
        "p256" => generate_typed::<frost_p256::P256Sha256>(algorithm, min_signers, max_signers),
        "k256" => {
            generate_typed::<frost_secp256k1::Secp256K1Sha256>(algorithm, min_signers, max_signers)
        }
        other => Err(CryptoError::UnsupportedAlgorithm(other.to_owned())),
    }
}

fn generate_typed<C: frost_core::Ciphersuite>(
    algorithm: &str,
    min_signers: u16,
    max_signers: u16,
) -> Result<(Vec<ShareBundle>, Vec<u8>), CryptoError> {
    let mut rng = rand::rngs::OsRng;
    let (shares, pubkeys) = frost_core::keys::generate_with_dealer::<C, _>(
        max_signers,
        min_signers,
        frost_core::keys::IdentifierList::Default,
        &mut rng,
    )
    .map_err(|e| CryptoError::UnsupportedAlgorithm(format!("FROST keygen: {e}")))?;

    let group_public = pubkeys
        .verifying_key()
        .serialize()
        .map_err(|e| CryptoError::UnsupportedAlgorithm(format!("FROST serialize: {e}")))?;

    let bundles: Vec<ShareBundle> = shares
        .into_iter()
        .map(|(id, secret_share)| {
            let key_package = frost_core::keys::KeyPackage::<C>::try_from(secret_share)
                .expect("valid secret share produces valid key package");
            ShareBundle {
                identifier: id.serialize(),
                signing_share: key_package.signing_share().serialize(),
                verifying_share: key_package
                    .verifying_share()
                    .serialize()
                    .unwrap_or_default(),
                min_signers,
                algorithm: algorithm.to_owned(),
            }
        })
        .collect();

    Ok((bundles, group_public))
}

/// Split an existing private key into threshold shares for social recovery.
///
/// # Errors
///
/// Returns `CryptoError::UnsupportedAlgorithm` for unknown algorithms.
/// Returns `CryptoError::InvalidKey` if the key cannot be deserialized.
pub fn split_for_recovery(
    algorithm: &str,
    private_key: &[u8],
    min_guardians: u16,
    max_guardians: u16,
) -> Result<(Vec<ShareBundle>, Vec<u8>), CryptoError> {
    match algorithm {
        "ed25519" => split_typed::<frost_ed25519::Ed25519Sha512>(
            algorithm,
            private_key,
            min_guardians,
            max_guardians,
        ),
        "p256" => split_typed::<frost_p256::P256Sha256>(
            algorithm,
            private_key,
            min_guardians,
            max_guardians,
        ),
        "k256" => split_typed::<frost_secp256k1::Secp256K1Sha256>(
            algorithm,
            private_key,
            min_guardians,
            max_guardians,
        ),
        other => Err(CryptoError::UnsupportedAlgorithm(other.to_owned())),
    }
}

fn split_typed<C: frost_core::Ciphersuite>(
    algorithm: &str,
    private_key: &[u8],
    min_guardians: u16,
    max_guardians: u16,
) -> Result<(Vec<ShareBundle>, Vec<u8>), CryptoError> {
    let mut rng = rand::rngs::OsRng;
    let signing_key = frost_core::SigningKey::<C>::deserialize(private_key)
        .map_err(|_| CryptoError::InvalidKey)?;

    let (shares, pubkeys) = frost_core::keys::split::<C, _>(
        &signing_key,
        max_guardians,
        min_guardians,
        frost_core::keys::IdentifierList::Default,
        &mut rng,
    )
    .map_err(|e| CryptoError::UnsupportedAlgorithm(format!("FROST split: {e}")))?;

    let group_public = pubkeys
        .verifying_key()
        .serialize()
        .map_err(|e| CryptoError::UnsupportedAlgorithm(format!("FROST serialize: {e}")))?;

    let bundles: Vec<ShareBundle> = shares
        .into_iter()
        .map(|(id, secret_share)| {
            let key_package = frost_core::keys::KeyPackage::<C>::try_from(secret_share)
                .expect("valid secret share produces valid key package");
            ShareBundle {
                identifier: id.serialize(),
                signing_share: key_package.signing_share().serialize(),
                verifying_share: key_package
                    .verifying_share()
                    .serialize()
                    .unwrap_or_default(),
                min_signers: min_guardians,
                algorithm: algorithm.to_owned(),
            }
        })
        .collect();

    Ok((bundles, group_public))
}

/// Reconstruct a signing key from threshold shares.
///
/// Requires at least `min_signers` shares.
///
/// # Errors
///
/// Returns `CryptoError::InvalidKey` if shares cannot be deserialized
/// or if the threshold is not met.
pub fn reconstruct(algorithm: &str, share_bundles: &[ShareBundle]) -> Result<Vec<u8>, CryptoError> {
    match algorithm {
        "ed25519" => reconstruct_typed::<frost_ed25519::Ed25519Sha512>(share_bundles),
        "p256" => reconstruct_typed::<frost_p256::P256Sha256>(share_bundles),
        "k256" => reconstruct_typed::<frost_secp256k1::Secp256K1Sha256>(share_bundles),
        other => Err(CryptoError::UnsupportedAlgorithm(other.to_owned())),
    }
}

fn reconstruct_typed<C: frost_core::Ciphersuite>(
    share_bundles: &[ShareBundle],
) -> Result<Vec<u8>, CryptoError> {
    let key_packages: Vec<frost_core::keys::KeyPackage<C>> = share_bundles
        .iter()
        .map(|bundle| {
            let identifier = frost_core::Identifier::<C>::deserialize(&bundle.identifier)
                .map_err(|_| CryptoError::InvalidKey)?;

            let signing_share =
                frost_core::keys::SigningShare::<C>::deserialize(&bundle.signing_share)
                    .map_err(|_| CryptoError::InvalidKey)?;

            let verifying_share =
                frost_core::keys::VerifyingShare::<C>::deserialize(&bundle.verifying_share)
                    .map_err(|_| CryptoError::InvalidKey)?;

            // VerifyingKey for KeyPackage::new — reconstruct() only reads
            // identifier, signing_share, and min_signers, so the verifying_key
            // value is unused. Derive a placeholder from the signing share.
            let placeholder_vk = frost_core::VerifyingKey::<C>::from(
                &frost_core::SigningKey::<C>::deserialize(bundle.signing_share.as_slice())
                    .map_err(|_| CryptoError::InvalidKey)?,
            );

            Ok(frost_core::keys::KeyPackage::<C>::new(
                identifier,
                signing_share,
                verifying_share,
                placeholder_vk,
                bundle.min_signers,
            ))
        })
        .collect::<Result<Vec<_>, CryptoError>>()?;

    let signing_key = frost_core::keys::reconstruct::<C>(&key_packages)
        .map_err(|e| CryptoError::UnsupportedAlgorithm(format!("FROST reconstruct: {e}")))?;

    Ok(signing_key.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_2_of_3_ed25519() {
        let (shares, group_pk) = generate_shares("ed25519", 2, 3).unwrap();
        assert_eq!(shares.len(), 3);
        assert!(!group_pk.is_empty());
        for share in &shares {
            assert_eq!(share.algorithm, "ed25519");
            assert_eq!(share.min_signers, 2);
            assert!(!share.identifier.is_empty());
            assert!(!share.signing_share.is_empty());
        }
    }

    #[test]
    fn generate_2_of_3_p256() {
        let (shares, group_pk) = generate_shares("p256", 2, 3).unwrap();
        assert_eq!(shares.len(), 3);
        assert!(!group_pk.is_empty());
        for share in &shares {
            assert_eq!(share.algorithm, "p256");
        }
    }

    #[test]
    fn generate_2_of_3_k256() {
        let (shares, group_pk) = generate_shares("k256", 2, 3).unwrap();
        assert_eq!(shares.len(), 3);
        assert!(!group_pk.is_empty());
        for share in &shares {
            assert_eq!(share.algorithm, "k256");
        }
    }

    #[test]
    fn generate_unsupported_algorithm() {
        let result = generate_shares("rsa", 2, 3);
        assert!(result.is_err());
    }

    #[test]
    fn split_bad_key_length() {
        let result = split_for_recovery("ed25519", &[0u8; 16], 2, 3);
        assert!(matches!(result, Err(CryptoError::InvalidKey)));
    }

    #[test]
    fn split_bad_key_length_p256() {
        let result = split_for_recovery("p256", &[0u8; 16], 2, 3);
        assert!(matches!(result, Err(CryptoError::InvalidKey)));
    }

    #[test]
    fn split_bad_key_length_k256() {
        let result = split_for_recovery("k256", &[0u8; 16], 2, 3);
        assert!(matches!(result, Err(CryptoError::InvalidKey)));
    }
}
