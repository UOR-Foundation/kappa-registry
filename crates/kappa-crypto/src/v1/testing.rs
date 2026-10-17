//! Fixture authorities, fixture key stores, and adversarial signers for
//! tests that exercise signature verification.
//!
//! The typed signing boundaries refuse to sign for an anchor the signer
//! does not own, so an honest `Signer` cannot produce a forged record. The
//! forgeries here pass every structural check a verifier makes (protected
//! algorithm, media type, key identifier, attached payload) and differ
//! only in the signature itself, which is the property verification must
//! reject.

use std::path::Path;

use kappa_fixture::{FixtureRoot, SetupError};

use crate::keystore::KeyStore;
use crate::{CryptoError, Signer, SigningAuthority};

/// Open, or reopen, the key store at `relative` inside `root`. The store
/// retains the scope, so a store that escapes its test (into a detached
/// worker or an `Arc`) keeps the directory alive, and closing the scope is
/// refused while the store lives. Reopening the same `relative` path in the
/// same scope observes what an earlier store left durable.
pub fn key_store_in(root: &FixtureRoot, relative: &Path) -> Result<KeyStore, SetupError> {
    Ok(KeyStore::new(root.resolve(relative)?)?.retaining(root.owner()))
}

/// A key store in a fresh scope of its own, which it retains.
pub fn key_store() -> Result<KeyStore, SetupError> {
    key_store_in(&FixtureRoot::temporary()?, Path::new("keys"))
}

/// Deterministic Ed25519 test authority from a seed byte.
///
/// Returns a `SigningAuthority` with a coherent signer and derived
/// anchor. This is the single test fixture construction site for
/// store and handler tests that need signing capability.
pub fn fixture_authority(seed: u8) -> Result<SigningAuthority, CryptoError> {
    let signer = crate::ed25519::Ed25519Signer::from_bytes(&[seed; 32])?;
    SigningAuthority::new(std::sync::Arc::new(signer))
}

/// Deterministic Ed25519 test authority from a full 32-byte seed.
pub fn fixture_authority_from_seed(seed: &[u8; 32]) -> Result<SigningAuthority, CryptoError> {
    let signer = crate::ed25519::Ed25519Signer::from_bytes(seed)?;
    SigningAuthority::new(std::sync::Arc::new(signer))
}

/// Deterministic Ed25519 test signer from a seed byte.
///
/// Returns the concrete `Ed25519Signer` so tests exercise the actual
/// implementation including backend-specific behavior. Callers that
/// need `Arc<dyn Signer>` for store config wrap it themselves.
///
/// The seed is expanded to `[seed; 32]`.
pub fn fixture_signer(seed: u8) -> Result<crate::ed25519::Ed25519Signer, CryptoError> {
    crate::ed25519::Ed25519Signer::from_bytes(&[seed; 32])
}

/// Deterministic Ed25519 test signer from a full 32-byte seed.
pub fn fixture_signer_from_seed(
    seed: &[u8; 32],
) -> Result<crate::ed25519::Ed25519Signer, CryptoError> {
    crate::ed25519::Ed25519Signer::from_bytes(seed)
}

/// Presents `claimed`'s algorithm and public key and signs with `actual`.
///
/// An envelope produced through `Impostor` names the claimed anchor and
/// carries the genuine payload; only signature verification against the
/// claimed key can reject it.
pub struct Impostor<C, A> {
    pub claimed: C,
    pub actual: A,
}

impl<C: Signer, A: Signer> Signer for Impostor<C, A> {
    fn algorithm(&self) -> &'static str {
        self.claimed.algorithm()
    }

    fn public_key(&self) -> &[u8] {
        self.claimed.public_key()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.actual.sign(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose;
    use crate::ed25519::Ed25519Signer;
    use kappa_types::Kappa;
    use kappa_types::signed::content_types;

    #[test]
    fn impostor_envelope_fails_only_on_the_signature() -> Result<(), CryptoError> {
        let claimed = Ed25519Signer::from_bytes(&[1; 32])?;
        let anchor = Kappa::from_key(claimed.algorithm(), claimed.public_key())?;
        let public_key = claimed.public_key().to_vec();
        let impostor = Impostor {
            claimed,
            actual: Ed25519Signer::from_bytes(&[2; 32])?,
        };
        let forged = cose::sign(&impostor, &anchor, content_types::WATERMARK, b"payload")?;
        let result = cose::verify(
            &forged,
            &anchor,
            &public_key,
            content_types::WATERMARK,
            b"payload",
        );
        assert!(
            matches!(result, Err(CryptoError::InvalidSignature)),
            "expected a signature failure, got {result:?}"
        );
        Ok(())
    }
}
