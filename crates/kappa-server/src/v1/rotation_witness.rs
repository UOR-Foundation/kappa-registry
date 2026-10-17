//! Rotation witnesses: the countersignatures an authority rotation needs
//! before it activates (`kappa_store::epoch_authority`).
//!
//! A witness proves a signer other than the outgoing and the incoming
//! authority countersigned the exact succession record; the store refuses
//! a witness by either rotating key, so a source misconfigured with a node
//! key fails closed. [`KeyWitness`] signs with a witness key the operator
//! provisions (`KAPPA_ROTATION_WITNESS_KEY_FILE`); a node without one is
//! [`Unwitnessed`], and its rotations are refused before anything commits.

use std::path::Path;
use std::sync::Arc;

use kappa_crypto::Signer;
use kappa_crypto::ed25519::Ed25519Signer;
use kappa_store::{ActivationDomain, Kappa, StoreError, Succession, WitnessEvidence, sign_witness};

/// A source of rotation witness countersignatures.
pub trait RotationWitnesses: Send + Sync {
    /// Countersign `succession` in the lineage from `origin`, activating in
    /// `domain`.
    fn countersign(
        &self,
        succession: &Succession,
        origin: &Kappa,
        domain: ActivationDomain,
    ) -> Result<Vec<WitnessEvidence>, StoreError>;
}

/// No witness is configured: every rotation is refused.
pub struct Unwitnessed;

impl RotationWitnesses for Unwitnessed {
    fn countersign(
        &self,
        _: &Succession,
        _: &Kappa,
        _: ActivationDomain,
    ) -> Result<Vec<WitnessEvidence>, StoreError> {
        Err(StoreError::Rejected(
            "no rotation witness is configured".into(),
        ))
    }
}

/// A witness signing with one provisioned key, valid from the succession's
/// effective time.
pub struct KeyWitness {
    signer: Arc<dyn Signer>,
}

impl KeyWitness {
    pub fn new(signer: Arc<dyn Signer>) -> Self {
        Self { signer }
    }

    /// The Ed25519 witness key in `path`: its 32-byte seed, raw or as 64
    /// hexadecimal characters.
    pub fn load(path: &Path) -> Result<Self, StoreError> {
        let contents = std::fs::read(path)?;
        let seed: [u8; 32] = match contents.len() {
            32 => contents.as_slice().try_into().map_err(|_| invalid(path))?,
            _ => {
                let text = std::str::from_utf8(&contents)
                    .map_err(|_| invalid(path))?
                    .trim();
                hex::decode(text)
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(|| invalid(path))?
            }
        };
        let signer = Ed25519Signer::from_bytes(&seed).map_err(|error| {
            StoreError::Rejected(format!("rotation witness key {}: {error}", path.display()))
        })?;
        Ok(Self::new(Arc::new(signer)))
    }
}

fn invalid(path: &Path) -> StoreError {
    StoreError::Rejected(format!(
        "rotation witness key {} is neither a 32-byte seed nor its hex",
        path.display()
    ))
}

impl RotationWitnesses for KeyWitness {
    fn countersign(
        &self,
        succession: &Succession,
        origin: &Kappa,
        domain: ActivationDomain,
    ) -> Result<Vec<WitnessEvidence>, StoreError> {
        Ok(vec![sign_witness(
            self.signer.as_ref(),
            succession,
            origin,
            domain,
            succession.effective_at_ms,
            None,
        )?])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_witness_key_loads_raw_or_hex_and_nothing_else() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let raw = dir.path().join("raw");
        std::fs::write(&raw, [5u8; 32])?;
        KeyWitness::load(&raw)?;
        let hexed = dir.path().join("hex");
        std::fs::write(&hexed, format!("{}\n", hex::encode([5u8; 32])))?;
        KeyWitness::load(&hexed)?;
        let short = dir.path().join("short");
        std::fs::write(&short, [5u8; 31])?;
        assert!(KeyWitness::load(&short).is_err());
        let garbage = dir.path().join("garbage");
        std::fs::write(&garbage, "not a key")?;
        assert!(KeyWitness::load(&garbage).is_err());
        Ok(())
    }
}
