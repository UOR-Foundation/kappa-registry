//! Verifiable Random Function trait (seam S13).
//!
//! Produces a deterministic output from (secret_key, input) plus
//! a proof that anyone with the public key can verify. Used for
//! quorum selection, leader election, and committee sortition.

use super::CryptoError;

/// A VRF produces (output, proof) where proof is publicly verifiable.
pub trait Vrf: Send + Sync {
    /// Evaluate the VRF: produce output and proof from input.
    fn evaluate(&self, input: &[u8]) -> Result<VrfOutput, CryptoError>;

    /// Verify a VRF output against a public key.
    fn verify(
        &self,
        public_key: &[u8],
        input: &[u8],
        output: &[u8],
        proof: &[u8],
    ) -> Result<bool, CryptoError>;

    /// The public key for this VRF instance.
    fn public_key(&self) -> &[u8];
}

/// Output of a VRF evaluation: deterministic output bytes and a proof.
pub struct VrfOutput {
    /// The pseudorandom output (32 bytes for ECVRF-EDWARDS25519-SHA512-TAI).
    pub output: Vec<u8>,
    /// The proof that output was correctly derived from (secret_key, input).
    /// Verifiable by anyone with the public key.
    pub proof: Vec<u8>,
}
