use super::CryptoError;

/// Output of a VRF evaluation: a pseudorandom output and a proof
/// that the output was correctly derived from the input and the
/// secret key.
pub struct VrfOutput {
    output: Vec<u8>,
    proof: Vec<u8>,
}

impl VrfOutput {
    pub fn new(output: Vec<u8>, proof: Vec<u8>) -> Self {
        Self { output, proof }
    }

    pub fn output(&self) -> &[u8] {
        &self.output
    }
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.output, self.proof)
    }
}

/// Verifiable Random Function trait.
///
/// A VRF produces a pseudorandom output from an input and a secret
/// key, along with a proof that the output is correct. Anyone with
/// the public key can verify the proof without the secret key.
///
/// Used for deterministic-but-unpredictable selection (shard
/// assignment, leader election) where the selector must prove they
/// did not manipulate the outcome.
pub trait Vrf: Send + Sync {
    /// Evaluate the VRF on an input. Returns the pseudorandom output
    /// and a proof of correctness.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::SigningFailed` if the evaluation fails.
    fn evaluate(&self, input: &[u8]) -> Result<VrfOutput, CryptoError>;

    /// Verify that an output was correctly produced from an input
    /// by the holder of the given public key.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKey` if the public key is
    /// malformed.
    fn verify(
        &self,
        public_key: &[u8],
        input: &[u8],
        output: &[u8],
        proof: &[u8],
    ) -> Result<bool, CryptoError>;

    /// The VRF public key bytes.
    fn public_key(&self) -> &[u8];
}
