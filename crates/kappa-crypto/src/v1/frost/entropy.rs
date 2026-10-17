use rand_core_06::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::CryptoError;

/// FROST 3.0.0 round1::commit consumes exactly two 32-byte fills, as
/// specified by RFC 9591 nonce generation. Acquire both before generating
/// any signing state so OS failure remains a typed, pre-publication error.
pub(super) struct NonceEntropy {
    bytes: Zeroizing<[u8; 64]>,
    offset: usize,
}

impl NonceEntropy {
    pub(super) fn acquire() -> Result<Self, CryptoError> {
        let mut bytes = Zeroizing::new([0; 64]);
        getrandom::fill(bytes.as_mut()).map_err(|error| CryptoError::KeyGeneration {
            algorithm: "frost-ed25519".into(),
            reason: error.to_string(),
        })?;
        Ok(Self { bytes, offset: 0 })
    }
}

impl CryptoRng for NonceEntropy {}

impl RngCore for NonceEntropy {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        // The exact pinned FROST implementation requests only 64 bytes.
        // Exhaustion is an upstream-contract invariant, never an OS failure.
        let end = self.offset + destination.len();
        destination.copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.fill_bytes(destination);
        Ok(())
    }
}
