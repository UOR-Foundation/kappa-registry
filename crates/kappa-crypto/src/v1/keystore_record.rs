//! The on-disk key record and key generation.
//!
//! One record is one immutable file:
//!
//! ```text
//! MAGIC (10) | u16 algorithm length | algorithm
//!            | u16 public key length | public key
//!            | u16 secret length | secret
//!            | BLAKE3 of everything before it (32)
//! ```
//!
//! The hash detects corruption and torn writes of the whole record; it is
//! unkeyed, so it does not authenticate a record against a writer able to
//! replace the file. What binds a record to its identity is that loading
//! reconstructs the signer from the secret and requires it to reproduce the
//! recorded algorithm and public key, and, for node records, the record name
//! derived from that public key.

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::{CryptoError, Signer};

/// Largest record accepted when loading.
pub(super) const MAX_RECORD_BYTES: u64 = 16 * 1024;
const MAGIC: &[u8; 10] = b"KAPPA-KEY\x01";
const HASH_BYTES: usize = 32;
/// Bound on rejection-sampling attempts for an elliptic-curve scalar. A
/// uniformly random 32-byte string is a valid P-256 or secp256k1 scalar with
/// probability above 1 - 2^-32, so exhausting this bound means the entropy
/// source is broken.
const SCALAR_ATTEMPTS: usize = 64;

/// A validated key record.
pub(super) struct KeyRecord {
    pub algorithm: String,
    pub public_key: Vec<u8>,
    pub secret: Zeroizing<Vec<u8>>,
}

fn damaged(name: &str, reason: &str) -> CryptoError {
    CryptoError::IntegrityFailure {
        path: format!("{name}.key"),
        reason: reason.into(),
    }
}

fn put(out: &mut Vec<u8>, field: &[u8], what: &str) -> Result<(), CryptoError> {
    let length = u16::try_from(field.len()).map_err(|_| CryptoError::InvalidKey {
        reason: format!("{what} exceeds the key record field bound"),
    })?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

fn take<'a>(input: &mut &'a [u8], name: &str) -> Result<&'a [u8], CryptoError> {
    let (length, rest) = input
        .split_first_chunk::<2>()
        .ok_or_else(|| damaged(name, "truncated record"))?;
    let length = usize::from(u16::from_be_bytes(*length));
    if rest.len() < length {
        return Err(damaged(name, "truncated record"));
    }
    let (field, rest) = rest.split_at(length);
    *input = rest;
    Ok(field)
}

impl KeyRecord {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let mut out = Zeroizing::new(Vec::with_capacity(
            MAGIC.len()
                + 6
                + self.algorithm.len()
                + self.public_key.len()
                + self.secret.len()
                + HASH_BYTES,
        ));
        out.extend_from_slice(MAGIC);
        put(&mut out, self.algorithm.as_bytes(), "algorithm")?;
        put(&mut out, &self.public_key, "public key")?;
        put(&mut out, &self.secret, "secret")?;
        let hash = blake3::hash(&out);
        out.extend_from_slice(hash.as_bytes());
        Ok(out)
    }

    /// Decode and fully validate the record stored as `name`.
    pub fn decode(bytes: &[u8], name: &str) -> Result<Self, CryptoError> {
        let body_len = bytes
            .len()
            .checked_sub(HASH_BYTES)
            .ok_or_else(|| damaged(name, "truncated record"))?;
        let (body, hash) = bytes.split_at(body_len);
        if blake3::hash(body).as_bytes().as_slice() != hash {
            return Err(damaged(name, "record hash does not match its contents"));
        }
        let mut input = body
            .strip_prefix(MAGIC.as_slice())
            .ok_or_else(|| damaged(name, "not a key record"))?;
        let algorithm = std::str::from_utf8(take(&mut input, name)?)
            .map_err(|_| damaged(name, "algorithm is not UTF-8"))?
            .to_owned();
        let public_key = take(&mut input, name)?.to_vec();
        let secret = Zeroizing::new(take(&mut input, name)?.to_vec());
        if !input.is_empty() {
            return Err(damaged(name, "trailing bytes in record"));
        }
        let record = Self {
            algorithm,
            public_key,
            secret,
        };
        record.signer(name)?;
        Ok(record)
    }

    /// Reconstruct the signer and require it to reproduce the recorded
    /// algorithm and public key.
    pub fn signer(&self, name: &str) -> Result<Arc<dyn Signer>, CryptoError> {
        let signer = signer_from(&self.algorithm, &self.secret)?;
        if signer.algorithm() != self.algorithm || signer.public_key() != self.public_key {
            return Err(damaged(
                name,
                "secret does not derive the recorded algorithm and public key",
            ));
        }
        Ok(signer)
    }
}

/// A signer reconstructed from a stored secret for `algorithm`.
fn signer_from(algorithm: &str, secret: &[u8]) -> Result<Arc<dyn Signer>, CryptoError> {
    match algorithm {
        "ed25519" => {
            let seed: &[u8; 32] = secret.try_into().map_err(|_| CryptoError::InvalidKey {
                reason: format!("ed25519 secret is {} bytes, expected 32", secret.len()),
            })?;
            Ok(Arc::new(crate::ed25519::Ed25519Signer::from_bytes(seed)?))
        }
        "p256" => Ok(Arc::new(crate::ecdsa::P256Signer::from_bytes(secret)?)),
        "k256" => Ok(Arc::new(crate::ecdsa::K256Signer::from_bytes(secret)?)),
        other => Err(CryptoError::UnsupportedAlgorithm {
            algorithm: other.to_string(),
        }),
    }
}

/// Fill `buffer` from the operating system's entropy source.
fn entropy(algorithm: &str, buffer: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buffer).map_err(|error| CryptoError::KeyGeneration {
        algorithm: algorithm.into(),
        reason: format!("entropy source: {error}"),
    })
}

/// A fresh key for `algorithm`, with its record. Entropy failures are
/// returned, never turned into panics, and every candidate secret lives in
/// a zeroizing buffer.
pub(super) fn generate(algorithm: &str) -> Result<(KeyRecord, Arc<dyn Signer>), CryptoError> {
    match algorithm {
        "ed25519" | "p256" | "k256" => {}
        other => {
            return Err(CryptoError::UnsupportedAlgorithm {
                algorithm: other.to_string(),
            });
        }
    }
    for _ in 0..SCALAR_ATTEMPTS {
        let mut secret = Zeroizing::new(vec![0u8; 32]);
        entropy(algorithm, &mut secret)?;
        // Ed25519 accepts every seed; a curve scalar out of range is
        // rejected and resampled.
        let Ok(signer) = signer_from(algorithm, &secret) else {
            continue;
        };
        let record = KeyRecord {
            algorithm: algorithm.to_owned(),
            public_key: signer.public_key().to_vec(),
            secret,
        };
        return Ok((record, signer));
    }
    Err(CryptoError::KeyGeneration {
        algorithm: algorithm.into(),
        reason: "entropy source produced no valid scalar".into(),
    })
}
