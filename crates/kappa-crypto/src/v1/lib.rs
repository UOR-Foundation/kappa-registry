pub mod aead;
pub mod anchor;
pub mod cose;
pub mod ecdsa;
pub mod ed25519;
pub mod epoch_verification;
pub mod framing;
pub mod frost;
/// Durable private keys. Unix only: ownership and durability are defined
/// through descriptor-relative POSIX operations and the effective user.
#[cfg(unix)]
pub mod keystore;
#[cfg(unix)]
mod keystore_dir;
#[cfg(unix)]
mod keystore_record;
pub mod kms;
pub mod ml_dsa;
pub mod node;
pub mod prf;
pub mod signed_types;
pub mod sigv4;
#[cfg(any(test, feature = "test-util"))]
pub mod testing;
pub mod time_verification;
pub mod verified;
pub mod vrf_trait;
pub use verified::Verified;

/// Errors from cryptographic operations.
///
/// This is the public error type that crosses module boundaries.
/// Backend modules (ed25519, ecdsa, frost, aead, keystore, kms, prf)
/// define their own internal error types with backend-specific context.
/// Each backend implements From<BackendError> for CryptoError so call
/// sites write ? and the conversion happens in one place. Zero
/// .map_err with hardcoded strings at call sites.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    #[error(transparent)]
    KeyFraming(#[from] kappa_types::kappa::KappaParseError),
    #[error(transparent)]
    Framing(#[from] framing::FramingError),
    #[error("unsupported algorithm: {algorithm}")]
    UnsupportedAlgorithm { algorithm: String },

    #[error("invalid key: {reason}")]
    InvalidKey { reason: String },

    #[error("invalid signature")]
    InvalidSignature,

    #[error("signing failed: {algorithm}: {reason}")]
    SigningFailed { algorithm: String, reason: String },

    #[error("verification failed: {algorithm}: {reason}")]
    VerificationFailed { algorithm: String, reason: String },

    #[error("serialization failed: {context}: {reason}")]
    Serialization { context: String, reason: String },

    #[error("deserialization failed: {context}: {reason}")]
    Deserialization { context: String, reason: String },

    #[error("key generation failed: {algorithm}: {reason}")]
    KeyGeneration { algorithm: String, reason: String },

    #[error("integrity check failed: {path}: {reason}")]
    IntegrityFailure { path: String, reason: String },

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// A node authority rotation from `last` ended with an unknown backend
    /// outcome; no authority signs until a restart selects the committed
    /// one.
    #[error(
        "node authority unresolved after a rotation from {last} with unknown outcome; restart to restore the committed authority"
    )]
    AuthorityUnresolved {
        last: Box<kappa_types::kappa::Kappa>,
    },

    /// A node authority transition panicked; whether its backend change
    /// committed is unknown, and no authority signs until a restart.
    #[error("node authority transition was interrupted; restart to restore it")]
    AuthorityInterrupted,

    /// The node's live authority differs from the backend's committed one;
    /// no authority signs until a restart selects the committed one.
    #[error(
        "node authority {live} differs from the committed authority {committed}; restart to restore the committed authority"
    )]
    AuthorityDiverged {
        live: Box<kappa_types::kappa::Kappa>,
        committed: Box<kappa_types::kappa::Kappa>,
    },

    /// A node authority change was attempted under the custody of a key
    /// store other than the one holding the live authority's key.
    #[error("node authority change attempted under another key store's custody")]
    CustodyMismatch,
}

/// Signing trait. Implementations own the private key material.
pub trait Signer: Send + Sync {
    /// The algorithm name ("ed25519", "p256", "k256").
    fn algorithm(&self) -> &'static str;

    /// The public key bytes. For Ed25519: 32 bytes. For P-256/K-256:
    /// 33 bytes (compressed SEC1 point).
    fn public_key(&self) -> &[u8];

    /// Sign a message. Returns the signature bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::SigningFailed` if the signing operation
    /// fails.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// FROST threshold signing round 1 state.
///
/// Produced by `ThresholdSigner::precompute_round1`. Consumed by
/// `ThresholdSigner::sign_share`. Move-only -- nonces are single-use.
/// Using them twice leaks the private key share.
pub struct Round1State {
    nonces: frost_ed25519::round1::SigningNonces,
    commitments: Vec<u8>,
    signer_id: Vec<u8>,
    group_public_key: Vec<u8>,
}

impl Round1State {
    pub(crate) fn new(
        nonces: frost_ed25519::round1::SigningNonces,
        commitments: Vec<u8>,
        signer_id: Vec<u8>,
        group_public_key: Vec<u8>,
    ) -> Self {
        Self {
            nonces,
            commitments,
            signer_id,
            group_public_key,
        }
    }

    pub fn commitments(&self) -> &[u8] {
        &self.commitments
    }

    pub(crate) fn consume(
        self,
        signer_id: &[u8],
        group_public_key: &[u8],
    ) -> Result<frost_ed25519::round1::SigningNonces, CryptoError> {
        if self.signer_id != signer_id || self.group_public_key != group_public_key {
            return Err(CryptoError::SigningFailed {
                algorithm: "frost-ed25519".into(),
                reason: "round one state belongs to another signing key".into(),
            });
        }
        Ok(self.nonces)
    }
}

/// A participant's commitment for FROST round 1.
pub struct Commitment {
    signer_id: Vec<u8>,
    data: Vec<u8>,
}

impl Commitment {
    pub fn new(signer_id: Vec<u8>, data: Vec<u8>) -> Self {
        Self { signer_id, data }
    }

    pub fn signer_id(&self) -> &[u8] {
        &self.signer_id
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// A participant's signature share for FROST round 2.
pub struct SignatureShare {
    signer_id: Vec<u8>,
    data: Vec<u8>,
}

impl SignatureShare {
    pub fn new(signer_id: Vec<u8>, data: Vec<u8>) -> Self {
        Self { signer_id, data }
    }

    pub fn signer_id(&self) -> &[u8] {
        &self.signer_id
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// FROST threshold signing trait.
pub trait ThresholdSigner: Send + Sync {
    fn algorithm(&self) -> &'static str;
    fn group_public_key(&self) -> &[u8];

    /// Generate round 1 nonces and commitments.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::KeyGeneration` if the RNG fails.
    fn precompute_round1(&mut self) -> Result<Round1State, CryptoError>;

    /// Produce a signature share. Consumes round1 by move to prevent
    /// nonce reuse.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::SigningFailed` if share computation fails.
    fn sign_share(
        &mut self,
        round1: Round1State,
        message: &[u8],
        commitments: &[Commitment],
    ) -> Result<SignatureShare, CryptoError>;
}

/// Signature verification trait.
pub trait Verifier: Send + Sync {
    /// Verify a signature against a public key and message.
    ///
    /// Returns `Ok(true)` if valid, `Ok(false)` if invalid.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKey` if the public key bytes
    /// are malformed for this algorithm.
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError>;
}

/// Dispatch to the appropriate verifier for an algorithm string.
///
/// # Errors
///
/// Returns `CryptoError::UnsupportedAlgorithm` if the algorithm
/// string does not map to a known verifier.
pub fn verifier_for(algorithm: &str) -> Result<Box<dyn Verifier>, CryptoError> {
    match algorithm {
        "ed25519" | "frost-ed25519" => Ok(Box::new(ed25519::Ed25519Verifier)),
        "p256" => Ok(Box::new(ecdsa::P256EcdsaVerifier)),
        "k256" => Ok(Box::new(ecdsa::K256EcdsaVerifier)),
        "ml-dsa-65" => Ok(Box::new(ml_dsa::MlDsa65Verifier)),
        "frost-p256" => Ok(Box::new(frost::P256SchnorrVerifier)),
        "frost-secp256k1" => Ok(Box::new(frost::K256SchnorrVerifier)),
        _ => Err(CryptoError::UnsupportedAlgorithm {
            algorithm: algorithm.to_string(),
        }),
    }
}

pub use anchor::{
    AsserterAnchor, NodeAnchor, SubjectAnchor, anchor_from_key_str, asserter_from_signature,
    asserter_kappa_from_signature,
};
pub use node::NodeIdentity;

/// Established signing authority: a signer and its derived anchor,
/// constructed together and kept coherent.
///
/// This is the single boundary where signer-to-anchor derivation
/// happens. Backends receive this; they do not construct signers or
/// derive anchors independently. Fields are private: a holder can
/// replace the whole unit but never one half of it, so every
/// publication signs under the anchor its signer derives.
///
/// Cloning shares the signer; the anchor is copied.
#[derive(Clone)]
pub struct SigningAuthority {
    signer: std::sync::Arc<dyn Signer>,
    anchor: kappa_types::kappa::Kappa,
}

impl SigningAuthority {
    /// Construct from an owned signer. Derives the anchor once.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::KeyFraming` if the algorithm name or
    /// public key length exceeds the framing limit.
    pub fn new(signer: std::sync::Arc<dyn Signer>) -> Result<Self, CryptoError> {
        let anchor = kappa_types::kappa::Kappa::from_key(signer.algorithm(), signer.public_key())?;
        Ok(Self { signer, anchor })
    }

    /// The derived content-address anchor.
    pub fn anchor(&self) -> &kappa_types::kappa::Kappa {
        &self.anchor
    }

    /// The signing capability.
    pub fn signer(&self) -> &dyn Signer {
        &*self.signer
    }

    /// Shared ownership of the signer for store injection.
    pub fn signer_arc(&self) -> &std::sync::Arc<dyn Signer> {
        &self.signer
    }
}
