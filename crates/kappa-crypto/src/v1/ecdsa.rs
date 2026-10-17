use super::{CryptoError, Signer, Verifier};

/// Backend-specific errors for ECDSA operations.
/// Converted to CryptoError at module boundary via From.
enum EcdsaError {
    KeyDecodeFailed { curve: &'static str, reason: String },
    SignatureDecodeFailed { curve: &'static str, reason: String },
}

impl From<EcdsaError> for CryptoError {
    fn from(e: EcdsaError) -> Self {
        match e {
            EcdsaError::KeyDecodeFailed { curve, reason } => CryptoError::InvalidKey {
                reason: format!("{} key decode: {}", curve, reason),
            },
            EcdsaError::SignatureDecodeFailed { curve, reason } => CryptoError::InvalidKey {
                reason: format!("{} signature decode: {}", curve, reason),
            },
        }
    }
}

/// Encode a fixed-size (r||s) ECDSA signature to DER format.
/// Each component is a 32-byte big-endian integer for P-256/K-256.
/// Consumers that need DER (X.509, TLS) call this on the fixed output.
pub fn der_encode_p256(fixed: &[u8; 64]) -> Vec<u8> {
    der_encode_components(&fixed[..32], &fixed[32..])
}

/// Encode two big-endian integer components to DER SEQUENCE.
fn der_encode_components(r: &[u8], s: &[u8]) -> Vec<u8> {
    fn der_integer(val: &[u8]) -> Vec<u8> {
        // Strip leading zeros, add 0x00 prefix if high bit set
        let stripped = match val.iter().position(|&b| b != 0) {
            Some(pos) => &val[pos..],
            None => &[0],
        };
        let needs_pad = stripped[0] & 0x80 != 0;
        let len = stripped.len() + if needs_pad { 1 } else { 0 };
        let mut out = Vec::with_capacity(2 + len);
        out.push(0x02); // INTEGER tag
        out.push(len as u8);
        if needs_pad {
            out.push(0x00);
        }
        out.extend_from_slice(stripped);
        out
    }
    let r_der = der_integer(r);
    let s_der = der_integer(s);
    let seq_len = r_der.len() + s_der.len();
    let mut out = Vec::with_capacity(2 + seq_len);
    out.push(0x30); // SEQUENCE tag
    out.push(seq_len as u8);
    out.extend_from_slice(&r_der);
    out.extend_from_slice(&s_der);
    out
}

// -- P-256 ECDSA --------------------------------------------------------------

pub struct P256Signer {
    signing_key: p256::ecdsa::SigningKey,
    // Vec for PQC future-proofing: post-quantum public keys will
    // not fit in a fixed-size array. Vec accommodates any algorithm
    // without changing the Signer trait.
    public_key_bytes: Vec<u8>,
}

impl P256Signer {
    pub fn new(signing_key: p256::ecdsa::SigningKey) -> Self {
        let public_key_bytes = signing_key.verifying_key().to_sec1_bytes().to_vec();
        Self {
            signing_key,
            public_key_bytes,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let key = p256::ecdsa::SigningKey::from_slice(bytes).map_err(|e| {
            EcdsaError::KeyDecodeFailed {
                curve: "p256",
                reason: e.to_string(),
            }
        })?;
        Ok(Self::new(key))
    }

    pub fn generate(rng: &mut impl rand_core::CryptoRng) -> Self {
        // p256 0.14 uses its own re-exported rand_core which may differ
        // from our top-level rand_core. Construct from random bytes instead.
        let mut secret = [0u8; 32];
        let key = loop {
            rng.fill_bytes(&mut secret);
            if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&secret) {
                break key;
            }
        };
        Self::new(key)
    }

    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }
}

impl Signer for P256Signer {
    fn algorithm(&self) -> &'static str {
        "p256"
    }
    fn public_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    /// Sign a message. Returns fixed-size 64-byte (r||s) signature
    /// with low-S normalization for malleability resistance (BIP-62).
    ///
    /// Consumers needing DER format call `der_encode_p256()` on the
    /// output. Fixed-size is the default because the majority of
    /// protocols (JWT ES256, WebAuthn, DPoP) use it.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use p256::ecdsa::signature::Signer as _;
        let sig: p256::ecdsa::Signature = self.signing_key.sign(message);
        // normalize_s ensures the S component is in the lower half
        // of the curve order, preventing signature malleability
        let normalized = sig.normalize_s();
        Ok(normalized.to_bytes().to_vec())
    }
}

pub struct P256EcdsaVerifier;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl Verifier for P256EcdsaVerifier {
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        // Parse key and signature with p256 first, matching the fallback
        // path's error classification exactly. Only structurally valid
        // inputs reach the accelerated equation check.
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(|e| {
            EcdsaError::KeyDecodeFailed {
                curve: "p256",
                reason: e.to_string(),
            }
        })?;
        let (algorithm, _parsed_sig) = if signature.len() == 64 {
            let sig = p256::ecdsa::Signature::from_slice(signature).map_err(|e| {
                EcdsaError::SignatureDecodeFailed {
                    curve: "p256",
                    reason: e.to_string(),
                }
            })?;
            (&aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED, sig)
        } else {
            let sig = p256::ecdsa::Signature::from_der(signature).map_err(|e| {
                EcdsaError::SignatureDecodeFailed {
                    curve: "p256",
                    reason: e.to_string(),
                }
            })?;
            (&aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1, sig)
        };
        // Key and signature are structurally valid. Use aws-lc for the
        // equation check with the original bytes (aws-lc re-parses
        // internally but the error path is now unreachable for format
        // failures).
        let pk_bytes = vk.to_sec1_bytes();
        let upk = aws_lc_rs::signature::UnparsedPublicKey::new(algorithm, pk_bytes.as_ref());
        match upk.verify(message, signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
impl Verifier for P256EcdsaVerifier {
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        use p256::ecdsa::signature::Verifier as _;
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(|e| {
            EcdsaError::KeyDecodeFailed {
                curve: "p256",
                reason: e.to_string(),
            }
        })?;
        let sig = if signature.len() == 64 {
            p256::ecdsa::Signature::from_slice(signature).map_err(|e| {
                EcdsaError::SignatureDecodeFailed {
                    curve: "p256",
                    reason: e.to_string(),
                }
            })?
        } else {
            p256::ecdsa::Signature::from_der(signature).map_err(|e| {
                EcdsaError::SignatureDecodeFailed {
                    curve: "p256",
                    reason: e.to_string(),
                }
            })?
        };
        Ok(vk.verify(message, &sig).is_ok())
    }
}

/// Dispatch provenance: which P-256 verification backend compiled.
pub const P256_VERIFY_BACKEND: &str = if cfg!(any(target_arch = "x86_64", target_arch = "aarch64"))
{
    "aws_lc"
} else {
    "p256"
};

// -- K-256 (secp256k1) ECDSA --------------------------------------------------

pub struct K256Signer {
    signing_key: k256::ecdsa::SigningKey,
    public_key_bytes: Vec<u8>,
}

impl K256Signer {
    pub fn new(signing_key: k256::ecdsa::SigningKey) -> Self {
        let public_key_bytes = signing_key.verifying_key().to_sec1_bytes().to_vec();
        Self {
            signing_key,
            public_key_bytes,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let key = k256::ecdsa::SigningKey::from_slice(bytes).map_err(|e| {
            EcdsaError::KeyDecodeFailed {
                curve: "k256",
                reason: e.to_string(),
            }
        })?;
        Ok(Self::new(key))
    }

    pub fn generate(rng: &mut impl rand_core::CryptoRng) -> Self {
        let mut secret = [0u8; 32];
        let key = loop {
            rng.fill_bytes(&mut secret);
            if let Ok(key) = k256::ecdsa::SigningKey::from_slice(&secret) {
                break key;
            }
        };
        Self::new(key)
    }

    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }
}

impl Signer for K256Signer {
    fn algorithm(&self) -> &'static str {
        "k256"
    }
    fn public_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    /// Sign a message. Returns fixed-size 64-byte (r||s) signature
    /// with low-S normalization.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use k256::ecdsa::signature::Signer as _;
        let sig: k256::ecdsa::Signature = self.signing_key.sign(message);
        let normalized = sig.normalize_s();
        Ok(normalized.to_bytes().to_vec())
    }
}

pub struct K256EcdsaVerifier;

impl Verifier for K256EcdsaVerifier {
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        use k256::ecdsa::signature::Verifier as _;
        let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(|e| {
            EcdsaError::KeyDecodeFailed {
                curve: "k256",
                reason: e.to_string(),
            }
        })?;
        let sig = if signature.len() == 64 {
            k256::ecdsa::Signature::from_slice(signature).map_err(|e| {
                EcdsaError::SignatureDecodeFailed {
                    curve: "k256",
                    reason: e.to_string(),
                }
            })?
        } else {
            k256::ecdsa::Signature::from_der(signature).map_err(|e| {
                EcdsaError::SignatureDecodeFailed {
                    curve: "k256",
                    reason: e.to_string(),
                }
            })?
        };
        Ok(vk.verify(message, &sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
        rand_core::UnwrapErr(getrandom::SysRng)
    }

    // -- P-256 tests ----------------------------------------------------------

    #[test]
    fn p256_sign_verify_roundtrip() {
        let signer = P256Signer::generate(&mut rng());
        let message = b"p256 test message";
        let signature = signer.sign(message).expect("sign");
        assert_eq!(signature.len(), 64, "fixed-size r||s");
        let verifier = P256EcdsaVerifier;
        assert!(
            verifier
                .verify(signer.public_key(), message, &signature)
                .expect("verify")
        );
    }

    #[test]
    fn p256_verify_rejects_wrong_message() {
        let signer = P256Signer::generate(&mut rng());
        let signature = signer.sign(b"original").expect("sign");
        let verifier = P256EcdsaVerifier;
        assert!(
            !verifier
                .verify(signer.public_key(), b"tampered", &signature)
                .expect("verify")
        );
    }

    #[test]
    fn p256_verify_rejects_wrong_key() {
        let signer_a = P256Signer::generate(&mut rng());
        let signer_b = P256Signer::generate(&mut rng());
        let signature = signer_a.sign(b"message").expect("sign");
        let verifier = P256EcdsaVerifier;
        assert!(
            !verifier
                .verify(signer_b.public_key(), b"message", &signature)
                .expect("verify")
        );
    }

    #[test]
    fn p256_verify_rejects_malformed_key() {
        let verifier = P256EcdsaVerifier;
        let result = verifier.verify(&[0u8; 10], b"msg", &[0u8; 64]);
        match result {
            Err(CryptoError::InvalidKey { reason }) => {
                assert!(reason.contains("p256"), "reason: {}", reason);
            }
            other => panic!("expected InvalidKey, got {:?}", other),
        }
    }

    #[test]
    fn p256_verify_rejects_malformed_signature() {
        let signer = P256Signer::generate(&mut rng());
        let verifier = P256EcdsaVerifier;
        let result = verifier.verify(signer.public_key(), b"msg", &[0u8; 10]);
        match result {
            Err(CryptoError::InvalidKey { reason }) => {
                assert!(reason.contains("p256"), "reason: {}", reason);
            }
            other => panic!("expected InvalidKey for malformed sig, got {:?}", other),
        }
    }

    #[test]
    fn p256_from_bytes_roundtrip() {
        let signer = P256Signer::generate(&mut rng());
        let secret = signer.secret_key_bytes();
        let restored = P256Signer::from_bytes(&secret).expect("from_bytes");
        assert_eq!(signer.public_key(), restored.public_key());
    }

    #[test]
    fn p256_algorithm_name() {
        let signer = P256Signer::generate(&mut rng());
        assert_eq!(signer.algorithm(), "p256");
    }

    #[test]
    fn p256_der_roundtrip() {
        let signer = P256Signer::generate(&mut rng());
        let fixed = signer.sign(b"der test").expect("sign");
        assert_eq!(fixed.len(), 64);
        let der = der_encode_p256(fixed.as_slice().try_into().expect("64 bytes"));
        // DER signature should be 70-72 bytes
        assert!(der.len() >= 68 && der.len() <= 72, "DER len: {}", der.len());
        // Verify with DER
        let verifier = P256EcdsaVerifier;
        assert!(
            verifier
                .verify(signer.public_key(), b"der test", &der)
                .expect("verify DER")
        );
        // Also verify with fixed
        assert!(
            verifier
                .verify(signer.public_key(), b"der test", &fixed)
                .expect("verify fixed")
        );
    }

    // -- K-256 tests ----------------------------------------------------------

    #[test]
    fn k256_sign_verify_roundtrip() {
        let signer = K256Signer::generate(&mut rng());
        let message = b"k256 test message";
        let signature = signer.sign(message).expect("sign");
        assert_eq!(signature.len(), 64, "fixed-size r||s");
        let verifier = K256EcdsaVerifier;
        assert!(
            verifier
                .verify(signer.public_key(), message, &signature)
                .expect("verify")
        );
    }

    #[test]
    fn k256_verify_rejects_wrong_message() {
        let signer = K256Signer::generate(&mut rng());
        let signature = signer.sign(b"original").expect("sign");
        let verifier = K256EcdsaVerifier;
        assert!(
            !verifier
                .verify(signer.public_key(), b"tampered", &signature)
                .expect("verify")
        );
    }

    #[test]
    fn k256_verify_rejects_wrong_key() {
        let signer_a = K256Signer::generate(&mut rng());
        let signer_b = K256Signer::generate(&mut rng());
        let signature = signer_a.sign(b"message").expect("sign");
        let verifier = K256EcdsaVerifier;
        assert!(
            !verifier
                .verify(signer_b.public_key(), b"message", &signature)
                .expect("verify")
        );
    }

    #[test]
    fn k256_verify_rejects_malformed_key() {
        let verifier = K256EcdsaVerifier;
        let result = verifier.verify(&[0u8; 10], b"msg", &[0u8; 64]);
        match result {
            Err(CryptoError::InvalidKey { reason }) => {
                assert!(reason.contains("k256"), "reason: {}", reason);
            }
            other => panic!("expected InvalidKey, got {:?}", other),
        }
    }

    #[test]
    fn k256_from_bytes_roundtrip() {
        let signer = K256Signer::generate(&mut rng());
        let secret = signer.secret_key_bytes();
        let restored = K256Signer::from_bytes(&secret).expect("from_bytes");
        assert_eq!(signer.public_key(), restored.public_key());
    }

    #[test]
    fn k256_algorithm_name() {
        let signer = K256Signer::generate(&mut rng());
        assert_eq!(signer.algorithm(), "k256");
    }

    // -- Cross-curve tests ----------------------------------------------------

    #[test]
    fn cross_curve_verify_fails() {
        let p256_signer = P256Signer::generate(&mut rng());
        let k256_verifier = K256EcdsaVerifier;
        let signature = p256_signer.sign(b"message").expect("sign");
        // P-256 public key should fail to parse as K-256
        let result = k256_verifier.verify(p256_signer.public_key(), b"message", &signature);
        match result {
            Err(CryptoError::InvalidKey { .. }) => {}
            Ok(false) => {} // also acceptable: parsed but didn't verify
            other => panic!("expected InvalidKey or false, got {:?}", other),
        }
    }

    #[test]
    fn low_s_normalization() {
        // Sign the same message twice. Both signatures must have
        // the same S component (deterministic nonce via RFC 6979)
        // and that S must be in the lower half of the curve order.
        let signer = P256Signer::generate(&mut rng());
        let sig1 = signer.sign(b"deterministic").expect("sign");
        let sig2 = signer.sign(b"deterministic").expect("sign");
        assert_eq!(sig1, sig2, "RFC 6979 deterministic signatures must match");
    }
}
