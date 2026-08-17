//! Nix key and signature format parsing.
//!
//! Nix keys and signatures use the format "name:base64data" with
//! standard base64 (+/= alphabet, with padding). This module handles
//! parsing and formatting only. Cryptographic operations (sign, verify)
//! are performed by kappa-core's Ed25519Signer/Ed25519Verifier in the
//! server handler layer.
//!
//! Nix/libsodium secret keys are 64 bytes: 32-byte seed concatenated
//! with 32-byte public key. kappa-core's Ed25519Signer::from_bytes
//! takes the 32-byte seed, extracted via secret_key_seed().

use base64::Engine;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignError {
    #[error("invalid key format: expected 'name:base64'")]
    InvalidKeyFormat,
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("wrong key length: expected {expected}, got {got}")]
    WrongKeyLength { expected: usize, got: usize },
}

/// Parse a Nix key string "name:base64data" into (name, raw_bytes).
pub fn parse_nix_key(key_str: &str) -> Result<(String, Vec<u8>), SignError> {
    let (name, encoded) = key_str
        .split_once(':')
        .ok_or(SignError::InvalidKeyFormat)?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    Ok((name.to_string(), bytes))
}

/// Parse a Nix public key "name:base64" into (name, [u8; 32]).
pub fn parse_public_key(key_str: &str) -> Result<(String, [u8; 32]), SignError> {
    let (name, bytes) = parse_nix_key(key_str)?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| SignError::WrongKeyLength {
            expected: 32,
            got: v.len(),
        })?;
    Ok((name, key))
}

/// Parse a Nix secret key "name:base64" into (name, [u8; 64]).
/// Nix/libsodium secret keys are 64 bytes: 32-byte seed || 32-byte public key.
pub fn parse_secret_key(key_str: &str) -> Result<(String, [u8; 64]), SignError> {
    let (name, bytes) = parse_nix_key(key_str)?;
    let key: [u8; 64] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| SignError::WrongKeyLength {
            expected: 64,
            got: v.len(),
        })?;
    Ok((name, key))
}

/// Extract the 32-byte Ed25519 seed from a 64-byte Nix secret key.
/// The seed is the first 32 bytes. Pass to Ed25519Signer::from_bytes.
pub fn secret_key_seed(secret_key: &[u8; 64]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&secret_key[..32]);
    seed
}

/// Format a signature for a narinfo Sig field.
/// Returns "keyname:base64sig" with standard base64 and = padding.
pub fn format_signature(key_name: &str, signature_bytes: &[u8]) -> String {
    format!(
        "{}:{}",
        key_name,
        base64::engine::general_purpose::STANDARD.encode(signature_bytes)
    )
}

/// Parse a narinfo Sig field "keyname:base64sig" into (name, 64 raw sig bytes).
pub fn parse_signature(sig_field: &str) -> Result<(String, [u8; 64]), SignError> {
    let (name, encoded) = sig_field
        .split_once(':')
        .ok_or(SignError::InvalidKeyFormat)?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    let sig: [u8; 64] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| SignError::WrongKeyLength {
            expected: 64,
            got: v.len(),
        })?;
    Ok((name.to_string(), sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_real_public_key() {
        let key_str = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=";
        let (name, bytes) = parse_public_key(key_str).unwrap();
        assert_eq!(name, "cache.nixos.org-1");
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn parse_key_wrong_length() {
        let key_str = format!(
            "test:{}",
            base64::engine::general_purpose::STANDARD.encode([0u8; 16])
        );
        assert!(matches!(
            parse_public_key(&key_str),
            Err(SignError::WrongKeyLength {
                expected: 32,
                got: 16
            })
        ));
    }

    #[test]
    fn parse_key_no_colon() {
        assert!(matches!(
            parse_nix_key("nocolon"),
            Err(SignError::InvalidKeyFormat)
        ));
    }

    #[test]
    fn format_signature_roundtrips() {
        let sig_bytes = [42u8; 64];
        let formatted = format_signature("test-key-1", &sig_bytes);
        let (name, parsed_bytes) = parse_signature(&formatted).unwrap();
        assert_eq!(name, "test-key-1");
        assert_eq!(parsed_bytes, sig_bytes);
    }

    #[test]
    fn secret_key_seed_extracts_first_32() {
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&[1u8; 32]);
        key[32..].copy_from_slice(&[2u8; 32]);
        let seed = secret_key_seed(&key);
        assert_eq!(seed, [1u8; 32]);
    }

    #[test]
    fn parse_signature_wrong_length() {
        let bad = format!(
            "test:{}",
            base64::engine::general_purpose::STANDARD.encode([0u8; 32])
        );
        assert!(matches!(
            parse_signature(&bad),
            Err(SignError::WrongKeyLength {
                expected: 64,
                got: 32
            })
        ));
    }

    #[test]
    fn parse_signature_no_colon() {
        assert!(matches!(
            parse_signature("nocolon"),
            Err(SignError::InvalidKeyFormat)
        ));
    }

    #[test]
    fn format_signature_standard_base64() {
        // Verify the output uses standard base64 (may contain +, /, =)
        let sig_bytes = [0xffu8; 64];
        let formatted = format_signature("key", &sig_bytes);
        let (_, encoded) = formatted.split_once(':').unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert_eq!(decoded.len(), 64);
        assert_eq!(decoded, sig_bytes);
    }

    #[test]
    fn parse_secret_key_valid_length() {
        let key_bytes = [7u8; 64];
        let key_str = format!(
            "my-cache:{}",
            base64::engine::general_purpose::STANDARD.encode(key_bytes)
        );
        let (name, parsed) = parse_secret_key(&key_str).unwrap();
        assert_eq!(name, "my-cache");
        assert_eq!(parsed, key_bytes);
    }
}
