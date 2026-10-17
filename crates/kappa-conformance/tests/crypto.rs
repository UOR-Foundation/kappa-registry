//! Crypto primitive conformance tests.

use kappa_crypto::anchor::{NodeAnchor, anchor_from_key_str, asserter_from_signature};
use kappa_crypto::ecdsa::{K256EcdsaVerifier, K256Signer, P256EcdsaVerifier, P256Signer};
use kappa_crypto::ed25519::{Ed25519Signer, Ed25519Verifier};
use kappa_crypto::{Signer, Verifier, verifier_for};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
    rand_core::UnwrapErr(getrandom::SysRng)
}

#[test]
fn ed25519_sign_verify() -> TestResult {
    let signer = Ed25519Signer::generate(&mut rng())?;
    let sig = signer.sign(b"msg")?;
    let v = Ed25519Verifier;
    assert!(v.verify(signer.public_key(), b"msg", &sig)?);
    Ok(())
}

#[test]
fn ed25519_wrong_message() -> TestResult {
    let signer = Ed25519Signer::generate(&mut rng())?;
    let sig = signer.sign(b"right")?;
    let v = Ed25519Verifier;
    assert!(!v.verify(signer.public_key(), b"wrong", &sig)?);
    Ok(())
}

#[test]
fn ed25519_wrong_key() -> TestResult {
    let s1 = Ed25519Signer::generate(&mut rng())?;
    let s2 = Ed25519Signer::generate(&mut rng())?;
    let sig = s1.sign(b"msg")?;
    let v = Ed25519Verifier;
    assert!(!v.verify(s2.public_key(), b"msg", &sig)?);
    Ok(())
}

#[test]
fn ed25519_deterministic() -> TestResult {
    let signer = Ed25519Signer::from_bytes(&[42u8; 32])?;
    let s1 = signer.sign(b"det")?;
    let s2 = signer.sign(b"det")?;
    assert_eq!(s1, s2);
    Ok(())
}

#[test]
fn p256_sign_verify() {
    let signer = P256Signer::generate(&mut rng());
    let sig = signer.sign(b"p256").unwrap();
    let v = P256EcdsaVerifier;
    assert!(v.verify(signer.public_key(), b"p256", &sig).unwrap());
}

#[test]
fn k256_sign_verify() {
    let signer = K256Signer::generate(&mut rng());
    let sig = signer.sign(b"k256").unwrap();
    let v = K256EcdsaVerifier;
    assert!(v.verify(signer.public_key(), b"k256", &sig).unwrap());
}

#[test]
fn verifier_dispatch() {
    assert!(verifier_for("ed25519").is_ok());
    assert!(verifier_for("frost-ed25519").is_ok());
    assert!(verifier_for("p256").is_ok());
    assert!(verifier_for("k256").is_ok());
    assert!(verifier_for("frost-p256").is_ok());
    assert!(verifier_for("frost-secp256k1").is_ok());
    assert!(verifier_for("unknown").is_err());
}

#[test]
fn asserter_from_valid_signature() -> TestResult {
    let signer = Ed25519Signer::generate(&mut rng())?;
    let sig = signer.sign(b"prove")?;
    let asserter_anchor = asserter_from_signature("ed25519", signer.public_key(), b"prove", &sig)?;
    let expected = NodeAnchor::from_key("ed25519", signer.public_key())?;
    assert_eq!(asserter_anchor.as_str(), expected.as_str());
    Ok(())
}

#[test]
fn asserter_from_invalid_signature_fails() -> TestResult {
    let signer = Ed25519Signer::generate(&mut rng())?;
    let result = asserter_from_signature("ed25519", signer.public_key(), b"msg", &[0u8; 64]);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn anchor_deterministic() -> TestResult {
    let a1 = NodeAnchor::from_key("ed25519", &[1u8; 32])?;
    let a2 = NodeAnchor::from_key("ed25519", &[1u8; 32])?;
    assert_eq!(a1, a2);
    Ok(())
}

#[test]
fn anchor_uses_kappa_format() -> TestResult {
    let a = NodeAnchor::from_key("ed25519", &[1u8; 32])?;
    assert!(a.as_str().starts_with("sha256:"));
    Ok(())
}

#[test]
fn anchor_from_key_str_matches() -> TestResult {
    let s = anchor_from_key_str("ed25519", &[1u8; 32])?;
    let n = NodeAnchor::from_key("ed25519", &[1u8; 32])?;
    assert_eq!(s, n.as_str());
    Ok(())
}
