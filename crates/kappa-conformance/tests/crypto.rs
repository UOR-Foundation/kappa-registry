//! Crypto primitive conformance tests.

use kappa_core::crypto::anchor::{anchor_from_key_str, asserter_from_signature, NodeAnchor};
use kappa_core::crypto::ecdsa::{K256EcdsaVerifier, K256Signer, P256EcdsaVerifier, P256Signer};
use kappa_core::crypto::ed25519::{Ed25519Signer, Ed25519Verifier};
use kappa_core::crypto::{verifier_for, Signer, Verifier};

fn rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
    rand_core::UnwrapErr(getrandom::SysRng)
}

#[test]
fn ed25519_sign_verify() {
    let signer = Ed25519Signer::generate(&mut rng());
    let sig = signer.sign(b"msg").unwrap();
    let v = Ed25519Verifier;
    assert!(v.verify(signer.public_key(), b"msg", &sig).unwrap());
}

#[test]
fn ed25519_wrong_message() {
    let signer = Ed25519Signer::generate(&mut rng());
    let sig = signer.sign(b"right").unwrap();
    let v = Ed25519Verifier;
    assert!(!v.verify(signer.public_key(), b"wrong", &sig).unwrap());
}

#[test]
fn ed25519_wrong_key() {
    let s1 = Ed25519Signer::generate(&mut rng());
    let s2 = Ed25519Signer::generate(&mut rng());
    let sig = s1.sign(b"msg").unwrap();
    let v = Ed25519Verifier;
    assert!(!v.verify(s2.public_key(), b"msg", &sig).unwrap());
}

#[test]
fn ed25519_deterministic() {
    let signer = Ed25519Signer::from_bytes(&[42u8; 32]);
    let s1 = signer.sign(b"det").unwrap();
    let s2 = signer.sign(b"det").unwrap();
    assert_eq!(s1, s2);
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
fn asserter_from_valid_signature() {
    let signer = Ed25519Signer::generate(&mut rng());
    let sig = signer.sign(b"prove").unwrap();
    let asserter = asserter_from_signature("ed25519", signer.public_key(), b"prove", &sig).unwrap();
    let expected = NodeAnchor::from_key("ed25519", signer.public_key());
    assert_eq!(asserter.as_str(), expected.as_str());
}

#[test]
fn asserter_from_invalid_signature_fails() {
    let signer = Ed25519Signer::generate(&mut rng());
    let result = asserter_from_signature("ed25519", signer.public_key(), b"msg", &[0u8; 64]);
    assert!(result.is_err());
}

#[test]
fn anchor_deterministic() {
    let a1 = NodeAnchor::from_key("ed25519", &[1u8; 32]);
    let a2 = NodeAnchor::from_key("ed25519", &[1u8; 32]);
    assert_eq!(a1, a2);
}

#[test]
fn anchor_uses_kappa_format() {
    let a = NodeAnchor::from_key("ed25519", &[1u8; 32]);
    assert!(a.as_str().starts_with("sha256:"));
}

#[test]
fn anchor_from_key_str_matches() {
    let s = anchor_from_key_str("ed25519", &[1u8; 32]);
    let n = NodeAnchor::from_key("ed25519", &[1u8; 32]);
    assert_eq!(s, n.as_str());
}
