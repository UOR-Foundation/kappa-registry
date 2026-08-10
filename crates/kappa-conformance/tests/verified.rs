//! VerifiedContent conformance tests.

use kappa_core::kappa::{Axis, KappaLabel};
use kappa_core::verified::VerifiedContent;

#[test]
fn verified_content_closed_constructor() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/verified_content_closed.rs");
}

#[test]
fn compute_produces_correct_kappa() {
    let content = b"hello verified content";
    let vc = VerifiedContent::compute(Axis::Sha256, content.to_vec()).unwrap();
    let expected = KappaLabel::sha256(content);
    assert_eq!(vc.kappa(), expected.as_str());
}

#[test]
fn verify_accepts_correct_digest() {
    let content = b"verify me";
    let label = KappaLabel::sha256(content);
    let vc = VerifiedContent::verify(label.as_str(), content.to_vec()).unwrap();
    assert_eq!(vc.kappa(), label.as_str());
    assert_eq!(vc.content(), content);
}

#[test]
fn verify_rejects_wrong_digest() {
    let content = b"wrong content";
    let wrong_label = KappaLabel::sha256(b"different content");
    let result = VerifiedContent::verify(wrong_label.as_str(), content.to_vec());
    assert!(result.is_err());
}

#[test]
fn verify_rejects_malformed_digest() {
    let result = VerifiedContent::verify("not-a-valid-label", b"content".to_vec());
    assert!(result.is_err());
}

#[test]
fn content_and_kappa_accessors() {
    let content = b"accessor test";
    let vc = VerifiedContent::compute(Axis::Blake3, content.to_vec()).unwrap();
    assert_eq!(vc.content(), content);
    assert!(vc.kappa().starts_with("blake3:"));
    assert_eq!(vc.axis(), Axis::Blake3);
    assert_eq!(vc.label().axis(), "blake3");
}

#[test]
fn into_content_consumes() {
    let content = b"consume me";
    let vc = VerifiedContent::compute(Axis::Sha256, content.to_vec()).unwrap();
    let kappa = vc.kappa().to_string();
    let bytes = vc.into_content();
    assert_eq!(bytes, content);
    // vc is consumed -- kappa was captured before into_content
    assert!(kappa.starts_with("sha256:"));
}

#[test]
fn len_and_is_empty() {
    let vc = VerifiedContent::compute(Axis::Sha256, b"nonempty".to_vec()).unwrap();
    assert_eq!(vc.len(), 8);
    assert!(!vc.is_empty());

    let vc_empty = VerifiedContent::compute(Axis::Sha256, b"".to_vec()).unwrap();
    assert_eq!(vc_empty.len(), 0);
    assert!(vc_empty.is_empty());
}

#[test]
fn compute_sha1_with_collision_detection() {
    let content = b"sha1 collision detection test";
    let vc = VerifiedContent::compute(Axis::Sha1, content.to_vec()).unwrap();
    assert!(vc.kappa().starts_with("sha1:"));
}

#[test]
fn streaming_proof_closed_constructor() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/streaming_proof_closed.rs");
}

#[test]
fn compute_all_six_axes() {
    let content = b"all axes";
    for axis in [Axis::Sha1, Axis::Sha256, Axis::Blake3, Axis::Sha512, Axis::Sha3_256, Axis::Keccak256] {
        let vc = VerifiedContent::compute(axis, content.to_vec()).unwrap();
        assert!(vc.kappa().contains(':'));
        assert_eq!(vc.content(), content);
    }
}
