// This file must FAIL to compile.
// StreamingVerificationProof constructors are pub(crate) -- external
// crates cannot create proofs. The only way to obtain one is through
// streaming_compute_kappa() or streaming_compute_multi() inside kappa-core.

fn main() {
    // Attempt to call pub(crate) constructor -- must fail with E0624
    let _proof = kappa_core::verified::StreamingVerificationProof::single(
        "sha256:abc".to_string(),
    );
}
