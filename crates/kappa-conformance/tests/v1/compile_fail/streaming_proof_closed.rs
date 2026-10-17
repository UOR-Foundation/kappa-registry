// This file must FAIL to compile.
//
// StreamingVerificationProof::single is pub(crate). External crates
// cannot call it. The only way to obtain a proof is through
// streaming_compute_kappa() or streaming_compute_multi() inside
// kappa_store, which perform the actual hash computation.
//
// If this file compiles, the streaming verification invariant is
// broken and upload_complete can accept fabricated proofs.

fn main() {
    // Attempt to call pub(crate) constructor. This must fail with
    // E0624 (method is private to crate).
    let _proof = kappa_store::verified::StreamingVerificationProof::single(
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    );
}
