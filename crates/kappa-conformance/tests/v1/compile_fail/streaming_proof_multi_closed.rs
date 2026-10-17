// This file must FAIL to compile.
//
// StreamingVerificationProof::multi is pub(crate). External crates
// cannot call it. Proofs are produced only by streaming hash
// computations inside kappa_store that have actually processed bytes.

fn main() {
    let _proof = kappa_store::verified::StreamingVerificationProof::multi(
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        vec![],
    );
}
