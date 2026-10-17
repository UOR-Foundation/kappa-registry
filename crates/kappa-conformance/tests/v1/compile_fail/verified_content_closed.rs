// This file must FAIL to compile.
//
// VerifiedContent has a private _seal field. External crates cannot
// construct it via struct literal syntax. The only path to a
// VerifiedContent is compute() or verify(), both of which hash the
// content and prove the digest matches before returning the seal.
//
// If this file compiles, the VerifiedContent invariant is broken
// and unverified content can reach blob_put.

fn main() {
    // Attempt direct struct construction. This must fail because
    // the _seal field's type (Seal) is private to kappa_store and
    // cannot be named or instantiated from an external crate.
    //
    // The compiler error should be E0451 (field is private) or
    // E0063 (missing field) -- either proves the seal holds.
    let _v = kappa_store::verified::VerifiedContent {
        label: kappa_store::kappa::Kappa::compute(
            kappa_store::axis::Axis::Sha256,
            b"test",
        ).unwrap(),
        content: b"test".to_vec(),
        _seal: (),
    };
}
