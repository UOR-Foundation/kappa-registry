// This file must FAIL to compile.
//
// AsserterAnchor::from_verified is pub(crate). External crates
// cannot construct an AsserterAnchor directly. The only path is
// asserter_from_signature(), which verifies the cryptographic
// signature before returning the anchor.
//
// If this file compiles, any code can fabricate asserter anchors
// without proving possession of the signing key.

fn main() {
    let _anchor = kappa_crypto::anchor::AsserterAnchor::from_verified(
        "ed25519",
        &[0u8; 32],
    );
}
