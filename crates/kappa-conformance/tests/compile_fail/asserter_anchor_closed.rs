// This file must FAIL to compile.
// AsserterAnchor's constructor is pub(crate) -- external crates
// cannot construct it directly. The only way to obtain an
// AsserterAnchor is through asserter_from_signature().

fn main() {
    // This should fail: from_verified is pub(crate)
    let _anchor = kappa_core::crypto::anchor::AsserterAnchor::from_verified(
        "ed25519",
        &[1u8; 32],
    );
}
