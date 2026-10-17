// This file must FAIL to compile.
//
// VerifiedSuccession's fields are private. The only path to one is
// VerifiedSuccession::verify, which admits both COSE signatures against
// keys proven to derive the old and new anchors, and retains the old
// anchor's verified key for the watermark that accompanies the record.
//
// If this file compiles, an unsigned succession can reach the store.

fn forge(
    admitted: kappa_crypto::Verified<kappa_store::identity::Succession>,
) -> kappa_store::VerifiedSuccession {
    kappa_store::VerifiedSuccession {
        inner: admitted,
        old_public_key: Vec::new(),
    }
}

fn main() {}
