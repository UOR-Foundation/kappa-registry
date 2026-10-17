// This file must FAIL to compile.
//
// kappa_crypto::Verified<T> marks a record whose signature kappa-crypto
// has checked. Its field and its constructor are private to kappa-crypto;
// the only paths to one are the admit_* functions in signed_types.
//
// If this file compiles, any caller can label an unverified record as
// verified.

fn forge_by_literal(
    record: kappa_store::identity::Succession,
) -> kappa_crypto::Verified<kappa_store::identity::Succession> {
    kappa_crypto::Verified(record)
}

fn forge_by_constructor(
    record: kappa_store::identity::Succession,
) -> kappa_crypto::Verified<kappa_store::identity::Succession> {
    kappa_crypto::Verified::from_verified(record)
}

fn main() {}
