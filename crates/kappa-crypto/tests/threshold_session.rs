use kappa_crypto::frost::{FrostEd25519Coordinator, FrostEd25519Signer};
use kappa_crypto::{Commitment, ThresholdSigner};

fn group() -> (Vec<FrostEd25519Signer>, FrostEd25519Coordinator) {
    let (shares, public) = frost_ed25519::keys::generate_with_dealer(
        3,
        2,
        frost_ed25519::keys::IdentifierList::Default,
        rand_core_06::OsRng,
    )
    .expect("dealer generation");
    let signers = shares
        .into_values()
        .map(|share| {
            FrostEd25519Signer::new(share.try_into().expect("validated share")).expect("signer")
        })
        .collect();
    (
        signers,
        FrostEd25519Coordinator::new(public).expect("coordinator"),
    )
}

#[test]
fn nonce_state_cannot_cross_group_or_participant_boundaries() {
    let (mut original, _) = group();
    let (mut other, _) = group();
    let state = original[0].precompute_round1().expect("round one");
    assert!(other[0].sign_share(state, b"operation", &[]).is_err());
    let state = original[0].precompute_round1().expect("round one");
    assert!(original[1].sign_share(state, b"operation", &[]).is_err());
}

#[test]
fn duplicate_participants_are_rejected_before_signing_or_aggregation() {
    let (mut signers, coordinator) = group();
    let first = signers[0].precompute_round1().expect("first round one");
    let second = signers[1].precompute_round1().expect("second round one");
    let commitments = vec![
        Commitment::new(signers[0].identifier(), first.commitments().to_vec()),
        Commitment::new(signers[1].identifier(), second.commitments().to_vec()),
    ];
    let duplicate = vec![
        Commitment::new(signers[0].identifier(), first.commitments().to_vec()),
        Commitment::new(signers[0].identifier(), first.commitments().to_vec()),
    ];
    assert!(
        coordinator
            .aggregate(b"operation", &duplicate, &[])
            .is_err()
    );
    let shares = vec![
        signers[0]
            .sign_share(first, b"operation", &commitments)
            .expect("first share"),
        signers[1]
            .sign_share(second, b"operation", &commitments)
            .expect("second share"),
    ];
    let duplicated_shares = vec![
        kappa_crypto::SignatureShare::new(
            shares[0].signer_id().to_vec(),
            shares[0].data().to_vec(),
        ),
        kappa_crypto::SignatureShare::new(
            shares[0].signer_id().to_vec(),
            shares[0].data().to_vec(),
        ),
        kappa_crypto::SignatureShare::new(
            shares[1].signer_id().to_vec(),
            shares[1].data().to_vec(),
        ),
    ];
    assert!(
        coordinator
            .aggregate(b"operation", &commitments, &duplicated_shares)
            .is_err()
    );
    assert!(
        coordinator
            .aggregate(b"changed operation", &commitments, &shares)
            .is_err()
    );
    assert!(
        coordinator
            .aggregate(b"operation", &commitments, &shares)
            .is_ok()
    );
    let fresh = signers[0].precompute_round1().expect("fresh round one");
    assert!(
        signers[0]
            .sign_share(fresh, b"operation", &duplicate)
            .is_err()
    );
}
