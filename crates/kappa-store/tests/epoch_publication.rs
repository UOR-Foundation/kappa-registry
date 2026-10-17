use std::sync::Arc;

use kappa_crypto::{SigningAuthority, ed25519::Ed25519Signer};
use kappa_store::epoch_authority::{Activation, EpochAuthority, sign_witness};
use kappa_store::epoch_publication::{
    EpochPublication, EpochPublicationInput, check_ledger_digests, verify_epoch_authority,
    verify_persisted_epoch,
};
use kappa_store::succession_ops::VerifiedSuccession;
use kappa_types::{
    ActivationDomain, EpochRoot, Kappa, NamespaceRef, SignedPayload, Succession, SuccessionReason,
    canonical::from_canonical, clock::ClockMs, epoch::EpochMutation,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn authority(seed: u8) -> Result<SigningAuthority, Box<dyn std::error::Error>> {
    Ok(SigningAuthority::new(Arc::new(Ed25519Signer::from_bytes(
        &[seed; 32],
    )?))?)
}

fn prepare(
    namespace: &NamespaceRef,
    predecessor: Option<&EpochRoot>,
    now: i64,
    authority: &EpochAuthority,
    signer_override: Option<&Kappa>,
) -> Result<EpochPublication, kappa_types::StoreError> {
    EpochPublication::prepare(
        EpochPublicationInput {
            namespace,
            predecessor,
            state_root: [7; 32],
            tag_count: 4,
            mutations: &Vec::<EpochMutation>::new(),
            now: ClockMs::from_raw(now),
            signer_override,
        },
        authority,
    )
}

fn rotate(
    store: &EpochAuthority,
    next: &SigningAuthority,
    effective_at_ms: i64,
) -> Result<EpochAuthority, Box<dyn std::error::Error>> {
    let old = store.current();
    let record = kappa_crypto::signed_types::sign_succession(
        Succession {
            old_anchor: old.anchor().clone(),
            new_anchor: next.anchor().clone(),
            reason: SuccessionReason::Rotation,
            effective_at_ms,
            chain_anchor: None,
            prev_identifier: None,
            old_cose_signature: SignedPayload::empty(),
            new_cose_signature: SignedPayload::empty(),
        },
        old.signer(),
        next.signer(),
    )?;
    let verified = VerifiedSuccession::verify(
        record,
        old.signer().algorithm(),
        old.signer().public_key(),
        next.signer().algorithm(),
        next.signer().public_key(),
    )?;
    let domain = ActivationDomain {
        control: [5; 16],
        incarnation: [6; 16],
    };
    let witness = sign_witness(
        &Ed25519Signer::from_bytes(&[42; 32])?,
        verified.inner(),
        store.origin().anchor(),
        domain,
        i64::MIN,
        None,
    )?;
    let activation = Activation {
        domain,
        witnesses: vec![witness],
    };
    Ok(store
        .rotate(
            next.clone(),
            verified,
            activation,
            ClockMs::from_raw(effective_at_ms),
        )?
        .0)
}

#[test]
fn publication_binds_ledger_edge_authority_and_immediate_predecessor() -> TestResult {
    let store = EpochAuthority::new(authority(12)?)?;
    let namespace = NamespaceRef::deterministic("publication");
    let first = prepare(&namespace, None, 100, &store, None)?;
    let second = prepare(&namespace, Some(first.root()), 101, &store, None)?;
    assert_eq!(second.root().epoch_number(), 2);
    assert_eq!(second.root().prev_identifier(), Some(first.root().kappa()));
    assert_eq!(second.root().ledger_root(), second.ledger().kappa());
    assert_eq!(&second.edge().source, second.root_blob().kappa());
    assert_eq!(&second.edge().target, second.ledger().kappa());
    assert_eq!(second.root().state_digest(), &[7; 32]);
    assert_eq!(second.root().tag_count(), 4);
    assert!(second.root().rotation_kappa().is_none());
    assert!(second.rotation_record().is_none());
    kappa_crypto::signed_types::verify_epoch(second.root(), store.current().signer().public_key())?;
    kappa_types::VerifiedContent::verify(second.root().kappa(), second.root_blob().content())?;
    Ok(())
}

#[test]
fn publication_rejects_cross_namespace_regression_and_unowned_signing_key() -> TestResult {
    let store = EpochAuthority::new(authority(12)?)?;
    let namespace = NamespaceRef::deterministic("publication");
    let first = prepare(&namespace, None, 100, &store, None)?;
    let other_namespace = NamespaceRef::deterministic("other");
    assert!(prepare(&other_namespace, Some(first.root()), 101, &store, None).is_err());
    assert!(prepare(&namespace, Some(first.root()), 99, &store, None).is_err());
    // A store whose signer is not the authority the caller requires
    // cannot publish under that authority.
    let attacker = EpochAuthority::new(authority(13)?)?;
    assert!(matches!(
        prepare(&namespace, None, 101, &attacker, Some(store.anchor())),
        Err(kappa_types::StoreError::Conflict(_))
    ));
    // Nor can another authority continue a history it holds no path into.
    assert!(matches!(
        prepare(&namespace, Some(first.root()), 101, &attacker, None),
        Err(kappa_types::StoreError::Rejected(_) | kappa_types::StoreError::Conflict(_))
    ));
    Ok(())
}

#[test]
fn persisted_epoch_requires_signed_authority_and_exact_ledger_correspondence() -> TestResult {
    let signer_authority = authority(12)?;
    let store = EpochAuthority::new(signer_authority.clone())?;
    let namespace = NamespaceRef::deterministic("publication");
    let publication = prepare(&namespace, None, 100, &store, None)?;
    verify_persisted_epoch(publication.root(), &store, publication.ledger().content())?;
    assert!(verify_persisted_epoch(publication.root(), &store, b"different ledger").is_err());
    let other = EpochAuthority::new(authority(13)?)?;
    assert!(
        verify_persisted_epoch(publication.root(), &other, publication.ledger().content()).is_err()
    );
    let build = |mutations_root| {
        EpochRoot::build(kappa_types::epoch_root::EpochRootInput {
            namespace: &namespace,
            epoch_number: 1,
            prev_identifier: None,
            state_digest: [7; 32],
            mutations_root,
            timestamp: ClockMs::from_raw(100),
            signer_anchor: signer_authority.anchor(),
            tag_count: 4,
            rotation_kappa: None,
            ledger_root: publication.ledger().kappa(),
        })
    };
    assert!(
        verify_persisted_epoch(&build([0; 32]), &store, publication.ledger().content()).is_err()
    );
    let contradictory =
        kappa_crypto::signed_types::sign_epoch(build([9; 32]), signer_authority.signer())?;
    assert!(
        verify_persisted_epoch(&contradictory, &store, publication.ledger().content()).is_err()
    );
    Ok(())
}

/// The split checks agree with the complete verifier: the ledger identity
/// and mutation root computed over the persisted ledger correspond, a
/// different identity or root is refused, and digest correspondence admits
/// no authority on its own.
#[test]
fn ledger_digest_correspondence_is_separate_from_authority() -> TestResult {
    let signer_authority = authority(12)?;
    let store = EpochAuthority::new(signer_authority)?;
    let namespace = NamespaceRef::deterministic("digests");
    let mutations = vec![EpochMutation {
        op: kappa_types::MutationOp::TagSet,
        kappa: Kappa::sha256(b"target"),
        timestamp_ms: 100,
        context: Some("latest".into()),
    }];
    let publication = EpochPublication::prepare(
        EpochPublicationInput {
            namespace: &namespace,
            predecessor: None,
            state_root: [7; 32],
            tag_count: 1,
            mutations: &mutations,
            now: ClockMs::from_raw(100),
            signer_override: None,
        },
        &store,
    )?;
    let root = publication.root();
    let ledger = Kappa::compute(root.ledger_root().axis(), publication.ledger().content())?;
    let tree = kappa_types::epoch_root::mutations_merkle_root(&mutations);
    check_ledger_digests(root, &ledger, &tree)?;
    verify_epoch_authority(root, &store)?;
    verify_persisted_epoch(root, &store, publication.ledger().content())?;
    assert!(matches!(
        check_ledger_digests(root, &Kappa::sha256(b"other ledger"), &tree),
        Err(kappa_types::StoreError::Rejected(_))
    ));
    assert!(matches!(
        check_ledger_digests(root, &ledger, &[0; 32]),
        Err(kappa_types::StoreError::Rejected(_))
    ));
    let other = EpochAuthority::new(authority(13)?)?;
    check_ledger_digests(root, &ledger, &tree)?;
    assert!(matches!(
        verify_epoch_authority(root, &other),
        Err(kappa_types::StoreError::Rejected(_))
    ));
    Ok(())
}

/// A namespace last published under A, idle while the store rotates
/// A -> B -> C, publishes its next epoch under C carrying the whole path;
/// replay's successor rule admits it, the history A signed stays
/// admissible, and A cannot be used to sign anything dated after its
/// retirement.
#[test]
fn idle_namespace_publishes_across_several_rotations() -> TestResult {
    let (a, b, c) = (authority(1)?, authority(2)?, authority(3)?);
    let namespace = NamespaceRef::deterministic("idle");
    let at_a = EpochAuthority::new(a.clone())?;
    let first = prepare(&namespace, None, 50, &at_a, None)?;

    let at_c = rotate(&rotate(&at_a, &b, 100)?, &c, 200)?;
    verify_persisted_epoch(first.root(), &at_c, first.ledger().content())?;

    let second = prepare(&namespace, Some(first.root()), 300, &at_c, None)?;
    assert_eq!(second.root().signer_anchor(), c.anchor());
    let record = second
        .rotation_record()
        .ok_or("transition epoch without its path")?;
    assert_eq!(second.root().rotation_kappa(), Some(record.kappa()));
    let links: Vec<Succession> = from_canonical(record.content())?;
    assert_eq!(links.len(), 2);
    assert_eq!(&links[0].old_anchor, a.anchor());
    assert_eq!(&links[1].new_anchor, c.anchor());
    assert!(
        second
            .retained_links()
            .iter()
            .any(|(link, _)| &link.target == record.kappa()),
        "the path is retained with the epoch"
    );
    verify_persisted_epoch(second.root(), &at_c, second.ledger().content())?;

    let outgoing = [
        (a.signer().algorithm(), a.signer().public_key()),
        (b.signer().algorithm(), b.signer().public_key()),
    ];
    kappa_crypto::epoch_verification::check_successor(
        first.root(),
        second.root(),
        c.signer().public_key(),
        Some(kappa_crypto::epoch_verification::SuccessionPath {
            links: &links,
            outgoing: &outgoing,
        }),
    )?;

    // The next epoch under C needs no evidence.
    let third = prepare(&namespace, Some(second.root()), 301, &at_c, None)?;
    assert!(third.root().rotation_kappa().is_none());

    // A retired key cannot author admissible history after retirement.
    let forged = kappa_crypto::signed_types::sign_epoch(
        EpochRoot::build(kappa_types::epoch_root::EpochRootInput {
            namespace: &namespace,
            epoch_number: 2,
            prev_identifier: Some(first.root().kappa()),
            state_digest: [7; 32],
            mutations_root: kappa_types::epoch_root::mutations_merkle_root(&Vec::new()),
            timestamp: ClockMs::from_raw(150),
            signer_anchor: a.anchor(),
            tag_count: 4,
            rotation_kappa: None,
            ledger_root: first.ledger().kappa(),
        }),
        a.signer(),
    )?;
    assert!(matches!(
        verify_persisted_epoch(&forged, &at_c, first.ledger().content()),
        Err(kappa_types::StoreError::Rejected(_))
    ));
    Ok(())
}
