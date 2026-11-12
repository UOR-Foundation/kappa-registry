use std::sync::Arc;

use kappa_crypto::{SigningAuthority, ed25519::Ed25519Signer};
use kappa_store::epoch_authority::{Activation, EpochAuthority, sign_witness};
use kappa_store::epoch_publication::{
    EpochCandidate, EpochPublication, EpochPublicationInput, SigningReservation,
    admit_persisted_epoch, check_ledger_digests, verify_epoch_authority, verify_persisted_epoch,
};
use kappa_store::namespace_commitment::StateInput;
use kappa_store::succession_ops::VerifiedSuccession;
use kappa_types::merkle::StreamingTree;
use kappa_types::state_index::{self, Node, NodeSource};
use kappa_types::state_key;
use kappa_types::work::{Dimension, Work, WorkLimit, WorkMeter};
use kappa_types::{
    ActivationDomain, AuthorityState, EpochRoot, Kappa, NamespaceRef, SignedPayload, Succession,
    SuccessionReason,
    canonical::{canonical_bytes, from_canonical},
    clock::ClockMs,
    epoch::EpochMutation,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn retirement_retains_transition_evidence_without_retaining_payload() -> TestResult {
    use kappa_store::transition::{PreparedTransition, RecordTransition, TransitionDomain};
    use kappa_types::content::{ContentAdmission, ContentRetirementRecord};
    let store = EpochAuthority::new(authority(12)?)?;
    let namespace = NamespaceRef::deterministic("retirement-evidence");
    let payload = Kappa::sha256(b"retirable bytes");
    let record = RecordTransition::ContentRetire(ContentRetirementRecord::new(
        ContentAdmission::new(*namespace.id(), [1; 16], payload.clone(), 15),
    ));
    let evidence = kappa_types::VerifiedContent::compute(
        kappa_types::Axis::Sha256,
        &record.canonical_bytes(),
    )?;
    let transition = PreparedTransition::bind(
        TransitionDomain::new(
            *namespace.id(),
            kappa_types::LogicalIncarnation::from_bytes([1; 16]),
        ),
        record,
        evidence,
        ClockMs::from_raw(100),
    )?;
    let mutations = vec![transition.mutation().clone()];
    let (auth, index_root, nodes) = build_state(&namespace, [1; 16], Some(store.anchor()))?;
    let history = StreamingTree::default();
    let candidate = EpochPublication::prepare(
        EpochPublicationInput {
            namespace: &namespace,
            predecessor: None,
            state_root: [0; 32],
            tag_count: 0,
            mutations: &mutations,
            now: ClockMs::from_raw(100),
            signer_override: None,
            state: StateInput {
                authority: &auth,
                index_root,
                index: &nodes,
                predecessor: None,
                history: &history,
            },
        },
        &store,
        &mut WorkMeter::unbounded(),
    )?;
    let publication = signed(candidate, &store)?;
    assert!(
        publication
            .retained_links()
            .iter()
            .any(|(edge, _)| &edge.target == transition.evidence().kappa())
    );
    assert!(
        !publication
            .retained_links()
            .iter()
            .any(|(edge, _)| edge.target == payload)
    );
    Ok(())
}

/// Sign `candidate` at its own coordinate, as a backend does once it has
/// recorded the coordinate consumed, and take its publication.
fn signed(
    mut candidate: EpochCandidate,
    authority: &EpochAuthority,
) -> Result<EpochPublication, kappa_types::StoreError> {
    let reservation =
        SigningReservation::recorded(candidate.namespace()?, candidate.epoch_number());
    candidate.sign(authority, &reservation, &mut WorkMeter::unbounded())?;
    candidate.into_publication(reservation).map_err(|_| {
        kappa_types::StoreError::Internal("a signed candidate did not complete".into())
    })
}

/// `verify_persisted_epoch` on an unbounded allowance: the admission's
/// outcome, not its work, under test.
fn persisted(
    root: &EpochRoot,
    authority: &EpochAuthority,
    ledger: &[u8],
) -> Result<(), kappa_types::StoreError> {
    verify_persisted_epoch(root, authority, ledger, &mut WorkMeter::unbounded())
}

fn authority(seed: u8) -> Result<SigningAuthority, Box<dyn std::error::Error>> {
    Ok(SigningAuthority::new(Arc::new(Ed25519Signer::from_bytes(
        &[seed; 32],
    )?))?)
}

/// An in-memory node source for the state index: holds all created nodes.
struct TestNodes(std::collections::BTreeMap<[u8; 32], Node>);

impl TestNodes {
    const fn new() -> Self {
        Self(std::collections::BTreeMap::new())
    }

    fn absorb(&mut self, update: &state_index::Update) {
        for node in &update.created {
            self.0.insert(node.hash(), *node);
        }
    }
}

impl NodeSource for TestNodes {
    fn node(&self, hash: &[u8; 32]) -> Result<Node, kappa_types::StoreError> {
        self.0
            .get(hash)
            .copied()
            .ok_or_else(|| kappa_types::StoreError::NotFound(hex::encode(hash)))
    }
}

/// Build the authority record and state index for a namespace under
/// test, returning everything `StateInput` needs.
fn build_state(
    namespace: &NamespaceRef,
    incarnation: [u8; 16],
    owner: Option<&Kappa>,
) -> Result<(AuthorityState, [u8; 32], TestNodes), Box<dyn std::error::Error>> {
    let auth = AuthorityState::new(
        *namespace.id(),
        incarnation,
        owner.cloned(),
        namespace.display_name().to_owned(),
        None,
        false,
    )?;
    let auth_bytes = canonical_bytes(&auth);
    let (path, value) = state_key::authority_entry(&auth_bytes);
    let mut nodes = TestNodes::new();
    let mut meter = WorkMeter::unbounded();
    let update = state_index::apply(
        &nodes,
        state_index::EMPTY,
        &[(path, Some(value))],
        &mut meter,
    )?;
    nodes.absorb(&update);
    Ok((auth, update.root, nodes))
}

/// Prepare a publication with a correct state commitment. The state
/// always uses a fixed incarnation and an owner derived from the
/// store's current anchor.
fn prepare(
    namespace: &NamespaceRef,
    predecessor: Option<&EpochRoot>,
    now: i64,
    store: &EpochAuthority,
    signer_override: Option<&Kappa>,
) -> Result<EpochPublication, kappa_types::StoreError> {
    let incarnation = [1; 16];
    let (auth, index_root, nodes) = build_state(namespace, incarnation, Some(store.anchor()))
        .map_err(|error| kappa_types::StoreError::Internal(error.to_string()))?;
    let history = StreamingTree::default();
    let state_input = StateInput {
        authority: &auth,
        index_root,
        index: &nodes,
        predecessor: None,
        history: &history,
    };
    let mut meter = WorkMeter::unbounded();
    let candidate = EpochPublication::prepare(
        EpochPublicationInput {
            namespace,
            predecessor,
            state_root: [7; 32],
            tag_count: 4,
            mutations: &Vec::<EpochMutation>::new(),
            now: ClockMs::from_raw(now),
            signer_override,
            state: state_input,
        },
        store,
        &mut meter,
    )?;
    signed(candidate, store)
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
    persisted(publication.root(), &store, publication.ledger().content())?;
    assert!(persisted(publication.root(), &store, b"different ledger").is_err());
    let other = EpochAuthority::new(authority(13)?)?;
    assert!(persisted(publication.root(), &other, publication.ledger().content()).is_err());
    let forged_state = Kappa::sha256(b"forged-state-for-mutation-root-mismatch");
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
            state: &forged_state,
        })
    };
    assert!(persisted(&build([0; 32]), &store, publication.ledger().content()).is_err());
    let contradictory =
        kappa_crypto::signed_types::sign_epoch(build([9; 32]), signer_authority.signer())?;
    assert!(persisted(&contradictory, &store, publication.ledger().content()).is_err());
    Ok(())
}

/// Admission charges the signature it verifies before verifying it: an
/// allowance with no signature left is refused with nothing charged, and
/// the same admission on an allowance that holds it succeeds and charges
/// exactly one signature.
#[test]
fn persisted_epoch_admission_is_refused_before_it_verifies() -> TestResult {
    let store = EpochAuthority::new(authority(12)?)?;
    let namespace = NamespaceRef::deterministic("admission-work");
    let publication = prepare(&namespace, None, 100, &store, None)?;
    let mut starved = WorkMeter::new(WorkLimit::unbounded().with(Dimension::Signatures, 0));
    let refused = admit_persisted_epoch(
        publication.root(),
        &store,
        publication.ledger(),
        &mut starved,
    );
    assert!(
        matches!(refused, Err(kappa_types::StoreError::WorkRefused(_))),
        "{refused:?}"
    );
    assert_eq!(
        starved.used(),
        &Work::default(),
        "a refusal charges nothing"
    );
    let mut allowed = WorkMeter::new(WorkLimit::unbounded().with(Dimension::Signatures, 1));
    let mutations = admit_persisted_epoch(
        publication.root(),
        &store,
        publication.ledger(),
        &mut allowed,
    )?;
    assert!(mutations.is_empty());
    assert_eq!(allowed.used().get(Dimension::Signatures), 1);
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
    let (auth, index_root, nodes) = build_state(&namespace, [1; 16], Some(store.anchor()))
        .map_err(|error| kappa_types::StoreError::Internal(error.to_string()))?;
    let history = StreamingTree::default();
    let state_input = StateInput {
        authority: &auth,
        index_root,
        index: &nodes,
        predecessor: None,
        history: &history,
    };
    let mut meter = WorkMeter::unbounded();
    let candidate = EpochPublication::prepare(
        EpochPublicationInput {
            namespace: &namespace,
            predecessor: None,
            state_root: [7; 32],
            tag_count: 1,
            mutations: &mutations,
            now: ClockMs::from_raw(100),
            signer_override: None,
            state: state_input,
        },
        &store,
        &mut meter,
    )?;
    let publication = signed(candidate, &store)?;
    let root = publication.root();
    let ledger = Kappa::compute(root.ledger_root().axis(), publication.ledger().content())?;
    let tree = kappa_types::epoch_root::mutations_merkle_root(&mutations);
    check_ledger_digests(root, &ledger, &tree)?;
    verify_epoch_authority(root, &store)?;
    persisted(root, &store, publication.ledger().content())?;
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
    persisted(first.root(), &at_c, first.ledger().content())?;

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
    persisted(second.root(), &at_c, second.ledger().content())?;

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
    let retired_key_state = Kappa::sha256(b"retired-key-forged-epoch-state");
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
            state: &retired_key_state,
        }),
        a.signer(),
    )?;
    assert!(matches!(
        persisted(&forged, &at_c, first.ledger().content()),
        Err(kappa_types::StoreError::Rejected(_))
    ));
    Ok(())
}
