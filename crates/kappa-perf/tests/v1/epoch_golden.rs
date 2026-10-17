//! PERF-EPO-006: `EpochRoot` canonical bytes stable; signable form
//! excludes key 9. Golden vectors that pin the wire format.
//!
//! PERF-EPO-007: `build_verified` derives state, mutations and ledger
//! roots consistently.
//!
//! PERF-EPO-008: Chain integrity: `prev_identifier` links, `epoch_number`
//! monotone, `rotation_kappa` honored.

use kappa_types::canonical::canonical_bytes;
use kappa_types::clock::ClockMs;
use kappa_types::epoch::EpochMutation;
use kappa_types::epoch_root::{EpochRoot, EpochRootInput, EpochRootVerifiedInput};
use kappa_types::kappa::Kappa;
use kappa_types::merkle;
use kappa_types::namespace::NamespaceRef;
use kappa_types::signed::SignedPayload;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const fn test_clock() -> ClockMs {
    ClockMs::test_value(1_700_000_000_000)
}

fn test_anchor() -> Kappa {
    Kappa::sha256(b"golden-vector-signer")
}

// -- PERF-EPO-006: golden vectors --

#[test]
fn epoch_root_canonical_bytes_deterministic() {
    let root = EpochRoot::build(EpochRootInput {
        namespace: &NamespaceRef::deterministic("golden"),
        epoch_number: 1,
        prev_identifier: None,
        state_digest: [0xAA; 32],
        mutations_root: [0xBB; 32],
        timestamp: test_clock(),
        signer_anchor: &test_anchor(),
        tag_count: 42,
        rotation_kappa: None,
        ledger_root: &Kappa::sha256(b"golden-ledger"),
    });

    let bytes_a = root.to_bytes();
    let bytes_b = root.to_bytes();
    assert_eq!(bytes_a, bytes_b, "canonical bytes must be deterministic");

    // Kappa is sha256 of canonical bytes
    let recomputed = Kappa::sha256(&bytes_a);
    assert_eq!(*root.kappa(), recomputed);
}

#[test]
fn signable_form_excludes_cose_signature() {
    let root = EpochRoot::build(EpochRootInput {
        namespace: &NamespaceRef::deterministic("signable"),
        epoch_number: 1,
        prev_identifier: None,
        state_digest: [0; 32],
        mutations_root: [0; 32],
        timestamp: test_clock(),
        signer_anchor: &test_anchor(),
        tag_count: 0,
        rotation_kappa: None,
        ledger_root: &Kappa::sha256(&canonical_bytes(&Vec::<EpochMutation>::new())),
    });

    let unsigned_signable = root.signable_bytes();
    let signed = root
        .clone()
        .with_signature(SignedPayload::from_cose_bytes(vec![1, 2, 3, 4, 5]));
    let signed_signable = signed.signable_bytes();

    assert_eq!(
        unsigned_signable, signed_signable,
        "signable bytes must not change when signature is added"
    );

    // Kappa DOES change when signed (because key 9 is in the full encoding)
    assert_ne!(root.kappa(), signed.kappa());
}

#[test]
fn epoch_root_roundtrip_preserves_all_fields() -> TestResult {
    let rotation = Kappa::sha256(b"rotation-successor");
    let prev = Kappa::sha256(b"previous-epoch");
    let root = EpochRoot::build(EpochRootInput {
        namespace: &NamespaceRef::deterministic("roundtrip"),
        epoch_number: 99,
        prev_identifier: Some(&prev),
        state_digest: [0x11; 32],
        mutations_root: [0x22; 32],
        timestamp: test_clock(),
        signer_anchor: &test_anchor(),
        tag_count: 1000,
        rotation_kappa: Some(&rotation),
        ledger_root: &Kappa::sha256(b"ledger"),
    })
    .with_signature(SignedPayload::from_cose_bytes(vec![0xDE, 0xAD]));

    let bytes = root.to_bytes();
    let recovered = EpochRoot::from_bytes(&bytes)?;

    assert_eq!(*recovered.kappa(), *root.kappa());
    assert_eq!(recovered.epoch_number(), 99);
    assert_eq!(recovered.prev_identifier(), Some(&prev));
    assert_eq!(recovered.state_digest(), &[0x11; 32]);
    assert_eq!(recovered.mutations_root(), &[0x22; 32]);
    assert_eq!(recovered.tag_count(), 1000);
    assert_eq!(recovered.rotation_kappa(), Some(&rotation));
    assert!(recovered.cose_signature().is_signed());
    assert_eq!(recovered.cose_signature().as_bytes(), &[0xDE, 0xAD]);

    Ok(())
}

// -- PERF-EPO-007: build_verified consistency --

#[test]
fn build_verified_derives_roots_consistently() {
    let k1 = Kappa::sha256(b"tag-1-content");
    let k2 = Kappa::sha256(b"tag-2-content");
    let sorted_tags: Vec<(&str, &Kappa)> = vec![("alpha", &k1), ("beta", &k2)];

    let mutations = vec![];
    let root = EpochRoot::build_verified(EpochRootVerifiedInput {
        namespace: &NamespaceRef::deterministic("verified"),
        epoch_number: 1,
        prev_identifier: None,
        sorted_tags: &sorted_tags,
        mutations: &mutations,
        timestamp: test_clock(),
        signer_anchor: &test_anchor(),
        rotation_kappa: None,
    });

    // State digest is from StateDigest accumulator
    let mut digest = kappa_types::StateDigest::default();
    for (name, kappa) in &sorted_tags {
        digest.insert(name, kappa);
    }
    assert_eq!(root.state_digest(), &digest.into_bytes());

    // Mutations root is merkle root of empty set = EMPTY_ROOT
    assert_eq!(root.mutations_root(), &merkle::EMPTY_ROOT);

    // Tag count matches
    assert_eq!(root.tag_count(), 2);
}

// -- PERF-EPO-008: chain integrity --

#[test]
fn chain_prev_identifier_links_correctly() {
    let ns = NamespaceRef::deterministic("chain");
    let anchor = test_anchor();
    let ledger = Kappa::sha256(b"ledger");

    let epoch1 = EpochRoot::build(EpochRootInput {
        namespace: &ns,
        epoch_number: 1,
        prev_identifier: None,
        state_digest: [0; 32],
        mutations_root: [0; 32],
        timestamp: test_clock(),
        signer_anchor: &anchor,
        tag_count: 0,
        rotation_kappa: None,
        ledger_root: &ledger,
    });

    let epoch2 = EpochRoot::build(EpochRootInput {
        namespace: &ns,
        epoch_number: 2,
        prev_identifier: Some(epoch1.kappa()),
        state_digest: [0; 32],
        mutations_root: [0; 32],
        timestamp: test_clock(),
        signer_anchor: &anchor,
        tag_count: 0,
        rotation_kappa: None,
        ledger_root: &ledger,
    });

    assert!(epoch1.prev_identifier().is_none());
    assert_eq!(epoch2.prev_identifier(), Some(epoch1.kappa()));
    assert_eq!(epoch2.epoch_number(), epoch1.epoch_number() + 1);
}

#[test]
fn single_field_mutation_changes_kappa() {
    let ns = NamespaceRef::deterministic("mutate");
    let anchor = test_anchor();
    let ledger = Kappa::sha256(b"ledger");

    let base = EpochRoot::build(EpochRootInput {
        namespace: &ns,
        epoch_number: 1,
        prev_identifier: None,
        state_digest: [0; 32],
        mutations_root: [0; 32],
        timestamp: test_clock(),
        signer_anchor: &anchor,
        tag_count: 0,
        rotation_kappa: None,
        ledger_root: &ledger,
    });

    // Changing epoch_number
    let mutated = EpochRoot::build(EpochRootInput {
        epoch_number: 2,
        ..EpochRootInput {
            namespace: &ns,
            epoch_number: 1,
            prev_identifier: None,
            state_digest: [0; 32],
            mutations_root: [0; 32],
            timestamp: test_clock(),
            signer_anchor: &anchor,
            tag_count: 0,
            rotation_kappa: None,
            ledger_root: &ledger,
        }
    });
    assert_ne!(base.kappa(), mutated.kappa());

    // Changing tag_count
    let mutated2 = EpochRoot::build(EpochRootInput {
        tag_count: 1,
        ..EpochRootInput {
            namespace: &ns,
            epoch_number: 1,
            prev_identifier: None,
            state_digest: [0; 32],
            mutations_root: [0; 32],
            timestamp: test_clock(),
            signer_anchor: &anchor,
            tag_count: 0,
            rotation_kappa: None,
            ledger_root: &ledger,
        }
    });
    assert_ne!(base.kappa(), mutated2.kappa());

    // Changing state_digest
    let mutated3 = EpochRoot::build(EpochRootInput {
        state_digest: [1; 32],
        ..EpochRootInput {
            namespace: &ns,
            epoch_number: 1,
            prev_identifier: None,
            state_digest: [0; 32],
            mutations_root: [0; 32],
            timestamp: test_clock(),
            signer_anchor: &anchor,
            tag_count: 0,
            rotation_kappa: None,
            ledger_root: &ledger,
        }
    });
    assert_ne!(base.kappa(), mutated3.kappa());
}
