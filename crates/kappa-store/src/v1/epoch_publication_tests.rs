use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::atomic::{AtomicU8, AtomicUsize};
use std::thread;
use std::time::{Duration, Instant};

use kappa_crypto::ed25519::Ed25519Signer;
use kappa_crypto::{CryptoError, Signer, SigningAuthority};
use kappa_types::epoch::MutationOp;
use kappa_types::merkle::StreamingTree;
use kappa_types::state_index::{self, Node, NodeSource};
use kappa_types::work::WorkLimit;
use kappa_types::{AuthorityState, state_key};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Mutations over every collision-free axis, with absent, empty and long
/// contexts and negative and positive timestamps of every integer width.
fn mutations(count: usize) -> Vec<EpochMutation> {
    let digest = |axis: Axis, seed: &[u8]| match axis {
        Axis::Sha512 => Kappa::sha512(seed),
        Axis::Blake3 => Kappa::blake3(seed),
        Axis::Sha3_256 => Kappa::sha3_256(seed),
        _ => Kappa::sha256(seed),
    };
    let axes = [Axis::Sha256, Axis::Sha512, Axis::Blake3, Axis::Sha3_256];
    (0..count)
        .map(|index| EpochMutation {
            op: MutationOp::TagSet,
            kappa: digest(axes[index % axes.len()], &index.to_be_bytes()),
            timestamp_ms: [i64::MIN, -1, 0, 23, 24, 70_000, i64::MAX][index % 7],
            context: (index % 3 != 0).then(|| "n".repeat(index % 40)),
        })
        .collect()
}

/// The ledger built element by element is the canonical encoding of the
/// whole array, and its mutation root is the one verifiers recompute,
/// across every array-header width a ledger reaches here.
#[test]
fn ledger_encoding_is_the_canonical_array_and_its_root() -> TestResult {
    for count in [0, 1, 23, 24, 255, 256, 300] {
        let mutations = mutations(count);
        let mut meter = WorkMeter::unbounded();
        let (ledger, root) = encode_ledger(&mutations, &mut meter)?;
        let canonical = canonical_bytes(&mutations.clone());
        assert_eq!(ledger.content(), canonical.as_slice(), "{count} mutations");
        assert_eq!(root, mutations_merkle_root(&mutations), "{count} mutations");
        assert_eq!(
            meter.used().get(Dimension::BytesAllocated),
            canonical.len() as u64 + count as u64 * 2 * size_of::<usize>() as u64
        );
    }
    Ok(())
}

/// A ledger whose bound does not fit is refused before any element is
/// encoded, and the refusal charges nothing.
#[test]
fn ledger_refused_at_its_bound_charges_nothing() {
    let mutations = mutations(10);
    let mut meter = WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesAllocated, 16));
    assert!(encode_ledger(&mutations, &mut meter).is_err());
    assert_eq!(meter.used().get(Dimension::BytesAllocated), 0);
    assert_eq!(meter.used().get(Dimension::BytesHashed), 0);
}

#[derive(Default)]
struct Nodes(BTreeMap<[u8; 32], Node>);

impl NodeSource for Nodes {
    fn node(&self, hash: &[u8; 32]) -> Result<Node, StoreError> {
        self.0
            .get(hash)
            .copied()
            .ok_or_else(|| StoreError::Internal("node unavailable".into()))
    }
}

struct Genesis {
    namespace: NamespaceRef,
    authority_state: AuthorityState,
    nodes: Nodes,
    index_root: [u8; 32],
    history: StreamingTree,
    mutations: Vec<EpochMutation>,
}

fn genesis(count: usize) -> Result<Genesis, Box<dyn std::error::Error>> {
    let namespace = NamespaceRef::deterministic("epoch-publication-reservation");
    let authority_state =
        AuthorityState::new(*namespace.id(), [9; 16], None, "team".into(), None, false)?;
    let mut nodes = Nodes::default();
    let change = state_key::authority_entry(&canonical_bytes(&authority_state));
    let update = state_index::apply(
        &nodes,
        state_index::EMPTY,
        &[(change.0, Some(change.1))],
        &mut WorkMeter::unbounded(),
    )?;
    for node in update.created {
        nodes.0.insert(node.hash(), node);
    }
    Ok(Genesis {
        namespace,
        authority_state,
        nodes,
        index_root: update.root,
        history: StreamingTree::new(),
        mutations: mutations(count),
    })
}

fn epoch_authority() -> Result<EpochAuthority, Box<dyn std::error::Error>> {
    Ok(EpochAuthority::new(SigningAuthority::new(Arc::new(
        Ed25519Signer::from_bytes(&[3; 32])?,
    ))?)?)
}

fn input(genesis: &Genesis) -> EpochPublicationInput<'_> {
    EpochPublicationInput {
        namespace: &genesis.namespace,
        predecessor: None,
        state_root: [0; 32],
        tag_count: 0,
        mutations: &genesis.mutations,
        now: ClockMs::from_raw(1_000),
        signer_override: None,
        state: StateInput {
            authority: &genesis.authority_state,
            index_root: genesis.index_root,
            index: &genesis.nodes,
            predecessor: None,
            history: &genesis.history,
        },
    }
}

/// The fixture key, counting its invocations and returning whatever
/// `mode` selects: a signature, a refusal, wrong signature bytes, or a
/// signature returned only after `SLOW_SIGNER` has elapsed.
struct Counted {
    inner: Ed25519Signer,
    calls: AtomicUsize,
    mode: AtomicU8,
}

const SIGNS: u8 = 0;
const REFUSES: u8 = 1;
const CORRUPTS: u8 = 2;
const WRONG_LENGTH: u8 = 3;
const SLOW: u8 = 4;

/// How long a `SLOW` signer takes: longer than `DEADLINE`, so a deadline
/// set when the signer is invoked has passed when it returns.
const SLOW_SIGNER: Duration = Duration::from_millis(400);
const DEADLINE: Duration = Duration::from_millis(200);

impl Signer for Counted {
    fn algorithm(&self) -> &'static str {
        self.inner.algorithm()
    }
    fn public_key(&self) -> &[u8] {
        self.inner.public_key()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.calls.fetch_add(1, SeqCst);
        match self.mode.load(SeqCst) {
            REFUSES => Err(CryptoError::SigningFailed {
                algorithm: "ed25519".into(),
                reason: "refused by the test signer".into(),
            }),
            CORRUPTS => Ok(vec![0; 64]),
            WRONG_LENGTH => Ok(vec![0xa5; 63]),
            SLOW => {
                thread::sleep(SLOW_SIGNER);
                self.inner.sign(message)
            }
            _ => self.inner.sign(message),
        }
    }
}

fn counted(mode: u8) -> Result<(Arc<Counted>, EpochAuthority), Box<dyn std::error::Error>> {
    let signer = Arc::new(Counted {
        inner: Ed25519Signer::from_bytes(&[3; 32])?,
        calls: AtomicUsize::new(0),
        mode: AtomicU8::new(mode),
    });
    let authority = EpochAuthority::new(SigningAuthority::new(
        Arc::clone(&signer) as Arc<dyn Signer>
    )?)?;
    Ok((signer, authority))
}

fn calls(signer: &Counted) -> usize {
    signer.calls.load(SeqCst)
}

/// A reservation of another coordinate is refused before the signer is
/// invoked and leaves the candidate prepared; the right one signs, and the
/// publication carries the reservation it consumed. What signing and its
/// generated evidence took stayed within what was admitted beforehand.
#[test]
fn signing_consumes_exactly_its_reserved_coordinate() -> TestResult {
    let genesis = genesis(40)?;
    let (signer, authority) = counted(SIGNS)?;
    let mut meter = WorkMeter::unbounded();
    let mut candidate = EpochPublication::prepare(input(&genesis), &authority, &mut meter)?;
    assert_eq!(candidate.epoch_number(), 1);
    let admitted = candidate.work.total();
    let wrong = SigningReservation::recorded(*genesis.namespace.id(), 2);
    assert!(candidate.sign(&authority, &wrong, &mut meter).is_err());
    assert_eq!(candidate.phase(), PublicationPhase::Prepared);
    assert_eq!(
        calls(&signer),
        0,
        "the signer is not invoked for another coordinate"
    );

    let before = *meter.used();
    let reservation = SigningReservation::recorded(*genesis.namespace.id(), 1);
    candidate.sign(&authority, &reservation, &mut meter)?;
    assert_eq!(calls(&signer), 1);
    let Ok(publication) = candidate.into_publication(reservation) else {
        return Err("a completely signed candidate yields its publication".into());
    };
    let consumed = |dimension| meter.used().get(dimension) - before.get(dimension);
    assert!(consumed(Dimension::BytesAllocated) <= admitted.allocated);
    assert!(consumed(Dimension::BytesHashed) <= admitted.hashed);
    assert_eq!(consumed(Dimension::Signatures), admitted.signatures);
    assert!(consumed(Dimension::BytesAllocated) > 0);
    verify_epoch(
        publication.root(),
        authority.current().signer().public_key(),
    )?;
    assert_eq!(
        publication.retained_links().len(),
        retained_targets(
            None,
            None,
            publication.committed(),
            &genesis.mutations,
            &mut WorkMeter::unbounded()
        )?
        .len()
    );
    let (root, _, reservation) = publication.into_parts();
    assert_eq!(reservation.epoch_number(), root.epoch_number());
    assert_eq!(reservation.namespace(), genesis.namespace.id());
    Ok(())
}

/// A signer that refuses leaves the candidate with its exact material and
/// the refusal; the signer is never invoked again at that coordinate, and
/// no publication can be taken from the candidate.
#[test]
fn a_refused_signature_is_retained_and_never_retried() -> TestResult {
    let genesis = genesis(3)?;
    let (signer, authority) = counted(REFUSES)?;
    let mut meter = WorkMeter::unbounded();
    let mut candidate = EpochPublication::prepare(input(&genesis), &authority, &mut meter)?;
    let unsigned = candidate.unsigned.kappa().clone();
    let reservation = SigningReservation::recorded(*genesis.namespace.id(), 1);
    assert!(
        candidate
            .sign(&authority, &reservation, &mut meter)
            .is_err()
    );
    assert_eq!(candidate.phase(), PublicationPhase::SignerRefused);
    assert_eq!(candidate.disposition(), RecoveryDisposition::Terminal);
    assert!(candidate.returned_signature().is_none());
    signer.mode.store(SIGNS, SeqCst);
    assert!(
        candidate
            .sign(&authority, &reservation, &mut meter)
            .is_err()
    );
    assert_eq!(
        calls(&signer),
        1,
        "the signer is invoked once per coordinate"
    );
    assert!(candidate.signed_root().is_none());
    let Err(returned) = candidate.into_publication(reservation) else {
        return Err("a refused candidate yielded a publication".into());
    };
    let (candidate, reservation) = *returned;
    assert_eq!(
        candidate.unsigned.kappa(),
        &unsigned,
        "the material is retained"
    );
    assert_eq!(reservation.epoch_number(), 1);
    Ok(())
}

/// A returned signature that fails verification is kept as returned with
/// the root formed from it; the failure is conclusive, so later calls
/// neither invoke the signer nor verify again.
#[test]
fn a_returned_signature_is_kept_through_failed_completion() -> TestResult {
    let genesis = genesis(3)?;
    let (signer, authority) = counted(CORRUPTS)?;
    let mut meter = WorkMeter::unbounded();
    let mut candidate = EpochPublication::prepare(input(&genesis), &authority, &mut meter)?;
    let reservation = SigningReservation::recorded(*genesis.namespace.id(), 1);
    assert!(
        candidate
            .sign(&authority, &reservation, &mut meter)
            .is_err()
    );
    let Some(returned) = candidate.signed_root().map(|root| root.kappa().clone()) else {
        return Err("the returned signature was dropped".into());
    };
    assert_eq!(candidate.phase(), PublicationPhase::SignatureInvalid);
    assert_eq!(candidate.disposition(), RecoveryDisposition::Terminal);
    assert_eq!(candidate.returned_signature(), Some([0; 64].as_slice()));
    let verified = meter.used().get(Dimension::Signatures);
    signer.mode.store(SIGNS, SeqCst);
    assert!(
        candidate
            .sign(&authority, &reservation, &mut meter)
            .is_err()
    );
    assert_eq!(calls(&signer), 1, "completion never re-signs");
    assert_eq!(
        meter.used().get(Dimension::Signatures),
        verified,
        "a conclusive verification failure is not verified again"
    );
    assert_eq!(
        candidate.signed_root().map(EpochRoot::kappa),
        Some(&returned)
    );
    assert!(candidate.into_publication(reservation).is_err());
    Ok(())
}

/// A meter that cannot admit signing refuses at preparation or at
/// admission, before any coordinate is recorded.
#[test]
fn unadmitted_signing_refuses_before_a_coordinate_is_needed() -> TestResult {
    let genesis = genesis(4)?;
    let authority = epoch_authority()?;
    let mut probe = WorkMeter::unbounded();
    let candidate = EpochPublication::prepare(input(&genesis), &authority, &mut probe)?;
    let prepared = probe.used().get(Dimension::BytesAllocated);
    let short = prepared + candidate.work.total().allocated - 1;
    let mut meter = WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesAllocated, short));
    assert!(EpochPublication::prepare(input(&genesis), &authority, &mut meter).is_err());
    Ok(())
}

/// Bytes of the wrong length for the signing profile are kept exactly as
/// returned; the envelope refusal is conclusive, no root is formed, and
/// later calls do no work and never invoke the signer.
#[test]
fn malformed_length_output_survives_envelope_rejection() -> TestResult {
    let genesis = genesis(1)?;
    let (signer, authority) = counted(WRONG_LENGTH)?;
    let mut meter = WorkMeter::unbounded();
    let mut candidate = EpochPublication::prepare(input(&genesis), &authority, &mut meter)?;
    let reservation = SigningReservation::recorded(*genesis.namespace.id(), 1);
    assert!(
        candidate
            .sign(&authority, &reservation, &mut meter)
            .is_err()
    );
    assert_eq!(candidate.returned_signature(), Some([0xa5; 63].as_slice()));
    assert!(candidate.signed_root().is_none());
    assert_eq!(candidate.phase(), PublicationPhase::SignatureInvalid);
    assert_eq!(candidate.disposition(), RecoveryDisposition::Terminal);
    let consumed = *meter.used();
    for _ in 0..2 {
        assert!(
            candidate
                .sign(&authority, &reservation, &mut meter)
                .is_err()
        );
        assert_eq!(candidate.returned_signature(), Some([0xa5; 63].as_slice()));
        for dimension in Dimension::ALL {
            assert_eq!(meter.used().get(dimension), consumed.get(dimension));
        }
    }
    assert_eq!(calls(&signer), 1);
    let Err(returned) = candidate.into_publication(reservation) else {
        return Err("invalid signature produced a publication".into());
    };
    let (candidate, reservation) = *returned;
    assert_eq!(candidate.returned_signature(), Some([0xa5; 63].as_slice()));
    assert_eq!(reservation.epoch_number(), 1);
    Ok(())
}

/// A signer that returns valid bytes after the work deadline has passed
/// leaves the candidate holding those exact bytes, resumable: no root is
/// formed under the expired allowance, and a later call under a fresh one
/// forms the root from the retained bytes without invoking the signer.
#[test]
fn a_deadline_crossed_while_signing_keeps_the_returned_bytes() -> TestResult {
    let genesis = genesis(2)?;
    let (signer, authority) = counted(SLOW)?;
    let mut candidate =
        EpochPublication::prepare(input(&genesis), &authority, &mut WorkMeter::unbounded())?;
    let expected = signer.inner.sign(candidate.envelope.to_be_signed())?;
    let reservation = SigningReservation::recorded(*genesis.namespace.id(), 1);
    let mut expiring =
        WorkMeter::new(WorkLimit::unbounded().with_deadline(Instant::now() + DEADLINE));
    let interrupted = candidate.sign(&authority, &reservation, &mut expiring);
    assert!(
        interrupted.is_err(),
        "the expired allowance admits no formation"
    );
    assert_eq!(calls(&signer), 1);
    assert_eq!(candidate.phase(), PublicationPhase::SignatureReturned);
    assert_eq!(candidate.disposition(), RecoveryDisposition::Resumable);
    assert_eq!(candidate.returned_signature(), Some(expected.as_slice()));
    assert!(candidate.signed_root().is_none());
    assert_eq!(
        expiring.used().get(Dimension::Signatures),
        1,
        "the invocation is accounted although the deadline passed during it"
    );

    signer.mode.store(SIGNS, SeqCst);
    let mut fresh = WorkMeter::unbounded();
    candidate.sign(&authority, &reservation, &mut fresh)?;
    assert_eq!(
        calls(&signer),
        1,
        "the retained bytes are used, not re-signed"
    );
    let formed = candidate
        .unsigned
        .clone()
        .with_signature(candidate.envelope.complete(&expected)?);
    let Ok(publication) = candidate.into_publication(reservation) else {
        return Err("a resumed candidate yields its publication".into());
    };
    assert_eq!(publication.root().kappa(), formed.kappa());
    verify_epoch(
        publication.root(),
        authority.current().signer().public_key(),
    )?;
    Ok(())
}

/// Resumption admits each unit before it runs: an allowance with no
/// signature left forms the root but does not verify it, and a fresh
/// allowance verifies and completes the same root. Each call accounts only
/// the work it performed.
#[test]
fn resumption_admits_each_unit_and_keeps_the_formed_root() -> TestResult {
    let genesis = genesis(2)?;
    let (signer, authority) = counted(SLOW)?;
    let mut candidate =
        EpochPublication::prepare(input(&genesis), &authority, &mut WorkMeter::unbounded())?;
    let reservation = SigningReservation::recorded(*genesis.namespace.id(), 1);
    let mut expiring =
        WorkMeter::new(WorkLimit::unbounded().with_deadline(Instant::now() + DEADLINE));
    assert!(
        candidate
            .sign(&authority, &reservation, &mut expiring)
            .is_err()
    );
    assert_eq!(candidate.phase(), PublicationPhase::SignatureReturned);

    let mut unsigning = WorkMeter::new(WorkLimit::unbounded().with(Dimension::Signatures, 0));
    assert!(
        candidate
            .sign(&authority, &reservation, &mut unsigning)
            .is_err()
    );
    assert_eq!(candidate.phase(), PublicationPhase::Completing);
    assert_eq!(candidate.disposition(), RecoveryDisposition::Resumable);
    assert_eq!(
        unsigning.used().get(Dimension::Signatures),
        0,
        "no verification ran without an admitted signature"
    );
    assert_eq!(
        unsigning.used().get(Dimension::BytesAllocated),
        candidate.work.formation.allocated,
        "only the formation was performed and accounted"
    );
    let Some(formed) = candidate.signed_root().map(|root| root.kappa().clone()) else {
        return Err("the formed root was not retained".into());
    };

    let mut fresh = WorkMeter::unbounded();
    candidate.sign(&authority, &reservation, &mut fresh)?;
    assert_eq!(
        fresh.used().get(Dimension::Signatures),
        candidate.work.verification.signatures
    );
    assert!(fresh.used().get(Dimension::BytesHashed) > 0);
    assert_eq!(calls(&signer), 1);
    let Ok(publication) = candidate.into_publication(reservation) else {
        return Err("a resumed candidate yields its publication".into());
    };
    assert_eq!(
        publication.root().kappa(),
        &formed,
        "the formed root is published"
    );
    Ok(())
}

/// A record of the returned bytes that is refused does not lose them and
/// does not let signing progress past them: the next call records the same
/// bytes before it forms the root, and the signer is invoked once.
#[test]
fn a_refused_record_of_returned_bytes_is_retried_before_progress() -> TestResult {
    let genesis = genesis(2)?;
    let (signer, authority) = counted(SIGNS)?;
    let mut candidate =
        EpochPublication::prepare(input(&genesis), &authority, &mut WorkMeter::unbounded())?;
    let reservation = SigningReservation::recorded(*genesis.namespace.id(), 1);
    let mut events: Vec<Option<Vec<u8>>> = Vec::new();
    let mut signatures_recorded = Vec::new();
    let mut refusing = |event: SigningEvent<'_>, work: &Work| {
        signatures_recorded.push(work.get(Dimension::Signatures));
        match event {
            SigningEvent::Invoking => {
                events.push(None);
                Ok(())
            }
            SigningEvent::Returned(bytes) => {
                events.push(Some(bytes.to_vec()));
                Err(StoreError::Unavailable("custody not durable".into()))
            }
        }
    };
    assert!(matches!(
        candidate.sign_recorded(
            &authority,
            &reservation,
            &mut WorkMeter::unbounded(),
            &mut refusing
        ),
        Err(StoreError::Unavailable(_))
    ));
    assert_eq!(candidate.phase(), PublicationPhase::SignatureReturned);
    let Some(returned) = candidate.returned_signature().map(<[u8]>::to_vec) else {
        return Err("the returned bytes were dropped".into());
    };
    let mut accepting = |event: SigningEvent<'_>, work: &Work| {
        signatures_recorded.push(work.get(Dimension::Signatures));
        events.push(match event {
            SigningEvent::Invoking => None,
            SigningEvent::Returned(bytes) => Some(bytes.to_vec()),
        });
        Ok(())
    };
    candidate.sign_recorded(
        &authority,
        &reservation,
        &mut WorkMeter::unbounded(),
        &mut accepting,
    )?;
    assert_eq!(calls(&signer), 1);
    assert_eq!(
        events,
        vec![None, Some(returned.clone()), Some(returned)],
        "the refused record is retried with the same bytes before the root is formed"
    );
    assert_eq!(
        signatures_recorded,
        vec![0, 1, 0],
        "each record carries the work its meter consumed by then: none before the \
         invocation, the invocation's signature after it, and nothing yet on the \
         fresh meter of the retry"
    );
    assert!(candidate.into_publication(reservation).is_ok());
    Ok(())
}

/// A candidate rebuilt from the same inputs takes back where its recorded
/// signing stood: an invocation with no recorded bytes is terminal and its
/// signer is never invoked again; recorded bytes are used as they are,
/// without invoking the signer or recording them again, and yield the root
/// an uninterrupted signing forms.
#[test]
fn a_restored_signing_never_invokes_the_signer_again() -> TestResult {
    let genesis = genesis(3)?;
    let reservation = || SigningReservation::recorded(*genesis.namespace.id(), 1);
    let (signer, authority) = counted(SIGNS)?;

    let mut uninterrupted =
        EpochPublication::prepare(input(&genesis), &authority, &mut WorkMeter::unbounded())?;
    uninterrupted.sign(&authority, &reservation(), &mut WorkMeter::unbounded())?;
    let Some(expected) = uninterrupted.signed_root().map(|root| root.kappa().clone()) else {
        return Err("the uninterrupted candidate formed no root".into());
    };
    let Some(signature) = uninterrupted.returned_signature().map(<[u8]>::to_vec) else {
        return Err("the uninterrupted candidate kept no bytes".into());
    };
    assert_eq!(calls(&signer), 1);

    let mut invoked =
        EpochPublication::prepare(input(&genesis), &authority, &mut WorkMeter::unbounded())?;
    invoked.restore(RecordedSigning::Invoked)?;
    assert_eq!(invoked.phase(), PublicationPhase::SignerInvoked);
    assert_eq!(invoked.disposition(), RecoveryDisposition::Terminal);
    assert!(
        invoked
            .sign(&authority, &reservation(), &mut WorkMeter::unbounded())
            .is_err()
    );
    assert_eq!(
        calls(&signer),
        1,
        "an uncertain invocation is never repeated"
    );

    let mut returned =
        EpochPublication::prepare(input(&genesis), &authority, &mut WorkMeter::unbounded())?;
    returned.restore(RecordedSigning::Returned(signature))?;
    let mut recorded = 0;
    returned.sign_recorded(
        &authority,
        &reservation(),
        &mut WorkMeter::unbounded(),
        &mut |_, _| {
            recorded += 1;
            Ok(())
        },
    )?;
    assert_eq!(calls(&signer), 1, "restored bytes are not re-signed");
    assert_eq!(recorded, 0, "restored bytes are already recorded");
    assert_eq!(
        returned.signed_root().map(EpochRoot::kappa),
        Some(&expected)
    );
    assert!(
        returned.restore(RecordedSigning::Prepared).is_err(),
        "a candidate that progressed is not restored again"
    );
    Ok(())
}

/// Every epoch edge the signed root generates fits the bound admitted from
/// the unsigned root, whatever the axis of its target.
#[test]
fn epoch_edges_fit_their_bound_on_every_axis() -> TestResult {
    let genesis = genesis(1)?;
    let authority = epoch_authority()?;
    let candidate =
        EpochPublication::prepare(input(&genesis), &authority, &mut WorkMeter::unbounded())?;
    let root = candidate.unsigned;
    for axis in [
        Axis::Sha256,
        Axis::Sha512,
        Axis::Blake3,
        Axis::Sha1,
        Axis::Sha3_256,
        Axis::Keccak256,
    ] {
        let target = Kappa::compute(axis, b"edge target")?;
        let encoded = canonical_bytes(&epoch_edge(&root, &target)).len() as u64;
        assert!(encoded <= epoch_edge_bound(&root, &target), "{axis}");
    }
    Ok(())
}
