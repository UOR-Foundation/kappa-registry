//! Governed retirement over the memory store: authority is the governing
//! namespace's published operation carrying the principal's signed request
//! and the target record that authorized it, never a tag or a current
//! ownership comparison.

use kappa_crypto::Signer;
use kappa_crypto::ed25519::Ed25519Signer;
use kappa_crypto::signed_types::{admit_retirement_request, sign_retirement_request};
use kappa_handler::clock_at;
use kappa_store::governed_retirement::{
    TargetObservation, publish_retirement, retire, retirement_tag, verify_retirement,
};
use kappa_store::time::Clock;
use kappa_store::{
    Axis, BlobStore, ClockMs, Disposition, EpochStore, ExecutionStore, Kappa, NamespaceRef,
    NamespaceStore, ObservedHead, OperationAdmission, RetirementDecision, RetirementRequest,
    StoreError, TagUpdate, VerifiedContent, canonical_bytes,
};
use kappa_store_memory::InMemoryStore;
use kappa_store_memory::test_support::test_store;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The memory store admits a retirement as any operation: it has no
/// capacity a release must publish through.
fn admitted<'s>(
    store: &'s InMemoryStore,
) -> impl FnOnce(
    &NamespaceRef,
    [u8; 32],
    Kappa,
    &dyn Clock,
) -> Result<OperationAdmission<'s>, StoreError>
+ 's {
    move |namespace, operation, request, clock| {
        store.begin_operation(namespace, operation, request, clock)
    }
}

fn anchor(signer: &Ed25519Signer) -> Result<Kappa, StoreError> {
    Ok(Kappa::from_key(signer.algorithm(), signer.public_key())?)
}

fn create(
    store: &InMemoryStore,
    name: &str,
    owner: &Kappa,
) -> Result<NamespaceRef, Box<dyn std::error::Error>> {
    let ns = NamespaceRef::generate(name, ClockMs::from_raw(1000))?;
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(1000))?)?;
    execution.namespace_create(Some(owner), None)?;
    execution.publish()?;
    Ok(ns)
}

/// The observation a backend makes of present storage under its
/// reservation.
fn observe(store: &InMemoryStore, target: &NamespaceRef) -> Result<TargetObservation, StoreError> {
    let (epoch_number, root) = store.epoch_current(target)?;
    Ok(TargetObservation {
        record: store.namespace_info(target)?,
        head: Some(ObservedHead { epoch_number, root }),
    })
}

fn signed_request(
    signer: &Ed25519Signer,
    governing: &NamespaceRef,
    target: &NamespaceRef,
    head: Option<ObservedHead>,
) -> Result<kappa_crypto::Verified<RetirementRequest>, Box<dyn std::error::Error>> {
    let request = RetirementRequest::new(
        *governing.id(),
        *target.id(),
        [7; 16],
        Disposition::RetirePresent,
        head,
        2000,
        signer.algorithm(),
        signer.public_key(),
    )?;
    Ok(admit_retirement_request(sign_retirement_request(
        request, signer,
    )?)?)
}

struct Fixture {
    store: InMemoryStore,
    owner: Ed25519Signer,
    governing: NamespaceRef,
    target: NamespaceRef,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let store = test_store()?.into_store();
    let owner = Ed25519Signer::from_bytes(&[11; 32])?;
    let owner_anchor = anchor(&owner)?;
    let governing = create(&store, "control", &owner_anchor)?;
    let target = create(&store, "doomed", &owner_anchor)?;
    Ok(Fixture {
        store,
        owner,
        governing,
        target,
    })
}

#[test]
fn an_owner_signed_request_publishes_a_verifiable_retirement_once() -> TestResult {
    let f = fixture()?;
    let observation = observe(&f.store, &f.target)?;
    let request = signed_request(&f.owner, &f.governing, &f.target, observation.head.clone())?;
    let clock = clock_at(ClockMs::from_raw(3000))?;
    let retired = retire(
        &f.store,
        &f.governing,
        &request,
        &observation,
        &clock,
        admitted(&f.store),
    )?;
    assert_eq!(retired.decision().target(), f.target.id());
    assert_eq!(retired.decision().principal(), &anchor(&f.owner)?);
    assert_eq!(retired.evidence().ns.id(), f.target.id());
    let epoch = f.store.epoch_current(&f.governing)?;
    // The same signed request is the same operation: it replays.
    let again = retire(
        &f.store,
        &f.governing,
        &request,
        &observation,
        &clock,
        admitted(&f.store),
    )?;
    assert_eq!(again.record(), retired.record());
    assert_eq!(
        f.store.epoch_current(&f.governing)?,
        epoch,
        "a replay published again"
    );
    let found = verify_retirement(&f.store, &f.governing, f.target.id(), &[7; 16])?
        .ok_or("retirement not found")?;
    assert_eq!(found.record(), retired.record());
    assert!(verify_retirement(&f.store, &f.governing, f.target.id(), &[8; 16])?.is_none());
    Ok(())
}

/// A retry of a committed retirement replays from its evidence even after
/// the target moved on: the target is not inspected again.
#[test]
fn a_committed_retirement_replays_without_inspecting_the_target() -> TestResult {
    let f = fixture()?;
    let observation = observe(&f.store, &f.target)?;
    let request = signed_request(&f.owner, &f.governing, &f.target, observation.head.clone())?;
    let first = retire(
        &f.store,
        &f.governing,
        &request,
        &observation,
        &clock_at(ClockMs::from_raw(3000))?,
        admitted(&f.store),
    )?;
    let mut execution = f
        .store
        .begin_execution(&f.target, &clock_at(ClockMs::from_raw(3500))?)?;
    execution.tag_put(
        "later",
        &TagUpdate::Set {
            kappa: Kappa::sha256(b"later"),
        },
    )?;
    execution.publish()?;
    let replayed = retire(
        &f.store,
        &f.governing,
        &request,
        &observation,
        &clock_at(ClockMs::from_raw(4000))?,
        admitted(&f.store),
    )?;
    assert_eq!(replayed.record(), first.record());
    Ok(())
}

#[test]
fn a_principal_that_does_not_own_the_target_publishes_nothing() -> TestResult {
    let f = fixture()?;
    let stranger = Ed25519Signer::from_bytes(&[12; 32])?;
    let observation = observe(&f.store, &f.target)?;
    let request = signed_request(&stranger, &f.governing, &f.target, observation.head.clone())?;
    let refused = retire(
        &f.store,
        &f.governing,
        &request,
        &observation,
        &clock_at(ClockMs::from_raw(3000))?,
        admitted(&f.store),
    );
    assert!(
        matches!(refused, Err(StoreError::Rejected(_))),
        "{refused:?}"
    );
    assert!(verify_retirement(&f.store, &f.governing, f.target.id(), &[7; 16])?.is_none());
    Ok(())
}

#[test]
fn a_moved_head_is_not_the_one_the_principal_signed() -> TestResult {
    let f = fixture()?;
    let observation = observe(&f.store, &f.target)?;
    let request = signed_request(&f.owner, &f.governing, &f.target, observation.head.clone())?;
    let mut execution = f
        .store
        .begin_execution(&f.target, &clock_at(ClockMs::from_raw(2500))?)?;
    execution.tag_put(
        "moved",
        &TagUpdate::Set {
            kappa: Kappa::sha256(b"x"),
        },
    )?;
    execution.publish()?;
    let refused = retire(
        &f.store,
        &f.governing,
        &request,
        &observation,
        &clock_at(ClockMs::from_raw(3000))?,
        admitted(&f.store),
    );
    assert!(
        matches!(refused, Err(StoreError::Rejected(_))),
        "{refused:?}"
    );
    Ok(())
}

/// A writer of the governing namespace plants a decision naming the owner
/// as principal, with a request it signed itself: the signature does not
/// correspond. Planting a correctly signed request outside its operation
/// has no receipt.
#[test]
fn planted_records_are_not_authority() -> TestResult {
    let f = fixture()?;
    let observation = observe(&f.store, &f.target)?;
    let attacker = Ed25519Signer::from_bytes(&[13; 32])?;
    let forged = signed_request(&attacker, &f.governing, &f.target, observation.head.clone())?;
    let mut execution = f
        .store
        .begin_execution(&f.governing, &clock_at(ClockMs::from_raw(3000))?)?;
    let request = VerifiedContent::compute(Axis::Sha256, &canonical_bytes(forged.get()))?;
    let evidence = VerifiedContent::compute(Axis::Sha256, &canonical_bytes(&observation.record))?;
    execution.blob_put(&request)?;
    execution.blob_put(&evidence)?;
    let decision = RetirementDecision::new(
        *f.governing.id(),
        *f.target.id(),
        [7; 16],
        Disposition::RetirePresent,
        observation.head,
        request.kappa().clone(),
        anchor(&f.owner)?,
        evidence.kappa().clone(),
    )?;
    let record = VerifiedContent::compute(Axis::Sha256, &canonical_bytes(&decision))?;
    execution.blob_put(&record)?;
    execution.tag_put(
        &retirement_tag(f.target.id(), &[7; 16]),
        &TagUpdate::CreateIfAbsent {
            kappa: record.kappa().clone(),
        },
    )?;
    execution.publish()?;
    let verdict = verify_retirement(&f.store, &f.governing, f.target.id(), &[7; 16]);
    assert!(
        matches!(verdict, Err(StoreError::Rejected(_))),
        "{verdict:?}"
    );

    // The owner's genuine request for another incarnation, published by an
    // execution that is not its operation: no receipt names it.
    let current = observe(&f.store, &f.target)?;
    let genuine = RetirementRequest::new(
        *f.governing.id(),
        *f.target.id(),
        [8; 16],
        Disposition::RetirePresent,
        current.head.clone(),
        2000,
        f.owner.algorithm(),
        f.owner.public_key(),
    )?;
    let genuine = admit_retirement_request(sign_retirement_request(genuine, &f.owner)?)?;
    let mut execution = f
        .store
        .begin_execution(&f.governing, &clock_at(ClockMs::from_raw(3100))?)?;
    publish_retirement(&mut *execution, &genuine, &current)?;
    execution.publish()?;
    let verdict = verify_retirement(&f.store, &f.governing, f.target.id(), &[8; 16]);
    assert!(
        matches!(verdict, Err(StoreError::Rejected(_))),
        "{verdict:?}"
    );
    Ok(())
}

#[test]
fn a_committed_release_survives_a_change_of_ownership() -> TestResult {
    let f = fixture()?;
    let observation = observe(&f.store, &f.target)?;
    let request = signed_request(&f.owner, &f.governing, &f.target, observation.head.clone())?;
    retire(
        &f.store,
        &f.governing,
        &request,
        &observation,
        &clock_at(ClockMs::from_raw(3000))?,
        admitted(&f.store),
    )?;
    let mut execution = f
        .store
        .begin_execution(&f.governing, &clock_at(ClockMs::from_raw(4000))?)?;
    execution.namespace_transfer(&Kappa::sha256(b"new owner"))?;
    execution.publish()?;
    assert!(verify_retirement(&f.store, &f.governing, f.target.id(), &[7; 16])?.is_some());
    Ok(())
}

#[test]
fn a_second_decision_for_one_instance_conflicts() -> TestResult {
    let f = fixture()?;
    let observation = observe(&f.store, &f.target)?;
    let first = signed_request(&f.owner, &f.governing, &f.target, observation.head.clone())?;
    retire(
        &f.store,
        &f.governing,
        &first,
        &observation,
        &clock_at(ClockMs::from_raw(3000))?,
        admitted(&f.store),
    )?;
    let later = RetirementRequest::new(
        *f.governing.id(),
        *f.target.id(),
        [7; 16],
        Disposition::RetirePresent,
        observation.head.clone(),
        2001,
        f.owner.algorithm(),
        f.owner.public_key(),
    )?;
    let later = admit_retirement_request(sign_retirement_request(later, &f.owner)?)?;
    let second = retire(
        &f.store,
        &f.governing,
        &later,
        &observation,
        &clock_at(ClockMs::from_raw(3001))?,
        admitted(&f.store),
    );
    assert!(
        second.is_err(),
        "a second decision for one instance was admitted"
    );
    assert!(
        f.store.blob_exists_in(
            &f.governing,
            verify_retirement(&f.store, &f.governing, f.target.id(), &[7; 16])?
                .ok_or("lost")?
                .record()
        )?
    );
    Ok(())
}

/// Evidence larger than the bound a decision is read back under is refused
/// before anything is published. Published, it could never verify, and the
/// create-only locator would keep every later decision for the instance
/// out: verification would fail on the oversize record instead of finding
/// no locator.
#[test]
fn evidence_beyond_the_record_bound_publishes_nothing() -> TestResult {
    let store = test_store()?.into_store();
    let owner = Ed25519Signer::from_bytes(&[11; 32])?;
    let owner_anchor = anchor(&owner)?;
    let governing = create(&store, "control", &owner_anchor)?;
    let target = create(&store, &"x".repeat(80 * 1024), &owner_anchor)?;
    let observation = observe(&store, &target)?;
    assert!(
        canonical_bytes(&observation.record).len() > 64 * 1024,
        "control: the evidence record exceeds the bound"
    );
    let request = signed_request(&owner, &governing, &target, observation.head.clone())?;
    let before = store.epoch_current(&governing)?;
    let refused = retire(
        &store,
        &governing,
        &request,
        &observation,
        &clock_at(ClockMs::from_raw(3000))?,
        admitted(&store),
    );
    assert!(
        matches!(refused, Err(StoreError::Rejected(_))),
        "{refused:?}"
    );
    assert_eq!(
        store.epoch_current(&governing)?,
        before,
        "a refused retirement published"
    );
    assert!(verify_retirement(&store, &governing, target.id(), &[7; 16])?.is_none());
    Ok(())
}
