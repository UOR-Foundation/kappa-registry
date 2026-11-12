//! The budget's admission table and accounting, without a store. The
//! `Resolving` class needs a `ReleaseGrant`, which only a store's recovery
//! obligations mint; its schedules are in `settlement_release_tests`.

use super::*;
use crate::allocation::Protection;
use crate::representation::AllocationId;
use crate::storage_instance::Incarnation;

fn pin(protection: &Arc<Protection>, bytes: u64) -> Result<Pin, StoreError> {
    Ok(protection.pin(AllocationId::generate()?)?.with_bytes(bytes))
}

fn ordinary(budget: &Arc<UnsettledBudget>, entries: u64, bytes: u64) -> Result<Charge, StoreError> {
    budget.admit(Class::Ordinary, entries, bytes)
}

fn instance(byte: u8) -> StorageInstance {
    StorageInstance::new([byte; 16], Incarnation::Known([byte; 16]))
}

#[test]
fn charges_are_refused_at_either_bound_and_released_on_drop() -> Result<(), StoreError> {
    let protection = Arc::new(Protection::default());
    let budget = Arc::new(UnsettledBudget::new(2, 100));
    let first = budget.reserve(&[pin(&protection, 60)?], Class::Ordinary)?;
    assert!(
        budget
            .reserve(&[pin(&protection, 50)?], Class::Ordinary)
            .is_err(),
        "bytes bound"
    );
    let second = budget.reserve(&[pin(&protection, 30)?], Class::Ordinary)?;
    assert!(
        budget
            .reserve(&[pin(&protection, 1)?], Class::Ordinary)
            .is_err(),
        "entries bound"
    );
    assert_eq!(budget.charged(), (2, 90));
    // An empty reservation is admitted at the bound and charges nothing.
    let empty = budget.reserve(&[], Class::Ordinary)?;
    assert_eq!(budget.charged(), (2, 90));
    drop(empty);
    drop(first);
    assert_eq!(budget.charged(), (1, 30));
    let mut parked = Parked::new(Vec::new(), second);
    parked.append(Parked::new(
        Vec::new(),
        budget.reserve(&[pin(&protection, 70)?], Class::Ordinary)?,
    ));
    assert_eq!(parked.entries(), 2);
    assert_eq!(parked.bytes(), 100);
    assert_eq!(budget.charged(), (2, 100));
    drop(parked);
    assert_eq!(budget.charged(), (0, 0));
    Ok(())
}

#[test]
fn overflow_is_refused_even_under_an_unbounded_maximum() -> Result<(), StoreError> {
    let budget = Arc::new(UnsettledBudget::new(u64::MAX, u64::MAX));
    let held = ordinary(&budget, 1, u64::MAX - 1)?;
    assert!(matches!(
        ordinary(&budget, 1, 2),
        Err(StoreError::CapacityExceeded(_))
    ));
    assert!(budget.debt(0, 2).is_err(), "debt overflowed the counter");
    drop(held);
    assert_eq!(budget.charged(), (0, 0));
    Ok(())
}

#[test]
fn a_preparation_charge_travels_with_its_pin_and_is_not_reserved_twice() -> Result<(), StoreError> {
    let protection = Arc::new(Protection::default());
    let budget = Arc::new(UnsettledBudget::new(4, 1000));
    let prepared = pin(&protection, 100)?.charged(ordinary(&budget, 1, 100)?);
    assert_eq!(budget.charged(), (1, 100));
    let sealed = pin(&protection, 10)?;
    let pins = vec![prepared, sealed];
    // Only the sealed record's pin is new to the budget.
    let publication = budget.reserve(&pins, Class::Ordinary)?;
    assert_eq!((publication.entries(), publication.bytes()), (1, 10));
    assert_eq!(budget.charged(), (2, 110));
    let parked = Parked::new(pins, publication);
    assert_eq!((parked.entries(), parked.bytes()), (2, 110));
    drop(parked);
    assert_eq!(budget.charged(), (0, 0));
    // A preparation dropped uninstalled releases its own charge.
    let abandoned = pin(&protection, 7)?.charged(ordinary(&budget, 1, 7)?);
    assert_eq!(budget.charged(), (1, 7));
    drop(abandoned);
    assert_eq!(budget.charged(), (0, 0));
    Ok(())
}

#[test]
fn debt_exceeds_the_bound_and_blocks_reservations_until_released() -> Result<(), StoreError> {
    let budget = Arc::new(UnsettledBudget::new(2, 100));
    let debt = budget.debt(5, 500)?;
    assert_eq!(budget.charged(), (5, 500));
    assert!(ordinary(&budget, 0, 0).is_err());
    drop(debt);
    assert!(ordinary(&budget, 1, 1).is_ok());
    Ok(())
}

type Debt = fn(&Arc<UnsettledBudget>, u64, u64) -> Result<Charge, StoreError>;

#[test]
fn remeasurement_at_counter_limit_never_reserves_the_same_debt_twice() -> Result<(), StoreError> {
    let budget = Arc::new(UnsettledBudget::new(1, 1));
    let mut debt = budget.debt(u64::MAX, u64::MAX)?;
    debt.measure(u64::MAX, u64::MAX)?;
    assert_eq!(budget.charged(), (u64::MAX, u64::MAX));
    debt.measure(1, 1)?;
    assert_eq!(budget.charged(), (1, 1));
    assert!(ordinary(&budget, 1, 0).is_err());
    drop(debt);
    assert_eq!(budget.charged(), (0, 0));
    Ok(())
}

#[test]
fn failed_measurement_keeps_its_closure_and_other_ownership() -> Result<(), StoreError> {
    let budget = Arc::new(UnsettledBudget::new(u64::MAX, u64::MAX));
    let other = budget.debt(1, u64::MAX)?;
    let cause = Closure::Obligation(instance(9));
    let mut unknown = budget.unmeasured(cause)?;
    assert!(unknown.measure(2, 1).is_err());
    assert_eq!(budget.charged(), (1, u64::MAX));
    assert_eq!(budget.closures(), vec![cause]);
    drop(other);
    unknown.measure(2, 1)?;
    assert_eq!(budget.charged(), (2, 1));
    assert!(budget.closures().is_empty());
    drop(unknown);
    assert_eq!(budget.charged(), (0, 0));
    Ok(())
}

/// `debt` as it was: the entry sum is assigned before the byte sum is
/// checked, so a refused byte overflow leaves the entries charged with no
/// `Charge` to release them.
fn partially_updating_debt(
    budget: &Arc<UnsettledBudget>,
    entries: u64,
    bytes: u64,
) -> Result<Charge, StoreError> {
    let mut held = budget.held();
    let overflow = || StoreError::CapacityExceeded("unsettled charge counter overflow".into());
    held.entries = held.entries.checked_add(entries).ok_or_else(overflow)?;
    held.bytes = held.bytes.checked_add(bytes).ok_or_else(overflow)?;
    drop(held);
    Ok(budget.charge(entries, bytes, None))
}

/// Whether `debt`, refused by a byte overflow while charging a nonzero
/// number of entries, leaves no charge behind once everything held is
/// released.
fn refused_debt_charges_nothing(debt: Debt) -> Result<bool, StoreError> {
    let budget = Arc::new(UnsettledBudget::new(u64::MAX, u64::MAX));
    let held = ordinary(&budget, 1, u64::MAX - 1)?;
    let refused = matches!(debt(&budget, 1, 2), Err(StoreError::CapacityExceeded(_)));
    drop(held);
    Ok(refused && budget.charged() == (0, 0))
}

#[test]
fn a_debt_refused_by_byte_overflow_charges_no_entries() -> Result<(), StoreError> {
    assert!(
        !refused_debt_charges_nothing(partially_updating_debt)?,
        "control: the check catches the partial update"
    );
    assert!(refused_debt_charges_nothing(UnsettledBudget::debt)?);
    Ok(())
}

type Unmeasured = fn(&Arc<UnsettledBudget>) -> Result<Charge, StoreError>;

/// Unmeasured ownership charged as it was: zero debt.
fn zero_debt(budget: &Arc<UnsettledBudget>) -> Result<Charge, StoreError> {
    budget.debt(0, 0)
}

fn startup(budget: &Arc<UnsettledBudget>) -> Result<Charge, StoreError> {
    budget.unmeasured(Closure::Startup)
}

/// Whether the charge `unmeasured` takes refuses every ordinary admission
/// while held, an empty one included, with capacity to spare, and nothing
/// once released.
fn unmeasured_ownership_closes_admission(unmeasured: Unmeasured) -> Result<bool, StoreError> {
    let budget = Arc::new(UnsettledBudget::new(2, 100));
    let charge = unmeasured(&budget)?;
    let closed = matches!(
        ordinary(&budget, 1, 1),
        Err(StoreError::CapacityExceeded(_))
    ) && matches!(
        ordinary(&budget, 0, 0),
        Err(StoreError::CapacityExceeded(_))
    );
    drop(charge);
    let reopened = ordinary(&budget, 1, 1).is_ok();
    Ok(closed && reopened && budget.charged() == (0, 0))
}

#[test]
fn unmeasured_ownership_closes_admission_until_released() -> Result<(), StoreError> {
    assert!(
        !unmeasured_ownership_closes_admission(zero_debt)?,
        "control: zero debt admits against ownership nobody measured"
    );
    assert!(unmeasured_ownership_closes_admission(startup)?);
    Ok(())
}

/// The pool stays closed while any cause holds it, counted per cause: two
/// charges of one obligation and the startup closure each release only
/// themselves, and the refusal names every cause still holding the pool
/// with what ends it.
#[test]
fn closures_are_counted_per_cause_and_named_in_the_refusal() -> Result<(), StoreError> {
    let budget = Arc::new(UnsettledBudget::new(8, 800));
    let lost = instance(3);
    let at_open = budget.unmeasured(Closure::Startup)?;
    let first = budget.unmeasured(Closure::Obligation(lost))?;
    let second = budget.unmeasured(Closure::Obligation(lost))?;
    assert_eq!(
        budget.closures(),
        vec![Closure::Startup, Closure::Obligation(lost)]
    );
    drop(at_open);
    assert_eq!(budget.closures(), vec![Closure::Obligation(lost)]);
    let Err(StoreError::CapacityExceeded(refusal)) = ordinary(&budget, 0, 0) else {
        return Err(StoreError::Internal("a closed pool admitted".into()));
    };
    assert!(refusal.contains(&lost.to_string()), "{refusal}");
    assert!(
        refusal.contains(&Exit::SettlementOrRelease.to_string()),
        "{refusal}"
    );
    drop(first);
    assert!(
        ordinary(&budget, 0, 0).is_err(),
        "one charge of the cause remains"
    );
    drop(second);
    assert!(budget.closures().is_empty());
    assert!(ordinary(&budget, 1, 1).is_ok());
    Ok(())
}

/// Every closure declares an exit, and only the startup closure ends with
/// the enumeration.
#[test]
fn every_closure_declares_its_exit() {
    assert_eq!(Closure::Startup.exit(), Exit::Enumeration);
    assert_eq!(
        Closure::Obligation(instance(4)).exit(),
        Exit::SettlementOrRelease
    );
}

#[test]
fn concurrent_reservations_never_exceed_the_bound() -> Result<(), StoreError> {
    let protection = Arc::new(Protection::default());
    let budget = Arc::new(UnsettledBudget::new(5, u64::MAX));
    let start = std::sync::Barrier::new(16);
    let outcomes = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..16)
            .map(|_| {
                let (budget, protection, start) = (&budget, &protection, &start);
                scope.spawn(move || -> Result<Option<Charge>, StoreError> {
                    let pin = pin(protection, 1)?;
                    start.wait();
                    Ok(budget
                        .reserve(std::slice::from_ref(&pin), Class::Ordinary)
                        .ok())
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .map_err(|_| StoreError::Internal("reservation worker panicked".into()))?
            })
            .collect::<Result<Vec<_>, StoreError>>()
    })?;
    let granted = outcomes.iter().filter(|outcome| outcome.is_some()).count();
    assert_eq!(granted, 5);
    assert_eq!(budget.charged(), (5, 5));
    drop(outcomes);
    assert_eq!(budget.charged(), (0, 0));
    Ok(())
}
