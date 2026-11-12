use std::sync::Barrier;

use kappa_store::{ClockMs, ResourceKind};

use super::*;

fn namespace() -> NamespaceRef {
    NamespaceRef::deterministic("budget")
}

fn head(phase: ResourcePhase, total_bytes: u64) -> ResourceHead {
    ResourceHead {
        namespace_id: namespace().id().to_vec(),
        incarnation: vec![7; 16],
        kind: ResourceKind::Sequential,
        revision: 1,
        phase,
        total_bytes,
        member_count: 1,
        max_bytes: 0,
        created_at_ms: 0,
        expires_at_ms: i64::MAX,
        completion: None,
        prepared: None,
        context: None,
    }
}

fn mutation(op: MutationOp, name: &str) -> EpochMutation {
    EpochMutation {
        op,
        kappa: kappa_store::Kappa::sha256(name.as_bytes()),
        timestamp_ms: ClockMs::from_raw(1).as_i64(),
        context: Some(name.to_string()),
    }
}

/// Record `head` for `id` as a fresh observation.
fn observe(budget: &StagingBudget, id: &str, head: Option<&ResourceHead>) {
    let observation = budget.issue();
    StagingBudget::apply(&mut budget.lock(), observation.seq, &namespace(), id, head);
}

#[test]
fn exactly_the_ceiling_is_admitted_under_contention() {
    let budget = Arc::new(StagingBudget::new(4, 0));
    let barrier = Barrier::new(16);
    let admitted: usize = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let (budget, barrier) = (&budget, &barrier);
                scope.spawn(move || {
                    barrier.wait();
                    let admission = budget.admit_open();
                    // Hold the reservation past every other attempt.
                    barrier.wait();
                    usize::from(admission.is_ok())
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap_or(0)).sum()
    });
    assert_eq!(admitted, 4);
    // Every reservation dropped: the slots are back.
    assert!(budget.admit_open().is_ok());
}

#[test]
fn a_dropped_reservation_returns_exactly_its_charge() -> Result<(), HandlerError> {
    let budget = Arc::new(StagingBudget::new(0, 100));
    let first = budget.admit_bytes(60)?;
    assert!(budget.admit_bytes(41).is_err());
    let second = budget.admit_bytes(40)?;
    drop(first);
    assert!(budget.admit_bytes(61).is_err());
    assert!(budget.admit_bytes(60).is_ok());
    drop(second);
    assert_eq!(budget.lock().pending_bytes, 0);
    assert_eq!(budget.lock().pending_open, 0);
    Ok(())
}

#[test]
fn an_owned_reservation_is_returned_only_where_it_is_dropped()
-> Result<(), Box<dyn std::error::Error>> {
    let budget = Arc::new(StagingBudget::new(1, 0));
    let admission = budget.admit_open()?;
    let (release, released) = std::sync::mpsc::channel::<()>();
    // The worker holds the reservation as an execution's work does; the
    // caller that admitted it has nothing left to drop.
    let worker = std::thread::spawn(move || {
        let held = admission;
        let signal = released.recv();
        drop(held);
        signal
    });
    assert!(budget.admit_open().is_err());
    release.send(())?;
    worker.join().map_err(|_| "worker panicked")??;
    assert!(budget.admit_open().is_ok());
    Ok(())
}

#[test]
fn committed_heads_replace_their_previous_figure_and_release_on_every_exit() {
    let budget = Arc::new(StagingBudget::new(1, 100));
    observe(&budget, "a", Some(&head(ResourcePhase::Open, 30)));
    assert_eq!((budget.open_count(), budget.staged_bytes()), (1, 30));
    assert!(budget.admit_open().is_err());
    observe(&budget, "a", Some(&head(ResourcePhase::Prepared, 70)));
    assert_eq!(budget.staged_bytes(), 70);
    assert!(budget.admit_bytes(31).is_err());
    observe(&budget, "a", Some(&head(ResourcePhase::Completed, 70)));
    assert_eq!((budget.open_count(), budget.staged_bytes()), (0, 0));
    observe(&budget, "b", Some(&head(ResourcePhase::Open, 10)));
    observe(&budget, "b", Some(&head(ResourcePhase::Discarded, 10)));
    assert_eq!((budget.open_count(), budget.staged_bytes()), (0, 0));
    observe(&budget, "c", Some(&head(ResourcePhase::Open, 5)));
    // A deleted head, observed twice, releases exactly once.
    observe(&budget, "c", None);
    observe(&budget, "c", None);
    assert_eq!((budget.open_count(), budget.staged_bytes()), (0, 0));
    assert!(!budget.unresolved());
}

/// Two workers observe the same resource; the one issued later resolved
/// later and wins whichever order they record in.
#[test]
fn observations_record_in_issue_order_whichever_order_they_run_in() {
    let budget = Arc::new(StagingBudget::new(0, 0));
    let ns = namespace();
    let earlier = budget.issue();
    let later = budget.issue();
    StagingBudget::apply(
        &mut budget.lock(),
        later.seq,
        &ns,
        "a",
        Some(&head(ResourcePhase::Open, 20)),
    );
    StagingBudget::apply(
        &mut budget.lock(),
        earlier.seq,
        &ns,
        "a",
        Some(&head(ResourcePhase::Open, 10)),
    );
    assert_eq!(budget.staged_bytes(), 20);

    // A deletion recorded by the later observation is not undone by the
    // earlier one's stale head, while the earlier one is in flight or
    // after it was dropped.
    let stale = budget.issue();
    let deleting = budget.issue();
    StagingBudget::apply(&mut budget.lock(), deleting.seq, &ns, "a", None);
    assert_eq!((budget.open_count(), budget.staged_bytes()), (0, 0));
    StagingBudget::apply(
        &mut budget.lock(),
        stale.seq,
        &ns,
        "a",
        Some(&head(ResourcePhase::Open, 20)),
    );
    assert_eq!((budget.open_count(), budget.staged_bytes()), (0, 0));
    assert!(
        budget
            .lock()
            .ended
            .contains_key(&(*ns.id(), "a".to_string()))
    );
    // Once nothing earlier is in flight the deletion record is pruned.
    drop(earlier);
    drop(later);
    drop(stale);
    drop(deleting);
    assert!(budget.lock().ended.is_empty());
    assert!(budget.lock().inflight.is_empty());
}

/// A scan's result replaces what earlier observations recorded, keeps
/// what later ones recorded, honours deletions recorded after it, and
/// resolves the projection. The store-backed rebuild and settle paths are
/// exercised in `kappa-server/tests/background_tasks.rs`.
#[test]
fn a_scan_is_an_ordered_observation_of_the_whole_store() -> Result<(), StoreError> {
    let budget = Arc::new(StagingBudget::new(0, 0));
    let ns = namespace();
    let key = |id: &str| (*ns.id(), id.to_string());
    observe(&budget, "stale", Some(&head(ResourcePhase::Open, 100)));
    budget.invalidate("test");
    assert!(budget.admit_open().is_err());
    let scan = budget.issue();
    let newer = budget.issue();
    StagingBudget::apply(
        &mut budget.lock(),
        newer.seq,
        &ns,
        "fresh",
        Some(&head(ResourcePhase::Open, 7)),
    );
    StagingBudget::apply(&mut budget.lock(), newer.seq, &ns, "gone", None);
    let found = vec![
        (key("a"), 5),
        (key("b"), 11),
        (key("fresh"), 1),
        (key("gone"), 9),
    ];
    let count = StagingBudget::record_scan(&mut budget.lock(), scan.seq, found)?;
    assert_eq!(count, 4);
    // "stale" was older than the scan and is gone; "fresh" keeps the
    // newer figure; "gone" was deleted after the scan was issued.
    assert_eq!((budget.open_count(), budget.staged_bytes()), (3, 23));
    assert!(!budget.unresolved());
    assert!(budget.admit_open().is_ok());
    Ok(())
}

/// An observation applied between two namespaces of a scan sees a total
/// that already includes what the scan recorded: replacing a figure the
/// scan installed subtracts exactly that figure, so the interleaving
/// neither underflows nor invalidates, and the finished scan agrees.
#[test]
fn an_observation_between_scanned_namespaces_keeps_the_total_exact() -> Result<(), StoreError> {
    let budget = Arc::new(StagingBudget::new(0, 0));
    let ns = namespace();
    let key = |id: &str| (*ns.id(), id.to_string());
    observe(&budget, "r", Some(&head(ResourcePhase::Open, 5)));
    let scan = budget.issue();
    StagingBudget::record_found(&mut budget.lock(), scan.seq, key("r"), 11);
    assert_eq!(budget.staged_bytes(), 11);
    let later = budget.issue();
    StagingBudget::apply(
        &mut budget.lock(),
        later.seq,
        &ns,
        "r",
        Some(&head(ResourcePhase::Open, 12)),
    );
    assert!(
        !budget.unresolved(),
        "an observation during a scan invalidated the projection"
    );
    assert_eq!(budget.staged_bytes(), 12);
    StagingBudget::finish_scan(&mut budget.lock(), scan.seq)?;
    assert_eq!((budget.open_count(), budget.staged_bytes()), (1, 12));
    assert!(!budget.unresolved());
    Ok(())
}

/// An invalidation recorded after a scan was issued is not cleared by
/// that scan: the publication it stands for may postdate it. A scan
/// issued after the invalidation clears it.
#[test]
fn a_scan_does_not_clear_a_later_invalidation() -> Result<(), StoreError> {
    let budget = Arc::new(StagingBudget::new(0, 0));
    let early = budget.issue();
    budget.invalidate("after the scan was issued");
    StagingBudget::record_scan(&mut budget.lock(), early.seq, Vec::new())?;
    assert!(
        budget.unresolved(),
        "an earlier scan cleared a later invalidation"
    );
    let later = budget.issue();
    StagingBudget::record_scan(&mut budget.lock(), later.seq, Vec::new())?;
    assert!(!budget.unresolved());
    Ok(())
}

/// An accounting invariant that fails closes admission rather than
/// continuing on a figure that may undercount; a scan issued after it
/// reopens admission.
#[test]
fn an_invariant_failure_leaves_the_projection_unresolved() -> Result<(), StoreError> {
    let budget = Arc::new(StagingBudget::new(0, 0));
    budget.release_pending_bytes(1);
    assert!(budget.unresolved());
    assert!(budget.admit_open().is_err());
    assert!(budget.admit_bytes(1).is_err());
    let scan = budget.issue();
    StagingBudget::record_scan(&mut budget.lock(), scan.seq, Vec::new())?;
    assert!(budget.admit_open().is_ok());
    Ok(())
}

/// Advancing the oldest observer releases only obsolete deletion records.
#[test]
fn deletion_records_follow_the_oldest_remaining_observation() {
    let budget = StagingBudget::new(0, 0);
    let ns = namespace();
    let oldest = budget.issue();
    let first = budget.issue();
    StagingBudget::apply(&mut budget.lock(), first.seq, &ns, "first", None);
    let middle = budget.issue();
    let second = budget.issue();
    StagingBudget::apply(&mut budget.lock(), second.seq, &ns, "second", None);
    drop(first);
    drop(second);
    assert_eq!(budget.lock().ended.len(), 2);
    drop(oldest);
    {
        let accounts = budget.lock();
        assert_eq!(accounts.ended.len(), 1);
        assert!(
            accounts
                .ended
                .contains_key(&(*ns.id(), "second".to_string()))
        );
    }
    // The remaining deletion still prevents this observer's stale head
    // from resurrecting the resource after the floor advances.
    StagingBudget::apply(
        &mut budget.lock(),
        middle.seq,
        &ns,
        "second",
        Some(&head(ResourcePhase::Open, 10)),
    );
    assert_eq!((budget.open_count(), budget.staged_bytes()), (0, 0));
    drop(middle);
    assert!(budget.lock().ended.is_empty());
}

/// Deletion records are bounded even while the oldest observation stalls.
#[test]
fn deletion_records_are_bounded() {
    let budget = Arc::new(StagingBudget::new(0, 0));
    let ns = namespace();
    let stalled = budget.issue();
    for index in 0..=MAX_ENDED {
        let observation = budget.issue();
        StagingBudget::apply(
            &mut budget.lock(),
            observation.seq,
            &ns,
            &index.to_string(),
            None,
        );
    }
    assert!(budget.lock().ended.is_empty());
    assert!(budget.unresolved());
    drop(stalled);
}

/// Sequence exhaustion closes the projection for good: the terminal
/// invalidation can never be reached by a rebuild.
#[test]
fn sequence_exhaustion_closes_admission() {
    let budget = Arc::new(StagingBudget::new(0, 0));
    budget.lock().next_seq = u64::MAX;
    let last = budget.issue();
    assert_eq!(last.seq, u64::MAX);
    assert!(budget.unresolved());
    drop(last);
    assert!(budget.admit_open().is_err());
}

#[test]
fn only_head_tags_are_resource_transitions() {
    assert_eq!(
        head_id(&mutation(MutationOp::TagSet, "_resource/abc")),
        Some("abc")
    );
    assert_eq!(
        head_id(&mutation(MutationOp::TagDelete, "_resource/abc")),
        Some("abc")
    );
    assert_eq!(
        head_id(&mutation(MutationOp::TagSet, "_resource/abc/m/1")),
        None
    );
    assert_eq!(head_id(&mutation(MutationOp::TagSet, "object")), None);
    assert_eq!(
        head_id(&mutation(MutationOp::MetadataUpdate, "_resource/abc")),
        None
    );
}
