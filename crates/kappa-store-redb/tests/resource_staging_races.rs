//! Staged resources under contention and time, on both backends: a put of
//! the same identity converges, abort and expiry release, exactly one of
//! two racing discards publishes, a stage racing a discard leaks nothing,
//! a dropped execution leaves the resource committable, a frozen
//! generation is idempotent for its request and superseded by another,
//! and concurrent preparations of the same bytes publish one
//! representation.

mod support;

use std::sync::Barrier;

use kappa_handler::clock_at;
use kappa_store::resource;
use kappa_store::{
    Axis, BlobStore, ContentIdentity, ExecutionStore, Kappa, ResourceKind, ResourcePhase,
    Retirement, StoreError,
};

use support::resource::{open, recorded_compositions, stage};
use support::{Staging, TestResult, at, bounds, computed, create, prepare, publish, staging_dirs};

fn asserter() -> Kappa {
    support::resource::asserter()
}

fn exercise_membership_and_release(store: &(impl Staging + ?Sized)) -> TestResult {
    let ns = create(store, "membership")?;
    let now = at(1_700_000_003_000);
    let id = open(store, &ns, ResourceKind::Membership, 0, now)?;
    let content = b"idempotent member";
    let identity = Kappa::sha256(content);
    let put = |now| -> Result<u64, StoreError> {
        let prepared = prepare(store, ContentIdentity::Verified(identity.clone()), content)?;
        publish(store, &ns, now, |e| {
            Ok(resource::stage(e, &asserter(), &id, prepared, 0, None)?
                .0
                .member_count)
        })
    };
    assert_eq!(put(now)?, 1);
    // The same identity converges: one member, no second reservation.
    assert_eq!(put(now)?, 1);
    let head = resource::resolve(store, &ns, &id)?
        .ok_or("resource vanished")?
        .head;
    assert_eq!(head.total_bytes, content.len() as u64);
    // Membership resources take no position.
    assert!(matches!(
        stage(store, &ns, &id, b"positioned", 1, None, now),
        Err(StoreError::Rejected(_))
    ));

    // A dropped execution leaves the resource committable.
    {
        let mut execution = store.begin_execution(&ns, &clock_at(now)?)?;
        resource::discard(&mut *execution, &asserter(), &id)?;
        drop(execution);
    }
    assert_eq!(
        resource::resolve(store, &ns, &id)?
            .ok_or("resource vanished")?
            .head
            .phase,
        ResourcePhase::Open
    );

    // Exactly one of two racing discards publishes; the other observes a
    // head already transitioned and changes nothing.
    let barrier = Barrier::new(2);
    let outcomes: Vec<Result<bool, StoreError>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let (ns, id, barrier) = (&ns, &id, &barrier);
                scope.spawn(move || {
                    barrier.wait();
                    publish(store, ns, now, |e| resource::discard(e, &asserter(), id))
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| StoreError::Internal("discard racer panicked".into()))
                    .and_then(|outcome| outcome)
            })
            .collect()
    });
    let discarded = outcomes.iter().filter(|o| matches!(o, Ok(true))).count();
    assert_eq!(discarded, 1, "{outcomes:?}");
    assert!(resource::resolve(store, &ns, &id)?.is_none());
    // Staging into a discarded resource is refused and publishes nothing.
    assert!(matches!(
        stage(store, &ns, &id, b"after discard", 0, None, now),
        Err(StoreError::NotFound(_))
    ));
    assert!(!store.blob_exists(&Kappa::sha256(b"after discard"))?);
    Ok(())
}

/// A stage racing a discard of the same resource: whichever publishes
/// second conflicts, and no member content remains retained once the
/// resource is gone.
fn exercise_stage_racing_discard(store: &(impl Staging + ?Sized)) -> TestResult {
    let ns = create(store, "race")?;
    let now = at(1_700_000_003_500);
    for round in 0..16u8 {
        let id = open(store, &ns, ResourceKind::Sequential, 0, now)?;
        let bytes = vec![round; 256];
        let identity = Kappa::sha256(&bytes);
        let barrier = Barrier::new(2);
        let (staged, discarded) = std::thread::scope(|scope| {
            let (ns, id, barrier, bytes) = (&ns, &id, &barrier, &bytes);
            let writer = scope.spawn(move || {
                let prepared = computed(store, bytes)?;
                barrier.wait();
                publish(store, ns, now, |e| {
                    resource::stage(e, &asserter(), id, prepared, 0, None).map(|_| ())
                })
            });
            let releaser = scope.spawn(move || {
                barrier.wait();
                publish(store, ns, now, |e| resource::discard(e, &asserter(), id))
            });
            (writer.join(), releaser.join())
        });
        let staged = staged.map_err(|_| "writer panicked")?;
        let discarded = discarded.map_err(|_| "releaser panicked")?;
        match (&staged, &discarded) {
            // The stage published first and the discard followed it,
            // retiring the member; or the discard published first and the
            // stage found no open head.
            (Ok(()) | Err(StoreError::Conflict(_) | StoreError::NotFound(_)), Ok(true)) => {}
            // The stage published first and the discard conflicted: it is
            // retried here.
            (Ok(()), Err(StoreError::Conflict(_))) => {
                assert!(publish(store, &ns, now, |e| {
                    resource::discard(e, &asserter(), &id)
                })?);
            }
            other => return Err(format!("round {round}: {other:?}").into()),
        }
        assert!(
            resource::resolve(store, &ns, &id)?.is_none(),
            "round {round}"
        );
        // Nothing names the member any more: retirement is permitted or
        // the content was never published.
        publish(store, &ns, now, |e| {
            let retirement = e.content_retire(&identity)?;
            assert!(
                matches!(retirement, Retirement::Retired | Retirement::Absent),
                "round {round}: {retirement:?}"
            );
            Ok(())
        })?;
        assert!(!store.blob_exists(&identity)?, "round {round}");
    }
    Ok(())
}

fn exercise_expiry(store: &(impl Staging + ?Sized)) -> TestResult {
    let ns = create(store, "expiry")?;
    let opened = at(1_700_000_004_000);
    let id = open(store, &ns, ResourceKind::Sequential, 0, opened)?;
    let other = create(store, "expiry-other")?;
    let other_id = open(store, &other, ResourceKind::Sequential, 0, opened)?;
    let observed = resource::resolve(store, &ns, &id)?
        .ok_or("resource vanished")?
        .head
        .revision;
    // Fresh: through the deadline the resource stays.
    for elapsed in [0, 1, 60_000] {
        let expired = publish(store, &ns, opened.add_physical_ms(elapsed), |e| {
            resource::expire(e, &asserter(), &id, observed)
        })?;
        assert!(!expired, "{elapsed} ms");
    }
    // A stage since the observation defeats the stale expiry. It is
    // admitted at the deadline itself, the last moment of the window, and
    // after every epoch above: a namespace's epochs never regress in time.
    stage(
        store,
        &ns,
        &id,
        b"renewed",
        0,
        None,
        opened.add_physical_ms(60_000),
    )?;
    let stale = publish(store, &ns, opened.add_physical_ms(120_000), |e| {
        resource::expire(e, &asserter(), &id, observed)
    })?;
    assert!(!stale);
    let current = resource::resolve(store, &ns, &id)?
        .ok_or("resource vanished")?
        .head
        .revision;
    let expired = publish(store, &ns, opened.add_physical_ms(120_000), |e| {
        resource::expire(e, &asserter(), &id, current)
    })?;
    assert!(expired);
    assert!(resource::resolve(store, &ns, &id)?.is_none());
    // Expiry is scoped: the other namespace's resource is untouched, and
    // staging into an expired window is refused.
    assert!(resource::resolve(store, &other, &other_id)?.is_some());
    assert!(matches!(
        stage(
            store,
            &other,
            &other_id,
            b"late",
            0,
            None,
            opened.add_physical_ms(120_000)
        ),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

fn exercise_frozen_generation(store: &(impl Staging + ?Sized)) -> TestResult {
    let ns = create(store, "frozen")?;
    let now = at(1_700_000_005_000);
    let id = open(store, &ns, ResourceKind::Sequential, 0, now)?;
    stage(store, &ns, &id, b"abc", 0, None, now)?;
    let request = Kappa::sha256(b"request");
    let generation = publish(store, &ns, now, |e| {
        Ok(resource::prepare(e, &asserter(), &id, &request, &[])?.generation)
    })?;
    // Preparation closes admission.
    assert!(matches!(
        stage(store, &ns, &id, b"d", 3, None, now),
        Err(StoreError::Conflict(_))
    ));
    // The same request is idempotent and writes nothing: a caller that
    // discards the execution publishes no epoch. A different request
    // supersedes.
    let (before, _) = store.epoch_current(&ns)?;
    let again = {
        let mut execution = store.begin_execution(&ns, &clock_at(now)?)?;
        let prepared = resource::prepare(&mut *execution, &asserter(), &id, &request, &[])?;
        assert!(!prepared.frozen);
        execution.abort()?;
        prepared.generation
    };
    assert_eq!(again, generation);
    assert_eq!(store.epoch_current(&ns)?.0, before);
    let other = Kappa::sha256(b"other request");
    let superseded = publish(store, &ns, now, |e| {
        let prepared = resource::prepare(e, &asserter(), &id, &other, &[])?;
        assert!(prepared.frozen);
        Ok(prepared.generation)
    })?;
    assert_ne!(superseded, generation);
    // Evidence for the superseded generation cannot be produced or used.
    assert!(matches!(
        resource::prepare_composition(
            store,
            &ns,
            &id,
            &generation,
            Axis::Sha256,
            bounds().deadline
        ),
        Err(StoreError::Conflict(_))
    ));
    // A deadline already passed streams nothing and produces no evidence.
    assert!(matches!(
        resource::prepare_composition(
            store,
            &ns,
            &id,
            &superseded,
            Axis::Sha256,
            std::time::Instant::now()
        ),
        Err(StoreError::Rejected(_))
    ));
    let evidence = resource::prepare_composition(
        store,
        &ns,
        &id,
        &superseded,
        Axis::Sha256,
        bounds().deadline,
    )?;
    assert_eq!(evidence.identity(), &Kappa::sha256(b"abc"));
    let (installed, binding) = publish(store, &ns, now, |e| {
        let completed = resource::complete(e, &asserter(), &id, &evidence, None)?;
        assert!(!completed.replayed);
        Ok((completed.installed.kappa, completed.binding))
    })?;
    assert_eq!(installed, Kappa::sha256(b"abc"));
    assert_eq!(binding.request, other);
    assert_eq!(binding.generation, superseded);
    // A composite of one member is that member's own bytes: its committed
    // representation is selected and no new composition is recorded.
    assert!(recorded_compositions(store, &ns)?.is_empty());
    // Completing again with the same evidence replays the binding and is
    // marked as a replay, so a caller repeats none of its effects.
    let replayed = publish(store, &ns, now, |e| {
        let completed = resource::complete(e, &asserter(), &id, &evidence, None)?;
        Ok((
            completed.replayed,
            completed.binding,
            completed.installed.newly_stored,
        ))
    })?;
    assert_eq!(replayed, (true, binding, false));
    // Evidence of one resource cannot complete another.
    let stranger = open(store, &ns, ResourceKind::Sequential, 0, now)?;
    assert!(matches!(
        publish(store, &ns, now, |e| {
            resource::complete(e, &asserter(), &stranger, &evidence, None).map(|_| ())
        }),
        Err(StoreError::Rejected(_))
    ));
    Ok(())
}

/// A stream whose every read fails.
struct Failing;

impl std::io::Read for Failing {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("injected stream failure"))
    }
}

fn exercise_concurrent_preparation(store: &(impl Staging + ?Sized)) -> TestResult {
    let ns = create(store, "concurrent")?;
    let now = at(1_700_000_006_000);
    let bytes = vec![42u8; 131_079];
    let identity = Kappa::sha256(&bytes);
    let barrier = Barrier::new(8);
    let inserted: usize = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (bytes, ns, barrier) = (&bytes, &ns, &barrier);
                scope.spawn(move || -> Result<bool, StoreError> {
                    let prepared = computed(store, bytes)?;
                    barrier.wait();
                    publish(store, ns, now, |e| {
                        Ok(e.content_install(prepared)?.newly_stored)
                    })
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| StoreError::Internal("preparer panicked".into()))
                    .and_then(|outcome| outcome)
                    .map(usize::from)
            })
            .sum::<Result<usize, StoreError>>()
    })?;
    assert_eq!(inserted, 1);
    assert_eq!(store.blob_get(&identity)?, bytes);

    // A failing stream prepares nothing and exposes no content.
    assert!(matches!(
        store.prepare_content(
            ContentIdentity::Computed(Axis::Sha256),
            &mut Failing,
            bounds()
        ),
        Err(StoreError::Io(_))
    ));
    let expected = Kappa::sha256(b"expected");
    assert!(
        prepare(
            store,
            ContentIdentity::Verified(expected.clone()),
            b"different"
        )
        .is_err()
    );
    assert!(!store.blob_exists(&expected)?);
    Ok(())
}

fn exercise(store: &(impl Staging + ?Sized)) -> TestResult {
    exercise_membership_and_release(store)?;
    exercise_stage_racing_discard(store)?;
    exercise_expiry(store)?;
    exercise_frozen_generation(store)?;
    exercise_concurrent_preparation(store)
}

#[test]
fn memory_resources_survive_races_expiry_and_supersession() -> TestResult {
    let fixture = kappa_store_memory::test_support::test_store()?;
    exercise(fixture.store())?;
    assert_eq!(
        staging_dirs(fixture.blob_root())?,
        Vec::<std::path::PathBuf>::new()
    );
    Ok(())
}

#[test]
fn persistent_resources_survive_races_expiry_and_supersession() -> TestResult {
    let store = kappa_store_redb::test_support::persistent_store()?;
    exercise(store.store())?;
    assert_eq!(
        staging_dirs(store.blob_root())?,
        Vec::<std::path::PathBuf>::new()
    );
    Ok(())
}

#[test]
fn execution_view_includes_private_stages() -> TestResult {
    let fixture = kappa_store_memory::test_support::test_store()?;
    let store = fixture.store();
    let ns = create(store, "private-view")?;
    let now = at(1_700_000_007_000);
    let id = open(store, &ns, ResourceKind::Sequential, 0, now)?;
    let identity = Kappa::sha256(b"xyz");
    let prepared = computed(store, b"xyz")?;
    let mut execution = store.begin_execution(&ns, &clock_at(now)?)?;
    resource::stage(&mut *execution, &asserter(), &id, prepared, 0, None)?;
    // The execution sees its own stage; the committed store does not yet.
    let head = resource::resolve_in(&*execution, &id)?
        .ok_or("head missing")?
        .head;
    assert_eq!(resource::members_in(&*execution, &head)?.len(), 1);
    assert_eq!(head.member_count, 1);
    assert_eq!(execution.namespace().id(), ns.id());
    assert!(!store.blob_exists(&identity)?, "staged content is private");
    let committed = resource::resolve(store, &ns, &id)?
        .ok_or("head missing")?
        .head;
    assert_eq!(committed.member_count, 0);
    execution.abort()?;
    assert!(!store.blob_exists(&identity)?, "abort publishes nothing");
    assert_eq!(
        resource::resolve(store, &ns, &id)?
            .ok_or("head missing")?
            .head
            .revision,
        committed.revision
    );
    Ok(())
}
