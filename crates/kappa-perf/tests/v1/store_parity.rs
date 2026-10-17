//! PERF-STO-001: memory and redb parity. The same execution sequence, from
//! the same namespace identity, signer and timestamps, must produce the
//! same epochs on both backends: the same epoch numbers, state digests,
//! tag counts and signed root identities, and the same replayed state.
//! Resource expiry, decided from the committed head against the execution's
//! time, must agree too.
//!
//! PERF-STO-002: execution isolation. Private writes are invisible until
//! publish; abort and drop leave no trace and do not advance the epoch.

use kappa_handler::clock_at;
use kappa_store::resource;
use kappa_store::{
    ClockMs, Kappa, KappaStore, NamespaceRef, ResourceKind, StoreError, TagStore, TagUpdate,
    replay_to,
};

use crate::common::{
    TestResult, WALL_T0, create_ns, hlc, memory_store, on_both_backends, redb_store,
};

// -- PERF-STO-002: isolation --

#[test]
fn private_writes_invisible_until_publish() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "isolation")?;
        let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2000))?)?;
        execution.tag_put(
            "private",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"invisible"),
            },
        )?;
        // The execution sees its own write; the store does not.
        assert_eq!(
            execution.tag_get("private")?.map(|entry| entry.kappa),
            Some(Kappa::sha256(b"invisible"))
        );
        assert!(matches!(
            store.tag_get(&ns, "private"),
            Err(StoreError::NotFound(_))
        ));
        assert_eq!(store.epoch_current(&ns)?.0, 1);

        let published = execution.publish()?;
        assert_eq!(published.epoch_number, 2);
        assert_eq!(
            store.tag_get(&ns, "private")?.kappa,
            Kappa::sha256(b"invisible")
        );
        assert_eq!(store.epoch_current(&ns)?, (2, published.root));
        Ok(())
    })
}

#[test]
fn abort_and_drop_leave_no_trace() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "abort")?;
        let before = (store.epoch_current(&ns)?, store.epoch_state(&ns)?);

        let mut aborted = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2000))?)?;
        aborted.tag_put(
            "aborted",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"vanish"),
            },
        )?;
        aborted.abort()?;

        let mut dropped = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2001))?)?;
        dropped.tag_put(
            "dropped",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"vanish"),
            },
        )?;
        drop(dropped);

        for name in ["aborted", "dropped"] {
            assert!(
                matches!(store.tag_get(&ns, name), Err(StoreError::NotFound(_))),
                "{name} visible"
            );
        }
        assert_eq!((store.epoch_current(&ns)?, store.epoch_state(&ns)?), before);

        // The writer is released: the next execution publishes normally.
        let mut next = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2002))?)?;
        next.tag_put(
            "kept",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"kept"),
            },
        )?;
        assert_eq!(next.publish()?.epoch_number, 2);
        Ok(())
    })
}

// -- PERF-STO-001: parity --

/// `SplitMix64`: a fixed, dependency-free sequence so both backends receive
/// byte-identical operations.
struct SplitMix(u64);

impl SplitMix {
    const fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// `bound` is a nonzero constant at every call site.
    const fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

#[derive(Debug, Clone)]
enum Op {
    Set(String, Kappa),
    Delete(String),
}

#[derive(Debug, Clone)]
struct Batch {
    at: ClockMs,
    ops: Vec<Op>,
    publish: bool,
}

/// Forty executions over a 64-name key space: sets, overwrites and deletes
/// of live names, with every fifth execution aborted.
fn sequence(seed: u64) -> Result<Vec<Batch>, Box<dyn std::error::Error>> {
    let mut rng = SplitMix(seed);
    let mut live = std::collections::BTreeSet::new();
    let mut batches = Vec::new();
    for index in 0..40u64 {
        let mut ops = Vec::new();
        let mut staged = live.clone();
        for _ in 0..=rng.below(24) {
            let name = format!("key-{}", rng.below(64));
            if staged.contains(&name) && rng.below(3) == 0 {
                staged.remove(&name);
                ops.push(Op::Delete(name));
            } else {
                staged.insert(name.clone());
                ops.push(Op::Set(name, Kappa::sha256(&rng.next().to_le_bytes())));
            }
        }
        let publish = index % 5 != 4;
        if publish {
            live = staged;
        }
        batches.push(Batch {
            at: hlc(WALL_T0 + index * 1000)?,
            ops,
            publish,
        });
    }
    Ok(batches)
}

/// Per published epoch: number, root identity, state digest and tag count.
type Trace = Vec<(u64, Kappa, [u8; 32], u64)>;

fn run(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    batches: &[Batch],
) -> Result<Trace, Box<dyn std::error::Error>> {
    let mut execution = store.begin_execution(ns, &clock_at(hlc(WALL_T0 - 1)?)?)?;
    execution.namespace_create(None, None)?;
    execution.publish()?;
    let mut trace = Vec::new();
    for batch in batches {
        let mut execution = store.begin_execution(ns, &clock_at(batch.at)?)?;
        for op in &batch.ops {
            match op {
                Op::Set(name, kappa) => execution.tag_put(
                    name,
                    &TagUpdate::Set {
                        kappa: kappa.clone(),
                    },
                )?,
                Op::Delete(name) => execution.tag_delete(name)?,
            }
        }
        if batch.publish {
            execution.publish()?;
            let (number, root) = store.epoch_current(ns)?;
            let (digest, count) = store.epoch_state(ns)?;
            trace.push((number, root, digest, count));
        } else {
            execution.abort()?;
        }
    }
    Ok(trace)
}

#[test]
fn random_sequences_produce_identical_epochs_on_both_backends() -> TestResult {
    for seed in [1, 0xDEAD_BEEF, 0x5EED_0000_0000_0042] {
        let batches = sequence(seed)?;
        let ns = NamespaceRef::deterministic("parity");
        let memory = memory_store()?;
        let redb = redb_store()?;
        let on_memory = run(&memory, &ns, &batches)?;
        let on_redb = run(&redb, &ns, &batches)?;
        assert_eq!(on_memory.len(), 32, "seed {seed}: 40 executions, 8 aborted");
        for (index, (m, r)) in on_memory.iter().zip(&on_redb).enumerate() {
            assert_eq!(m, r, "seed {seed}: epoch {} diverges", index + 2);
        }

        let head = on_memory.last().map_or(1, |(number, ..)| *number);
        let replayed = replay_to(&memory, &ns, head)?;
        assert_eq!(
            replayed,
            replay_to(&redb, &ns, head)?,
            "seed {seed}: replay diverges"
        );
        for (name, kappa) in &replayed.tags {
            assert_eq!(&memory.tag_get(&ns, name)?.kappa, kappa);
            assert_eq!(&redb.tag_get(&ns, name)?.kappa, kappa);
        }
        assert_eq!(
            replayed.tags.len() as u64,
            on_memory.last().map_or(0, |(.., count)| *count)
        );
    }
    Ok(())
}

// -- Resource expiry parity --

const RESOURCE_TTL_MS: u64 = 3600 * 1000;

fn asserter() -> Kappa {
    Kappa::sha256(b"parity")
}

/// Expire `id` as the eviction task does: against the revision it observed,
/// at physical time `at`.
fn expire(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    id: &str,
    observed: u64,
    at: ClockMs,
) -> Result<bool, StoreError> {
    let mut execution = store.begin_execution(ns, &clock_at(at)?)?;
    let expired = resource::expire(&mut *execution, &asserter(), id, observed)?;
    if expired {
        execution.publish()?;
    } else {
        execution.abort()?;
    }
    Ok(expired)
}

fn resource_lives_for_its_window(store: &dyn KappaStore) -> TestResult {
    let ns = create_ns(store, "resources")?;
    let opened = hlc(WALL_T0)?;
    let mut execution = store.begin_execution(&ns, &clock_at(opened)?)?;
    let head = resource::open(
        &mut *execution,
        &asserter(),
        ResourceKind::Sequential,
        0,
        opened.add_physical_ms(RESOURCE_TTL_MS),
        None,
    )?;
    execution.publish()?;
    let id = head.id();
    let observed = head.revision;
    // A second, a minute and an hour later the resource is alive; the
    // deadline itself is inclusive.
    for elapsed in [1_000, 60_000, RESOURCE_TTL_MS] {
        assert!(
            !expire(store, &ns, &id, observed, hlc(WALL_T0 + elapsed)?)?,
            "{elapsed} ms"
        );
        assert!(resource::resolve(store, &ns, &id)?.is_some());
    }
    let expired_at = hlc(WALL_T0 + RESOURCE_TTL_MS + 1)?;
    assert!(expire(store, &ns, &id, observed, expired_at)?);
    assert!(resource::resolve(store, &ns, &id)?.is_none());
    assert!(!expire(store, &ns, &id, observed, expired_at)?);
    Ok(())
}

#[test]
fn resources_expire_after_their_window_on_both_backends() -> TestResult {
    on_both_backends(resource_lives_for_its_window)
}
