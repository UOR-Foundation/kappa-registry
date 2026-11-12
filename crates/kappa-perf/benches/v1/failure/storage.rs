//! Storage gone or unreadable at reopen: the namespace's directory renamed
//! away (`lost_storage`), or its database replaced by an empty file
//! (`empty_database`). Both are injected on the filesystem, outside the
//! store, as the store's own recovery tests inject them, and the store is
//! opened on redb's file backend so what it reads is what the directory
//! holds. Each record carries the store response that proves the fault
//! reached it: `Unavailable` on a miss, never absence, while discovery is
//! incomplete. Measured: the reopen; the refusal a client meets on the lost
//! namespace; what a sibling namespace on the same store meets while
//! another's storage is lost, recorded under whatever outcome it returns
//! (an isolation finding, not a pass condition); bounded settlement steps
//! while an obligation is unreadable, until discovery reaches a readable
//! sibling's unsettled content; and, once the storage is put back,
//! settlement to completion.

use std::time::Duration;

use kappa_perf::bench::{BenchResult, filesystem_fault, outcome, time_once};
use kappa_perf::calibrate::CalibratedSession;
use kappa_store::work::Dimension;
use kappa_store::{
    Axis, BlobStore, ExecutionStore, Kappa, MaintenanceStore, StoreError, VerifiedContent,
};

use crate::maintenance::settle_to_completion;
use crate::recording::{record_settlement, record_under_fault};
use crate::store::{FaultToken, Io, SIGNATURES, Scale, Site, budget, id, publish};

/// Reads timed against the lost namespace per cycle.
const MISSES: usize = 256;
/// Publications attempted on the sibling per cycle.
const SIBLING_WRITES: usize = 32;

/// What a miss must answer while an obligation is unresolved: the evidence
/// the filesystem fault reached the store.
const OBSERVED: &str = "Unavailable on a miss while discovery is incomplete";

/// The bound the store's recovery tests establish for discovery under a
/// one-entry budget with one unreadable obligation among `readable`
/// namespaces: `16 * (readable + 1) + 32` steps.
const fn discovery_bound(readable: u64) -> u64 {
    16 * (readable + 1) + 32
}

pub fn register(
    s: &mut CalibratedSession,
    root: &kappa_fixture::FixtureRoot,
    scale: &Scale,
) -> BenchResult {
    lost_storage(s, root, scale)?;
    empty_database(s, root, scale)
}

/// Publish `bytes` as a blob of `ns` without settling it, and return its
/// identity: content discovery must reconstruct after a reopen.
fn publish_blob(
    store: &kappa_store_redb::PersistentStore,
    site: &Site,
    ns: &kappa_store::NamespaceRef,
    bytes: &[u8],
) -> Result<Kappa, Box<dyn std::error::Error>> {
    let content = VerifiedContent::compute(Axis::Sha256, bytes)?;
    let mut execution = store.begin_execution(ns, &site.clock)?;
    execution.blob_put(&content)?;
    execution.publish()?;
    Ok(Kappa::sha256(bytes))
}

/// A miss that must be `Unavailable`: discovery incomplete, never absence.
fn unavailable_miss(
    store: &kappa_store_redb::PersistentStore,
    absent: &Kappa,
) -> Result<Duration, Box<dyn std::error::Error>> {
    let (read, elapsed) = time_once(|| store.blob_get(absent));
    match read {
        Err(StoreError::Unavailable(_)) => Ok(elapsed),
        other => Err(format!(
            "a miss while an obligation is unresolved answered {other:?}, expected Unavailable"
        )
        .into()),
    }
}

fn lost_storage(
    s: &mut CalibratedSession,
    root: &kappa_fixture::FixtureRoot,
    scale: &Scale,
) -> BenchResult {
    let token = FaultToken::LostStorage;
    let site = Site::prepare(root, token.as_str())?;
    let directory = site.namespace_dir();
    let displaced = site.dir().join("displaced");
    let mut opens = Vec::new();
    let mut misses = Vec::with_capacity(MISSES);
    let mut sibling: Vec<(&'static str, Duration)> = Vec::new();
    let mut passes = Vec::new();
    for round in 0..scale.cycles {
        {
            let store = site.open(Io::File, |_| {})?;
            publish(&store, &site.clock, &site.ns, 0, round)?;
        }
        std::fs::rename(&directory, &displaced)?;
        site.evict_page_cache()?;
        let (store, open) = time_once(|| site.open(Io::File, |_| {}));
        let store = store?;
        opens.push(open);
        for _ in 0..MISSES {
            misses.push(unavailable_miss(&store, &site.absent)?);
        }
        for index in 0..SIBLING_WRITES {
            let (result, elapsed) =
                time_once(|| publish(&store, &site.clock, &site.sibling, index, round));
            sibling.push((outcome(&result)?, elapsed));
        }
        drop(store);
        std::fs::rename(&displaced, &directory)?;
        let restored = site.open(Io::File, |_| {})?;
        passes.push(settle_to_completion(
            &restored,
            &budget(4096, SIGNATURES),
            &site.absent,
        )?);
    }
    let summary = filesystem_fault(token.as_str(), OBSERVED, u64::try_from(misses.len())?);
    record_under_fault(
        s,
        &id(
            "lat",
            "recovery.open",
            &[
                ("backend", "redb"),
                ("fault", token.as_str()),
                ("io", Io::File.as_str()),
                ("pending", "1"),
                ("state", "cold"),
            ],
        )?,
        &opens,
        "PERF-SYS-021",
        &summary,
    )?;
    record_under_fault(
        s,
        &id(
            "lat",
            "store.blob_get",
            &[
                ("backend", "redb"),
                ("fault", token.as_str()),
                ("io", Io::File.as_str()),
                ("outcome", "refused_unavailable"),
            ],
        )?,
        &misses,
        "PERF-SYS-021",
        &summary,
    )?;
    // The sibling's outcomes, each token its own record: what one tenant's
    // lost storage does to another is recorded, not asserted.
    let mut tokens: Vec<&'static str> = sibling.iter().map(|(token, _)| *token).collect();
    tokens.sort_unstable();
    tokens.dedup();
    for seen in tokens {
        let durations: Vec<Duration> = sibling
            .iter()
            .filter(|(token, _)| *token == seen)
            .map(|(_, elapsed)| *elapsed)
            .collect();
        record_under_fault(
            s,
            &id(
                "lat",
                "store.publish",
                &[
                    ("backend", "redb"),
                    ("durability", "immediate"),
                    ("fault", token.as_str()),
                    ("io", Io::File.as_str()),
                    ("mutations", "1"),
                    ("outcome", seen),
                ],
            )?,
            &durations,
            "PERF-SYS-021",
            &summary,
        )?;
    }
    record_settlement(
        s,
        &[
            ("backend", "redb"),
            ("budget", "4096"),
            ("fault", token.as_str()),
            ("io", Io::File.as_str()),
            ("pending", "1"),
        ],
        &passes,
        "PERF-SYS-021",
        &summary,
    )
}

fn empty_database(
    s: &mut CalibratedSession,
    root: &kappa_fixture::FixtureRoot,
    scale: &Scale,
) -> BenchResult {
    let token = FaultToken::EmptyDatabase;
    let site = Site::prepare(root, token.as_str())?;
    let directory = site.namespace_dir();
    let displaced = site.dir().join("displaced");
    let database = directory.join("state.redb");
    let bound = discovery_bound(1);
    let mut opens = Vec::new();
    let mut bounded_steps = Vec::new();
    let mut passes = Vec::new();
    let mut responses = 0u64;
    for round in 0..scale.cycles {
        // Both namespaces hold an epoch past their checkpoint at the fault:
        // the faulted one a tag, the readable sibling a blob whose identity
        // only discovery can make readable again after the reopen.
        let sibling_bytes = format!("failure bench: sibling content, round {round}").into_bytes();
        let sibling_blob = {
            let store = site.open(Io::File, |_| {})?;
            publish(&store, &site.clock, &site.ns, 0, round)?;
            publish_blob(&store, &site, &site.sibling, &sibling_bytes)?
        };
        std::fs::rename(&directory, &displaced)?;
        std::fs::create_dir_all(&directory)?;
        std::fs::File::create(&database)?;
        site.evict_page_cache()?;
        let (store, open) = time_once(|| {
            site.open(Io::File, |config| {
                config.recovery_step = budget(3, SIGNATURES);
            })
        });
        let store = store?;
        opens.push(open);
        // One-entry steps while an obligation is unreadable. Discovery must
        // not starve behind it (settlement_recovery_tests, the unreadable
        // obligation under a one-entry budget): the readable sibling's
        // content must become readable by identity within the store's
        // established bound. A held result answers whatever the coverage
        // (store_access), so this is observable through the public read.
        // Throughout, a miss stays Unavailable, never absence: the
        // unreadable obligation keeps discovery incomplete.
        let limit = budget(1, SIGNATURES);
        let mut continuation = None;
        let mut steps = 0u64;
        let mut served_at = None;
        loop {
            let (progress, elapsed) = time_once(|| store.settle(&limit, continuation.take()));
            let progress = progress?;
            bounded_steps.push(elapsed);
            steps += 1;
            if progress.consumed.get(Dimension::Entries) > 1 {
                return Err(format!(
                    "a one-entry step examined {} entries",
                    progress.consumed.get(Dimension::Entries)
                )
                .into());
            }
            unavailable_miss(&store, &site.absent)?;
            responses += 1;
            match store.blob_get(&sibling_blob) {
                Ok(bytes) if bytes == sibling_bytes => {
                    served_at = Some(steps);
                    break;
                }
                Ok(bytes) => {
                    return Err(format!(
                        "the sibling's blob read back {} bytes that are not what it published",
                        bytes.len()
                    )
                    .into());
                }
                Err(StoreError::Unavailable(_)) => {}
                Err(other) => {
                    return Err(format!(
                        "the sibling's unsettled blob answered {other:?} while discovery runs"
                    )
                    .into());
                }
            }
            if progress.continuation.is_none() || steps >= bound {
                break;
            }
            continuation = progress.continuation;
        }
        let Some(served_at) = served_at else {
            return Err(format!(
                "the readable sibling's content was not discovered within {bound} one-entry steps behind an unreadable obligation"
            )
            .into());
        };
        eprintln!(
            "empty_database round {round}: sibling content discovered after {served_at} one-entry steps (bound {bound})"
        );
        if !database.try_exists()? {
            return Err("an unreadable database was removed".into());
        }
        drop(store);
        std::fs::remove_dir_all(&directory)?;
        std::fs::rename(&displaced, &directory)?;
        let restored = site.open(Io::File, |_| {})?;
        passes.push(settle_to_completion(
            &restored,
            &budget(4096, SIGNATURES),
            &site.absent,
        )?);
    }
    let summary = filesystem_fault(token.as_str(), OBSERVED, responses);
    record_under_fault(
        s,
        &id(
            "lat",
            "recovery.open",
            &[
                ("backend", "redb"),
                ("fault", token.as_str()),
                ("io", Io::File.as_str()),
                ("pending", "1"),
                ("state", "cold"),
            ],
        )?,
        &opens,
        "PERF-SYS-021",
        &summary,
    )?;
    record_under_fault(
        s,
        &id(
            "lat",
            "settlement.step",
            &[
                ("backend", "redb"),
                ("budget", "1"),
                ("fault", token.as_str()),
                ("io", Io::File.as_str()),
                ("pending", "1"),
            ],
        )?,
        &bounded_steps,
        "PERF-SYS-021",
        &summary,
    )?;
    record_settlement(
        s,
        &[
            ("backend", "redb"),
            ("budget", "4096"),
            ("fault", token.as_str()),
            ("io", Io::File.as_str()),
            ("pending", "1"),
        ],
        &passes,
        "PERF-SYS-021",
        &summary,
    )
}
