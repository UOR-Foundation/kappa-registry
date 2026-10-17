//! Identity-index workload coverage. These are substrate workloads, not
//! substitutes for public protocol, durable-store, or graph acceptance tests.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use kappa_cursor::{KappaCursor, TERMINATED};
use kappa_succinct::{IncrementalDigest, LoudsDsTrie, TrieConfig, TrieError, TrieIndex};
use sha2::{Digest, Sha256, Sha512};

#[derive(Clone, Copy, Debug)]
enum Population {
    Sha256,
    Sha512,
    SharedPrefix,
}

impl Population {
    /// The `KAPPA_SCALE_POPULATION` token, as `succinct-scale.sh` names rungs.
    const fn token(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
            Self::SharedPrefix => "prefix",
        }
    }
}

/// One retained reader's seek latency percentiles.
struct ReaderSeeks {
    p50: Duration,
    p99: Duration,
}

/// What `contention` measured: per-mutation-batch and per-rebuild latency,
/// and each retained reader's seek percentiles.
struct Contention {
    mutation_latency: Vec<Duration>,
    rebuild_latency: Vec<Duration>,
    readers: Vec<ReaderSeeks>,
}

fn populations() -> Vec<Population> {
    match std::env::var("KAPPA_SCALE_POPULATION").as_deref() {
        Ok("sha256") => vec![Population::Sha256],
        Ok("sha512") => vec![Population::Sha512],
        Ok("prefix") => vec![Population::SharedPrefix],
        Err(std::env::VarError::NotPresent) | Ok("all") => vec![
            Population::Sha256,
            Population::Sha512,
            Population::SharedPrefix,
        ],
        _ => panic!("KAPPA_SCALE_POPULATION must be sha256, sha512, prefix, or all"),
    }
}

fn identity(population: Population, number: u64) -> Vec<u8> {
    let input = number.to_be_bytes();
    match population {
        Population::Sha256 => {
            let mut key = vec![0];
            key.extend_from_slice(&Sha256::digest(input));
            key
        }
        Population::Sha512 => {
            let mut key = vec![1];
            key.extend_from_slice(&Sha512::digest(input));
            key
        }
        // Ordered namespace/repository-like prefixes are an adversarial shape
        // for traversal; they do not claim to be content hashes or wire tags.
        Population::SharedPrefix => {
            let mut key = vec![2; 33];
            key[0] = 0;
            key[25..].copy_from_slice(&input);
            key
        }
    }
}

fn verify_snapshot(snapshot: &kappa_succinct::TrieSnapshot, expected: &[Vec<u8>]) {
    let mut digest = IncrementalDigest::new();
    let mut cursor = snapshot.cursor();
    for key in expected {
        assert_eq!(cursor.key(), key);
        digest.insert(key);
        cursor.advance();
    }
    assert_eq!(cursor.key(), TERMINATED);
    assert_eq!(cursor.advance(), TERMINATED);
    assert_eq!(snapshot.logical_digest(), digest.value());
}

fn peak_rss_kib() -> Option<u64> {
    // Linux process high-water RSS, including setup and all retained versions.
    // Run endurance tests alone to avoid attributing other tests' peaks here.
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|line| line.starts_with("VmHWM:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn percentile(samples: &mut [Duration], percent: usize) -> Duration {
    samples.sort_unstable();
    samples[(samples.len() * percent).div_ceil(100).saturating_sub(1)]
}

fn retained_seeks(
    snapshot: &kappa_succinct::TrieSnapshot,
    expected: &[Vec<u8>],
    reader: usize,
    samples: &mut Vec<Duration>,
    record: bool,
) {
    for query in 0..128 {
        let position = (query * 7919 + reader * 101) % expected.len();
        let mut cursor = snapshot.cursor();
        let start = Instant::now();
        assert_eq!(cursor.seek(&expected[position]), expected[position]);
        if record {
            samples.push(start.elapsed());
        }
    }
}

struct ReleaseReaders<'a>(&'a AtomicUsize);

impl Drop for ReleaseReaders<'_> {
    fn drop(&mut self) {
        self.0.store(usize::MAX, Ordering::Release);
    }
}

struct Feedback {
    stop: Option<std::sync::mpsc::Sender<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Feedback {
    fn start(population: Population, count: usize) -> Self {
        let (stop, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let start = Instant::now();
            while matches!(
                receiver.recv_timeout(Duration::from_secs(10)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                eprintln!(
                    "{population:?}: workload heartbeat keys={count}, elapsed={:?}, process_peak_rss_kib={:?}",
                    start.elapsed(),
                    peak_rss_kib()
                );
            }
        });
        Self {
            stop: Some(stop),
            worker: Some(worker),
        }
    }
}

impl Drop for Feedback {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(worker) = self.worker.take() {
            assert!(worker.join().is_ok(), "feedback worker panicked");
        }
    }
}

fn setting(name: &str, default: usize) -> Result<usize, TrieError> {
    match std::env::var(name) {
        Ok(value) => value.parse().map_err(|_| TrieError::VerificationFailed),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(_) => Err(TrieError::VerificationFailed),
    }
}

fn reader_work(
    snapshot: &kappa_succinct::TrieSnapshot,
    expected: &[Vec<u8>],
    reader: usize,
    published: &AtomicUsize,
    commands: std::sync::mpsc::Receiver<usize>,
    acknowledge: &std::sync::mpsc::Sender<(usize, bool)>,
) -> Vec<Duration> {
    let mut samples = Vec::new();
    for round in commands {
        retained_seeks(snapshot, expected, reader, &mut samples, true);
        if acknowledge.send((round, false)).is_err() {
            return samples;
        }
        while published.load(Ordering::Acquire) < round {
            retained_seeks(snapshot, expected, reader, &mut samples, false);
            std::thread::yield_now();
        }
        retained_seeks(snapshot, expected, reader, &mut samples, true);
        if acknowledge.send((round, true)).is_err() {
            return samples;
        }
    }
    if reader == 0 {
        verify_snapshot(snapshot, expected);
    }
    samples
}

fn exercise(
    population: Population,
    count: usize,
    readers: usize,
    rounds: usize,
) -> Result<(), TrieError> {
    assert!(count > 0 && readers > 0 && rounds > 0);
    let _feedback = Feedback::start(population, count);
    let started = Instant::now();
    let batch = setting("KAPPA_SCALE_MUTATIONS_PER_ROUND", 64)?;
    assert!(batch > 0);
    let added = rounds
        .checked_mul(batch)
        .ok_or(TrieError::VerificationFailed)?;
    eprintln!("{population:?}: generating {count} identities");
    let mut initial = Vec::with_capacity(count);
    for n in 0..count as u64 {
        initial.push(identity(population, n));
        if (n + 1) % 1_000_000 == 0 {
            eprintln!(
                "{population:?}: generated {}/{count}, elapsed {:?}, peak RSS KiB {:?}",
                n + 1,
                started.elapsed(),
                peak_rss_kib()
            );
        }
    }
    eprintln!(
        "{population:?}: sorting {count} identities, elapsed {:?}",
        started.elapsed()
    );
    initial.sort_unstable();
    assert!(initial.windows(2).all(|pair| pair[0] < pair[1]));
    let index = Arc::new(TrieIndex::new(TrieConfig::default()));
    eprintln!(
        "{population:?}: constructing initial index, elapsed {:?}",
        started.elapsed()
    );
    index.build_initial(initial.iter().map(Vec::as_slice))?;
    eprintln!(
        "{population:?}: initial index published after {:?}, peak RSS KiB {:?}",
        started.elapsed(),
        peak_rss_kib()
    );
    let retained = index.trie_snapshot()?;
    let Contention {
        mut mutation_latency,
        mut rebuild_latency,
        readers: reader_seeks,
    } = contention(
        population, &index, &initial, readers, rounds, batch, started,
    )?;
    verify_snapshot(&retained, &initial);
    let mut expected = initial;
    expected.extend((0..added as u64).map(|n| identity(population, count as u64 + n)));
    expected.sort_unstable();
    verify_snapshot(&index.trie_snapshot()?, &expected);
    verify_reconstruction(population, &expected, started)?;
    let elapsed = started.elapsed();
    let peak_rss = peak_rss_kib().ok_or(TrieError::VerificationFailed)?;
    let mutation_p99 = percentile(&mut mutation_latency, 99);
    let rebuild_p99 = percentile(&mut rebuild_latency, 99);
    eprintln!(
        "{population:?}: initial_keys={count} final_keys={} readers={readers} rounds={rounds} mutation_calls={} elapsed={elapsed:?} process_peak_rss_kib={peak_rss} mutation_batch_p99={mutation_p99:?} rebuild_p99={rebuild_p99:?}",
        expected.len(),
        added * 3,
    );
    // One machine record per run: integer nanoseconds and KiB, key=value,
    // which succinct-scale.sh copies into named results.tsv columns for the
    // performance envelope (KAPPA-PERF-001 PERF-DOC-021).
    let seek = |pick: fn(&ReaderSeeks) -> Duration| {
        let values = reader_seeks.iter().map(pick);
        (values.clone().min(), values.max())
    };
    let (Some(seek_p50_min), Some(seek_p50_max)) = seek(|r| r.p50) else {
        return Err(TrieError::VerificationFailed);
    };
    let (Some(seek_p99_min), Some(seek_p99_max)) = seek(|r| r.p99) else {
        return Err(TrieError::VerificationFailed);
    };
    eprintln!(
        "scale_result population={} initial_keys={count} final_keys={} readers={readers} rounds={rounds} mutation_calls={} elapsed_ns={} peak_rss_kib={peak_rss} mutation_batch_p99_ns={} rebuild_p99_ns={} seek_p50_min_ns={} seek_p50_max_ns={} seek_p99_min_ns={} seek_p99_max_ns={}",
        population.token(),
        expected.len(),
        added * 3,
        elapsed.as_nanos(),
        mutation_p99.as_nanos(),
        rebuild_p99.as_nanos(),
        seek_p50_min.as_nanos(),
        seek_p50_max.as_nanos(),
        seek_p99_min.as_nanos(),
        seek_p99_max.as_nanos(),
    );
    Ok(())
}

fn contention(
    population: Population,
    index: &TrieIndex,
    initial: &[Vec<u8>],
    readers: usize,
    rounds: usize,
    batch: usize,
    started: Instant,
) -> Result<Contention, TrieError> {
    let count = initial.len();
    let snapshots = (0..readers)
        .map(|_| index.trie_snapshot())
        .collect::<Result<Vec<_>, _>>()?;
    let barrier = Arc::new(Barrier::new(readers + 1));
    let published = AtomicUsize::new(0);
    let mut mutation_latency = Vec::new();
    let mut rebuild_latency = Vec::new();
    let mut reader_seeks = Vec::with_capacity(readers);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        let mut controls = Vec::new();
        let release_readers = ReleaseReaders(&published);
        for (reader, snapshot) in snapshots.into_iter().enumerate() {
            let barrier = barrier.clone();
            let expected = &initial;
            let published = &published;
            let (command, commands) = std::sync::mpsc::channel();
            let (acknowledge, acknowledgments) = std::sync::mpsc::channel();
            controls.push((command, acknowledgments));
            handles.push(scope.spawn(move || {
                barrier.wait();
                let seek_latency = reader_work(
                    &snapshot,
                    expected,
                    reader,
                    published,
                    commands,
                    &acknowledge,
                );
                eprintln!("{population:?}: reader {reader} checks complete");
                seek_latency
            }));
        }
        barrier.wait();
        for round in 0..rounds {
            for (command, _) in &controls {
                command
                    .send(round + 1)
                    .map_err(|_| TrieError::VerificationFailed)?;
            }
            for (_, acknowledgments) in &controls {
                assert_eq!(
                    acknowledgments
                        .recv()
                        .map_err(|_| TrieError::VerificationFailed)?,
                    (round + 1, false)
                );
            }
            for operation in 0..batch {
                let sequence = round * batch + operation;
                let start = Instant::now();
                let removed = identity(population, (sequence % count) as u64);
                index.delete(removed.clone())?;
                index.insert(identity(population, (count + sequence) as u64))?;
                index.insert(removed)?;
                mutation_latency.push(start.elapsed());
            }
            let start = Instant::now();
            eprintln!("{population:?}: rebuilding round {}/{rounds}", round + 1);
            // Release readers even if rebuilding fails, so scoped cleanup can
            // join them rather than leaving them spinning on publication.
            let rebuilt = index.rebuild();
            published.store(round + 1, Ordering::Release);
            rebuilt?;
            rebuild_latency.push(start.elapsed());
            for (_, acknowledgments) in &controls {
                assert_eq!(
                    acknowledgments
                        .recv()
                        .map_err(|_| TrieError::VerificationFailed)?,
                    (round + 1, true)
                );
            }
            eprintln!(
                "{population:?}: round {} retained-reader overlap verified: {readers} readers checked before and after publication",
                round + 1
            );
            eprintln!(
                "{population:?}: rebuild round {}/{rounds} published, elapsed {:?}, peak RSS KiB {:?}",
                round + 1,
                started.elapsed(),
                peak_rss_kib()
            );
        }
        drop(release_readers);
        drop(controls);
        for handle in handles {
            let mut samples = handle.join().map_err(|_| TrieError::VerificationFailed)?;
            let p50 = percentile(&mut samples, 50);
            let p99 = percentile(&mut samples, 99);
            eprintln!("{population:?}: retained-reader seek p50={p50:?} p99={p99:?}");
            reader_seeks.push(ReaderSeeks { p50, p99 });
        }
        Ok::<(), TrieError>(())
    })?;
    Ok(Contention {
        mutation_latency,
        rebuild_latency,
        readers: reader_seeks,
    })
}

fn verify_reconstruction(
    population: Population,
    expected: &[Vec<u8>],
    started: Instant,
) -> Result<(), TrieError> {
    // Reconstruction recovery at the index boundary; durable registry crash
    // recovery is a separate backend contract, not established by this check.
    eprintln!(
        "{population:?}: building reconstruction-recovery input, elapsed {:?}",
        started.elapsed()
    );
    let trie = LoudsDsTrie::build(&TrieConfig::default(), expected.iter().map(Vec::as_slice))?;
    eprintln!(
        "{population:?}: serializing and validating recovery, elapsed {:?}",
        started.elapsed()
    );
    let recovered = LoudsDsTrie::deserialize(&trie.serialize()?)?;
    for position in (0..expected.len()).step_by((expected.len() / 128).max(1)) {
        let ordinal = recovered
            .ordinal(&expected[position])
            .ok_or(TrieError::VerificationFailed)?;
        assert_eq!(
            recovered
                .key_at(ordinal)
                .ok_or(TrieError::VerificationFailed)?,
            expected[position]
        );
    }
    Ok(())
}

#[test]
fn realistic_identities_survive_concurrent_readers_mutations_and_rebuilds() -> Result<(), TrieError>
{
    for population in populations() {
        exercise(population, 512, 4, 4)?;
    }
    Ok(())
}

#[test]
#[ignore = "endurance: 10M realistic identities, retained readers and rebuilds; high memory, potentially hours; use release --ignored --nocapture --test-threads=1"]
fn realistic_identity_scale_endurance() -> Result<(), TrieError> {
    let count = setting("KAPPA_SCALE_KEYS", 10_000_000)?;
    let readers = setting("KAPPA_SCALE_READERS", 16)?;
    let rounds = setting("KAPPA_SCALE_ROUNDS", 8)?;
    for population in populations() {
        eprintln!(
            "Starting {population:?}: {count} keys, {readers} readers, {rounds} rebuild rounds"
        );
        exercise(population, count, readers, rounds)?;
    }
    Ok(())
}

#[test]
#[ignore = "endurance: explicit 1K through 1B partition scale ladder; use KAPPA_SCALE_COUNTS to select rungs; release --ignored --nocapture"]
fn realistic_identity_scale_ladder() -> Result<(), TrieError> {
    let counts = std::env::var("KAPPA_SCALE_COUNTS")
        .unwrap_or_else(|_| "1000,10000,100000,1000000,10000000,100000000,1000000000".into());
    let readers = setting("KAPPA_SCALE_READERS", 16)?;
    let rounds = setting("KAPPA_SCALE_ROUNDS", 8)?;
    for count in counts.split(',') {
        let count = count
            .trim()
            .parse()
            .map_err(|_| TrieError::VerificationFailed)?;
        for population in populations() {
            eprintln!(
                "Scale ladder: {count} keys, {readers} readers, {rounds} rounds, {population:?}"
            );
            exercise(population, count, readers, rounds)?;
        }
    }
    Ok(())
}
