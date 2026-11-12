//! Plumbing shared by the bench binaries: fallible bodies, identifiers,
//! scale tiers, timing, deterministic data, and store fixtures.
//!
//! A criterion body returns a `Duration` and cannot return an error, so a
//! fallible operation inside it records its first failure in a [`Failure`]
//! and stops the sample. After the benchmark the failure is surfaced as the
//! register function's error, the bench binary exits non-zero, and the
//! session is never finalized: a sample that did not do its work never
//! becomes a record. `Failure` is `Sync`, so contended workers and
//! background threads report through the same recorder.

pub mod fixture;

use std::fmt::Display;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use kappa_store::StoreError;
use kappa_store_redb::test_support::Fired;

use crate::calibrate::condition::format_magnitude;
use crate::calibrate::grammar::ParseError;
use crate::calibrate::record::{FaultSummary, Injection};
use crate::calibrate::{Bench, CalibratedSession, LatencyHistogram, OscId, Work};

pub type BenchResult = Result<(), Box<dyn std::error::Error>>;

/// The run seed every deterministic choice of a bench draws from.
///
/// `KAPPA_PERF_SEED` as decimal, `0x` hex, or a 40-character git commit
/// hash whose low 64 bits are the seed (TigerBeetle's VOPR accepts a
/// commit hash the same way, so CI runs seeded by their commit stay
/// reproducible from the hash alone); absent, one is drawn from the OS.
/// Every bench binary prints it before its first measurement and the
/// session stamps it on every record, so a run is reproducible from its
/// dataset. A malformed value is an error, never a silent fallback.
pub fn seed() -> Result<u64, String> {
    match std::env::var("KAPPA_PERF_SEED") {
        Err(std::env::VarError::NotPresent) => {
            let mut bytes = [0u8; 8];
            getrandom::fill(&mut bytes).map_err(|error| format!("drawing a seed: {error}"))?;
            Ok(u64::from_le_bytes(bytes))
        }
        Err(error) => Err(format!("KAPPA_PERF_SEED: {error}")),
        Ok(raw) if raw.len() == 40 && raw.bytes().all(|b| b.is_ascii_hexdigit()) => {
            u64::from_str_radix(&raw[24..], 16)
                .map_err(|error| format!("KAPPA_PERF_SEED={raw}: {error}"))
        }
        Ok(raw) => match raw.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16),
            None => raw.parse::<u64>(),
        }
        .map_err(|error| {
            format!("KAPPA_PERF_SEED={raw}: expected decimal, 0x hex or a 40-hex commit: {error}")
        }),
    }
}

/// The `outcome` condition token of a store call's result: one token per
/// `StoreError` variant a measured call can return. A variant without a
/// token is an error, never a guessed token, because the token is part
/// of the measurement's identity.
pub fn outcome<T>(result: &Result<T, StoreError>) -> Result<&'static str, String> {
    Ok(match result {
        Ok(_) => "admitted",
        Err(StoreError::CapacityExceeded(_)) => "refused_capacity",
        Err(StoreError::Unavailable(_)) => "refused_unavailable",
        Err(StoreError::Conflict(_)) => "refused_conflict",
        Err(StoreError::Rejected(_)) => "refused_rejected",
        Err(StoreError::WorkRefused(_)) => "refused_work",
        Err(StoreError::Io(_)) => "refused_io",
        Err(StoreError::VersionMismatch { .. }) => "refused_version",
        Err(StoreError::DeadlineExceeded { .. }) => "deadline",
        Err(StoreError::PublicationIndeterminate { .. }) => "indeterminate",
        Err(StoreError::PublicationRecoveryRequired { .. }) => "recovery_required",
        Err(StoreError::PublicationRetained(_)) => "retained",
        Err(other) => return Err(format!("no outcome token for {other:?}")),
    })
}

/// The record form of what a fault backend did, named by the `fault`
/// condition token it was measured under.
pub fn backend_fault(armed: &str, fired: Fired) -> FaultSummary {
    FaultSummary {
        armed: armed.to_owned(),
        injection: Injection::Backend {
            performed: fired.performed,
            refused: fired.refused,
            performed_then_failed: fired.performed_then_failed,
            lost_bytes: fired.lost_bytes,
        },
    }
}

/// The record form of a fault injected on the filesystem: the kind of store
/// response that proves it reached the store, and how many such responses
/// the bench received.
pub fn filesystem_fault(armed: &str, observed: impl Into<String>, responses: u64) -> FaultSummary {
    FaultSummary {
        armed: armed.to_owned(),
        injection: Injection::Filesystem {
            observed: observed.into(),
            responses,
        },
    }
}

/// `f` and how long it took: one timed call, its result kept.
pub fn time_once<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let value = f();
    (value, start.elapsed())
}

/// First failure observed inside timed bodies, on any thread. The lock is
/// taken only to record or read a failure, never on the success path of
/// `ok`.
#[derive(Debug, Default)]
pub struct Failure(Mutex<Option<String>>);

impl Failure {
    /// A recorder whose owner panicked mid-record still holds the first
    /// failure, which is the value wanted.
    fn slot(&self) -> MutexGuard<'_, Option<String>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The value, or `None` after recording the error.
    pub fn ok<T, E: Display>(&self, result: Result<T, E>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(error) => {
                self.slot().get_or_insert_with(|| error.to_string());
                None
            }
        }
    }

    /// Record a failed invariant.
    pub fn fail(&self, why: impl Into<String>) {
        self.slot().get_or_insert_with(|| why.into());
    }

    pub fn failed(&self) -> bool {
        self.slot().is_some()
    }

    /// Surface and clear the first recorded failure.
    pub fn check(&self, what: &str) -> BenchResult {
        let recorded = self.slot().take();
        recorded.map_or_else(|| Ok(()), |error| Err(format!("{what}: {error}").into()))
    }
}

/// An HDR distribution of `runs` directly timed executions.
///
/// For operations too slow for criterion's sampling (rebuilds, sweeps,
/// ledger replays), and for operations whose tail is measured, not only
/// their typical cost. Returns `false`, after recording the diagnosis, when
/// its dependencies are not established and nothing ran.
pub fn distribution(
    s: &mut CalibratedSession,
    id: &OscId,
    runs: usize,
    work: Option<Work>,
    test_id: Option<&str>,
    mut run: impl FnMut() -> Result<Duration, Box<dyn std::error::Error>>,
) -> Result<bool, Box<dyn std::error::Error>> {
    if let Err(skip) = s.check_deps(id) {
        eprintln!("{skip}");
        s.skip(skip);
        return Ok(false);
    }
    let mut histogram = LatencyHistogram::new()?;
    for _ in 0..runs {
        histogram.record_duration(run()?)?;
    }
    s.record_histogram(id, &histogram, work, test_id)?;
    Ok(true)
}

pub fn osc(raw: &str) -> Result<OscId, ParseError> {
    raw.parse()
}

/// Canonical magnitude token (`65536` -> `64k`).
pub fn mag(bytes: usize) -> String {
    format_magnitude(u64::try_from(bytes).unwrap_or(u64::MAX))
}

pub fn bytes(n: usize) -> Option<Work> {
    u64::try_from(n).ok().map(Work::Bytes)
}

pub fn elements(n: usize) -> Option<Work> {
    u64::try_from(n).ok().map(Work::Elements)
}

pub fn bench<'a>(
    id: OscId,
    function: &'a str,
    param: impl Into<String>,
    work: Option<Work>,
    test_id: &'a str,
) -> Bench<'a> {
    Bench {
        id,
        function,
        param: Some(param.into()),
        work,
        test_id: Some(test_id),
    }
}

/// `iters` executions of `op`, timed as one span.
pub fn timed(iters: u64, mut op: impl FnMut()) -> Duration {
    let start = Instant::now();
    for _ in 0..iters {
        op();
    }
    start.elapsed()
}

/// Scale tier from `KAPPA_PERF_TIER`. Unknown values are an error naming
/// the valid ones; nothing silently falls back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Smoke,
    Standard,
    Full,
}

impl Tier {
    pub fn from_env() -> Result<Self, String> {
        match std::env::var("KAPPA_PERF_TIER") {
            Err(std::env::VarError::NotPresent) => Ok(Self::Standard),
            Err(error) => Err(format!("KAPPA_PERF_TIER: {error}")),
            Ok(value) => match value.as_str() {
                "smoke" => Ok(Self::Smoke),
                "standard" => Ok(Self::Standard),
                "full" => Ok(Self::Full),
                other => Err(format!(
                    "KAPPA_PERF_TIER={other}: expected smoke, standard or full"
                )),
            },
        }
    }

    /// `smoke`, `standard` and `full` values of a scale parameter.
    pub const fn pick<T: Copy>(self, smoke: T, standard: T, full: T) -> T {
        match self {
            Self::Smoke => smoke,
            Self::Standard => standard,
            Self::Full => full,
        }
    }

    /// Object sizes of the persistent datapath. The device floors and every
    /// store workload use this one list, so each store measurement has a
    /// same-size device floor to be validated and graded against.
    pub const fn storage_sizes(self) -> &'static [usize] {
        self.pick(
            &[4 << 10, 64 << 10, 1 << 20],
            &[4 << 10, 64 << 10, 1 << 20],
            &[4 << 10, 64 << 10, 1 << 20, 16 << 20],
        )
    }

    /// Thread counts for scaling curves: powers of two up to the tier's cap
    /// and never beyond the host's logical CPUs, since oversubscription
    /// measures the scheduler instead of the contended structure. The full
    /// tier ends at the logical CPU count itself.
    pub fn thread_counts(self, logical_cpus: u32) -> Vec<usize> {
        let logical = usize::try_from(logical_cpus).unwrap_or(usize::MAX).max(1);
        let cap = self.pick(2, 8, logical).min(logical);
        let mut counts: Vec<usize> = std::iter::successors(Some(1usize), |n| n.checked_mul(2))
            .take_while(|n| *n <= cap)
            .collect();
        if self == Self::Full && counts.last() != Some(&logical) {
            counts.push(logical);
        }
        counts
    }
}

/// Directory for on-device measurements.
///
/// `KAPPA_PERF_DEVICE_DIR`, else `<cargo target>/kappa-perf-device`. It
/// must be on the device under test; a tmpfs here measures memory and the
/// recorded storage says so.
pub fn device_dir() -> Result<PathBuf, std::io::Error> {
    let dir = std::env::var_os("KAPPA_PERF_DEVICE_DIR").map_or_else(
        || {
            crate::calibrate::backfill::cargo_target_directory()
                .unwrap_or_else(|| PathBuf::from("target"))
                .join("kappa-perf-device")
        },
        PathBuf::from,
    );
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// `SplitMix64`: deterministic offsets and permutations.
#[derive(Debug, Clone)]
pub struct SplitMix(pub u64);

impl SplitMix {
    pub const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `0..bound`.
    ///
    /// # Panics
    ///
    /// When `bound` is zero: an empty range has no member to return.
    pub fn below(&mut self, bound: usize) -> usize {
        assert!(bound > 0, "SplitMix::below on an empty range");
        let bound = u64::try_from(bound).unwrap_or(u64::MAX);
        usize::try_from(self.next_u64() % bound).unwrap_or(usize::MAX)
    }
}

/// Bytes with a position-dependent pattern, so no layer can deduplicate or
/// compress the work away.
pub fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = SplitMix(seed);
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        out.extend_from_slice(&rng.next_u64().to_le_bytes());
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_counts_never_exceed_the_host() {
        assert_eq!(Tier::Smoke.thread_counts(1), vec![1]);
        assert_eq!(Tier::Standard.thread_counts(6), vec![1, 2, 4]);
        assert_eq!(Tier::Standard.thread_counts(64), vec![1, 2, 4, 8]);
        assert_eq!(Tier::Full.thread_counts(12), vec![1, 2, 4, 8, 12]);
        assert_eq!(Tier::Full.thread_counts(16), vec![1, 2, 4, 8, 16]);
    }

    #[test]
    fn failure_keeps_the_first_cause_across_threads() {
        let failure = Failure::default();
        std::thread::scope(|scope| {
            scope.spawn(|| failure.fail("first"));
        });
        failure.fail("second");
        assert!(failure.failed());
        assert!(
            failure
                .check("op")
                .is_err_and(|error| error.to_string() == "op: first")
        );
        assert!(
            failure.check("op").is_ok(),
            "check clears the recorded failure"
        );
    }

    #[test]
    fn below_stays_in_range_and_pattern_is_deterministic() {
        let mut rng = SplitMix(9);
        assert!((0..10_000).all(|_| rng.below(7) < 7));
        assert_eq!(pattern(37, 4), pattern(37, 4));
        assert_ne!(pattern(37, 4), pattern(37, 5));
        assert_eq!(pattern(37, 4).len(), 37);
    }

    /// Every variant a measured call returns has exactly one token, the
    /// token is a registered `outcome` value, and a variant no bench
    /// measures is refused rather than guessed.
    #[test]
    fn outcome_tokens_are_registered_and_distinct() -> Result<(), Box<dyn std::error::Error>> {
        use crate::calibrate::condition::Conditions;
        let results: Vec<Result<(), StoreError>> = vec![
            Ok(()),
            Err(StoreError::CapacityExceeded(String::new())),
            Err(StoreError::Unavailable(String::new())),
            Err(StoreError::Conflict(String::new())),
            Err(StoreError::Rejected(String::new())),
            Err(StoreError::WorkRefused(
                kappa_store::work::WorkExhausted::Deadline,
            )),
            Err(StoreError::Io(std::io::Error::other("x"))),
            Err(StoreError::VersionMismatch {
                expected: 1,
                found: 2,
                current: None,
            }),
            Err(StoreError::DeadlineExceeded {
                namespace: [0; 16],
                overrun_ms: 1,
            }),
            Err(StoreError::PublicationIndeterminate {
                namespace: [0; 16],
                epoch_number: 2,
                root: Box::new(kappa_store::Kappa::sha256(b"root")),
                detail: String::new(),
            }),
            Err(StoreError::PublicationRecoveryRequired {
                namespace: [0; 16],
                epoch_number: 2,
                root: Box::new(kappa_store::Kappa::sha256(b"root")),
                detail: String::new(),
            }),
            Err(StoreError::PublicationRetained(Box::new(
                kappa_store::RetainedPublication {
                    namespace: [0; 16],
                    incarnation: [0; 16],
                    epoch_number: 2,
                    candidate: kappa_store::Kappa::sha256(b"candidate"),
                    signed_root: None,
                    phase: kappa_store::PublicationPhase::Prepared,
                    disposition: kappa_store::RecoveryDisposition::Resumable,
                    cause: String::new(),
                },
            ))),
        ];
        let mut tokens = std::collections::BTreeSet::new();
        for result in &results {
            let token = outcome(result)?;
            Conditions::parse(&format!("outcome={token}"))?;
            assert!(tokens.insert(token), "{token} given to two variants");
        }
        assert_eq!(tokens.len(), results.len());
        assert!(
            outcome::<()>(&Err(StoreError::NotSupported(String::new()))).is_err(),
            "an unmeasured variant has no token"
        );
        Ok(())
    }

    #[test]
    fn seeds_parse_from_every_accepted_form() {
        // The environment is process-wide; this test sets and restores it
        // and is the only test that touches KAPPA_PERF_SEED.
        let cases: [(&str, Option<u64>); 5] = [
            ("42", Some(42)),
            ("0x2a", Some(42)),
            (
                "00da3c77cc03ee28b34378ac4f40168cc22a78b5",
                Some(0x4f40_168c_c22a_78b5),
            ),
            ("forty-two", None),
            ("0xZZ", None),
        ];
        for (raw, expected) in cases {
            // SAFETY: tests in this binary run on one process; no other
            // test reads or writes this variable.
            unsafe { std::env::set_var("KAPPA_PERF_SEED", raw) };
            let parsed = seed();
            match expected {
                Some(value) => assert_eq!(parsed.as_ref().ok(), Some(&value), "{raw}: {parsed:?}"),
                None => assert!(parsed.is_err(), "{raw} must be refused"),
            }
        }
        // SAFETY: as above.
        unsafe { std::env::remove_var("KAPPA_PERF_SEED") };
        assert!(seed().is_ok(), "absent draws from the OS");
    }
}
