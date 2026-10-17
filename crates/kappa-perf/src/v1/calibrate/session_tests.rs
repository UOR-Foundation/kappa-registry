use super::*;
use crate::calibrate::record::Grade;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Dirs {
    _root: tempfile::TempDir,
    target: PathBuf,
    criterion: PathBuf,
}

fn dirs() -> Result<Dirs, std::io::Error> {
    let root = tempfile::tempdir()?;
    let target = root.path().join("target");
    let criterion = target.join("criterion");
    std::fs::create_dir_all(&criterion)?;
    Ok(Dirs {
        target,
        criterion,
        _root: root,
    })
}

fn session(dirs: &Dirs, name: &str, profile: Profile) -> Result<CalibratedSession, SessionError> {
    CalibratedSession::with_dirs(name, profile, "std", &dirs.target, &dirs.criterion)
}

fn id(raw: &str) -> Result<OscId, Box<dyn std::error::Error>> {
    Ok(raw.parse()?)
}

fn dataset_ids(path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut ids = Vec::new();
    for line in std::fs::read_to_string(path)?.lines() {
        ids.push(serde_json::from_str::<CalibrationPoint>(line)?.id);
    }
    Ok(ids)
}

#[test]
fn rejects_invalid_names_and_runtimes() -> TestResult {
    let dirs = dirs()?;
    assert!(matches!(
        session(&dirs, "Floors", Profile::L6Graded),
        Err(SessionError::InvalidName(_))
    ));
    assert!(matches!(
        session(&dirs, "", Profile::L6Graded),
        Err(SessionError::InvalidName(_))
    ));
    assert!(matches!(
        CalibratedSession::with_dirs(
            "ok",
            Profile::L6Graded,
            "No Way",
            &dirs.target,
            &dirs.criterion
        ),
        Err(SessionError::InvalidRuntime(_))
    ));
    Ok(())
}

#[test]
fn composites_skip_until_their_floors_are_recorded() -> TestResult {
    let dirs = dirs()?;
    let mut s = session(&dirs, "deps", Profile::L6Graded)?;
    let put = id("osc:bw/store.blob_put?axis=sha256&size=1m")?;
    let skip = s.check_deps(&put).err().ok_or("blob_put must be gated")?;
    for floor in ["hash.sha256", "device.seq_write", "mem.read"] {
        assert!(
            skip.missing.iter().any(|m| m == floor),
            "{floor} missing from {skip}"
        );
    }
    s.record_direct(&id("osc:bw/mem.read?size=1m")?, 1e10, None)?;
    s.record_direct(&id("osc:bw/hash.sha256?size=1m")?, 4e8, None)?;
    assert!(s.check_deps(&put).is_err(), "device floor still missing");
    s.record_direct(&id("osc:bw/device.seq_write?size=1m")?, 2e9, None)?;
    s.check_deps(&put)?;
    // Below L3 nothing is gated.
    session(&dirs, "ungated", Profile::L2Substrate)?.check_deps(&put)?;
    Ok(())
}

#[test]
fn same_host_baseline_floors_satisfy_dependencies() -> TestResult {
    let dirs = dirs()?;
    let mut floors = session(&dirs, "floors", Profile::L6Graded)?;
    floors.record_direct(&id("osc:lat/device.fdatasync?size=4k")?, 1_000_000.0, None)?;
    floors.record_direct(&id("osc:bw/device.seq_write?size=4k")?, 1e9, None)?;
    floors.finalize()?;

    let workload = session(&dirs, "workloads", Profile::L6Graded)?;
    assert_eq!(workload.baseline().len(), 2);
    workload.check_deps(&id("osc:lat/redb.commit?durability=immediate")?)?;
    Ok(())
}

/// Gating must not depend on bench order: a composite whose constituent was
/// measured, trusted, on this host by another session runs, wherever in its
/// own session it falls. Those records establish dependencies only; they
/// never become floors.
#[test]
fn other_sessions_establish_dependencies_but_never_floors() -> TestResult {
    let dirs = dirs()?;
    let mut floors = session(&dirs, "floors", Profile::L6Graded)?;
    floors.record_direct(&id("osc:lat/mem.alloc?alloc=fresh&size=64")?, 20.0, None)?;
    floors.record_direct(
        &id("osc:lat/canonical.decode?record=epoch_root")?,
        900.0,
        None,
    )?;
    floors.finalize()?;

    let replay = id("osc:lat/store.operation_replay?backend=memory")?;
    let before = session(&dirs, "contention", Profile::L6Graded)?;
    let skip = before
        .check_deps(&replay)
        .err()
        .ok_or("store.epoch_get is not established anywhere yet")?;
    assert_eq!(skip.missing, ["store.epoch_get"]);

    let mut workloads = session(&dirs, "workloads", Profile::L6Graded)?;
    workloads.record_direct(
        &id("osc:lat/store.epoch_get?backend=memory")?,
        5_000.0,
        None,
    )?;
    workloads.finalize()?;

    let after = session(&dirs, "contention", Profile::L6Graded)?;
    after.check_deps(&replay)?;
    assert_eq!(after.baseline().len(), 2, "workload records are not floors");
    assert!(!after.baseline().has_operation("store.epoch_get"));
    Ok(())
}

#[test]
fn physics_violations_are_untrusted_and_still_graded() -> TestResult {
    let dirs = dirs()?;
    let mut s = session(&dirs, "physics", Profile::L6Graded)?;
    s.record_direct(&id("osc:bw/hash.sha256?size=1m")?, 4e8, None)?;
    s.record_direct(
        &id("osc:bw/device.seq_write?durability=none&size=1m")?,
        2e9,
        None,
    )?;
    let put = id("osc:bw/store.blob_put?axis=sha256&durability=none&size=1m")?;
    s.record_direct(&put, 9e8, Some("PERF-STO-023"))?;
    let summary = s.finalize()?;
    let record = s
        .records()
        .find(|r| r.operation == "store.blob_put")
        .ok_or("missing")?;
    assert!(!record.trusted);
    assert!(
        record
            .diagnosis
            .iter()
            .any(|d| d.starts_with("blob_put_le_hash_sha256"))
    );
    let roofline = record.roofline.as_ref().ok_or("ungraded")?;
    assert_eq!(roofline.class, "ingest_single_object");
    assert_eq!(roofline.grade, Grade::A, "grade is independent of trust");
    assert_eq!(record.test_id.as_deref(), Some("PERF-STO-023"));
    assert!(
        record
            .dependencies
            .iter()
            .any(|d| d.contains("hash.sha256"))
    );
    assert_eq!(summary.untrusted.len(), 1);
    assert_eq!(summary.classes.len(), 1);
    Ok(())
}

/// A governor, turbo, SMT or isolation change mid-session refuses the next
/// record: the session's records would otherwise state conditions they
/// were not measured under.
#[test]
fn changed_run_conditions_refuse_further_records() -> TestResult {
    let dirs = dirs()?;
    let mut s = session(&dirs, "drift", Profile::L6Graded)?;
    s.record_direct(&id("osc:bw/mem.read?size=1m")?, 1e10, None)?;
    s.platform.governor = Some("a governor this host is not running".into());
    let refused = s.record_direct(&id("osc:bw/mem.copy?size=1m")?, 8e9, None);
    match refused {
        Err(SessionError::RunConditionsChanged { id, changes }) => {
            assert!(id.starts_with("osc:bw/mem.copy?size=1m"), "{id}");
            assert_eq!(changes.len(), 1, "{changes:?}");
            assert!(changes[0].starts_with("governor: "), "{changes:?}");
        }
        other => panic!("expected RunConditionsChanged, got {other:?}"),
    }
    assert_eq!(s.records().count(), 1, "the refused record was not kept");
    Ok(())
}

#[test]
fn production_records_carry_their_best_same_host_reference() -> TestResult {
    let dirs = dirs()?;
    let mut s = session(&dirs, "refs", Profile::L6Graded)?;
    s.record_direct(&id("osc:bw/mem.read?size=64k")?, 1e10, None)?;
    s.record_direct(&id("osc:bw/hash.sha256?size=64k")?, 1.4e8, None)?;
    s.record_direct(&id("osc:bw/hash.sha256?impl=aws_lc&size=64k")?, 4.6e8, None)?;
    let summary = s.finalize()?;
    let ours = s
        .records()
        .find(|r| r.id.starts_with("osc:bw/hash.sha256?size=64k"))
        .ok_or("production record missing")?;
    let reference = ours.reference.as_ref().ok_or("unpaired")?;
    assert_eq!(reference.implementation, "aws_lc");
    assert!(!reference.meets);
    assert!((reference.fraction - 1.4e8 / 4.6e8).abs() < 1e-9);
    let measured_reference = s
        .records()
        .find(|r| r.condition("impl").is_some())
        .ok_or("reference record missing")?;
    assert!(measured_reference.reference.is_none());
    assert_eq!(summary.references.len(), 1);
    assert!(
        summary
            .to_string()
            .contains("0 of 1 production measurements meet")
    );
    Ok(())
}

#[test]
fn criterion_results_are_backfilled_and_absent_ones_reported() -> TestResult {
    let dirs = dirs()?;
    let mut s = session(&dirs, "backfilled", Profile::L6Graded)?;
    let hash = id("osc:bw/hash.sha256?size=64k")?;
    s.record_criterion(
        &hash,
        HarnessCoords {
            group: "hash/64k".into(),
            function: Some("sha256".into()),
            value: None,
        },
        Some("PERF-HSH-010"),
    )?;
    let absent = id("osc:bw/hash.blake3?size=64k")?;
    s.record_criterion(
        &absent,
        HarnessCoords {
            group: "hash/64k".into(),
            function: Some("blake3".into()),
            value: None,
        },
        None,
    )?;

    let new_dir = dirs.criterion.join("hash_64k").join("sha256").join("new");
    std::fs::create_dir_all(&new_dir)?;
    std::fs::write(
        new_dir.join("benchmark.json"),
        r#"{"group_id":"hash/64k","function_id":"sha256","value_str":null,"throughput":{"Bytes":65536},"full_id":"hash/64k/sha256","directory_name":"hash_64k/sha256","title":"hash/64k/sha256"}"#,
    )?;
    let est = r#"{"confidence_interval":{"confidence_level":0.95,"lower_bound":150000.0,"upper_bound":170000.0},"point_estimate":163840.0,"standard_error":100.0}"#;
    std::fs::write(
        new_dir.join("estimates.json"),
        format!(
            r#"{{"mean":{est},"median":{est},"median_abs_dev":{est},"slope":{est},"std_dev":{est}}}"#
        ),
    )?;
    std::fs::write(
        new_dir.join("sample.json"),
        r#"{"sampling_mode":"Linear","iters":[1.0],"times":[163840.0]}"#,
    )?;

    let summary = s.finalize()?;
    let measured = s
        .records()
        .find(|r| r.operation == "hash.sha256")
        .ok_or("missing")?;
    // 65536 bytes in 163840 ns is 4e8 bytes/s.
    assert!((measured.value.ok_or("unmeasured")? - 4e8).abs() < 1.0);
    assert_eq!(
        measured
            .criterion
            .as_ref()
            .map(|c| c.typical_estimator.as_str()),
        Some("criterion.slope")
    );
    assert_eq!(summary.measured, 1);
    assert_eq!(summary.unmeasured.len(), 1);
    assert!(summary.unmeasured[0].1[0].contains("no estimates"));
    Ok(())
}

#[test]
fn dataset_merges_and_unmeasured_runs_leave_it_untouched() -> TestResult {
    let dirs = dirs()?;
    let path = dirs.target.join("calibration_merge.jsonl");
    let mut first = session(&dirs, "merge", Profile::L6Graded)?;
    first.record_direct(&id("osc:bw/mem.read?size=1m")?, 1e10, None)?;
    first.record_direct(&id("osc:bw/mem.copy?size=1m")?, 8e9, None)?;
    assert_eq!(first.finalize()?.dataset.as_deref(), Some(path.as_path()));
    assert_eq!(dataset_ids(&path)?.len(), 2);

    let mut second = session(&dirs, "merge", Profile::L6Graded)?;
    second.record_direct(&id("osc:bw/mem.read?size=1m")?, 1.1e10, None)?;
    second.finalize()?;
    let content = std::fs::read_to_string(&path)?;
    assert_eq!(
        content.lines().count(),
        2,
        "re-measured id replaced, other kept"
    );
    assert!(content.contains("1.1e10") || content.contains("11000000000"));

    let mut third = session(&dirs, "merge", Profile::L6Graded)?;
    third.record_criterion(
        &id("osc:bw/mem.zero?size=1m")?,
        HarnessCoords {
            group: "g".into(),
            function: None,
            value: None,
        },
        None,
    )?;
    assert_eq!(third.finalize()?.dataset, None);
    assert_eq!(std::fs::read_to_string(&path)?, content);
    Ok(())
}

#[test]
fn histograms_report_median_latency_and_mean_rate() -> TestResult {
    let dirs = dirs()?;
    let mut s = session(&dirs, "hist", Profile::L6Graded)?;
    let mut histogram = LatencyHistogram::new()?;
    for ns in [1_000, 1_000, 1_000, 9_000] {
        histogram.record(ns)?;
    }
    s.record_histogram(
        &id("osc:lat/store.tag_get?backend=memory")?,
        &histogram,
        None,
        None,
    )?;
    s.record_histogram(
        &id("osc:ops/store.tag_get?backend=memory")?,
        &histogram,
        None,
        None,
    )?;
    assert!(matches!(
        s.record_histogram(
            &id("osc:lat/store.tag_put")?,
            &LatencyHistogram::new()?,
            None,
            None
        ),
        Err(SessionError::EmptyHistogram { .. })
    ));
    let records: Vec<_> = s.records().collect();
    // Values carry HdrHistogram's three-significant-digit resolution.
    let within = |actual: f64, expected: f64| (actual - expected).abs() <= expected * 1e-3;
    assert!(
        within(records[0].value.ok_or("lat")?, 1_000.0),
        "median, not mean"
    );
    assert!(
        within(records[1].value.ok_or("ops")?, 1e9 / 3_000.0),
        "rate from mean"
    );
    assert!(records[0].histogram.is_some() && records[0].latency.is_some());
    Ok(())
}

#[test]
fn duplicates_are_rejected_and_substrate_is_bound() -> TestResult {
    let dirs = dirs()?;
    let mut s = session(&dirs, "dup", Profile::L2Substrate)?;
    let read = id("osc:bw/mem.read?size=1m")?;
    s.record_direct(&read, 1.0, None)?;
    assert!(matches!(
        s.record_direct(&read, 2.0, None),
        Err(SessionError::Duplicate(_))
    ));
    assert!(matches!(
        s.record_direct(&id("osc:bw/mem.copy?size=1m")?, f64::NAN, None),
        Err(SessionError::NonFinite { .. })
    ));
    let substrate = s
        .records()
        .next()
        .and_then(|r| r.substrate.clone())
        .ok_or("unbound")?;
    assert_eq!(substrate.rsplit('.').next(), Some("std"));
    Ok(())
}

#[test]
fn running_marker_is_written_at_construction_and_removed_at_finalize() -> TestResult {
    let dirs = dirs()?;
    let marker = dirs.target.join(".calibration_marker.running");
    assert!(!marker.exists());
    let mut s = session(&dirs, "marker", Profile::L6Graded)?;
    assert!(marker.exists(), "marker written at construction");
    s.record_direct(&id("osc:bw/mem.read?size=1m")?, 1e10, None)?;
    assert!(marker.exists(), "marker still present during recording");
    s.finalize()?;
    assert!(!marker.exists(), "marker removed at finalize");
    Ok(())
}

#[test]
fn incremental_writes_persist_records_before_finalize() -> TestResult {
    let dirs = dirs()?;
    let dataset = dirs.target.join("calibration_incr.jsonl");
    let mut s = session(&dirs, "incr", Profile::L6Graded)?;
    assert!(
        !dataset.exists(),
        "dataset does not exist before first record"
    );
    s.record_direct(&id("osc:bw/mem.read?size=1m")?, 1e10, None)?;
    // The record was appended immediately.
    let after_first = std::fs::read_to_string(&dataset)?;
    assert_eq!(
        after_first.lines().count(),
        1,
        "one record after first write"
    );
    assert!(after_first.contains("mem.read"));
    s.record_direct(&id("osc:bw/mem.copy?size=1m")?, 8e9, None)?;
    let after_second = std::fs::read_to_string(&dataset)?;
    assert_eq!(
        after_second.lines().count(),
        2,
        "two records after second write"
    );
    // Finalize merges and overwrites with analyzed records.
    s.finalize()?;
    let after_finalize = std::fs::read_to_string(&dataset)?;
    assert_eq!(
        after_finalize.lines().count(),
        2,
        "finalize does not duplicate records"
    );
    Ok(())
}

#[test]
fn previous_crash_is_reported_and_does_not_block_construction() -> TestResult {
    let dirs = dirs()?;
    let marker = dirs.target.join(".calibration_crash.running");
    // Simulate a crashed session by leaving a running marker.
    std::fs::create_dir_all(&dirs.target)?;
    std::fs::write(&marker, b"")?;
    assert!(marker.exists());
    // A new session of the same name detects and reports the crash,
    // but still constructs.
    let mut s = session(&dirs, "crash", Profile::L6Graded)?;
    assert!(
        marker.exists(),
        "marker from the old crash is still present until this session finalizes"
    );
    s.record_direct(&id("osc:bw/mem.read?size=1m")?, 1e10, None)?;
    s.finalize()?;
    assert!(!marker.exists(), "finalize clears the marker");
    Ok(())
}
