use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn id(raw: &str) -> Result<OscId, Box<dyn std::error::Error>> {
    Ok(raw.parse()?)
}

/// A measurement with only a value, as criterion and direct records have.
const fn at(id: &OscId, value: f64, from_baseline: bool) -> Established<'_> {
    Established {
        id,
        value,
        tail: None,
        from_baseline,
    }
}

#[test]
fn rule_ids_are_unique_and_selectors_name_registered_operations() {
    let rules = rules();
    let mut ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
    let total = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), total);
    for rule in &rules {
        for op in [rule.subject.op, rule.bound.op] {
            if let Op::Exact(op) = op {
                assert!(
                    super::super::operation::OperationPath::parse(op).is_ok(),
                    "{}: {op} not registered",
                    rule.id
                );
            }
        }
    }
}

#[test]
fn blob_put_faster_than_its_hash_is_rejected() -> TestResult {
    let rules = rules();
    let hash = id("osc:bw/hash.sha256?size=1m")?;
    let other_size = id("osc:bw/hash.sha256?size=4k")?;
    let put = id("osc:bw/store.blob_put?axis=sha256&backend=redb&size=1m")?;
    let established = [at(&hash, 400e6, false), at(&other_size, 1.0, false)];
    let ok = evaluate(&rules, &at(&put, 350e6, false), &established);
    let digest: Vec<_> = ok
        .iter()
        .filter(|r| r.rule == "blob_put_le_hash_sha256")
        .collect();
    assert_eq!(
        digest.len(),
        1,
        "only the same-size digest is a bound: {ok:?}"
    );
    assert!(digest[0].passed);
    let bad = evaluate(&rules, &at(&put, 900e6, false), &established);
    let violation = bad
        .iter()
        .find(|r| r.rule == "blob_put_le_hash_sha256")
        .ok_or("missing")?;
    assert!(!violation.passed);
    assert_eq!(violation.severity, Severity::Error);
    assert!(violation.diagnosis.is_some());
    Ok(())
}

/// Ingest runs the production digest on one object: a reference
/// implementation the store does not call, or the aggregate rate of several
/// objects hashed in parallel lanes, is not its physical bound.
#[test]
fn digest_bounds_are_the_single_object_production_digest() -> TestResult {
    let rules = rules();
    let ours = id("osc:bw/hash.sha256?size=1m")?;
    let reference = id("osc:bw/hash.sha256?impl=aws_lc&size=1m")?;
    let lanes = id("osc:bw/hash.sha256?objects=8&size=1m")?;
    let put = id("osc:bw/store.blob_put?axis=sha256&backend=redb&size=1m")?;
    let established = [
        at(&ours, 140e6, false),
        at(&reference, 460e6, false),
        at(&lanes, 135e6, false),
    ];
    let results = evaluate(&rules, &at(&put, 138e6, false), &established);
    let digest: Vec<_> = results
        .iter()
        .filter(|r| r.rule == "blob_put_le_hash_sha256")
        .collect();
    assert_eq!(digest.len(), 1, "{results:?}");
    assert_eq!(digest[0].bound_id, ours.canonical());
    assert!(digest[0].passed);
    Ok(())
}

/// redb 4.3.0 makes a durable commit with `StorageBackend::sync_data`
/// (`fdatasync`), never `fsync`: one is the floor, the other is not a bound.
#[test]
fn durable_commit_faster_than_fdatasync_is_rejected() -> TestResult {
    let rules = rules();
    let fdatasync = id("osc:lat/device.fdatasync?size=4k")?;
    let fsync = id("osc:lat/device.fsync?size=4k")?;
    let commit = id("osc:lat/redb.commit?durability=immediate")?;
    let relaxed = id("osc:lat/redb.commit?durability=none")?;
    let established = [
        at(&fdatasync, 1_000_000.0, true),
        at(&fsync, 2_000_000.0, true),
    ];
    let violated = evaluate(&rules, &at(&commit, 500_000.0, false), &established);
    assert!(
        violated
            .iter()
            .any(|r| r.rule == "redb_commit_ge_fdatasync" && !r.passed && r.bound_from_baseline),
        "{violated:?}"
    );
    // The gate warns rather than errors: fast NVMe write caches make
    // fdatasync return in microseconds on both sides of the comparison.
    assert!(
        violated
            .iter()
            .filter(|r| r.rule == "redb_commit_ge_fdatasync")
            .all(|r| r.severity == Severity::Warn),
        "redb commit gate should warn, not error: {violated:?}"
    );
    // One fdatasync plus page writes: durable, and slower than fsync is not
    // required of it. The 0.95 multiplier means 950,000 is the threshold.
    let durable = evaluate(&rules, &at(&commit, 1_200_000.0, false), &established);
    assert!(
        durable
            .iter()
            .filter(|r| r.severity == Severity::Error || r.severity == Severity::Warn)
            .all(|r| r.passed),
        "{durable:?}"
    );
    assert!(
        durable.iter().all(|r| r.bound_id != fsync.canonical()),
        "fsync is not a bound of a commit that never issues it: {durable:?}"
    );
    assert!(
        evaluate(&rules, &at(&relaxed, 500_000.0, false), &established).is_empty(),
        "non-durable commits are not bounded by a device sync"
    );
    Ok(())
}

#[test]
fn every_matching_bound_must_hold() -> TestResult {
    let rules = rules();
    let sha = id("osc:bw/hash.sha256?size=64k")?;
    let blake = id("osc:bw/hash.blake3?size=64k")?;
    let multi = id("osc:bw/hash.multi?size=64k")?;
    let established = [at(&sha, 400e6, false), at(&blake, 3e9, false)];
    let results = evaluate(&rules, &at(&multi, 500e6, false), &established);
    assert_eq!(results.len(), 2);
    assert!(
        results
            .iter()
            .any(|r| r.rule == "multi_axis_le_sha256" && !r.passed)
    );
    assert!(
        results
            .iter()
            .any(|r| r.rule == "multi_axis_le_blake3" && r.passed)
    );
    Ok(())
}

#[test]
fn thread_scaling_bound_uses_thread_ratio() -> TestResult {
    let rules = rules();
    let single = id("osc:ops/store.tag_get?backend=memory&threads=1t")?;
    let quad = id("osc:ops/store.tag_get?backend=memory&threads=4t")?;
    let other_backend = id("osc:ops/store.tag_get?backend=redb&threads=1t")?;
    let established = [at(&single, 1e6, false), at(&other_backend, 1.0, false)];
    let results = evaluate(&rules, &at(&quad, 3.9e6, false), &established);
    assert_eq!(
        results.len(),
        1,
        "only the same-backend single-thread rate bounds: {results:?}"
    );
    assert!(results[0].passed);
    assert!((results[0].bound - 4.4e6).abs() < 1.0);
    assert!(!evaluate(&rules, &at(&quad, 5e6, false), &established)[0].passed);
    assert!(evaluate(&rules, &at(&single, 1e6, false), &established).is_empty());
    Ok(())
}

#[test]
fn a_measurement_never_bounds_itself() -> TestResult {
    let rules = rules();
    let single = id("osc:ops/store.tag_get?threads=1t")?;
    let established = [at(&single, 1e6, false)];
    assert!(evaluate(&rules, &at(&single, 1e6, false), &established).is_empty());
    Ok(())
}

/// The time-to-first-result gate compares 99th percentiles, not medians:
/// a median within bounds does not excuse a tail that grew with the index,
/// and a measurement without a distribution is not compared at all.
#[test]
fn first_result_tail_at_ten_million_keys_is_bounded_by_the_hundred_thousand_tail() -> TestResult {
    let rules = rules();
    let small = id("osc:lat/index.advance?depth=33&keys=100000&state=warm&variant=first")?;
    let large = id("osc:lat/index.advance?depth=33&keys=10000000&state=warm&variant=first")?;
    let other_shape = id("osc:lat/index.advance?depth=8&keys=100000&state=warm&variant=first")?;
    let established = [
        Established {
            id: &small,
            value: 90.0,
            tail: Some(100.0),
            from_baseline: false,
        },
        Established {
            id: &other_shape,
            value: 1.0,
            tail: Some(1.0),
            from_baseline: false,
        },
    ];
    let gate = |value: f64, tail: Option<f64>| {
        evaluate(
            &rules,
            &Established {
                id: &large,
                value,
                tail,
                from_baseline: false,
            },
            &established,
        )
        .into_iter()
        .filter(|r| r.rule == "first_result_p99_10m_le_2x_100k")
        .collect::<Vec<_>>()
    };
    let held = gate(95.0, Some(190.0));
    assert_eq!(
        held.len(),
        1,
        "only the same key shape bounds the gate: {held:?}"
    );
    assert!(held[0].passed, "{held:?}");
    assert!((held[0].bound - 200.0).abs() < f64::EPSILON);
    assert!((held[0].observed - 190.0).abs() < f64::EPSILON);
    assert!(held[0].predicate.starts_with("p99 "), "{held:?}");
    let grown = gate(95.0, Some(250.0));
    assert!(!grown[0].passed, "a grown tail fails with a steady median");
    assert_eq!(grown[0].severity, Severity::Warn);
    assert!(
        gate(95.0, None).is_empty(),
        "no distribution, no comparison"
    );
    Ok(())
}
