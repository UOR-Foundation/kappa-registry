use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn magnitudes_canonicalize_by_value() -> TestResult {
    assert_eq!(
        Conditions::parse("size=65536")?,
        Conditions::parse("size=64k")?
    );
    assert_eq!(Conditions::new().size(1 << 20).get("size"), Some("1m"));
    assert_eq!(format_magnitude(1536), "1536");
    assert_eq!(format_magnitude(3 << 30), "3g");
    assert_eq!(parse_magnitude("16m")?, 16 << 20);
    Ok(())
}

#[test]
fn keys_sort_and_render() -> TestResult {
    let conditions = Conditions::parse("tags=1000&backend=redb")?;
    assert_eq!(conditions.to_string(), "?backend=redb&tags=1000");
    assert_eq!(Conditions::new().to_string(), "");
    Ok(())
}

#[test]
fn rejects_unregistered_duplicate_and_malformed() {
    assert_eq!(
        Conditions::parse("bogus=1"),
        Err(ConditionError::Unregistered("bogus".into()))
    );
    assert_eq!(
        Conditions::parse("size=1k&size=2k"),
        Err(ConditionError::Duplicate("size".into()))
    );
    for bad in ["size", "size=", "=1k", "size=1k&"] {
        assert!(
            matches!(Conditions::parse(bad), Err(ConditionError::Malformed(_))),
            "{bad}"
        );
    }
}

#[test]
fn typed_values_are_enforced() {
    for bad in [
        "backend=sqlite",
        "size=12x",
        "size=k",
        "size=01k",
        "tags=-1",
        "tags=1e3",
        "threads=4",
        "threads=0t",
        "threads=04t",
        "variant=AES",
        "contention=none+4t",
        "fanout=1k",
        "parts=02",
    ] {
        assert!(
            matches!(
                Conditions::parse(bad),
                Err(ConditionError::InvalidValue { .. })
            ),
            "{bad} must be rejected"
        );
    }
}

#[test]
fn compound_values_sort_and_deduplicate() -> TestResult {
    assert_eq!(
        Conditions::parse("contention=4t+1w+4t")?.get("contention"),
        Some("1w+4t")
    );
    Ok(())
}

#[test]
fn applicability_follows_the_registry() -> TestResult {
    let conditions = Conditions::parse("backend=redb&tags=10")?;
    conditions.check_applicable(&["store"])?;
    assert!(matches!(
        conditions.check_applicable(&["hash"]),
        Err(ConditionError::NotApplicable { .. })
    ));
    // `res` applies everywhere.
    Conditions::parse("res=ns_per_byte")?.check_applicable(&["mem"])?;
    Ok(())
}

#[test]
fn workload_and_contention_conditions_apply_where_they_are_measured() -> TestResult {
    Conditions::parse("fanout=100&parts=2")?.check_applicable(&["store"])?;
    // Store range reads land at random offsets (PERF-STO-024), graded
    // against the random-order device read.
    Conditions::parse("order=random")?.check_applicable(&["store"])?;
    Conditions::parse("durability=immediate")?.check_applicable(&["txn"])?;
    Conditions::parse("contention=1w")?.check_applicable(&["index"])?;
    // Rebuild cost is measured at fixed overflow depths over one base.
    Conditions::parse("overflow=50000")?.check_applicable(&["index"])?;
    // Open-loop requests: offered rate, connections, object size, the
    // server's backend and durability.
    Conditions::parse("backend=redb&connections=16&durability=immediate&rate=2000&size=64k")?
        .check_applicable(&["http"])?;
    assert!(matches!(
        Conditions::parse("rate=2000")?.check_applicable(&["store"]),
        Err(ConditionError::NotApplicable { .. })
    ));
    for (raw, domain) in [
        ("fanout=100", "index"),
        ("parts=2", "txn"),
        ("overflow=1000", "store"),
    ] {
        assert!(
            matches!(
                Conditions::parse(raw)?.check_applicable(&[domain]),
                Err(ConditionError::NotApplicable { .. })
            ),
            "{raw} must not apply to {domain}"
        );
    }
    Ok(())
}

#[test]
fn reference_and_multi_object_conditions_apply_to_digests_and_crypto() -> TestResult {
    Conditions::parse("impl=aws_lc&objects=8&size=64k")?.check_applicable(&["hash"])?;
    Conditions::parse("impl=aws_lc")?.check_applicable(&["crypto"])?;
    for (raw, domain) in [("impl=aws_lc", "store"), ("objects=8", "crypto")] {
        assert!(
            matches!(
                Conditions::parse(raw)?.check_applicable(&[domain]),
                Err(ConditionError::NotApplicable { .. })
            ),
            "{raw} must not apply to {domain}"
        );
    }
    assert!(matches!(
        Conditions::parse("impl=AWS-LC"),
        Err(ConditionError::InvalidValue { .. })
    ));
    Ok(())
}

#[test]
fn outcome_interference_and_fault_conditions_apply_where_they_are_measured() -> TestResult {
    Conditions::parse("backend=redb&durability=immediate&mutations=1&outcome=refused_capacity")?
        .check_applicable(&["store"])?;
    Conditions::parse("interference=gc_sweep")?.check_applicable(&["store"])?;
    Conditions::parse("backend=redb&crash_at=namespace&fault=crash&io=fault&pending=64")?
        .check_applicable(&["recovery"])?;
    Conditions::parse("backend=redb&budget=8&fault=none&io=file&pending=64")?
        .check_applicable(&["settlement"])?;
    Conditions::parse("io=file&outcome=admitted_after_settlement")?.check_applicable(&["store"])?;
    Conditions::parse("divergence=10&keys=100000")?.check_applicable(&["reconcile"])?;
    for (raw, domain) in [
        ("outcome=admitted", "recovery"),
        ("fault=crash", "http"),
        ("pending=1", "store"),
        ("budget=1", "store"),
        ("divergence=1", "store"),
        ("interference=none", "recovery"),
        ("crash_at=registry", "store"),
        ("io=fault", "http"),
    ] {
        assert!(
            matches!(
                Conditions::parse(raw)?.check_applicable(&[domain]),
                Err(ConditionError::NotApplicable { .. })
            ),
            "{raw} must not apply to {domain}"
        );
    }
    for bad in ["outcome=ok", "fault=power_loss", "interference=1w"] {
        assert!(
            matches!(
                Conditions::parse(bad),
                Err(ConditionError::InvalidValue { .. })
            ),
            "{bad} must be rejected"
        );
    }
    Ok(())
}

#[test]
fn superset_and_typed_accessors() -> TestResult {
    let specific = Conditions::parse("backend=redb&size=64k")?;
    let general = Conditions::parse("backend=redb")?;
    assert!(specific.is_superset_of(&general));
    assert!(!general.is_superset_of(&specific));
    assert_eq!(specific.magnitude("size"), Some(65_536));
    assert_eq!(Conditions::parse("tags=4096")?.count("tags"), Some(4096));
    Ok(())
}

#[test]
fn registry_keys_are_unique() {
    let mut keys: Vec<_> = SEEDED_CONDITIONS.iter().map(|def| def.key).collect();
    let total = keys.len();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), total);
}
