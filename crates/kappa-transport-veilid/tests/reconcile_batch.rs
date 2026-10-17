//! Reconciled tags publish one execution per namespace batch.

use kappa_handler::clock_at;
use kappa_store::canonical::from_canonical;
use kappa_store::epoch::EpochMutation;
use kappa_store::{
    BlobStore, ClockMs, EpochStore, Kappa, MutationOp, NamespaceRef, StoreError, TagStore,
};
use kappa_store_memory::{InMemoryStore, test_support};
use kappa_transport_veilid::reconcile::{
    NamespaceBatchOutcome, TagEntryWire, apply_namespace_batch,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn store() -> Result<InMemoryStore, Box<dyn std::error::Error>> {
    Ok(test_support::test_store()?.into_store())
}

fn at(offset_ms: i64) -> ClockMs {
    ClockMs::from_raw((1_700_000_000_000 + offset_ms) << 16)
}

fn wire(name: &str, content: &[u8]) -> TagEntryWire {
    TagEntryWire {
        name: name.to_string(),
        kappa: Kappa::sha256(content).to_string(),
        version: 1,
    }
}

fn ledger(
    store: &InMemoryStore,
    ns: &NamespaceRef,
) -> Result<Vec<EpochMutation>, Box<dyn std::error::Error>> {
    let (_, root) = store.epoch_current(ns)?;
    let root = store.epoch_get(&root)?;
    Ok(from_canonical(
        &store.blob_get_verified(root.ledger_root())?,
    )?)
}

#[test]
fn each_namespace_batch_publishes_exactly_one_epoch() -> TestResult {
    let store = store()?;
    let images = NamespaceRef::deterministic("images");
    let charts = NamespaceRef::deterministic("charts");
    let image_tags = [wire("a", b"a"), wire("b", b"b"), wire("c", b"c")];
    let chart_tags = [
        wire("x", b"x"),
        TagEntryWire {
            name: "broken".into(),
            kappa: "not-a-kappa".into(),
            version: 1,
        },
    ];

    let first = apply_namespace_batch(&store, &images, "images", &image_tags, &clock_at(at(1))?);
    let second = apply_namespace_batch(&store, &charts, "charts", &chart_tags, &clock_at(at(2))?);

    assert_eq!(
        first,
        NamespaceBatchOutcome {
            applied: 3,
            skipped: 0,
            errors: Vec::new(),
            epoch: Some(1),
        }
    );
    assert_eq!(
        second,
        NamespaceBatchOutcome {
            applied: 1,
            skipped: 1,
            errors: Vec::new(),
            epoch: Some(1),
        }
    );
    assert_eq!(store.epoch_current(&images)?.0, 1);
    assert_eq!(store.epoch_current(&charts)?.0, 1);
    let mutations = ledger(&store, &images)?;
    assert_eq!(mutations.len(), 3);
    assert!(mutations.iter().all(|m| m.op == MutationOp::TagSet));
    for tag in ["a", "b", "c"] {
        assert_eq!(
            store.tag_get(&images, tag)?.kappa,
            Kappa::sha256(tag.as_bytes())
        );
    }
    assert_eq!(store.tag_get(&charts, "x")?.kappa, Kappa::sha256(b"x"));
    Ok(())
}

#[test]
fn a_converged_batch_publishes_nothing() -> TestResult {
    let store = store()?;
    let ns = NamespaceRef::deterministic("converged");
    let tags = [wire("a", b"a"), wire("b", b"b")];
    let first = apply_namespace_batch(&store, &ns, "converged", &tags, &clock_at(at(1))?);
    assert_eq!(first.epoch, Some(1));

    let again = apply_namespace_batch(&store, &ns, "converged", &tags, &clock_at(at(2))?);

    assert_eq!(
        again,
        NamespaceBatchOutcome {
            applied: 2,
            skipped: 0,
            errors: Vec::new(),
            epoch: None,
        }
    );
    assert_eq!(store.epoch_current(&ns)?.0, 1);
    assert_eq!(store.tag_get(&ns, "a")?.version, 1);
    Ok(())
}

#[test]
fn a_failed_batch_publishes_nothing_and_leaves_other_namespaces_intact() -> TestResult {
    let store = store()?;
    let failing = NamespaceRef::deterministic("failing");
    let healthy = NamespaceRef::deterministic("healthy");
    apply_namespace_batch(
        &store,
        &failing,
        "failing",
        &[wire("seed", b"seed")],
        &clock_at(at(10))?,
    );

    // An authority issuing earlier than the namespace's last epoch is
    // rejected at publication, so the whole batch is discarded.
    let failed = apply_namespace_batch(
        &store,
        &failing,
        "failing",
        &[wire("late", b"late")],
        &clock_at(at(5))?,
    );
    let applied = apply_namespace_batch(
        &store,
        &healthy,
        "healthy",
        &[wire("ok", b"ok")],
        &clock_at(at(5))?,
    );

    assert_eq!(failed.applied, 0);
    assert_eq!(failed.skipped, 1);
    assert_eq!(failed.epoch, None);
    assert_eq!(failed.errors.len(), 1, "{:?}", failed.errors);
    assert!(matches!(
        store.tag_get(&failing, "late"),
        Err(StoreError::NotFound(_))
    ));
    assert_eq!(store.epoch_current(&failing)?.0, 1);
    assert_eq!(applied.epoch, Some(1));
    assert_eq!(store.tag_get(&healthy, "ok")?.kappa, Kappa::sha256(b"ok"));
    Ok(())
}
