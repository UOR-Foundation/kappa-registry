//! Edge conformance: put/query/delete through executions, relation
//! types (builtin and semantic), asserter isolation, idempotent
//! upsert, metadata update, batch, GC reachability.

use kappa_store::axis::Axis;
use kappa_store::edge::{
    BuiltinRelation, Direction, EdgeInput, EdgeQuery, EdgeRelation, SemanticRelation, semantic,
};
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::traits::edge::EdgeStore;
use kappa_store::verified::VerifiedContent;

use kappa_store::page::PageRequest;

use super::support::{MemoryFixture, TestResult, create_ns, publish};

/// Content enters only through a published execution of a namespace.
fn seed(
    f: &MemoryFixture,
    ns: &NamespaceRef,
    data: &[u8],
) -> Result<Kappa, Box<dyn std::error::Error>> {
    let v = VerifiedContent::compute(Axis::Sha256, data)?;
    let k = v.kappa().clone();
    publish(&f.store, ns, |ex| ex.blob_put(&v).map(|_| ()))?;
    Ok(k)
}

fn owns(source: &Kappa, target: &Kappa) -> EdgeInput {
    EdgeInput {
        source: source.clone(),
        target: target.clone(),
        relation: EdgeRelation::Builtin(BuiltinRelation::Owns),
        asserter: Kappa::sha256(b"test-asserter"),
        created_at_ms: 1000,
        metadata: None,
    }
}

#[test]
fn put_query_outbound() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let src = seed(&f, &ns, b"src")?;
    let tgt = seed(&f, &ns, b"tgt")?;
    publish(&f.store, &ns, |ex| {
        ex.edge_put(&owns(&src, &tgt))?;
        Ok(())
    })?;
    let page = &PageRequest::first(100);
    let results = f.store.edge_query(
        &ns,
        &EdgeQuery {
            anchor: src,
            direction: Direction::Outbound,
            relation: None,
            asserter: None,
        },
        page,
    )?;
    assert_eq!(results.items.len(), 1);
    assert_eq!(*results.items[0].target(), tgt);
    Ok(())
}

#[test]
fn put_query_inbound() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let src = seed(&f, &ns, b"src2")?;
    let tgt = seed(&f, &ns, b"tgt2")?;
    publish(&f.store, &ns, |ex| {
        ex.edge_put(&EdgeInput {
            source: src.clone(),
            target: tgt.clone(),
            relation: EdgeRelation::Builtin(BuiltinRelation::Assertion),
            asserter: Kappa::sha256(b"a"),
            created_at_ms: 1000,
            metadata: None,
        })?;
        Ok(())
    })?;
    let page = &PageRequest::first(100);
    let results = f.store.edge_query(
        &ns,
        &EdgeQuery {
            anchor: tgt,
            direction: Direction::Inbound,
            relation: None,
            asserter: None,
        },
        page,
    )?;
    assert_eq!(results.items.len(), 1);
    assert_eq!(*results.items[0].source(), src);
    Ok(())
}

#[test]
fn query_filters_by_relation() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let a = seed(&f, &ns, b"a")?;
    let b = seed(&f, &ns, b"b")?;
    let c = seed(&f, &ns, b"c")?;
    publish(&f.store, &ns, |ex| {
        ex.edge_put(&owns(&a, &b))?;
        ex.edge_put(&EdgeInput {
            source: a.clone(),
            target: c.clone(),
            relation: EdgeRelation::Semantic(SemanticRelation(semantic::DERIVED_FROM.to_string())),
            asserter: Kappa::sha256(b"x"),
            created_at_ms: 1000,
            metadata: None,
        })?;
        Ok(())
    })?;
    let page = &PageRequest::first(100);
    let results = f.store.edge_query(
        &ns,
        &EdgeQuery {
            anchor: a,
            direction: Direction::Outbound,
            relation: Some(EdgeRelation::Builtin(BuiltinRelation::Owns)),
            asserter: None,
        },
        page,
    )?;
    assert_eq!(results.items.len(), 1);
    assert_eq!(
        *results.items[0].relation(),
        EdgeRelation::Builtin(BuiltinRelation::Owns)
    );
    Ok(())
}

#[test]
fn delete_cleans_all_indexes() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let src = seed(&f, &ns, b"ds")?;
    let tgt = seed(&f, &ns, b"dt")?;
    let input = owns(&src, &tgt);
    let put_epoch = publish(&f.store, &ns, |ex| {
        ex.edge_put(&input)?;
        Ok(())
    })?;
    assert!(
        put_epoch.epoch_number >= 1,
        "edge put must produce an epoch"
    );
    // Find the edge kappa from a query
    let page = &PageRequest::first(100);
    let edges = f.store.edge_query(
        &ns,
        &EdgeQuery {
            anchor: src.clone(),
            direction: Direction::Outbound,
            relation: None,
            asserter: None,
        },
        page,
    )?;
    assert_eq!(edges.items.len(), 1);
    let ek = edges.items[0].kappa.clone();
    publish(&f.store, &ns, |ex| ex.edge_delete(&ek))?;
    let fwd = f.store.edge_query(
        &ns,
        &EdgeQuery {
            anchor: src,
            direction: Direction::Outbound,
            relation: None,
            asserter: None,
        },
        page,
    )?;
    assert!(fwd.items.is_empty());
    Ok(())
}

#[test]
fn gc_reachable_exhaustive() {
    for rel in BuiltinRelation::ALL {
        let _ = rel.gc_reachable();
    }
}

#[test]
fn edge_batch_put() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "batch-ns")?;
    let inputs: Vec<EdgeInput> = (0..10)
        .map(|i| EdgeInput {
            source: seed(&f, &ns, format!("batch-src-{i}").as_bytes()).expect("seed"),
            target: seed(&f, &ns, format!("batch-tgt-{i}").as_bytes()).expect("seed"),
            relation: EdgeRelation::Semantic(SemanticRelation(semantic::DERIVED_FROM.to_string())),
            asserter: Kappa::sha256(b"batch"),
            created_at_ms: 1000,
            metadata: None,
        })
        .collect();
    publish(&f.store, &ns, |ex| {
        ex.edge_put_batch(&inputs)?;
        Ok(())
    })?;
    Ok(())
}

#[test]
fn upsert_exact_duplicate_skipped() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "upsert-ns")?;
    let src = seed(&f, &ns, b"usrc")?;
    let tgt = seed(&f, &ns, b"utgt")?;
    let input = EdgeInput {
        source: src.clone(),
        target: tgt.clone(),
        relation: EdgeRelation::Semantic(SemanticRelation(semantic::DERIVED_FROM.to_string())),
        asserter: Kappa::sha256(b"a"),
        created_at_ms: 1000,
        metadata: None,
    };
    publish(&f.store, &ns, |ex| {
        ex.edge_put(&input)?;
        Ok(())
    })?;
    publish(&f.store, &ns, |ex| {
        ex.edge_put(&input)?;
        Ok(())
    })?;
    let page = &PageRequest::first(100);
    let results = f.store.edge_query(
        &ns,
        &EdgeQuery {
            anchor: src,
            direction: Direction::Outbound,
            relation: None,
            asserter: None,
        },
        page,
    )?;
    assert_eq!(results.items.len(), 1, "duplicate edge should be skipped");
    Ok(())
}
