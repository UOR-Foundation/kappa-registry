//! Tag conformance: set/get/delete/list through executions,
//! version monotonicity, compare-and-swap, create-if-absent,
//! namespace isolation, batch atomicity, prefix filter.

use kappa_handler::clock_at;
use kappa_store::ExecutionStore;
use kappa_store::axis::Axis;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::page::PageRequest;
use kappa_store::tag::TagUpdate;
use kappa_store::traits::tag::TagStore;
use kappa_store::verified::VerifiedContent;

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

#[test]
fn set_get_roundtrip() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let k = seed(&f, &ns, b"tag-content")?;
    publish(&f.store, &ns, |ex| {
        ex.tag_put("latest", &TagUpdate::Set { kappa: k.clone() })
    })?;
    let got = f.store.tag_get(&ns, "latest")?;
    assert_eq!(got.kappa, k);
    Ok(())
}

#[test]
fn version_increments() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let k1 = seed(&f, &ns, b"v1")?;
    let k2 = seed(&f, &ns, b"v2")?;
    let k3 = seed(&f, &ns, b"v3")?;
    publish(&f.store, &ns, |ex| {
        ex.tag_put("t", &TagUpdate::Set { kappa: k1.clone() })
    })?;
    publish(&f.store, &ns, |ex| {
        ex.tag_put("t", &TagUpdate::Set { kappa: k2.clone() })
    })?;
    publish(&f.store, &ns, |ex| {
        ex.tag_put("t", &TagUpdate::Set { kappa: k3.clone() })
    })?;
    let got = f.store.tag_get(&ns, "t")?;
    assert_eq!(got.version, 3);
    Ok(())
}

#[test]
fn delete_then_not_found() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let k = seed(&f, &ns, b"del")?;
    publish(&f.store, &ns, |ex| {
        ex.tag_put("t", &TagUpdate::Set { kappa: k.clone() })
    })?;
    publish(&f.store, &ns, |ex| ex.tag_delete("t"))?;
    assert!(f.store.tag_get(&ns, "t").is_err());
    Ok(())
}

#[test]
fn list_returns_sorted() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let kc = seed(&f, &ns, b"c")?;
    let ka = seed(&f, &ns, b"a")?;
    let kb = seed(&f, &ns, b"b")?;
    publish(&f.store, &ns, |ex| {
        ex.tag_put("c", &TagUpdate::Set { kappa: kc.clone() })?;
        ex.tag_put("a", &TagUpdate::Set { kappa: ka.clone() })?;
        ex.tag_put("b", &TagUpdate::Set { kappa: kb.clone() })?;
        Ok(())
    })?;
    let list = f.store.tag_list(&ns, None, &PageRequest::first(100))?;
    let names: Vec<&str> = list.items.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["a", "b", "c"]);
    Ok(())
}

#[test]
fn prefix_filters() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let k1 = seed(&f, &ns, b"p1")?;
    let k2 = seed(&f, &ns, b"p2")?;
    let k3 = seed(&f, &ns, b"p3")?;
    publish(&f.store, &ns, |ex| {
        ex.tag_put("v1.0", &TagUpdate::Set { kappa: k1.clone() })?;
        ex.tag_put("v1.1", &TagUpdate::Set { kappa: k2.clone() })?;
        ex.tag_put("v2.0", &TagUpdate::Set { kappa: k3.clone() })?;
        Ok(())
    })?;
    let result = f
        .store
        .tag_list(&ns, Some("v1."), &PageRequest::first(100))?;
    assert_eq!(result.len(), 2);
    Ok(())
}

#[test]
fn namespaces_isolated() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns1 = create_ns(&f.store, "ns1")?;
    let ns2 = create_ns(&f.store, "ns2")?;
    let k1 = seed(&f, &ns1, b"a")?;
    let k2 = seed(&f, &ns2, b"b")?;
    publish(&f.store, &ns1, |ex| {
        ex.tag_put("t", &TagUpdate::Set { kappa: k1.clone() })
    })?;
    publish(&f.store, &ns2, |ex| {
        ex.tag_put("t", &TagUpdate::Set { kappa: k2.clone() })
    })?;
    assert_eq!(f.store.tag_get(&ns1, "t")?.kappa, k1);
    assert_eq!(f.store.tag_get(&ns2, "t")?.kappa, k2);
    Ok(())
}

#[test]
fn batch_atomic_success() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let kx = seed(&f, &ns, b"x")?;
    let ky = seed(&f, &ns, b"y")?;
    let updates = vec![
        ("x".to_string(), TagUpdate::Set { kappa: kx.clone() }),
        ("y".to_string(), TagUpdate::Set { kappa: ky.clone() }),
    ];
    publish(&f.store, &ns, |ex| ex.tag_batch_update(&updates))?;
    assert_eq!(f.store.tag_get(&ns, "x")?.kappa, kx);
    assert_eq!(f.store.tag_get(&ns, "y")?.kappa, ky);
    Ok(())
}

#[test]
fn compare_and_swap_success() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let k1 = seed(&f, &ns, b"old")?;
    let k2 = seed(&f, &ns, b"new")?;
    publish(&f.store, &ns, |ex| {
        ex.tag_put("t", &TagUpdate::Set { kappa: k1.clone() })
    })?;
    publish(&f.store, &ns, |ex| {
        ex.tag_put(
            "t",
            &TagUpdate::CompareAndSwap {
                kappa: k2.clone(),
                expected_version: 1,
            },
        )
    })?;
    assert_eq!(f.store.tag_get(&ns, "t")?.kappa, k2);
    Ok(())
}

#[test]
fn compare_and_swap_version_mismatch() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let k1 = seed(&f, &ns, b"old")?;
    let k2 = seed(&f, &ns, b"new")?;
    publish(&f.store, &ns, |ex| {
        ex.tag_put("t", &TagUpdate::Set { kappa: k1.clone() })
    })?;
    // CAS with wrong version fails inside the execution
    let mut execution = f
        .store
        .begin_execution(&ns, &clock_at(super::support::test_now())?)?;
    let result = execution.tag_put(
        "t",
        &TagUpdate::CompareAndSwap {
            kappa: k2,
            expected_version: 999,
        },
    );
    assert!(result.is_err());
    execution.abort()?;
    assert_eq!(f.store.tag_get(&ns, "t")?.kappa, k1);
    Ok(())
}

#[test]
fn create_if_absent_success() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let k = seed(&f, &ns, b"new")?;
    publish(&f.store, &ns, |ex| {
        ex.tag_put("fresh", &TagUpdate::CreateIfAbsent { kappa: k.clone() })
    })?;
    assert_eq!(f.store.tag_get(&ns, "fresh")?.kappa, k);
    Ok(())
}

#[test]
fn create_if_absent_fails_when_exists() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let k1 = seed(&f, &ns, b"first")?;
    let k2 = seed(&f, &ns, b"second")?;
    publish(&f.store, &ns, |ex| {
        ex.tag_put("t", &TagUpdate::Set { kappa: k1.clone() })
    })?;
    let mut execution = f
        .store
        .begin_execution(&ns, &clock_at(super::support::test_now())?)?;
    let result = execution.tag_put("t", &TagUpdate::CreateIfAbsent { kappa: k2 });
    assert!(result.is_err());
    execution.abort()?;
    assert_eq!(f.store.tag_get(&ns, "t")?.kappa, k1);
    Ok(())
}
