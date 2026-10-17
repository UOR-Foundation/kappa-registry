//! Sequence conformance: monotonic increment through executions,
//! namespace isolation, name isolation, current reads.

use kappa_store::traits::sequence::SequenceStore;

use super::support::{MemoryFixture, TestResult, create_ns, publish};

#[test]
fn starts_at_zero() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    assert_eq!(f.store.sequence_current(&ns, "seq")?, 0);
    Ok(())
}

#[test]
fn next_increments() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    for expected in 1..=3 {
        publish(&f.store, &ns, |ex| {
            let val = ex.sequence_next("seq")?;
            assert_eq!(val, expected);
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn current_returns_last_value() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    publish(&f.store, &ns, |ex| {
        ex.sequence_next("seq")?;
        Ok(())
    })?;
    publish(&f.store, &ns, |ex| {
        ex.sequence_next("seq")?;
        Ok(())
    })?;
    assert_eq!(f.store.sequence_current(&ns, "seq")?, 2);
    Ok(())
}

#[test]
fn namespaces_independent() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns1 = create_ns(&f.store, "ns1")?;
    let ns2 = create_ns(&f.store, "ns2")?;
    publish(&f.store, &ns1, |ex| {
        ex.sequence_next("seq")?;
        ex.sequence_next("seq")?;
        Ok(())
    })?;
    assert_eq!(f.store.sequence_current(&ns1, "seq")?, 2);
    assert_eq!(f.store.sequence_current(&ns2, "seq")?, 0);
    Ok(())
}

#[test]
fn names_independent() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    publish(&f.store, &ns, |ex| {
        ex.sequence_next("a")?;
        ex.sequence_next("a")?;
        ex.sequence_next("b")?;
        Ok(())
    })?;
    assert_eq!(f.store.sequence_current(&ns, "a")?, 2);
    assert_eq!(f.store.sequence_current(&ns, "b")?, 1);
    Ok(())
}
