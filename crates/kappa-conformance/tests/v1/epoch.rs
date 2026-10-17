//! Epoch conformance: publication through executions produces signed
//! roots, epoch numbers increment, chain links via prev_identifier,
//! namespace isolation, epoch_get retrieves committed roots, ledger
//! root is content-addressable.

use kappa_store::kappa::Kappa;
use kappa_store::tag::TagUpdate;
use kappa_store::traits::epoch::EpochStore;

use super::support::{MemoryFixture, TestResult, create_ns, publish};

#[test]
fn publish_returns_epoch_and_kappa() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let published = publish(&f.store, &ns, |ex| {
        ex.tag_put(
            "t",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"content"),
            },
        )
    })?;
    // namespace_create was epoch 1, this tag_put is epoch 2
    assert!(published.epoch_number >= 1);
    assert!(published.root.to_string().starts_with("sha256:"));
    Ok(())
}

#[test]
fn epoch_number_increments() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let p1 = publish(&f.store, &ns, |ex| {
        ex.tag_put(
            "a",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"a"),
            },
        )
    })?;
    let p2 = publish(&f.store, &ns, |ex| {
        ex.tag_put(
            "b",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"b"),
            },
        )
    })?;
    assert_eq!(p2.epoch_number, p1.epoch_number + 1);
    Ok(())
}

#[test]
fn current_tracks_latest() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let p1 = publish(&f.store, &ns, |ex| {
        ex.tag_put(
            "t",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"first"),
            },
        )
    })?;
    let (n1, k1) = f.store.epoch_current(&ns)?;
    assert_eq!(n1, p1.epoch_number);
    assert_eq!(k1, p1.root);
    let p2 = publish(&f.store, &ns, |ex| {
        ex.tag_put(
            "t",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"second"),
            },
        )
    })?;
    let (n2, k2) = f.store.epoch_current(&ns)?;
    assert_eq!(n2, p2.epoch_number);
    assert_eq!(k2, p2.root);
    Ok(())
}

#[test]
fn get_returns_epoch_root() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let p = publish(&f.store, &ns, |ex| {
        ex.tag_put(
            "t",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"content"),
            },
        )
    })?;
    let root = f.store.epoch_get(&p.root)?;
    assert_eq!(root.epoch_number(), p.epoch_number);
    assert_eq!(*root.kappa(), p.root);
    Ok(())
}

#[test]
fn chain_links_via_prev_identifier() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let p1 = publish(&f.store, &ns, |ex| {
        ex.tag_put(
            "a",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"a"),
            },
        )
    })?;
    let p2 = publish(&f.store, &ns, |ex| {
        ex.tag_put(
            "b",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"b"),
            },
        )
    })?;
    let r2 = f.store.epoch_get(&p2.root)?;
    assert_eq!(r2.prev_identifier(), Some(&p1.root));
    Ok(())
}

#[test]
fn origin_has_no_prev() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    // The creation epoch is the origin
    let (_, root_kappa) = f.store.epoch_current(&ns)?;
    let root = f.store.epoch_get(&root_kappa)?;
    assert!(root.prev_identifier().is_none());
    Ok(())
}

#[test]
fn namespaces_independent() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns1 = create_ns(&f.store, "ns1")?;
    let ns2 = create_ns(&f.store, "ns2")?;
    publish(&f.store, &ns1, |ex| {
        ex.tag_put(
            "t",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"x"),
            },
        )
    })?;
    let (n1, _) = f.store.epoch_current(&ns1)?;
    let (n2, _) = f.store.epoch_current(&ns2)?;
    // ns1 has creation + 1 tag write = 2 epochs
    // ns2 has only creation = 1 epoch
    assert!(n1 > n2);
    Ok(())
}

#[test]
fn epoch_kappa_is_deterministic() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let p = publish(&f.store, &ns, |ex| {
        ex.tag_put(
            "t",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"deterministic"),
            },
        )
    })?;
    let root = f.store.epoch_get(&p.root)?;
    // The kappa is sha256(canonical_bytes(EpochRootData)), which is
    // recomputed from the stored bytes by EpochRoot::from_bytes.
    let recomputed = Kappa::sha256(&root.to_bytes());
    assert_eq!(*root.kappa(), recomputed);
    Ok(())
}

#[test]
fn epoch_root_roundtrip() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "ns")?;
    let p = publish(&f.store, &ns, |ex| {
        ex.tag_put(
            "t",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"roundtrip"),
            },
        )
    })?;
    let root = f.store.epoch_get(&p.root)?;
    let bytes = root.to_bytes();
    let recovered = kappa_store::EpochRoot::from_bytes(&bytes)?;
    assert_eq!(*recovered.kappa(), *root.kappa());
    assert_eq!(recovered.epoch_number(), root.epoch_number());
    Ok(())
}
