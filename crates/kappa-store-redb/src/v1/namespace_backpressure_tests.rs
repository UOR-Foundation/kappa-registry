//! Unsettled ownership as backpressure: bounded per namespace by committed
//! epochs and node-wide by the entries and physical bytes of parked
//! allocations, with every publication running while the registry writer
//! is held elsewhere.

use std::sync::{Arc, mpsc};

use kappa_store::{BlobStore, EpochStore, Kappa, StoreError};

use super::{TestResult, WATCHDOG, create, drain_settlement, publish_blob, write};
use crate::{PersistentStore, PersistentStoreConfig};

/// Physical bytes one external blob of `size` plain bytes occupies: its
/// payload and its Merkle sidecar of 32-byte nodes.
fn physical_bytes(size: usize) -> u64 {
    let chunks = (size as u64).div_ceil(crate::BLOB_CHUNK_SIZE as u64);
    size as u64 + kappa_types::merkle::node_count(chunks) * 32
}

/// Run `publication` on a worker while `blocker` is held on this thread.
/// The blocker is released on completion or on the watchdog, so a
/// publication that regresses to waiting on it fails here instead of
/// hanging the suite.
fn while_blocked<T: Send + 'static>(
    blocker: redb::WriteTransaction,
    publication: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Box<dyn std::error::Error>> {
    let (done, completion) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let outcome = publication();
        let _ = done.send(());
        outcome
    });
    let completed = completion.recv_timeout(WATCHDOG);
    drop(blocker);
    let outcome = worker.join().map_err(|_| "publication worker panicked")?;
    completed.map_err(|_| "publication waited on the shared registry writer")?;
    Ok(outcome)
}

/// Unsettled ownership is bounded twice and both bounds are backpressure:
/// per namespace by committed epochs (pins or not), node-wide by the
/// entries of parked allocations across namespaces. A publication the
/// node-wide bound refuses commits nothing; the charge is released as
/// settlement drains; the preparation budget is not what holds unsettled
/// content, so it is free again before settlement. Every publication runs
/// while the registry writer is held elsewhere.
#[test]
fn unsettled_ownership_is_bounded_per_namespace_and_node_wide() -> TestResult {
    const BYTES: usize = 256 * 1024;
    let root = tempfile::tempdir()?;
    let mut config = PersistentStoreConfig::new(
        root.path().join("blobs"),
        root.path().join("store.redb"),
        kappa_crypto::testing::fixture_authority(1)?,
    );
    config.max_unsettled_epochs = 3;
    config.max_unsettled_entries = 2;
    config.max_unsettled_bytes = u64::MAX;
    // One preparation at a time, with headroom for its chunk reservation:
    // preparation capacity is independently sufficient, so every refusal
    // below is the unsettled bound's.
    config.preparation_entries = 1;
    config.preparation_bytes = 4 * BYTES as u64;
    // A durability batch freezes queued preparations, so it is bounded by
    // the queue: one preparation per batch.
    config.durability_batch_entries = 1;
    config.durability_batch_bytes = 4 * BYTES as u64;
    let store = Arc::new(PersistentStore::new(config)?);
    let a = create(&store, "backlog-a")?;
    let b = create(&store, "backlog-b")?;
    drain_settlement(&store, &a)?;
    drain_settlement(&store, &b)?;

    let blocker = store.registry.begin_write()?;
    let (store_w, a_w, b_w) = (Arc::clone(&store), a.clone(), b.clone());
    let outcomes = while_blocked(blocker, move || -> Result<(), String> {
        let (store, a, b) = (&store_w, &a_w, &b_w);
        let fail = |error: StoreError| error.to_string();
        // Node-wide entries: one external blob per namespace fills the bound.
        publish_blob(store, a, 1, BYTES, 2000).map_err(fail)?;
        publish_blob(store, b, 2, BYTES, 2001).map_err(fail)?;
        if store.unsettled.charged().0 != 2 {
            return Err(format!(
                "charged {:?}, expected 2 entries",
                store.unsettled.charged()
            ));
        }
        // Preparation ownership ended at install: a third preparation fits
        // the one-entry preparation budget, and it is the publication that
        // is refused, before it commits.
        let head_before = store.epoch_current(a).map_err(fail)?;
        match publish_blob(store, a, 3, BYTES, 2002) {
            Err(StoreError::CapacityExceeded(_)) => {}
            other => return Err(format!("third blob not refused by the bound: {other:?}")),
        }
        if store.epoch_current(a).map_err(fail)? != head_before {
            return Err("a refused publication moved the head".into());
        }
        if store.unsettled.charged().0 != 2 {
            return Err("a refused publication charged the budget".into());
        }
        // Per-namespace epochs: a holds 1 (the blob); tag-only epochs carry
        // no pins and still count, so two more are admitted and the fourth
        // is refused at the bound of 3.
        write(store, a, 2003).map_err(fail)?;
        write(store, a, 2004).map_err(fail)?;
        match write(store, a, 2005) {
            Err(StoreError::CapacityExceeded(_)) => {}
            other => return Err(format!("fourth epoch not refused: {other:?}")),
        }
        if store.epoch_current(a).map_err(fail)?.0 != 4 {
            return Err("a's head is not at epoch 4".into());
        }
        // Another namespace is admitted under its own bound.
        write(store, b, 2006).map_err(fail)?;
        Ok(())
    })?;
    outcomes?;

    drain_settlement(&store, &a)?;
    assert_eq!(
        store.unsettled.charged().0,
        1,
        "a's entry released with its epochs"
    );
    drain_settlement(&store, &b)?;
    assert_eq!(store.unsettled.charged(), (0, 0));
    publish_blob(&store, &a, 3, BYTES, 3000)?;
    write(&store, &a, 3001)?;
    for fill in [1u8, 3] {
        assert_eq!(
            store.blob_get_in(&a, &Kappa::sha256(&vec![fill; BYTES]))?,
            vec![fill; BYTES]
        );
    }
    assert_eq!(
        store.blob_get_in(&b, &Kappa::sha256(&vec![2u8; BYTES]))?,
        vec![2u8; BYTES]
    );
    Ok(())
}

/// The byte bound charges the physical occupancy of each parked
/// allocation, payload and sidecar, as the preparation measured it: a
/// bound of exactly one blob's occupancy admits one and refuses the next
/// while entry capacity remains, and the charge is released by settlement.
#[test]
fn unsettled_bytes_charge_payload_and_sidecar_at_the_exact_bound() -> TestResult {
    const BYTES: usize = 256 * 1024 + 1;
    let occupancy = physical_bytes(BYTES);
    let root = tempfile::tempdir()?;
    let mut config = PersistentStoreConfig::new(
        root.path().join("blobs"),
        root.path().join("store.redb"),
        kappa_crypto::testing::fixture_authority(1)?,
    );
    config.max_unsettled_entries = 64;
    config.max_unsettled_bytes = occupancy;
    let store = PersistentStore::new(config)?;
    let ns = create(&store, "byte-bound")?;
    drain_settlement(&store, &ns)?;
    publish_blob(&store, &ns, 1, BYTES, 2000)?;
    assert_eq!(store.unsettled.charged(), (1, occupancy));
    let on_disk = {
        let active = store.namespace_snapshot(&ns)?;
        let parked = active
            .controller()
            .pending_pins
            .lock()
            .map_err(|_| "pending pins poisoned")?;
        let allocation = *parked
            .values()
            .flat_map(|parked| parked.pins.iter())
            .next()
            .ok_or("committed blob parked no pin")?
            .allocation();
        // No settlement or reclamation runs before the files are measured.
        drop(parked);
        std::fs::metadata(crate::allocation::allocation_path(
            &store.blob_root,
            &allocation,
        ))?
        .len()
            + std::fs::metadata(crate::allocation::chunk_list_path(
                &store.blob_root,
                &allocation,
            ))?
            .len()
    };
    assert_eq!(
        on_disk, occupancy,
        "the measured charge is the physical occupancy"
    );
    let head = store.epoch_current(&ns)?;
    assert!(matches!(
        publish_blob(&store, &ns, 2, BYTES, 2001),
        Err(StoreError::CapacityExceeded(_))
    ));
    assert_eq!(store.epoch_current(&ns)?, head);
    assert_eq!(store.unsettled.charged(), (1, occupancy));
    // A pin-free epoch charges no bytes and is admitted under the bound.
    write(&store, &ns, 2002)?;
    drain_settlement(&store, &ns)?;
    assert_eq!(store.unsettled.charged(), (0, 0));
    publish_blob(&store, &ns, 2, BYTES, 3000)?;
    assert_eq!(store.unsettled.charged(), (1, occupancy));
    Ok(())
}
