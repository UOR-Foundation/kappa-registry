//! Replay conformance: epoch chain replay reconstructs published
//! state, including tags, metadata, and sequence evidence.

use kappa_store::kappa::Kappa;
use kappa_store::page::PageRequest;
use kappa_store::tag::TagUpdate;
use kappa_store::traits::epoch::EpochStore;
use kappa_store::traits::tag::TagStore;

use super::support::{MemoryFixture, TestResult, create_ns, publish};

#[test]
fn replay_reconstructs_published_tags() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "replay")?;

    // Publish 10 tags across 3 executions
    for batch in 0..3 {
        publish(&f.store, &ns, |ex| {
            for i in 0..10 {
                let idx = batch * 10 + i;
                ex.tag_put(
                    &format!("key-{idx}"),
                    &TagUpdate::Set {
                        kappa: Kappa::sha256(format!("content-{idx}").as_bytes()),
                    },
                )?;
            }
            Ok(())
        })?;
    }

    // Snapshot live state
    let live_tags = f.store.tag_list(&ns, None, &PageRequest::first(100))?;
    assert_eq!(live_tags.items.len(), 30);

    // Replay to the current epoch
    let (current_epoch, _) = f.store.epoch_current(&ns)?;
    let replayed = kappa_store::replay_to(&f.store, &ns, current_epoch)?;
    assert_eq!(replayed.tags.len(), 30, "replayed state must have 30 tags");

    for tag in &live_tags.items {
        let replayed_kappa = replayed
            .tags
            .get(&tag.name)
            .unwrap_or_else(|| panic!("replayed state missing tag {}", tag.name));
        assert_eq!(
            *replayed_kappa, tag.kappa,
            "tag {} kappa mismatch in replay",
            tag.name
        );
    }
    Ok(())
}

#[test]
fn replay_target_beyond_current_returns_not_found() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "beyond")?;
    let result = kappa_store::replay_to(&f.store, &ns, 999);
    assert!(result.is_err(), "replay to a future epoch must fail");
    Ok(())
}

#[test]
fn replay_with_deletes_reflects_final_state() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "del-replay")?;
    publish(&f.store, &ns, |ex| {
        ex.tag_put(
            "keep",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"keep"),
            },
        )?;
        ex.tag_put(
            "remove",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"remove"),
            },
        )
    })?;
    publish(&f.store, &ns, |ex| ex.tag_delete("remove"))?;

    let (current, _) = f.store.epoch_current(&ns)?;
    let replayed = kappa_store::replay_to(&f.store, &ns, current)?;
    assert!(replayed.tags.contains_key("keep"));
    assert!(!replayed.tags.contains_key("remove"));
    Ok(())
}

#[test]
fn replay_metadata_evidence() -> TestResult {
    let f = MemoryFixture::new()?;
    let ns = create_ns(&f.store, "meta-replay")?;
    publish(&f.store, &ns, |ex| {
        ex.namespace_put_meta("policy", b"allow-all")
    })?;

    let (current, _) = f.store.epoch_current(&ns)?;
    let replayed = kappa_store::replay_to(&f.store, &ns, current)?;
    assert_eq!(
        replayed.metadata.get("policy").map(Vec::as_slice),
        Some(b"allow-all".as_slice())
    );
    Ok(())
}
