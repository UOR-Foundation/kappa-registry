//! Downstream semantic qualification for bounded serialization changes.
//! Each backend publishes the full history through its public execution API.
mod support;

use kappa_handler::clock_at;
use kappa_store::{Kappa, TagUpdate};
use support::{at, create, Staging, TestResult, T0};

fn sustained_history(store: &(impl Staging + ?Sized)) -> TestResult {
    let ns = create(store, "serialization-sustained")?;
    assert_eq!(store.epoch_current(&ns)?.0, 1, "genesis is the first epoch");
    let mut roots = Vec::new();
    let mut previous_time = None;
    for batch in 0..8u64 {
        for item in 0..32u64 {
            let index = batch * 32 + item;
            let tag = format!("publication-{index:03}");
            let identity = Kappa::sha256(tag.as_bytes());
            let time = at(T0 + i64::try_from(index)? + 1);
            let mut execution = store.begin_execution(&ns, &clock_at(time)?)?;
            execution.tag_put(
                &tag,
                &TagUpdate::Set {
                    kappa: identity.clone(),
                },
            )?;
            let published = execution.publish()?;
            assert_eq!(
                published.epoch_number,
                index + 2,
                "publication epochs must stay dense"
            );
            assert_eq!(store.epoch_current(&ns)?.0, index + 2);
            assert_eq!(store.tag_get(&ns, &tag)?.kappa, identity);
            let root = store.epoch_get(&published.root)?;
            assert_eq!(root.namespace_id(), ns.id());
            assert_eq!(root.kappa(), &published.root);
            if let Some(previous) = previous_time {
                assert!(
                    root.timestamp_ms() > previous,
                    "publication timestamps must increase"
                );
            }
            previous_time = Some(root.timestamp_ms());
            roots.push((published.epoch_number, published.root));
        }
        let head = 1 + (batch + 1) * 32;
        let replay = kappa_store::replay_to(store, &ns, head)?;
        for index in 0..(batch + 1) * 32 {
            let tag = format!("publication-{index:03}");
            assert_eq!(replay.tags.get(&tag), Some(&Kappa::sha256(tag.as_bytes())));
        }
        assert!(!replay
            .tags
            .contains_key(&format!("publication-{:03}", (batch + 1) * 32)));
    }
    assert_eq!(store.epoch_current(&ns)?.0, 257);
    // Retained root identities still resolve after all subsequent publications.
    // A later cache entry or serialization preparation must not replace them.
    for (epoch, identity) in roots {
        let root = store.epoch_get(&identity)?;
        assert_eq!(root.namespace_id(), ns.id());
        let replay = kappa_store::replay_to(store, &ns, epoch)?;
        let tag = format!("publication-{:03}", epoch - 2);
        assert_eq!(replay.tags.get(&tag), Some(&Kappa::sha256(tag.as_bytes())));
        assert!(!replay
            .tags
            .contains_key(&format!("publication-{:03}", epoch - 1)));
    }
    Ok(())
}

#[test]
fn memory_preserves_genesis_and_eight_batches_of_thirty_two_publications() -> TestResult {
    sustained_history(kappa_store_memory::test_support::test_store()?.store())
}

#[test]
fn persistent_preserves_genesis_and_eight_batches_of_thirty_two_publications() -> TestResult {
    // Production defaults retain the 256-unsettled-epoch ceiling; no enlarged
    // allowance or maintenance retry hides a refused publication at head 257.
    sustained_history(kappa_store_redb::test_support::persistent_store()?.store())
}
