use super::*;

fn contribution(namespace: u8, revision: u64) -> Contribution {
    Contribution {
        namespace: [namespace; 16],
        incarnation: 1,
        revision,
    }
}

#[test]
fn a_contribution_keeps_its_first_revision_and_unregisters_only_up_to_the_published_view() {
    let locator: Locator<String> = Locator::default();
    let key = "k".to_string();
    locator.register(&key, contribution(1, 3));
    locator.register(&key, contribution(1, 9));
    assert_eq!(
        locator.observe(&key, None, 8).candidates,
        [contribution(1, 3)]
    );
    // A view of revision 2 never held the contribution of revision 3.
    locator.unregister(&key, [1; 16], 1, 2);
    assert_eq!(locator.observe(&key, None, 8).candidates.len(), 1);
    // Another incarnation's cleanup leaves this incarnation's contribution.
    locator.unregister(&key, [1; 16], 2, 3);
    assert_eq!(locator.observe(&key, None, 8).candidates.len(), 1);
    locator.unregister(&key, [1; 16], 1, 3);
    assert!(locator.observe(&key, None, 8).candidates.is_empty());
}

#[test]
fn a_key_held_by_several_namespaces_keeps_each_contribution() {
    let locator: Locator<String> = Locator::default();
    let key = "shared".to_string();
    locator.register(&key, contribution(1, 1));
    locator.register(&key, contribution(2, 5));
    locator.unregister(&key, [1; 16], 1, 1);
    assert_eq!(
        locator.observe(&key, None, 8).candidates,
        [contribution(2, 5)]
    );
    locator.unregister(&key, [2; 16], 1, 5);
    assert!(locator.observe(&key, None, 8).candidates.is_empty());
    // Registered again after the key was emptied, it is a new contribution.
    locator.register(&key, contribution(1, 7));
    assert_eq!(
        locator.observe(&key, None, 8).candidates,
        [contribution(1, 7)]
    );
}

#[test]
fn observation_from_an_inclusive_bound_starts_at_that_namespace() {
    let locator: Locator<String> = Locator::default();
    let key = "k".to_string();
    for namespace in 0..4 {
        locator.register(&key, contribution(namespace, 1));
    }
    let from = [2u8; 16];
    let page = locator.observe_from(&key, Bound::Included(&from), 8);
    assert_eq!(page.candidates, [contribution(2, 1), contribution(3, 1)]);
}

#[test]
fn candidate_pages_continue_without_loss_for_a_popular_key() {
    let locator: Locator<String> = Locator::default();
    let key = "popular".to_string();
    for namespace in 0..10 {
        locator.register(&key, contribution(namespace, 1));
    }
    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let page = locator.observe(&key, after.as_ref(), 3);
        assert!(page.candidates.len() <= 3);
        seen.extend(
            page.candidates
                .iter()
                .map(|candidate| candidate.namespace[0]),
        );
        match page.more {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    assert_eq!(seen, (0..10).collect::<Vec<u8>>());
    // A zero limit still makes progress.
    let page = locator.observe(&key, None, 0);
    assert_eq!(page.candidates.len(), 1);
    assert_eq!(page.more, Some([0; 16]));
}

#[test]
fn range_merges_shards_in_key_order_and_bounds_owners_per_key() {
    let locator: Locator<String> = Locator::default();
    for index in 0..50u8 {
        locator.register(&format!("key{index:02}"), contribution(index, 1));
        locator.register(&format!("key{index:02}"), contribution(index + 100, 1));
    }
    let first = locator.range(Bound::Unbounded, 5, 1);
    let names: Vec<&str> = first.iter().map(|(key, _, _)| key.as_str()).collect();
    assert_eq!(names, ["key00", "key01", "key02", "key03", "key04"]);
    for (_, owners, more) in &first {
        assert_eq!(owners.len(), 1);
        assert!(
            more.is_some(),
            "the second owner is reachable by continuation"
        );
    }
    let next = locator.range(Bound::Excluded(&"key04".to_string()), 2, 4);
    assert_eq!(next[0].0, "key05");
    assert_eq!(next.len(), 2);
    assert!(next[0].2.is_none());
}
