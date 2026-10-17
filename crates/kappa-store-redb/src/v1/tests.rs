#[cfg(test)]
mod epoch_tests {
    use kappa_handler::clock_at;
    use kappa_store::ExecutionStore;
    use kappa_store::traits::blob::BlobStore;
    use kappa_store::traits::edge::EdgeStore;
    use kappa_store::traits::epoch::EpochStore;
    use kappa_store::traits::namespace::NamespaceStore;
    use kappa_store::traits::tag::TagStore;
    use kappa_types::PageRequest;
    use kappa_types::canonical::from_canonical;
    use kappa_types::clock::ClockMs;
    use kappa_types::edge::{BuiltinRelation, Direction, EdgeQuery, EdgeRelation};
    use kappa_types::epoch::EpochMutation;
    use kappa_types::epoch_root::mutations_merkle_root;
    use kappa_types::kappa::Kappa;
    use kappa_types::namespace::NamespaceRef;
    use kappa_types::tag::TagUpdate;
    use kappa_types::{MutationOp, StoreError};

    use kappa_fixture::{FixtureRoot, SetupError};

    use crate::PersistentStore;
    use crate::test_support::PersistentSpec;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The store description in `root`, reopenable by acquiring it again.
    fn spec(root: &FixtureRoot) -> PersistentSpec {
        PersistentSpec::new().in_root(root).db_file("test.redb")
    }

    fn test_store() -> Result<PersistentStore, SetupError> {
        Ok(spec(&FixtureRoot::temporary()?).acquire()?.into_store())
    }

    const fn now() -> ClockMs {
        ClockMs::from_raw(1_700_000_000_000i64 << 16)
    }

    const fn now2() -> ClockMs {
        ClockMs::from_raw(1_700_000_001_000i64 << 16)
    }

    fn set(content: &[u8]) -> TagUpdate {
        TagUpdate::Set {
            kappa: Kappa::sha256(content),
        }
    }

    /// Create `name` and write `tags` in one execution: epoch 1.
    fn create_with_tags(
        store: &PersistentStore,
        name: &str,
        tags: &[(&str, &[u8])],
    ) -> Result<(NamespaceRef, u64, Kappa), StoreError> {
        let ns = NamespaceRef::generate(name, now())?;
        let mut execution = store.begin_execution(&ns, &clock_at(now())?)?;
        execution.namespace_create(None, None)?;
        for (tag, content) in tags {
            execution.tag_put(tag, &set(content))?;
        }
        let published = execution.publish()?;
        Ok((ns, published.epoch_number, published.root))
    }

    fn ledger(store: &PersistentStore, root: &Kappa) -> Result<Vec<EpochMutation>, StoreError> {
        let root = store.epoch_get(root)?;
        Ok(from_canonical(&store.blob_get(root.ledger_root())?)?)
    }

    // C-11: committed tag state survives restart.
    #[test]
    fn digest_survives_restart() -> TestResult {
        let root = FixtureRoot::temporary()?;

        let digest_before;
        {
            let store = spec(&root).acquire()?.into_store();
            let contents: Vec<(String, Vec<u8>)> = (0..10)
                .map(|i| (format!("tag-{i}"), format!("content-{i}").into_bytes()))
                .collect();
            let tags: Vec<(&str, &[u8])> = contents
                .iter()
                .map(|(name, content)| (name.as_str(), content.as_slice()))
                .collect();
            let (ns, _, _) = create_with_tags(&store, "persist-ns", &tags)?;
            digest_before = store.epoch_state(&ns)?.0;
            assert_ne!(
                digest_before, [0u8; 32],
                "digest must be non-zero after 10 tags"
            );
        }

        let store = spec(&root).acquire()?.into_store();
        let ns = store.namespace_resolve("persist-ns", None)?;
        assert_eq!(
            digest_before,
            store.epoch_state(&ns)?.0,
            "committed tag state must survive process restart"
        );
        assert_eq!(store.epoch_current(&ns)?.0, 1);
        Ok(())
    }

    // Publication round-trip on PersistentStore.
    #[test]
    fn publication_roundtrip() -> TestResult {
        let store = test_store()?;
        let (ns, epoch_number, epoch_kappa) =
            create_with_tags(&store, "epoch-rt", &[("a", b"hello"), ("b", b"world")])?;
        let (state_root, tag_count) = store.epoch_state(&ns)?;
        assert_ne!(state_root, [0u8; 32]);
        assert_eq!(tag_count, 2);
        assert_eq!(epoch_number, 1);

        let root = store.epoch_get(&epoch_kappa)?;
        assert_eq!(root.epoch_number(), 1);
        assert!(root.prev_identifier().is_none());
        assert_eq!(root.state_digest(), &state_root);
        assert_eq!(root.tag_count(), 2);
        assert_ne!(root.mutations_root(), &[0u8; 32]);

        // The root links its committed ledger through an EpochRoot edge. The
        // root also links retained evidence (here the namespace record), and
        // edge pages are ordered by edge identity, so the ledger edge is
        // selected by its target rather than by position.
        let edges = store.edge_query(
            &ns,
            &EdgeQuery {
                anchor: epoch_kappa.clone(),
                direction: Direction::Outbound,
                relation: Some(EdgeRelation::Builtin(BuiltinRelation::EpochRoot)),
                asserter: None,
            },
            &PageRequest::first(16),
        )?;
        assert!(edges.next_after.is_none());
        assert_eq!(
            edges
                .items
                .iter()
                .filter(|edge| edge.target() == root.ledger_root())
                .count(),
            1
        );

        let mutations = ledger(&store, &epoch_kappa)?;
        assert_eq!(
            mutations
                .iter()
                .filter(|mutation| mutation.op == MutationOp::TagSet)
                .count(),
            2
        );
        assert_eq!(
            mutations_merkle_root(&mutations).as_slice(),
            root.mutations_root()
        );

        let (cur_num, cur_kappa) = store.epoch_current(&ns)?;
        assert_eq!(cur_num, 1);
        assert_eq!(cur_kappa, epoch_kappa);
        Ok(())
    }

    // Second epoch links to the first.
    #[test]
    fn epoch_chain_links() -> TestResult {
        let store = test_store()?;
        let (ns, _, k1) = create_with_tags(&store, "epoch-chain", &[("a", b"hello")])?;

        let mut execution = store.begin_execution(&ns, &clock_at(now2())?)?;
        execution.tag_put("b", &set(b"world"))?;
        let second = execution.publish()?;

        assert_eq!(second.epoch_number, 2);
        assert_ne!(second.root, k1);
        let root2 = store.epoch_get(&second.root)?;
        assert_eq!(root2.prev_identifier(), Some(&k1));
        assert_eq!(root2.tag_count(), 2);
        Ok(())
    }

    // Writes become durable only through publication. An execution lost to a
    // crash leaves no tag, no pending ledger residue, and no epoch; the
    // reopened store admits a new execution for the namespace.
    #[test]
    fn unpublished_execution_leaves_no_residue_after_restart() -> TestResult {
        let root = FixtureRoot::temporary()?;

        {
            let store = spec(&root).acquire()?.into_store();
            create_with_tags(&store, "crash-ns", &[])?;
            let ns = store.namespace_resolve("crash-ns", None)?;
            let mut execution = store.begin_execution(&ns, &clock_at(now2())?)?;
            execution.tag_put("crash-tag", &set(b"data"))?;
            // The process ends before publication: redb never commits the
            // execution's write transaction, exactly as when it is dropped.
            drop(execution);
        }

        let store = spec(&root).acquire()?.into_store();
        let ns = store.namespace_resolve("crash-ns", None)?;
        assert!(matches!(
            store.tag_get(&ns, "crash-tag"),
            Err(StoreError::NotFound(_))
        ));
        assert_eq!(store.epoch_current(&ns)?.0, 1);

        let mut execution = store.begin_execution(&ns, &clock_at(now2())?)?;
        execution.tag_put("after-restart", &set(b"data"))?;
        let published = execution.publish()?;
        assert_eq!(published.epoch_number, 2);
        let mutations = ledger(&store, &published.root)?;
        assert!(
            mutations
                .iter()
                .all(|mutation| { mutation.context.as_deref() != Some("crash-tag") })
        );
        assert!(mutations.iter().any(|mutation| {
            mutation.op == MutationOp::TagSet
                && mutation.context.as_deref() == Some("after-restart")
        }));
        Ok(())
    }

    // Replay on PersistentStore.
    #[test]
    fn replay_reconstructs_state_persistent() -> TestResult {
        let store = test_store()?;
        let (ns, _, _) =
            create_with_tags(&store, "replay-ns", &[("a", b"alpha"), ("b", b"bravo")])?;

        let mut execution = store.begin_execution(&ns, &clock_at(now2())?)?;
        execution.tag_delete("a")?;
        execution.publish()?;

        let state1 = kappa_store::replay::replay_to(&store, &ns, 1)?;
        assert_eq!(state1.tags.len(), 2);
        assert!(state1.tags.contains_key("a"));
        assert!(state1.tags.contains_key("b"));

        let state2 = kappa_store::replay::replay_to(&store, &ns, 2)?;
        assert_eq!(state2.tags.len(), 1);
        assert!(!state2.tags.contains_key("a"));
        assert!(state2.tags.contains_key("b"));
        Ok(())
    }
}
