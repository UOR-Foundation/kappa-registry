use kappa_handler::clock_at;
use kappa_store::{BlobStore, EdgeStore, ExecutionStore};
use kappa_store_memory::test_support;
use kappa_types::edge::{
    BuiltinRelation, Direction, EdgeInput, EdgeQuery, EdgeRelation, SemanticRelation,
};
use kappa_types::page::PageRequest;
use kappa_types::{ClockMs, Kappa, NamespaceRef, VerifiedContent};

#[test]
fn immutable_edges_preserve_identity_pages_and_shared_content()
-> Result<(), Box<dyn std::error::Error>> {
    let store = test_support::test_store()?.into_store();
    let ns = NamespaceRef::deterministic("one");
    let other = NamespaceRef::deterministic("two");
    let now = clock_at(ClockMs::from_raw(999))?;
    let source = Kappa::sha256(b"source");
    let mut input = EdgeInput {
        source: source.clone(),
        target: Kappa::sha256(b"target"),
        relation: EdgeRelation::Builtin(BuiltinRelation::Owns),
        asserter: source.clone(),
        created_at_ms: 7,
        metadata: Some(vec![1]),
    };

    let mut execution = store.begin_execution(&ns, &now)?;
    let first = execution.edge_put(&input)?;
    assert_eq!(
        execution.edge_put(&input)?,
        first,
        "identity is the content of the edge"
    );
    input.metadata = Some(vec![2]);
    let second = execution.edge_put(&input)?;
    assert_ne!(first, second);
    input.relation =
        EdgeRelation::Semantic(SemanticRelation("https://example.org/relation".into()));
    execution.edge_put_batch(&[input.clone(), input.clone()])?;
    execution.publish()?;

    // The same content is a member of another namespace independently.
    let mut shared = store.begin_execution(&other, &now)?;
    input.relation = EdgeRelation::Builtin(BuiltinRelation::Owns);
    input.metadata = Some(vec![1]);
    assert_eq!(shared.edge_put(&input)?, first);
    shared.publish()?;

    let query = EdgeQuery {
        anchor: source,
        direction: Direction::Both,
        relation: None,
        asserter: None,
    };
    let mut request = PageRequest::first(1);
    let mut identities = Vec::new();
    loop {
        let page = store.edge_query(&ns, &query, &request)?;
        assert!(page.len() <= 1);
        for edge in page.items {
            assert_eq!(edge.created_at_ms(), 7);
            VerifiedContent::verify(
                &edge.kappa,
                &kappa_types::canonical::canonical_bytes(&edge.input),
            )?;
            identities.push(edge.kappa);
        }
        match page.next_after {
            Some(next) => request.after = Some(next),
            None => break,
        }
    }
    assert_eq!(identities.len(), 3);
    assert!(identities.windows(2).all(|pair| pair[0] < pair[1]));

    // Membership removal in one namespace leaves the content and the other
    // namespace's membership in place.
    let mut removal = store.begin_execution(&ns, &now)?;
    removal.edge_delete(&first)?;
    removal.publish()?;
    assert!(store.blob_exists(&first)?);
    assert_eq!(
        store
            .edge_query(&ns, &query, &PageRequest::first(10))?
            .len(),
        2
    );
    assert_eq!(
        store
            .edge_query(&other, &query, &PageRequest::first(10))?
            .len(),
        1
    );
    Ok(())
}
