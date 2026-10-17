//! Shared fallible edge traversal. Adjacency consistency belongs to the
//! supplied storage/read view; successful traversal does not assert isolation.

use std::collections::{HashSet, VecDeque};

use kappa_types::{
    Direction, EdgeQuery, EdgeRelation, Kappa, NamespaceRef, PageRequest, StoreError,
};

use crate::traits::EdgeStore;

/// Walk all admitted outgoing relationships, including relationship objects.
///
/// Discovery is by full content identity, independent of storage ordinals.
/// A failed query or visitor aborts traversal; it cannot look like exhaustion.
/// The visitor runs once per identity and need not materialize the result set.
pub fn walk_edges<S: EdgeStore + ?Sized>(
    view: &S,
    namespaces: &[NamespaceRef],
    roots: &[Kappa],
    follow: impl Fn(&EdgeRelation) -> bool,
    mut visit: impl FnMut(&Kappa) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let mut discovered = HashSet::new();
    let mut frontier = VecDeque::new();
    for root in roots {
        if discovered.insert(root.clone()) {
            frontier.push_back(root.clone());
        }
    }
    while let Some(node) = frontier.pop_front() {
        visit(&node)?;
        for namespace in namespaces {
            let query = EdgeQuery {
                anchor: node.clone(),
                direction: Direction::Outbound,
                relation: None,
                asserter: None,
            };
            let mut request = PageRequest::first(256);
            let mut continuations = HashSet::new();
            loop {
                let page = view.edge_query(namespace, &query, &request)?;
                if page.items.len() > request.limit {
                    return Err(StoreError::Rejected(
                        "adjacency page exceeds requested bound".into(),
                    ));
                }
                for edge in &page.items {
                    if edge.source() != &node {
                        return Err(StoreError::Rejected(
                            "outbound adjacency contains another source".into(),
                        ));
                    }
                    if !follow(edge.relation()) {
                        continue;
                    }
                    for identity in [edge.target(), &edge.kappa] {
                        if discovered.insert(identity.clone()) {
                            frontier.push_back(identity.clone());
                        }
                    }
                }
                match page.next_after {
                    Some(next) => {
                        if page.items.is_empty() || !continuations.insert(next.clone()) {
                            return Err(StoreError::Rejected(
                                "adjacency continuation did not progress".into(),
                            ));
                        }
                        request.after = Some(next);
                    }
                    None => break,
                }
            }
        }
    }
    Ok(())
}

/// Materialize graph difference only at the API that requires a vector.
/// An empty relation selection follows no edges, as specified by `EdgeStore`.
pub fn edge_difference<S: EdgeStore + ?Sized>(
    view: &S,
    namespace: &NamespaceRef,
    have: &[Kappa],
    want: &[Kappa],
    relations: &[EdgeRelation],
) -> Result<Vec<Kappa>, StoreError> {
    let namespaces = std::slice::from_ref(namespace);
    let mut excluded = HashSet::new();
    walk_edges(
        view,
        namespaces,
        have,
        |relation| relations.contains(relation),
        |identity| {
            excluded.insert(identity.clone());
            Ok(())
        },
    )?;
    let mut result = Vec::new();
    walk_edges(
        view,
        namespaces,
        want,
        |relation| relations.contains(relation),
        |identity| {
            if !excluded.contains(identity) {
                result.push(identity.clone());
            }
            Ok(())
        },
    )?;
    result.sort();
    Ok(result)
}
