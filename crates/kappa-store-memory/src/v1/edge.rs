use std::ops::Bound::{Excluded, Unbounded};

use imbl::{OrdMap, OrdSet};
use kappa_cursor::{KappaCursor, SliceCursor};
use kappa_store::EdgeStore;
use kappa_types::canonical::canonical_bytes;
use kappa_types::edge::{Direction, Edge, EdgeInput, EdgeQuery};
use kappa_types::page::{Page, PageRequest};
use kappa_types::{Axis, Kappa, MutationOp, NamespaceRef, StoreError, VerifiedContent};

use super::InMemoryStore;
use super::execution::WriteCx;
use super::view::NamespaceView;

/// Namespace-local records and indexes, published together with the
/// namespace view. Index keys retain complete identities; shortened hashes
/// are never authoritative here.
#[derive(Clone, Default)]
pub struct EdgeState {
    records: OrdMap<Kappa, Edge>,
    outbound: OrdMap<Kappa, OrdSet<Kappa>>,
    inbound: OrdMap<Kappa, OrdSet<Kappa>>,
    relations: OrdMap<Vec<u8>, OrdSet<Kappa>>,
    asserters: OrdMap<Kappa, OrdSet<Kappa>>,
}

impl EdgeState {
    pub(crate) fn insert(&mut self, edge: Edge) -> bool {
        if self.records.contains_key(&edge.kappa) {
            return false;
        }
        self.outbound
            .entry(edge.source().clone())
            .or_default()
            .insert(edge.kappa.clone());
        self.inbound
            .entry(edge.target().clone())
            .or_default()
            .insert(edge.kappa.clone());
        self.relations
            .entry(canonical_bytes(edge.relation()))
            .or_default()
            .insert(edge.kappa.clone());
        self.asserters
            .entry(edge.asserter().clone())
            .or_default()
            .insert(edge.kappa.clone());
        self.records.insert(edge.kappa.clone(), edge);
        true
    }

    /// Whether an edge of this namespace retains `identity`: as its own
    /// record, or as the target of a retaining relation.
    pub(crate) fn retains(&self, identity: &Kappa) -> bool {
        self.records.contains_key(identity)
            || self.inbound.get(identity).is_some_and(|edges| {
                edges.iter().any(|edge| {
                    self.records
                        .get(edge)
                        .is_some_and(|edge| edge.relation().gc_reachable())
                })
            })
    }

    fn remove(&mut self, identity: &Kappa) -> Option<Edge> {
        let edge = self.records.remove(identity)?;
        for (index, anchor) in [
            (&mut self.outbound, edge.source()),
            (&mut self.inbound, edge.target()),
            (&mut self.asserters, edge.asserter()),
        ] {
            if let Some(keys) = index.get_mut(anchor) {
                keys.remove(identity);
                if keys.is_empty() {
                    index.remove(anchor);
                }
            }
        }
        let relation = canonical_bytes(edge.relation());
        if let Some(keys) = self.relations.get_mut(&relation) {
            keys.remove(identity);
            if keys.is_empty() {
                self.relations.remove(&relation);
            }
        }
        Some(edge)
    }

    fn matches(edge: &Edge, query: &EdgeQuery) -> bool {
        query
            .relation
            .as_ref()
            .is_none_or(|relation| edge.relation() == relation)
            && query
                .asserter
                .as_ref()
                .is_none_or(|asserter| edge.asserter() == asserter)
    }

    fn visit(
        &self,
        query: &EdgeQuery,
        after: Option<&Kappa>,
        mut visitor: impl FnMut(&Edge) -> bool,
    ) -> Result<(), StoreError> {
        let bounds = (after.map_or(Unbounded, Excluded), Unbounded);
        let outbound = self.outbound.get(&query.anchor);
        let inbound = self.inbound.get(&query.anchor);
        let empty = OrdSet::new();
        let left = match query.direction {
            Direction::Outbound | Direction::Both => outbound.unwrap_or(&empty),
            Direction::Inbound => &empty,
        };
        let right = match query.direction {
            Direction::Inbound | Direction::Both => inbound.unwrap_or(&empty),
            Direction::Outbound => &empty,
        };
        let relation_key = query.relation.as_ref().map(canonical_bytes);
        let relation_keys = relation_key
            .as_ref()
            .map(|key| self.relations.get(key).unwrap_or(&empty));
        let asserter_keys = query
            .asserter
            .as_ref()
            .map(|key| self.asserters.get(key).unwrap_or(&empty));
        // Choose the smallest available posting list. Direction::Both is an
        // ordered union, so its summed cardinality is a conservative estimate.
        // All remaining predicates are index membership checks, before loads.
        let adjacency_cost = left.len().saturating_add(right.len());
        let selected = [relation_keys, asserter_keys]
            .into_iter()
            .flatten()
            .min_by_key(|keys| keys.len());
        if let Some(selected) = selected.filter(|keys| keys.len() <= adjacency_cost) {
            for identity in selected.range::<_, Kappa>(bounds) {
                if !(left.contains(identity) || right.contains(identity))
                    || relation_keys.is_some_and(|keys| !keys.contains(identity))
                    || asserter_keys.is_some_and(|keys| !keys.contains(identity))
                {
                    continue;
                }
                let edge = self.records.get(identity).ok_or_else(|| {
                    StoreError::Internal("edge index references missing record".into())
                })?;
                if Self::matches(edge, query) && !visitor(edge) {
                    break;
                }
            }
            return Ok(());
        }
        let mut left = left.range::<_, Kappa>(bounds).peekable();
        let mut right = right.range::<_, Kappa>(bounds).peekable();
        loop {
            let identity = match (left.peek(), right.peek()) {
                (Some(a), Some(b)) if a == b => {
                    right.next();
                    left.next()
                }
                (Some(a), Some(b)) if a < b => left.next(),
                (_, Some(_)) => right.next(),
                (Some(_), None) => left.next(),
                (None, None) => break,
            };
            let Some(identity) = identity else {
                break;
            };
            if relation_keys.is_some_and(|keys| !keys.contains(identity))
                || asserter_keys.is_some_and(|keys| !keys.contains(identity))
            {
                continue;
            }
            let edge = self.records.get(identity).ok_or_else(|| {
                StoreError::Internal("edge index references missing record".into())
            })?;
            if Self::matches(edge, query) && !visitor(edge) {
                break;
            }
        }
        Ok(())
    }
}

impl WriteCx<'_> {
    /// Admit an edge's record, index it, and record `EdgePut` when the
    /// namespace did not already hold it.
    pub fn edge_put(&mut self, input: &EdgeInput) -> Result<Kappa, StoreError> {
        let content = VerifiedContent::compute(Axis::Sha256, &canonical_bytes(input))?;
        self.publish_content(&content)?;
        let edge = Edge {
            kappa: content.kappa().clone(),
            input: input.clone(),
        };
        if self.view.edges.insert(edge) {
            self.record(
                MutationOp::EdgePut,
                content.kappa().clone(),
                Some(input.relation.to_string()),
            );
        }
        Ok(content.kappa().clone())
    }

    /// Remove the edge from the namespace's membership. Its record stays
    /// admitted: the ledger that recorded the edge names it, and history is
    /// retained; retiring the record is a separate, explicit retirement.
    pub fn edge_delete(&mut self, identity: &Kappa) {
        if let Some(edge) = self.view.edges.remove(identity) {
            self.record(
                MutationOp::EdgeDelete,
                identity.clone(),
                Some(edge.relation().to_string()),
            );
        }
    }
}

/// One page of `query` over the edges of `view`.
pub fn edge_query_in(
    view: &NamespaceView,
    query: &EdgeQuery,
    page: &PageRequest,
) -> Result<Page<Edge>, StoreError> {
    if page.limit == 0 {
        return Ok(Page::empty());
    }
    let after = page.after.as_deref().map(Kappa::parse).transpose()?;
    let mut results = Vec::with_capacity(page.limit.min(1000));
    view.edges.visit(query, after.as_ref(), |edge| {
        results.push(edge.clone());
        results.len() <= page.limit
    })?;
    Ok(Page::from_oversized(results, page.limit, |edge| {
        edge.kappa.to_string()
    }))
}

impl EdgeStore for InMemoryStore {
    fn edge_query(
        &self,
        ns: &NamespaceRef,
        query: &EdgeQuery,
        page: &PageRequest,
    ) -> Result<Page<Edge>, StoreError> {
        edge_query_in(&self.view(ns.id()), query, page)
    }

    fn edge_cursor(
        &self,
        ns: &NamespaceRef,
        query: &EdgeQuery,
    ) -> Result<Box<dyn KappaCursor>, StoreError> {
        let mut keys = Vec::new();
        self.view(ns.id()).edges.visit(query, None, |edge| {
            keys.push(edge.kappa.key_bytes());
            true
        })?;
        // Owned key snapshot of one published view.
        Ok(Box::new(SliceCursor::from_owned(keys)))
    }
}

#[cfg(test)]
#[path = "edge_index_tests.rs"]
mod index_tests;
