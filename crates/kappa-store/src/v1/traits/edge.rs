use kappa_types::edge::{Edge, EdgeQuery, EdgeRelation};
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::namespace::NamespaceRef;
use kappa_types::page::{Page, PageRequest};

/// Published typed directed edges between kappa digests.
///
/// Each edge is content-addressed: its kappa is the canonical dCBOR of its
/// `EdgeInput`. Edge writes go through `ExecutionWrites` and publish with
/// their epoch.
pub trait EdgeStore: Send + Sync {
    /// Query edges matching filters, paginated.
    ///
    /// `EdgeQuery` carries domain filters: anchor, direction, relation,
    /// asserter. `PageRequest` carries pagination: limit, cursor.
    /// `Page<Edge>` carries results and `next_after` cursor.
    ///
    /// The asserter filter serves delegation chain walk (find all
    /// delegations from this anchor) and Ortelius supply chain
    /// queries (find all certifications by this authority).
    fn edge_query(
        &self,
        ns: &NamespaceRef,
        query: &EdgeQuery,
        page: &PageRequest,
    ) -> Result<Page<Edge>, StoreError>;

    /// Streaming cursor over edges matching the query.
    ///
    /// Returns raw `key_bytes` via `KappaCursor`. The caller
    /// deserializes individual edges on demand, or uses the
    /// `key_bytes` directly for membership checks and set operations.
    ///
    /// For large traversals (GC, reconciliation, delegation chain).
    fn edge_cursor(
        &self,
        ns: &NamespaceRef,
        query: &EdgeQuery,
    ) -> Result<Box<dyn kappa_cursor::KappaCursor + '_>, StoreError>;

    /// Kappas reachable from `want` but not from `have`,
    /// walking only edges whose relation is in `relations`.
    ///
    /// `relations` controls which edge types the graph walk
    /// follows. GC passes `gc_reachable` relations. Federation
    /// passes all. An empty slice follows no edges.
    fn edge_diff(
        &self,
        ns: &NamespaceRef,
        have: &[Kappa],
        want: &[Kappa],
        relations: &[EdgeRelation],
    ) -> Result<Vec<Kappa>, StoreError> {
        crate::graph::edge_difference(self, ns, have, want, relations)
    }
}
