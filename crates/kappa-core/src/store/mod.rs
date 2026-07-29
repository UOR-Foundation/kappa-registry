//! Store trait and implementations.

pub mod memory;

use crate::epoch::EpochRoot;
use crate::types::{Edge, EdgeQuery, EdgeRelation, EpochMutation, StoreError, TagEntry, TagUpdate};

/// Semantic storage interface for all registry operations.
pub trait KappaStore: Send + Sync {
    // -- Blob (5) -----------------------------------------------------------

    fn blob_put(&self, content: &[u8]) -> Result<String, StoreError>;
    fn blob_get(&self, kappa: &str) -> Result<Vec<u8>, StoreError>;
    fn blob_exists(&self, kappa: &str) -> Result<bool, StoreError>;
    fn blob_delete(&self, kappa: &str) -> Result<(), StoreError>;
    fn blob_get_range(&self, kappa: &str, offset: u64, length: u64)
        -> Result<Vec<u8>, StoreError>;

    // -- Tag (6) ------------------------------------------------------------

    fn tag_set(&self, ns: &str, name: &str, kappa: &str) -> Result<u64, StoreError>;
    fn tag_get(&self, ns: &str, name: &str) -> Result<TagEntry, StoreError>;
    fn tag_delete(&self, ns: &str, name: &str) -> Result<(), StoreError>;
    fn tag_list(&self, ns: &str) -> Result<Vec<TagEntry>, StoreError>;
    fn tag_prefix(&self, ns: &str, prefix: &str) -> Result<Vec<TagEntry>, StoreError>;
    fn tag_set_batch(&self, ns: &str, updates: &[TagUpdate]) -> Result<(), StoreError>;

    // -- Edge (3) -----------------------------------------------------------

    fn edge_put(&self, ns: &str, edge: &Edge) -> Result<String, StoreError>;
    fn edge_query(&self, ns: &str, query: &EdgeQuery) -> Result<Vec<Edge>, StoreError>;
    fn edge_delete(&self, ns: &str, edge_kappa: &str) -> Result<(), StoreError>;

    // -- Sequence (2) -------------------------------------------------------

    fn sequence_next(&self, ns: &str, name: &str) -> Result<u64, StoreError>;
    fn sequence_current(&self, ns: &str, name: &str) -> Result<u64, StoreError>;

    // -- Epoch (3) ----------------------------------------------------------

    fn epoch_advance(&self, ns: &str, mutations: Vec<EpochMutation>)
        -> Result<String, StoreError>;
    fn epoch_current(&self, ns: &str) -> Result<Option<String>, StoreError>;
    fn epoch_get(&self, kappa: &str) -> Result<EpochRoot, StoreError>;

    // -- Namespace (2) ------------------------------------------------------

    fn namespace_list(&self) -> Result<Vec<String>, StoreError>;
    fn namespace_exists(&self, ns: &str) -> Result<bool, StoreError>;
}
