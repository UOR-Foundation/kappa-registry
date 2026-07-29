//! Edge operations for InMemoryStore.
//!
//! Edges are content-addressed dCBOR blobs with four derived indexes:
//! forward (by source), reverse (by target), by relation, by asserter.
//! Indexes are maintained on put/delete and rebuilt from blobs on recovery.

use std::sync::RwLock;
use std::collections::HashMap;

use crate::canonical::canonical_bytes;
use crate::kappa::kappa_from_bytes;
use crate::types::*;

use super::InMemoryStore;

/// Map EdgeRelation to its permanent CBOR discriminant for index keys.
/// Exhaustive match -- adding a variant without handling it is a compile error.
fn relation_index(relation: &EdgeRelation) -> u64 {
    match relation {
        EdgeRelation::Owns => 0,
        EdgeRelation::ComposedOf => 1,
        EdgeRelation::Assertion => 2,
        EdgeRelation::Revocation => 3,
        EdgeRelation::Capability => 4,
        EdgeRelation::RecoveryShare => 5,
        EdgeRelation::EpochRoot => 6,
        EdgeRelation::AkdTreeNode => 7,
        EdgeRelation::ChunkManifest => 8,
        EdgeRelation::WitnessReceipt => 9,
        EdgeRelation::OffloadReceipt => 10,
        EdgeRelation::DerivedFrom => 11,
        EdgeRelation::CertifiedBy => 12,
        EdgeRelation::EvidenceProvenance => 13,
        EdgeRelation::SectionOf => 14,
    }
}

pub(super) fn edge_put(
    store: &InMemoryStore,
    ns: &str,
    edge: &Edge,
) -> Result<String, StoreError> {
    store.ensure_namespace(ns);

    let edge_bytes = canonical_bytes(edge);
    let edge_kappa = kappa_from_bytes(&edge_bytes);
    store.blob_put(&edge_bytes)?;

    let ns_hash = namespace_hash(ns);
    let ek_hash = item_hash(&edge_kappa);

    {
        store.edges.write().unwrap().insert((ns_hash, ek_hash), edge.clone());
    }

    fn push_index(
        index: &RwLock<HashMap<(u64, u64), Vec<String>>>,
        ns_hash: u64,
        key_hash: u64,
        edge_kappa: &str,
    ) {
        index.write().unwrap()
            .entry((ns_hash, key_hash))
            .or_default()
            .push(edge_kappa.to_string());
    }

    push_index(&store.fwd_index, ns_hash, item_hash(&edge.source), &edge_kappa);
    push_index(&store.rev_index, ns_hash, item_hash(&edge.target), &edge_kappa);
    push_index(&store.rel_index, ns_hash, relation_index(&edge.relation), &edge_kappa);
    push_index(&store.asr_index, ns_hash, item_hash(&edge.asserter), &edge_kappa);

    Ok(edge_kappa)
}

pub(super) fn edge_query(
    store: &InMemoryStore,
    ns: &str,
    query: &EdgeQuery,
) -> Result<Vec<Edge>, StoreError> {
    let ns_hash = namespace_hash(ns);
    let anchor_hash = item_hash(&query.anchor);

    let kappas = match query.direction {
        Direction::Outbound => {
            store.fwd_index.read().unwrap()
                .get(&(ns_hash, anchor_hash))
                .cloned()
                .unwrap_or_default()
        }
        Direction::Inbound => {
            store.rev_index.read().unwrap()
                .get(&(ns_hash, anchor_hash))
                .cloned()
                .unwrap_or_default()
        }
    };

    let edges = store.edges.read().unwrap();
    let mut result = Vec::new();
    for ek in &kappas {
        let ek_hash = item_hash(ek);
        if let Some(edge) = edges.get(&(ns_hash, ek_hash)) {
            if let Some(ref rel) = query.relation {
                if edge.relation != *rel {
                    continue;
                }
            }
            if let Some(ref asr) = query.asserter {
                if edge.asserter != *asr {
                    continue;
                }
            }
            result.push(edge.clone());
        }
    }
    Ok(result)
}

pub(super) fn edge_delete(
    store: &InMemoryStore,
    ns: &str,
    edge_kappa: &str,
) -> Result<(), StoreError> {
    let ns_hash = namespace_hash(ns);
    let ek_hash = item_hash(edge_kappa);

    let edge = store.edges.write().unwrap().remove(&(ns_hash, ek_hash));

    if let Some(edge) = edge {
        fn remove_from(
            index: &RwLock<HashMap<(u64, u64), Vec<String>>>,
            ns_hash: u64,
            key_hash: u64,
            kappa: &str,
        ) {
            if let Some(vec) = index.write().unwrap().get_mut(&(ns_hash, key_hash)) {
                vec.retain(|k| k != kappa);
            }
        }

        remove_from(&store.fwd_index, ns_hash, item_hash(&edge.source), edge_kappa);
        remove_from(&store.rev_index, ns_hash, item_hash(&edge.target), edge_kappa);
        remove_from(&store.rel_index, ns_hash, relation_index(&edge.relation), edge_kappa);
        remove_from(&store.asr_index, ns_hash, item_hash(&edge.asserter), edge_kappa);
    }

    store.blob_delete(edge_kappa)?;
    Ok(())
}
