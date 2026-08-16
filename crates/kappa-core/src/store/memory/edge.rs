//! Edge operations for InMemoryStore.
//!
//! Edges are content-addressed dCBOR blobs with four derived indexes:
//! forward (by source), reverse (by target), by relation, by asserter.
//! Indexes are maintained on put/delete and rebuilt from blobs on recovery.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::canonical::canonical_bytes;
use crate::kappa::kappa_from_bytes;
use crate::store::KappaStore;
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
        EdgeRelation::RefersTo => 15,
        EdgeRelation::Delegation => 16,
    }
}

pub(super) fn edge_put(store: &InMemoryStore, ns: &NamespaceRef, edge: &Edge) -> Result<(), StoreError> {
    store.ensure_namespace(ns);

    let edge_bytes = canonical_bytes(edge);
    let edge_kappa = kappa_from_bytes(&edge_bytes);
    store.ingest_compute(crate::kappa::Axis::Sha256, &edge_bytes)?;

    let uuid = *ns.uuid();
    let ek_hash = item_hash(&edge_kappa);

    // Upsert: check for existing edge with same (source, target, relation, asserter)
    {
        let src_hash = item_hash(&edge.source);
        let fwd = store.fwd_index.read().unwrap();
        if let Some(existing_kappas) = fwd.get(&(uuid, src_hash)) {
            let edges = store.edges.read().unwrap();
            for ek in existing_kappas {
                let ekh = item_hash(ek);
                if let Some(existing) = edges.get(&(uuid, ekh)) {
                    if existing.source == edge.source
                        && existing.target == edge.target
                        && existing.relation == edge.relation
                        && existing.asserter == edge.asserter
                    {
                        if existing.value_kappa == edge.value_kappa
                            && existing.metadata == edge.metadata
                        {
                            return Ok(()); // exact duplicate, skip
                        }
                        // Same logical edge, different value/metadata: update in place
                        drop(edges);
                        drop(fwd);
                        store.edges.write().unwrap().insert((uuid, ekh), edge.clone());
                        return Ok(());
                    }
                }
            }
        }
    }

    // New edge: insert and index
    {
        store
            .edges
            .write()
            .unwrap()
            .insert((uuid, ek_hash), edge.clone());
    }

    fn push_index(
        index: &RwLock<HashMap<([u8; 16], u64), Vec<String>>>,
        uuid: [u8; 16],
        key_hash: u64,
        edge_kappa: &str,
    ) {
        index
            .write()
            .unwrap()
            .entry((uuid, key_hash))
            .or_default()
            .push(edge_kappa.to_string());
    }

    push_index(
        &store.fwd_index,
        uuid,
        item_hash(&edge.source),
        &edge_kappa,
    );
    push_index(
        &store.rev_index,
        uuid,
        item_hash(&edge.target),
        &edge_kappa,
    );
    push_index(
        &store.rel_index,
        uuid,
        relation_index(&edge.relation),
        &edge_kappa,
    );
    push_index(
        &store.asr_index,
        uuid,
        item_hash(&edge.asserter),
        &edge_kappa,
    );

    Ok(())
}

pub(super) fn edge_query(
    store: &InMemoryStore,
    ns: &NamespaceRef,
    query: &EdgeQuery,
) -> Result<Vec<Edge>, StoreError> {
    let uuid = *ns.uuid();
    let anchor_hash = item_hash(&query.anchor);

    let kappas = match query.direction {
        Direction::Outbound => store
            .fwd_index
            .read()
            .unwrap()
            .get(&(uuid, anchor_hash))
            .cloned()
            .unwrap_or_default(),
        Direction::Inbound => store
            .rev_index
            .read()
            .unwrap()
            .get(&(uuid, anchor_hash))
            .cloned()
            .unwrap_or_default(),
    };

    let edges = store.edges.read().unwrap();
    let mut result = Vec::new();
    for ek in &kappas {
        let ek_hash = item_hash(ek);
        if let Some(edge) = edges.get(&(uuid, ek_hash)) {
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
    ns: &NamespaceRef,
    source: &str,
    target: &str,
    relation: EdgeRelation,
) -> Result<(), StoreError> {
    let uuid = *ns.uuid();

    // Find the edge kappa by scanning the source's forward index
    let edges = store.edges.read().unwrap();
    let edge_kappa = {
        let fwd = store.fwd_index.read().unwrap();
        let src_hash = item_hash(source);
        let candidates = fwd.get(&(uuid, src_hash)).cloned().unwrap_or_default();
        let mut found = None;
        for ek in &candidates {
            let ek_hash = item_hash(ek);
            if let Some(edge) = edges.get(&(uuid, ek_hash)) {
                if edge.source == source && edge.target == target && edge.relation == relation {
                    found = Some(ek.clone());
                    break;
                }
            }
        }
        found
    };
    drop(edges);

    let Some(edge_kappa) = edge_kappa else {
        return Ok(());
    };

    let ek_hash = item_hash(&edge_kappa);
    let edge = store.edges.write().unwrap().remove(&(uuid, ek_hash));

    if let Some(edge) = edge {
        fn remove_from(
            index: &RwLock<HashMap<([u8; 16], u64), Vec<String>>>,
            uuid: [u8; 16],
            key_hash: u64,
            kappa: &str,
        ) {
            if let Some(vec) = index.write().unwrap().get_mut(&(uuid, key_hash)) {
                vec.retain(|k| k != kappa);
            }
        }

        remove_from(
            &store.fwd_index,
            uuid,
            item_hash(&edge.source),
            &edge_kappa,
        );
        remove_from(
            &store.rev_index,
            uuid,
            item_hash(&edge.target),
            &edge_kappa,
        );
        remove_from(
            &store.rel_index,
            uuid,
            relation_index(&edge.relation),
            &edge_kappa,
        );
        remove_from(
            &store.asr_index,
            uuid,
            item_hash(&edge.asserter),
            &edge_kappa,
        );
    }

    store.blob_delete(&edge_kappa)?;
    Ok(())
}
