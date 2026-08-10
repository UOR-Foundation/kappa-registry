//! Edge operations for PersistentStore.
//!
//! Edges are content-addressed dCBOR blobs stored on the filesystem.
//! Four multimap indexes (forward, reverse, relation, asserter) in redb
//! enable querying by source, target, relation, or asserter.
//!
//! edge_delete uses a single write transaction for both the scan and
//! the removal to prevent TOCTOU races.

use redb::{ReadableDatabase, ReadableMultimapTable, ReadableTable};

use kappa_core::canonical::{canonical_bytes, from_canonical};
use kappa_core::types::*;

use crate::tables::*;
use crate::PersistentStore;

impl PersistentStore {
    pub(crate) fn edge_put_impl(&self, ns: &str, edge: &Edge) -> Result<(), StoreError> {
        let edge_bytes = canonical_bytes(edge);
        let edge_kappa = {
            use kappa_core::store::KappaStore;
            self.ingest_compute(kappa_core::kappa::Axis::Sha256, &edge_bytes)?.kappa
        };

        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        {
            let mut ns_table = txn.open_table(NAMESPACES).map_err(Self::redb_err)?;
            ns_table.insert(ns, ()).map_err(Self::redb_err)?;
            drop(ns_table);

            let edge_key = format!("{}\x00{}", ns, edge_kappa);
            let stored_bytes: Vec<u8> = match &self.table_encryptor {
                Some(enc) => enc.encrypt_value(&edge_key, &edge_bytes)
                    .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?,
                None => edge_bytes.clone(),
            };
            let mut edges = txn.open_table(EDGES).map_err(Self::redb_err)?;
            edges
                .insert(edge_key.as_str(), stored_bytes.as_slice())
                .map_err(Self::redb_err)?;
            drop(edges);

            let fwd_key = format!("{}\x00{}", ns, edge.source);
            let mut fwd = txn.open_multimap_table(EDGE_FWD).map_err(Self::redb_err)?;
            fwd.insert(fwd_key.as_str(), edge_kappa.as_str())
                .map_err(Self::redb_err)?;
            drop(fwd);

            let rev_key = format!("{}\x00{}", ns, edge.target);
            let mut rev = txn.open_multimap_table(EDGE_REV).map_err(Self::redb_err)?;
            rev.insert(rev_key.as_str(), edge_kappa.as_str())
                .map_err(Self::redb_err)?;
            drop(rev);

            let rel_key = format!("{}\x00{}", ns, edge.relation.as_str());
            let mut rel = txn.open_multimap_table(EDGE_REL).map_err(Self::redb_err)?;
            rel.insert(rel_key.as_str(), edge_kappa.as_str())
                .map_err(Self::redb_err)?;
            drop(rel);

            let asr_key = format!("{}\x00{}", ns, edge.asserter);
            let mut asr = txn.open_multimap_table(EDGE_ASR).map_err(Self::redb_err)?;
            asr.insert(asr_key.as_str(), edge_kappa.as_str())
                .map_err(Self::redb_err)?;
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(())
    }

    pub(crate) fn edge_query_impl(
        &self,
        ns: &str,
        query: &EdgeQuery,
    ) -> Result<Vec<Edge>, StoreError> {
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let index_key = format!("{}\x00{}", ns, query.anchor);

        let edge_kappas: Vec<String> = match query.direction {
            Direction::Outbound => {
                let table = txn.open_multimap_table(EDGE_FWD).map_err(Self::redb_err)?;
                table
                    .get(index_key.as_str())
                    .map_err(Self::redb_err)?
                    .filter_map(|v| v.ok().map(|v| v.value().to_string()))
                    .collect()
            }
            Direction::Inbound => {
                let table = txn.open_multimap_table(EDGE_REV).map_err(Self::redb_err)?;
                table
                    .get(index_key.as_str())
                    .map_err(Self::redb_err)?
                    .filter_map(|v| v.ok().map(|v| v.value().to_string()))
                    .collect()
            }
        };

        let edges_table = txn.open_table(EDGES).map_err(Self::redb_err)?;
        let mut results = Vec::new();
        for ek in &edge_kappas {
            let edge_key = format!("{}\x00{}", ns, ek);
            if let Some(val) = edges_table.get(edge_key.as_str()).map_err(Self::redb_err)? {
                let raw_bytes = val.value();
                let decrypted = match &self.table_encryptor {
                    Some(enc) => enc.decrypt_value(&edge_key, raw_bytes)
                        .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?,
                    None => raw_bytes.to_vec(),
                };
                let edge: Edge = from_canonical(&decrypted)
                    .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
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
                results.push(edge);
            }
        }
        Ok(results)
    }

    pub(crate) fn edge_delete_impl(
        &self,
        ns: &str,
        source: &str,
        target: &str,
        relation: EdgeRelation,
    ) -> Result<(), StoreError> {
        // Single write transaction for scan + removal (no TOCTOU)
        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        {
            // Scan phase: find the matching edge kappa
            let fwd_key = format!("{}\x00{}", ns, source);
            let fwd_table = txn.open_multimap_table(EDGE_FWD).map_err(Self::redb_err)?;
            let edges_table = txn.open_table(EDGES).map_err(Self::redb_err)?;

            let candidates: Vec<String> = fwd_table
                .get(fwd_key.as_str())
                .map_err(Self::redb_err)?
                .filter_map(|v| v.ok().map(|v| v.value().to_string()))
                .collect();

            let mut found_kappa = None;
            let mut found_edge = None;
            for ek in &candidates {
                let edge_key = format!("{}\x00{}", ns, ek);
                if let Some(val) = edges_table.get(edge_key.as_str()).map_err(Self::redb_err)? {
                    let raw_bytes = val.value();
                    let decrypted = match &self.table_encryptor {
                        Some(enc) => enc.decrypt_value(&edge_key, raw_bytes)
                            .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?,
                        None => raw_bytes.to_vec(),
                    };
                    let edge: Edge = from_canonical(&decrypted)
                        .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
                    if edge.source == source && edge.target == target && edge.relation == relation {
                        found_kappa = Some(ek.clone());
                        found_edge = Some(edge);
                        break;
                    }
                }
            }

            // Must drop read-only borrows before mutating
            drop(edges_table);
            drop(fwd_table);

            // Remove phase
            if let (Some(edge_kappa), Some(edge)) = (found_kappa, found_edge) {
                let edge_key = format!("{}\x00{}", ns, edge_kappa);
                let mut edges = txn.open_table(EDGES).map_err(Self::redb_err)?;
                edges.remove(edge_key.as_str()).map_err(Self::redb_err)?;
                drop(edges);

                let mut fwd = txn.open_multimap_table(EDGE_FWD).map_err(Self::redb_err)?;
                let fk = format!("{}\x00{}", ns, edge.source);
                fwd.remove(fk.as_str(), edge_kappa.as_str())
                    .map_err(Self::redb_err)?;
                drop(fwd);

                let mut rev = txn.open_multimap_table(EDGE_REV).map_err(Self::redb_err)?;
                let rk = format!("{}\x00{}", ns, edge.target);
                rev.remove(rk.as_str(), edge_kappa.as_str())
                    .map_err(Self::redb_err)?;
                drop(rev);

                let mut rel = txn.open_multimap_table(EDGE_REL).map_err(Self::redb_err)?;
                let rlk = format!("{}\x00{}", ns, edge.relation.as_str());
                rel.remove(rlk.as_str(), edge_kappa.as_str())
                    .map_err(Self::redb_err)?;
                drop(rel);

                let mut asr = txn.open_multimap_table(EDGE_ASR).map_err(Self::redb_err)?;
                let ak = format!("{}\x00{}", ns, edge.asserter);
                asr.remove(ak.as_str(), edge_kappa.as_str())
                    .map_err(Self::redb_err)?;

                // Edge blob deletion happens after commit
                // (filesystem, outside transaction)
                drop(asr);
                txn.commit().map_err(Self::redb_err)?;
                self.blob_delete_impl(&edge_kappa)?;
                return Ok(());
            }
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(())
    }
}
