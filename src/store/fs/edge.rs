//! Edge store backed by per-namespace redb databases.
//!
//! Each namespace gets its own `edges/{escaped_ns}.redb` file containing
//! four tables with compound string keys. All edge operations within a
//! namespace are atomic (single redb write transaction). Namespace
//! isolation is structural -- different files, different Database handles.

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, TableError};

use crate::store::fs::escape_namespace;
use crate::store::{Direction, EdgeRecord, StoreError};

const FORWARD: TableDefinition<&str, &str> = TableDefinition::new("edges_forward");
const REVERSE: TableDefinition<&str, &str> = TableDefinition::new("edges_reverse");
const BY_RELATION: TableDefinition<&str, &str> = TableDefinition::new("edges_by_relation");
const BY_KAPPA: TableDefinition<&str, &[u8]> = TableDefinition::new("edges_by_kappa");

fn db_path(root: &Path, ns: &str) -> PathBuf {
    root.join("edges")
        .join(format!("{}.redb", escape_namespace(ns)))
}

fn open_db(root: &Path, ns: &str) -> Result<Database, StoreError> {
    let path = db_path(root, ns);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Database::create(&path).map_err(|e| StoreError::Io(std::io::Error::other(e)))
}

fn redb_err(e: impl std::fmt::Display) -> StoreError {
    StoreError::Io(std::io::Error::other(e.to_string()))
}

/// Returns true if the error is TableDoesNotExist (table not yet created).
fn is_table_missing(e: &TableError) -> bool {
    matches!(e, TableError::TableDoesNotExist(_))
}

fn compound3(a: &str, b: &str, c: &str) -> String {
    format!("{a}\0{b}\0{c}")
}

fn prefix1(a: &str) -> String {
    format!("{a}\0")
}

fn prefix2(a: &str, b: &str) -> String {
    format!("{a}\0{b}\0")
}

fn deserialize_record(data: &[u8]) -> Result<EdgeRecord, StoreError> {
    serde_json::from_slice(data).map_err(|e| StoreError::Io(std::io::Error::other(e)))
}

fn serialize_record(record: &EdgeRecord) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(record).map_err(|e| StoreError::Io(std::io::Error::other(e)))
}

/// Collect values from a table where keys start with the given prefix.
fn prefix_scan_values(
    table: &impl ReadableTable<&'static str, &'static str>,
    prefix: &str,
) -> Result<Vec<String>, StoreError> {
    let mut results = Vec::new();
    let range = table.range(prefix..).map_err(redb_err)?;
    for entry in range {
        let entry = entry.map_err(redb_err)?;
        let key = entry.0.value();
        if !key.starts_with(prefix) {
            break;
        }
        results.push(entry.1.value().to_string());
    }
    Ok(results)
}

#[allow(clippy::too_many_arguments)]
pub fn put(
    root: &Path,
    ns: &str,
    edge_kappa: &str,
    src: &str,
    rel: &str,
    tgt: &str,
    _canon: &[u8],
    metadata: serde_json::Value,
) -> Result<bool, StoreError> {
    let db = open_db(root, ns)?;
    let write_txn = db.begin_write().map_err(redb_err)?;

    {
        let table = write_txn.open_table(BY_KAPPA).map_err(redb_err)?;
        if table.get(edge_kappa).map_err(redb_err)?.is_some() {
            return Ok(false);
        }
    }

    let record = EdgeRecord {
        edge_kappa: edge_kappa.to_string(),
        source: src.to_string(),
        relation: rel.to_string(),
        target: tgt.to_string(),
        metadata,
    };
    let record_bytes = serialize_record(&record)?;

    let fwd_key = compound3(src, rel, tgt);
    let rev_key = compound3(tgt, rel, src);
    let rel_key = compound3(rel, src, tgt);

    {
        let mut t = write_txn.open_table(FORWARD).map_err(redb_err)?;
        t.insert(fwd_key.as_str(), edge_kappa).map_err(redb_err)?;
    }
    {
        let mut t = write_txn.open_table(REVERSE).map_err(redb_err)?;
        t.insert(rev_key.as_str(), edge_kappa).map_err(redb_err)?;
    }
    {
        let mut t = write_txn.open_table(BY_RELATION).map_err(redb_err)?;
        t.insert(rel_key.as_str(), edge_kappa).map_err(redb_err)?;
    }
    {
        let mut t = write_txn.open_table(BY_KAPPA).map_err(redb_err)?;
        t.insert(edge_kappa, record_bytes.as_slice())
            .map_err(redb_err)?;
    }

    write_txn.commit().map_err(redb_err)?;
    Ok(true)
}

pub fn query(
    root: &Path,
    ns: &str,
    node: &str,
    dir: Direction,
    rel: Option<&str>,
    n: Option<usize>,
    last: Option<&str>,
) -> Result<Vec<EdgeRecord>, StoreError> {
    let db = match open_db(root, ns) {
        Ok(db) => db,
        Err(_) => return Ok(Vec::new()),
    };
    let read_txn = db.begin_read().map_err(redb_err)?;

    let mut edge_kappas: Vec<String> = Vec::new();

    if matches!(dir, Direction::Outbound | Direction::Both) {
        match read_txn.open_table(FORWARD) {
            Ok(table) => {
                let prefix = match rel {
                    Some(r) => prefix2(node, r),
                    None => prefix1(node),
                };
                edge_kappas.extend(prefix_scan_values(&table, &prefix)?);
            }
            Err(e) if is_table_missing(&e) => {}
            Err(e) => return Err(redb_err(e)),
        }
    }

    if matches!(dir, Direction::Inbound | Direction::Both) {
        match read_txn.open_table(REVERSE) {
            Ok(table) => {
                let prefix = match rel {
                    Some(r) => prefix2(node, r),
                    None => prefix1(node),
                };
                edge_kappas.extend(prefix_scan_values(&table, &prefix)?);
            }
            Err(e) if is_table_missing(&e) => {}
            Err(e) => return Err(redb_err(e)),
        }
    }

    let mut seen = HashSet::new();
    edge_kappas.retain(|ek| seen.insert(ek.clone()));

    let by_kappa = match read_txn.open_table(BY_KAPPA) {
        Ok(t) => t,
        Err(e) if is_table_missing(&e) => return Ok(Vec::new()),
        Err(e) => return Err(redb_err(e)),
    };
    let mut results = Vec::new();
    for ek in &edge_kappas {
        if let Some(guard) = by_kappa.get(ek.as_str()).map_err(redb_err)? {
            results.push(deserialize_record(guard.value())?);
        }
    }

    if let Some(cursor) = last {
        if let Some(pos) = results.iter().position(|e| e.edge_kappa == cursor) {
            results = results[pos + 1..].to_vec();
        }
    }

    if let Some(limit) = n {
        results.truncate(limit);
    }

    Ok(results)
}

pub fn remove(root: &Path, ns: &str, edge_kappa: &str) -> Result<bool, StoreError> {
    let db = match open_db(root, ns) {
        Ok(db) => db,
        Err(_) => return Ok(false),
    };
    let write_txn = db.begin_write().map_err(redb_err)?;

    let record_bytes = {
        let table = write_txn.open_table(BY_KAPPA).map_err(redb_err)?;
        let guard = table.get(edge_kappa).map_err(redb_err)?;
        match guard {
            Some(g) => g.value().to_vec(),
            None => return Ok(false),
        }
    };
    let record = deserialize_record(&record_bytes)?;

    let fwd_key = compound3(&record.source, &record.relation, &record.target);
    let rev_key = compound3(&record.target, &record.relation, &record.source);
    let rel_key = compound3(&record.relation, &record.source, &record.target);

    {
        let mut t = write_txn.open_table(FORWARD).map_err(redb_err)?;
        let _ = t.remove(fwd_key.as_str()).map_err(redb_err)?;
    }
    {
        let mut t = write_txn.open_table(REVERSE).map_err(redb_err)?;
        let _ = t.remove(rev_key.as_str()).map_err(redb_err)?;
    }
    {
        let mut t = write_txn.open_table(BY_RELATION).map_err(redb_err)?;
        let _ = t.remove(rel_key.as_str()).map_err(redb_err)?;
    }
    {
        let mut t = write_txn.open_table(BY_KAPPA).map_err(redb_err)?;
        let _ = t.remove(edge_kappa).map_err(redb_err)?;
    }

    write_txn.commit().map_err(redb_err)?;
    Ok(true)
}

pub fn remove_by_node(root: &Path, ns: &str, kappa: &str) -> Result<(), StoreError> {
    // Collect all edge kappas where this node is source or target
    let mut to_remove: Vec<String> = Vec::new();
    if let Ok(db) = open_db(root, ns) {
        if let Ok(read_txn) = db.begin_read() {
            if let Ok(fwd) = read_txn.open_table(FORWARD) {
                if let Ok(vals) = prefix_scan_values(&fwd, &prefix1(kappa)) {
                    to_remove.extend(vals);
                }
            }
            if let Ok(rev) = read_txn.open_table(REVERSE) {
                if let Ok(vals) = prefix_scan_values(&rev, &prefix1(kappa)) {
                    for v in vals {
                        if !to_remove.contains(&v) {
                            to_remove.push(v);
                        }
                    }
                }
            }
        }
    }

    for ek in &to_remove {
        let _ = remove(root, ns, ek);
    }

    Ok(())
}

pub fn walk(
    root: &Path,
    ns: &str,
    roots: &[String],
    rels: &[&str],
) -> Result<HashSet<String>, StoreError> {
    let db = match open_db(root, ns) {
        Ok(db) => db,
        Err(_) => return Ok(roots.iter().cloned().collect()),
    };
    let read_txn = db.begin_read().map_err(redb_err)?;
    let fwd = match read_txn.open_table(FORWARD) {
        Ok(t) => t,
        Err(e) if is_table_missing(&e) => return Ok(roots.iter().cloned().collect()),
        Err(e) => return Err(redb_err(e)),
    };

    let mut visited: HashSet<String> = roots.iter().cloned().collect();
    let mut queue: VecDeque<String> = roots.iter().cloned().collect();

    while let Some(node) = queue.pop_front() {
        let prefix = prefix1(&node);
        let range = fwd.range(prefix.as_str()..).map_err(redb_err)?;
        for entry in range {
            let entry = entry.map_err(redb_err)?;
            let key = entry.0.value();
            if !key.starts_with(&prefix) {
                break;
            }
            let parts: Vec<&str> = key.split('\0').collect();
            if parts.len() == 3 && rels.iter().any(|&r| r == parts[1]) {
                let target = parts[2].to_string();
                let edge_kappa = entry.1.value().to_string();
                if visited.insert(target.clone()) {
                    queue.push_back(target);
                }
                visited.insert(edge_kappa);
            }
        }
    }

    Ok(visited)
}

pub fn diff(
    root: &Path,
    ns: &str,
    have: &[String],
    want: &[String],
    rels: &[&str],
) -> Result<Vec<String>, StoreError> {
    let want_set = walk(root, ns, want, rels)?;

    let db = match open_db(root, ns) {
        Ok(db) => db,
        Err(_) => {
            let mut result: Vec<String> = want_set.into_iter().collect();
            result.sort();
            return Ok(result);
        }
    };
    let read_txn = db.begin_read().map_err(redb_err)?;
    let fwd = match read_txn.open_table(FORWARD) {
        Ok(t) => Some(t),
        Err(e) if is_table_missing(&e) => None,
        Err(e) => return Err(redb_err(e)),
    };

    let mut have_visited: HashSet<String> = have.iter().cloned().collect();
    let mut have_queue: VecDeque<String> = have.iter().cloned().collect();

    if let Some(ref fwd) = fwd {
        while let Some(node) = have_queue.pop_front() {
            if want_set.contains(&node) && !have.contains(&node) {
                continue;
            }
            let prefix = prefix1(&node);
            let range = fwd.range(prefix.as_str()..).map_err(redb_err)?;
            for entry in range {
                let entry = entry.map_err(redb_err)?;
                let key = entry.0.value();
                if !key.starts_with(&prefix) {
                    break;
                }
                let parts: Vec<&str> = key.split('\0').collect();
                if parts.len() == 3 && rels.iter().any(|&r| r == parts[1]) {
                    let target = parts[2].to_string();
                    let edge_kappa = entry.1.value().to_string();
                    if have_visited.insert(target.clone()) {
                        have_queue.push_back(target);
                    }
                    have_visited.insert(edge_kappa);
                }
            }
        }
    }

    let mut result: Vec<String> = want_set
        .into_iter()
        .filter(|k| !have_visited.contains(k))
        .collect();
    result.sort();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        (dir, root)
    }

    #[test]
    fn put_and_query_roundtrip() {
        let (_dir, root) = tmp_root();
        let ns = "test-ns";
        let created = put(
            &root,
            ns,
            "ek1",
            "src1",
            "owns",
            "tgt1",
            b"",
            serde_json::json!({}),
        )
        .unwrap();
        assert!(created);

        let results = query(
            &root,
            ns,
            "src1",
            Direction::Outbound,
            Some("owns"),
            None,
            None,
        )
        .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].edge_kappa, "ek1");
        assert_eq!(results[0].source, "src1");
        assert_eq!(results[0].target, "tgt1");
    }

    #[test]
    fn query_empty_namespace_returns_empty() {
        let (_dir, root) = tmp_root();
        let results = query(
            &root,
            "empty-ns",
            "node",
            Direction::Outbound,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn walk_empty_namespace_returns_roots() {
        let (_dir, root) = tmp_root();
        let roots = vec!["root1".to_string()];
        let visited = walk(&root, "empty-ns", &roots, &["owns"]).unwrap();
        assert!(visited.contains("root1"));
        assert_eq!(visited.len(), 1);
    }

    #[test]
    fn diff_identical_have_want_returns_empty() {
        let (_dir, root) = tmp_root();
        let ns = "diff-ns";
        // No edges -- just blobs. have=[A], want=[A], diff should be empty.
        let result = diff(&root, ns, &["A".into()], &["A".into()], &["owns"]).unwrap();
        assert!(result.is_empty(), "identical have/want: {result:?}");
    }

    #[test]
    fn diff_with_edges() {
        let (_dir, root) = tmp_root();
        let ns = "diff-edges";
        put(
            &root,
            ns,
            "e1",
            "A",
            "owns",
            "B",
            b"",
            serde_json::json!({}),
        )
        .unwrap();
        put(
            &root,
            ns,
            "e2",
            "B",
            "owns",
            "C",
            b"",
            serde_json::json!({}),
        )
        .unwrap();

        // want=[A], have=[] -- should get A, B, C, e1, e2
        let result = diff(&root, ns, &[], &["A".into()], &["owns"]).unwrap();
        assert!(result.contains(&"A".to_string()));
        assert!(result.contains(&"B".to_string()));
        assert!(result.contains(&"C".to_string()));

        // want=[A], have=[B] -- B and C reachable from have, but A and e1 only from want
        let result = diff(&root, ns, &["B".into()], &["A".into()], &["owns"]).unwrap();
        assert!(
            result.contains(&"A".to_string()),
            "A only reachable from want"
        );
    }

    #[test]
    fn remove_and_verify_gone() {
        let (_dir, root) = tmp_root();
        let ns = "rm-ns";
        put(
            &root,
            ns,
            "ek1",
            "s",
            "owns",
            "t",
            b"",
            serde_json::json!({}),
        )
        .unwrap();
        assert!(remove(&root, ns, "ek1").unwrap());
        let results = query(&root, ns, "s", Direction::Outbound, None, None, None).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn idempotent_put() {
        let (_dir, root) = tmp_root();
        let ns = "idem-ns";
        assert!(put(
            &root,
            ns,
            "ek1",
            "s",
            "owns",
            "t",
            b"",
            serde_json::json!({})
        )
        .unwrap());
        assert!(!put(
            &root,
            ns,
            "ek1",
            "s",
            "owns",
            "t",
            b"",
            serde_json::json!({})
        )
        .unwrap());
    }

    #[test]
    fn namespace_isolation() {
        let (_dir, root) = tmp_root();
        put(
            &root,
            "ns-a",
            "ek1",
            "s",
            "owns",
            "t",
            b"",
            serde_json::json!({}),
        )
        .unwrap();
        let results = query(&root, "ns-b", "s", Direction::Outbound, None, None, None).unwrap();
        assert!(results.is_empty(), "ns-b should not see ns-a edges");
    }
}
