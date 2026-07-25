//! Edge store backed by per-namespace redb databases.
//!
//! Each namespace gets its own `edges/{escaped_ns}.redb` file containing
//! four tables with compound string keys. All edge operations within a
//! namespace are atomic (single redb write transaction). Namespace
//! isolation is structural -- different files, different Database handles.

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, TableError};

use crate::store::fs::safe_name;
use crate::store::{Direction, EdgeRecord, StoreError};

const FORWARD: TableDefinition<&[u8], &str> = TableDefinition::new("edges_forward");
const REVERSE: TableDefinition<&[u8], &str> = TableDefinition::new("edges_reverse");
const BY_RELATION: TableDefinition<&[u8], &str> = TableDefinition::new("edges_by_relation");
const BY_KAPPA: TableDefinition<&str, &[u8]> = TableDefinition::new("edges_by_kappa");

fn db_path(root: &Path, ns: &str) -> PathBuf {
    root.join("edges").join(format!("{}.redb", safe_name(ns)))
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

fn is_table_missing(e: &TableError) -> bool {
    matches!(e, TableError::TableDoesNotExist(_))
}

/// Length-prefixed compound key: u16(a.len) + a + u16(b.len) + b + u16(c.len) + c.
/// No delimiter character. Injection-immune regardless of field content.
fn compound3(a: &str, b: &str, c: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + a.len() + b.len() + c.len());
    out.extend_from_slice(&(a.len() as u16).to_le_bytes());
    out.extend_from_slice(a.as_bytes());
    out.extend_from_slice(&(b.len() as u16).to_le_bytes());
    out.extend_from_slice(b.as_bytes());
    out.extend_from_slice(&(c.len() as u16).to_le_bytes());
    out.extend_from_slice(c.as_bytes());
    out
}

/// Prefix for scanning all entries where the first field equals `a`.
fn prefix1(a: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + a.len());
    out.extend_from_slice(&(a.len() as u16).to_le_bytes());
    out.extend_from_slice(a.as_bytes());
    out
}

/// Prefix for scanning entries where fields 1 and 2 equal `a` and `b`.
fn prefix2(a: &str, b: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + a.len() + b.len());
    out.extend_from_slice(&(a.len() as u16).to_le_bytes());
    out.extend_from_slice(a.as_bytes());
    out.extend_from_slice(&(b.len() as u16).to_le_bytes());
    out.extend_from_slice(b.as_bytes());
    out
}

/// Parse the third field from a length-prefixed compound key.
fn parse_field3(data: &[u8]) -> Option<&str> {
    let mut pos = 0;
    // Skip field 1
    let len1 = u16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?) as usize;
    pos += 2 + len1;
    // Skip field 2
    let len2 = u16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?) as usize;
    pos += 2 + len2;
    // Read field 3
    let len3 = u16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?) as usize;
    pos += 2;
    std::str::from_utf8(data.get(pos..pos + len3)?).ok()
}

/// Parse field 2 (relation) from a length-prefixed compound key.
fn parse_field2(data: &[u8]) -> Option<&str> {
    let mut pos = 0;
    let len1 = u16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?) as usize;
    pos += 2 + len1;
    let len2 = u16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?) as usize;
    pos += 2;
    std::str::from_utf8(data.get(pos..pos + len2)?).ok()
}

/// Compute exclusive upper bound for prefix range scan.
fn prefix_upper_bound(prefix: &[u8]) -> Vec<u8> {
    let mut bound = prefix.to_vec();
    while let Some(last) = bound.last_mut() {
        if *last < 0xFF {
            *last += 1;
            return bound;
        }
        bound.pop();
    }
    vec![0xFF; prefix.len() + 1]
}

fn deserialize_record(data: &[u8]) -> Result<EdgeRecord, StoreError> {
    serde_json::from_slice(data).map_err(|e| StoreError::Io(std::io::Error::other(e)))
}

fn serialize_record(record: &EdgeRecord) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(record).map_err(|e| StoreError::Io(std::io::Error::other(e)))
}

/// Collect values from a table where keys start with the given prefix.
fn prefix_scan_values(
    table: &impl ReadableTable<&'static [u8], &'static str>,
    prefix: &[u8],
) -> Result<Vec<String>, StoreError> {
    let mut results = Vec::new();
    let upper = prefix_upper_bound(prefix);
    let range = table.range(prefix..upper.as_slice()).map_err(redb_err)?;
    for entry in range {
        let entry = entry.map_err(redb_err)?;
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
        t.insert(fwd_key.as_slice(), edge_kappa).map_err(redb_err)?;
    }
    {
        let mut t = write_txn.open_table(REVERSE).map_err(redb_err)?;
        t.insert(rev_key.as_slice(), edge_kappa).map_err(redb_err)?;
    }
    {
        let mut t = write_txn.open_table(BY_RELATION).map_err(redb_err)?;
        t.insert(rel_key.as_slice(), edge_kappa).map_err(redb_err)?;
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
                let pfx = match rel {
                    Some(r) => prefix2(node, r),
                    None => prefix1(node),
                };
                edge_kappas.extend(prefix_scan_values(&table, &pfx)?);
            }
            Err(e) if is_table_missing(&e) => {}
            Err(e) => return Err(redb_err(e)),
        }
    }

    if matches!(dir, Direction::Inbound | Direction::Both) {
        match read_txn.open_table(REVERSE) {
            Ok(table) => {
                let pfx = match rel {
                    Some(r) => prefix2(node, r),
                    None => prefix1(node),
                };
                edge_kappas.extend(prefix_scan_values(&table, &pfx)?);
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
        let _ = t.remove(fwd_key.as_slice()).map_err(redb_err)?;
    }
    {
        let mut t = write_txn.open_table(REVERSE).map_err(redb_err)?;
        let _ = t.remove(rev_key.as_slice()).map_err(redb_err)?;
    }
    {
        let mut t = write_txn.open_table(BY_RELATION).map_err(redb_err)?;
        let _ = t.remove(rel_key.as_slice()).map_err(redb_err)?;
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
    let pfx = prefix1(kappa);
    if let Ok(db) = open_db(root, ns) {
        if let Ok(read_txn) = db.begin_read() {
            if let Ok(fwd) = read_txn.open_table(FORWARD) {
                if let Ok(vals) = prefix_scan_values(&fwd, &pfx) {
                    to_remove.extend(vals);
                }
            }
            if let Ok(rev) = read_txn.open_table(REVERSE) {
                if let Ok(vals) = prefix_scan_values(&rev, &pfx) {
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
        let pfx = prefix1(&node);
        let upper = prefix_upper_bound(&pfx);
        let range = fwd
            .range(pfx.as_slice()..upper.as_slice())
            .map_err(redb_err)?;
        for entry in range {
            let entry = entry.map_err(redb_err)?;
            let key = entry.0.value();
            if let (Some(relation), Some(target)) = (parse_field2(key), parse_field3(key)) {
                if rels.contains(&relation) {
                    let edge_kappa = entry.1.value().to_string();
                    if visited.insert(target.to_string()) {
                        queue.push_back(target.to_string());
                    }
                    visited.insert(edge_kappa);
                }
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
            let pfx = prefix1(&node);
            let upper = prefix_upper_bound(&pfx);
            let range = fwd
                .range(pfx.as_slice()..upper.as_slice())
                .map_err(redb_err)?;
            for entry in range {
                let entry = entry.map_err(redb_err)?;
                let key = entry.0.value();
                if let (Some(relation), Some(target)) = (parse_field2(key), parse_field3(key)) {
                    if rels.contains(&relation) {
                        let edge_kappa = entry.1.value().to_string();
                        if have_visited.insert(target.to_string()) {
                            have_queue.push_back(target.to_string());
                        }
                        have_visited.insert(edge_kappa);
                    }
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
