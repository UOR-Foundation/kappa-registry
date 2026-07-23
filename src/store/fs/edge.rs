use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};

use crate::store::fs::{atomic_write, escape_namespace};
use crate::store::{Direction, EdgeRecord, StoreError};

fn by_source_path(root: &Path, source: &str) -> PathBuf {
    root.join("index")
        .join("edges")
        .join("by-source")
        .join(format!("{}.json", escape_namespace(source)))
}

fn by_target_path(root: &Path, target: &str) -> PathBuf {
    root.join("index")
        .join("edges")
        .join("by-target")
        .join(format!("{}.json", escape_namespace(target)))
}

fn by_kappa_path(root: &Path, edge_kappa: &str) -> PathBuf {
    root.join("index")
        .join("edges")
        .join("by-kappa")
        .join(format!("{}.json", escape_namespace(edge_kappa)))
}

fn read_records(path: &Path) -> Vec<EdgeRecord> {
    match std::fs::read(path) {
        Ok(data) => serde_json::from_slice(&data).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

fn write_records(path: &Path, records: &[EdgeRecord]) -> Result<(), StoreError> {
    let data =
        serde_json::to_vec_pretty(records).map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    atomic_write(path, &data)
}

pub fn put(
    root: &Path,
    edge_kappa: &str,
    src: &str,
    rel: &str,
    tgt: &str,
    _canon: &[u8],
    metadata: serde_json::Value,
) -> Result<bool, StoreError> {
    let bk = by_kappa_path(root, edge_kappa);
    if bk.exists() {
        return Ok(false);
    }

    let record = EdgeRecord {
        edge_kappa: edge_kappa.to_string(),
        source: src.to_string(),
        relation: rel.to_string(),
        target: tgt.to_string(),
        metadata,
    };

    // by-source index
    let bs = by_source_path(root, src);
    let mut source_records = read_records(&bs);
    source_records.push(record.clone());
    write_records(&bs, &source_records)?;

    // by-target index
    let bt = by_target_path(root, tgt);
    let mut target_records = read_records(&bt);
    target_records.push(record.clone());
    write_records(&bt, &target_records)?;

    // by-kappa lookup
    let data = serde_json::to_vec(&record).map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    atomic_write(&bk, &data)?;

    Ok(true)
}

pub fn query(
    root: &Path,
    node: &str,
    dir: Direction,
    rel: Option<&str>,
    n: Option<usize>,
    last: Option<&str>,
) -> Result<Vec<EdgeRecord>, StoreError> {
    let mut results = Vec::new();

    if matches!(dir, Direction::Outbound | Direction::Both) {
        let path = by_source_path(root, node);
        let records = read_records(&path);
        results.extend(records);
    }

    if matches!(dir, Direction::Inbound | Direction::Both) {
        let path = by_target_path(root, node);
        let records = read_records(&path);
        results.extend(records);
    }

    // Deduplicate by edge_kappa
    let mut seen = HashSet::new();
    results.retain(|e| seen.insert(e.edge_kappa.clone()));

    // Relation filter
    if let Some(r) = rel {
        results.retain(|e| e.relation == r);
    }

    // Cursor pagination
    if let Some(cursor) = last {
        if let Some(pos) = results.iter().position(|e| e.edge_kappa == cursor) {
            results = results[pos + 1..].to_vec();
        }
    }

    // Page size
    if let Some(limit) = n {
        results.truncate(limit);
    }

    Ok(results)
}

pub fn remove(root: &Path, edge_kappa: &str) -> Result<bool, StoreError> {
    let bk = by_kappa_path(root, edge_kappa);
    if !bk.exists() {
        return Ok(false);
    }

    let data = std::fs::read(&bk)?;
    let record: EdgeRecord =
        serde_json::from_slice(&data).map_err(|e| StoreError::Io(std::io::Error::other(e)))?;

    // Remove from by-source
    let bs = by_source_path(root, &record.source);
    let mut source_records = read_records(&bs);
    source_records.retain(|e| e.edge_kappa != edge_kappa);
    write_records(&bs, &source_records)?;

    // Remove from by-target
    let bt = by_target_path(root, &record.target);
    let mut target_records = read_records(&bt);
    target_records.retain(|e| e.edge_kappa != edge_kappa);
    write_records(&bt, &target_records)?;

    // Remove by-kappa
    std::fs::remove_file(&bk)?;

    Ok(true)
}

pub fn remove_by_node(root: &Path, kappa: &str) -> Result<(), StoreError> {
    let bs = by_source_path(root, kappa);
    if bs.exists() {
        let records = read_records(&bs);
        for record in &records {
            let bt = by_target_path(root, &record.target);
            let mut target_records = read_records(&bt);
            target_records.retain(|e| e.source != kappa);
            if target_records.is_empty() {
                let _ = std::fs::remove_file(&bt);
            } else {
                let _ = write_records(&bt, &target_records);
            }
            let bk = by_kappa_path(root, &record.edge_kappa);
            let _ = std::fs::remove_file(&bk);
        }
        let _ = std::fs::remove_file(&bs);
    }

    let bt = by_target_path(root, kappa);
    if bt.exists() {
        let records = read_records(&bt);
        for record in &records {
            let bsrc = by_source_path(root, &record.source);
            let mut source_records = read_records(&bsrc);
            source_records.retain(|e| e.target != kappa);
            if source_records.is_empty() {
                let _ = std::fs::remove_file(&bsrc);
            } else {
                let _ = write_records(&bsrc, &source_records);
            }
            let bk = by_kappa_path(root, &record.edge_kappa);
            let _ = std::fs::remove_file(&bk);
        }
        let _ = std::fs::remove_file(&bt);
    }

    Ok(())
}

pub fn walk(root: &Path, roots: &[String], rels: &[&str]) -> Result<HashSet<String>, StoreError> {
    let mut visited: HashSet<String> = roots.iter().cloned().collect();
    let mut queue: VecDeque<String> = roots.iter().cloned().collect();

    while let Some(node) = queue.pop_front() {
        let path = by_source_path(root, &node);
        let records = read_records(&path);
        for record in records {
            if rels.iter().any(|&r| r == record.relation) {
                if visited.insert(record.target.clone()) {
                    queue.push_back(record.target);
                }
                visited.insert(record.edge_kappa);
            }
        }
    }

    Ok(visited)
}
