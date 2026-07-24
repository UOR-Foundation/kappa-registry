mod blob;
mod edge;
mod filter;
pub mod fingerprint;
mod pin;
mod schema;
mod tag;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::store::*;

pub struct FsStore {
    root: PathBuf,
}

impl FsStore {
    pub fn new(root: PathBuf) -> Result<Self, StoreError> {
        std::fs::create_dir_all(&root)?;
        Ok(FsStore { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Write content to dest atomically via tempfile in the same directory,
/// fsync content, rename, fsync parent directory.
pub fn atomic_write(dest: &Path, content: &[u8]) -> Result<(), StoreError> {
    use std::io::Write;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let parent = dest.parent().unwrap();
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(content)?;
    tmp.as_file().sync_all()?;
    tmp.persist(dest).map_err(|e| StoreError::Io(e.error))?;
    if let Ok(d) = std::fs::File::open(parent) {
        let _ = d.sync_all();
    }
    Ok(())
}

fn escape_namespace(ns: &str) -> String {
    ns.replace(':', "__").replace('/', "_")
}

impl KappaStore for FsStore {
    fn put(&self, kappa: &str, content: &[u8]) -> Result<bool, StoreError> {
        blob::put(&self.root, kappa, content)
    }
    fn get(&self, kappa: &str) -> Result<Option<Vec<u8>>, StoreError> {
        blob::get(&self.root, kappa)
    }
    fn exists(&self, kappa: &str) -> Result<bool, StoreError> {
        blob::exists(&self.root, kappa)
    }
    fn remove(&self, kappa: &str) -> Result<(), StoreError> {
        blob::remove(&self.root, kappa)
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        blob::list(&self.root, prefix)
    }
    fn put_meta(&self, kappa: &str, key: &str, val: &[u8]) -> Result<(), StoreError> {
        blob::put_meta(&self.root, kappa, key, val)
    }
    fn get_meta(&self, kappa: &str, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        blob::get_meta(&self.root, kappa, key)
    }

    fn tag_set(&self, path: &str, name: &str, kappa: &str) -> Result<(), StoreError> {
        tag::set(&self.root, path, name, kappa)
    }
    fn tag_get(&self, path: &str, name: &str) -> Result<Option<String>, StoreError> {
        tag::get(&self.root, path, name)
    }
    fn tag_list(&self, path: &str, opts: &TagListOpts) -> Result<TagPage, StoreError> {
        tag::list(&self.root, path, opts)
    }
    fn tag_delete(&self, path: &str, name: &str) -> Result<bool, StoreError> {
        tag::delete(&self.root, path, name)
    }
    fn tag_set_if(
        &self,
        path: &str,
        name: &str,
        kappa: &str,
        expected: Option<&str>,
    ) -> Result<bool, StoreError> {
        tag::set_if(&self.root, path, name, kappa, expected)
    }
    fn tag_all_kappas_global(&self) -> Result<Vec<String>, StoreError> {
        tag::all_kappas_global(&self.root)
    }
    fn tag_find_by_kappa(&self, ns: &str, kappa: &str) -> Result<Vec<String>, StoreError> {
        tag::find_by_kappa(&self.root, ns, kappa)
    }
    fn tag_set_batch(&self, ns: &str, updates: &[TagUpdate]) -> Result<BatchResult, StoreError> {
        tag::set_batch(&self.root, ns, updates)
    }
    fn tag_set_symbolic(&self, ns: &str, name: &str, target: &str) -> Result<(), StoreError> {
        tag::set_symbolic(&self.root, ns, name, target)
    }
    fn tag_get_raw(&self, ns: &str, name: &str) -> Result<Option<String>, StoreError> {
        tag::get_raw(&self.root, ns, name)
    }

    fn edge_put(
        &self,
        ns: &str,
        edge_kappa: &str,
        src: &str,
        rel: &str,
        tgt: &str,
        canon: &[u8],
        metadata: serde_json::Value,
    ) -> Result<bool, StoreError> {
        edge::put(&self.root, ns, edge_kappa, src, rel, tgt, canon, metadata)
    }
    fn edge_query(
        &self,
        ns: &str,
        node: &str,
        dir: Direction,
        rel: Option<&str>,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<Vec<EdgeRecord>, StoreError> {
        edge::query(&self.root, ns, node, dir, rel, n, last)
    }
    fn edge_remove(&self, ns: &str, edge_kappa: &str) -> Result<bool, StoreError> {
        edge::remove(&self.root, ns, edge_kappa)
    }
    fn edge_remove_by_node(&self, ns: &str, kappa: &str) -> Result<(), StoreError> {
        edge::remove_by_node(&self.root, ns, kappa)
    }
    fn edge_walk(
        &self,
        ns: &str,
        roots: &[String],
        rels: &[&str],
    ) -> Result<HashSet<String>, StoreError> {
        edge::walk(&self.root, ns, roots, rels)
    }
    fn edge_diff(
        &self,
        ns: &str,
        have: &[String],
        want: &[String],
        rels: &[&str],
    ) -> Result<Vec<String>, StoreError> {
        edge::diff(&self.root, ns, have, want, rels)
    }

    fn range_fingerprint(
        &self,
        ns: &str,
        lower: &str,
        upper: &str,
    ) -> Result<RangeFingerprint, StoreError> {
        fingerprint::range_fp(&self.root, ns, lower, upper)
    }
    fn range_items(&self, ns: &str, lower: &str, upper: &str) -> Result<Vec<String>, StoreError> {
        fingerprint::range_items(&self.root, ns, lower, upper)
    }

    fn pin(&self, protected: &str, ttl: u64, ctrl: &str) -> Result<String, StoreError> {
        pin::pin(&self.root, protected, ttl, ctrl)
    }
    fn unpin(&self, pin_kappa: &str, release: bool) -> Result<(), StoreError> {
        pin::unpin(&self.root, pin_kappa, release)
    }
    fn pin_roots(&self) -> Result<Vec<String>, StoreError> {
        pin::roots(&self.root)
    }
    fn pin_finalizers(&self) -> Result<Vec<(String, String)>, StoreError> {
        pin::finalizers(&self.root)
    }

    fn schema_register(
        &self,
        path: &str,
        scope: &str,
        content: &[u8],
    ) -> Result<String, StoreError> {
        schema::register(&self.root, path, scope, content)
    }
    fn schema_get(&self, path: &str, scope: &str) -> Result<Option<(String, Vec<u8>)>, StoreError> {
        schema::get(&self.root, path, scope)
    }
    fn schema_list(&self, path: &str) -> Result<Vec<SchemaRecord>, StoreError> {
        schema::list(&self.root, path)
    }

    fn filter_register(
        &self,
        path: &str,
        scope: &str,
        content: &[u8],
    ) -> Result<String, StoreError> {
        filter::register(&self.root, path, scope, content)
    }
    fn filter_list(&self, path: &str) -> Result<Vec<FilterRecord>, StoreError> {
        filter::list(&self.root, path)
    }
    fn filter_remove(&self, filter_kappa: &str) -> Result<bool, StoreError> {
        filter::remove(&self.root, filter_kappa)
    }
    fn filter_evaluate(&self, path: &str, content: &[u8]) -> Result<(), String> {
        filter::evaluate(&self.root, path, content)
    }

    fn list_by_meta(&self, key: &str, value: &str) -> Result<Vec<String>, StoreError> {
        blob::list_by_meta(&self.root, key, value)
    }

    fn bundle_create(&self, kappas: &[String], use_deltas: bool) -> Result<Vec<u8>, StoreError> {
        let mut objects: Vec<(&str, Vec<u8>)> = Vec::with_capacity(kappas.len());
        for k in kappas {
            let content = blob::get(&self.root, k)?.ok_or(StoreError::NotFound)?;
            objects.push((k.as_str(), content));
        }
        let refs: Vec<(&str, &[u8])> = objects.iter().map(|(k, c)| (*k, c.as_slice())).collect();
        Ok(crate::bundle::encode(&refs, use_deltas))
    }

    fn bundle_ingest(&self, bundle: &[u8]) -> Result<Vec<String>, StoreError> {
        let root = self.root.clone();
        let resolve = move |k: &str| blob::get(&root, k).ok().flatten();
        let entries = crate::bundle::decode(bundle, Some(&resolve))?;
        let mut ingested = Vec::with_capacity(entries.len());
        for entry in &entries {
            blob::put(&self.root, &entry.kappa, &entry.content)?;
            ingested.push(entry.kappa.clone());
        }
        Ok(ingested)
    }

    fn namespace_root(&self, ns: &str) -> Result<(Option<String>, usize), StoreError> {
        tag::namespace_root(&self.root, ns)
    }
    fn namespace_proof(&self, ns: &str, name: &str) -> Result<Option<NamespaceProof>, StoreError> {
        tag::namespace_proof(&self.root, ns, name)
    }
}
