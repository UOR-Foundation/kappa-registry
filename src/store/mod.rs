pub mod fs;

use std::collections::HashSet;

#[derive(Debug)]
pub enum StoreError {
    NotFound,
    Conflict(String),
    Io(std::io::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NotFound => write!(f, "not found"),
            StoreError::Conflict(msg) => write!(f, "conflict: {msg}"),
            StoreError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        StoreError::Io(std::io::Error::other(e))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Inbound,
    Outbound,
    Both,
}

impl Direction {
    pub fn parse(s: &str) -> Self {
        match s {
            "inbound" => Direction::Inbound,
            "both" => Direction::Both,
            _ => Direction::Outbound,
        }
    }
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct TagListOpts {
    pub n: Option<usize>,
    pub last: Option<String>,
    pub order: Option<String>,
    pub after: Option<String>,
    pub before: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TagPage {
    pub tags: Vec<TagEntry>,
    #[serde(skip)]
    pub has_more: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TagEntry {
    pub name: String,
    pub kappa: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EdgeRecord {
    pub edge_kappa: String,
    pub source: String,
    pub relation: String,
    pub target: String,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SchemaRecord {
    pub scope: String,
    pub kappa: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FilterRecord {
    pub scope: String,
    pub kappa: String,
}

pub trait KappaStore: Send + Sync + 'static {
    // blob (global by kappa)
    fn put(&self, kappa: &str, content: &[u8]) -> Result<bool, StoreError>;
    fn get(&self, kappa: &str) -> Result<Option<Vec<u8>>, StoreError>;
    fn exists(&self, kappa: &str) -> Result<bool, StoreError>;
    fn remove(&self, kappa: &str) -> Result<(), StoreError>;
    fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError>;
    fn put_meta(&self, kappa: &str, key: &str, val: &[u8]) -> Result<(), StoreError>;
    fn get_meta(&self, kappa: &str, key: &str) -> Result<Option<Vec<u8>>, StoreError>;

    // tag (scoped to namespace)
    fn tag_set(&self, ns: &str, name: &str, kappa: &str) -> Result<(), StoreError>;
    fn tag_get(&self, ns: &str, name: &str) -> Result<Option<String>, StoreError>;
    fn tag_list(&self, ns: &str, opts: &TagListOpts) -> Result<TagPage, StoreError>;
    fn tag_delete(&self, ns: &str, name: &str) -> Result<bool, StoreError>;
    fn tag_set_if(
        &self,
        ns: &str,
        name: &str,
        kappa: &str,
        expected: Option<&str>,
    ) -> Result<bool, StoreError>;
    fn tag_all_kappas_global(&self) -> Result<Vec<String>, StoreError>;

    // edge (global by canonical form)
    fn edge_put(
        &self,
        edge_kappa: &str,
        src: &str,
        rel: &str,
        tgt: &str,
        canon: &[u8],
        metadata: serde_json::Value,
    ) -> Result<bool, StoreError>;
    fn edge_query(
        &self,
        node: &str,
        dir: Direction,
        rel: Option<&str>,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<Vec<EdgeRecord>, StoreError>;
    fn edge_find(
        &self,
        node: &str,
        dir: Direction,
        rel: Option<&str>,
    ) -> Result<Vec<EdgeRecord>, StoreError> {
        self.edge_query(node, dir, rel, None, None)
    }
    fn edge_remove(&self, edge_kappa: &str) -> Result<bool, StoreError>;
    fn edge_remove_by_node(&self, kappa: &str) -> Result<(), StoreError>;
    fn edge_walk(&self, roots: &[String], rels: &[&str]) -> Result<HashSet<String>, StoreError>;

    // pin (global)
    fn pin(&self, protected: &str, ttl: u64, ctrl: &str) -> Result<String, StoreError>;
    fn unpin(&self, pin_kappa: &str, release: bool) -> Result<(), StoreError>;
    fn pin_roots(&self) -> Result<Vec<String>, StoreError>;
    fn pin_finalizers(&self) -> Result<Vec<(String, String)>, StoreError>;

    // schema (scoped to namespace)
    fn schema_register(&self, ns: &str, scope: &str, content: &[u8]) -> Result<String, StoreError>;
    fn schema_get(&self, ns: &str, scope: &str) -> Result<Option<(String, Vec<u8>)>, StoreError>;
    fn schema_list(&self, ns: &str) -> Result<Vec<SchemaRecord>, StoreError>;

    // filter (scoped to namespace)
    fn filter_register(&self, ns: &str, scope: &str, content: &[u8]) -> Result<String, StoreError>;
    fn filter_list(&self, ns: &str) -> Result<Vec<FilterRecord>, StoreError>;
    fn filter_remove(&self, filter_kappa: &str) -> Result<bool, StoreError>;
    fn filter_evaluate(&self, ns: &str, content: &[u8]) -> Result<(), String>;
}
