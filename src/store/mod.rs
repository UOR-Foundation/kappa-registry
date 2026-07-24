pub mod fs;

use std::collections::HashSet;

#[derive(Debug)]
pub enum StoreError {
    NotFound,
    Conflict(String),
    Io(std::io::Error),
    // P8 delta codec errors
    DeltaTruncated(&'static str),
    DeltaReservedOpcode,
    DeltaBaseSizeMismatch {
        expected: usize,
        got: usize,
    },
    DeltaResultSizeMismatch {
        expected: usize,
        got: usize,
    },
    DeltaCopyOutOfBounds {
        offset: usize,
        size: usize,
        base_len: usize,
    },
    DeltaUnresolvableBase(String),
    DeltaVarintOverflow,
    BundleTruncated(&'static str),
    BundleTrailerMismatch,
    BundleDecodeLimitExceeded,
    BundleDeltaInNoDeltaBundle,
    BundleKappaMismatch(String),
    BundleUnsupportedEntryType(u8),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NotFound => write!(f, "not found"),
            StoreError::DeltaTruncated(field) => write!(f, "truncated delta {field}"),
            StoreError::DeltaReservedOpcode => write!(f, "reserved delta opcode 0x00"),
            StoreError::DeltaBaseSizeMismatch { expected, got } => {
                write!(
                    f,
                    "delta base size mismatch: expected {expected}, got {got}"
                )
            }
            StoreError::DeltaResultSizeMismatch { expected, got } => {
                write!(
                    f,
                    "delta result size mismatch: expected {expected}, got {got}"
                )
            }
            StoreError::DeltaCopyOutOfBounds {
                offset,
                size,
                base_len,
            } => {
                write!(
                    f,
                    "copy out of bounds: offset={offset} size={size} base_len={base_len}"
                )
            }
            StoreError::DeltaUnresolvableBase(k) => write!(f, "unresolvable delta base: {k}"),
            StoreError::DeltaVarintOverflow => write!(f, "varint overflow"),
            StoreError::BundleTruncated(field) => write!(f, "truncated bundle {field}"),
            StoreError::BundleTrailerMismatch => write!(f, "bundle trailer mismatch"),
            StoreError::BundleDecodeLimitExceeded => write!(f, "bundle exceeds decode limit"),
            StoreError::BundleDeltaInNoDeltaBundle => write!(f, "delta entry in non-delta bundle"),
            StoreError::BundleKappaMismatch(k) => write!(f, "bundle entry kappa mismatch: {k}"),
            StoreError::BundleUnsupportedEntryType(t) => {
                write!(f, "unsupported entry type 0x{t:02x}")
            }
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

#[derive(Debug, Clone, serde::Serialize)]
pub struct NamespaceProof {
    pub tag: String,
    pub value: String,
    pub proof_format: String,
    pub leaves: Vec<(String, String)>,
    pub root: String,
}

/// A single tag update within an atomic batch. The namespace is not part of
/// the update -- all updates in a batch target the endpoint namespace,
/// derived from the URL path.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TagUpdate {
    /// Tag name.
    pub name: String,
    /// New kappa-label to bind.
    pub new_kappa: String,
    /// CAS expectation. None = create-if-absent (tag must not exist).
    /// Some(kappa) = tag must currently equal kappa.
    /// Some("") = unconditional (no CAS check).
    pub expected: Option<String>,
}

/// Result of an atomic batch tag update.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "result")]
pub enum BatchResult {
    #[serde(rename = "all_succeeded")]
    AllSucceeded,
    #[serde(rename = "failed")]
    Failed { index: usize, reason: String },
}

/// Result of a range fingerprint query for set reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RangeFingerprint {
    /// XOR-aggregated SHA-256 hash of all kappa-labels in the range.
    #[serde(with = "hex_fingerprint")]
    pub fingerprint: [u8; 32],
    /// Number of items in the range.
    pub count: usize,
}

mod hex_fingerprint {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(fp: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(fp))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let mut out = [0u8; 32];
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        out.copy_from_slice(&bytes);
        Ok(out)
    }
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
    fn tag_find_by_kappa(&self, ns: &str, kappa: &str) -> Result<Vec<String>, StoreError>;
    /// Atomically apply a batch of tag updates within a single namespace.
    /// All updates target `ns`. All CAS expectations are validated before
    /// any writes. If any check fails, no writes are applied.
    /// CAS comparisons operate on raw values -- a symbolic ref's raw value
    /// is "ref:target_name", not the resolved kappa-label.
    fn tag_set_batch(&self, ns: &str, updates: &[TagUpdate]) -> Result<BatchResult, StoreError>;

    /// Set a symbolic pointer: tag `name` in namespace `ns` points to tag
    /// `target` (another tag name within the same namespace). Stored as
    /// "ref:{target}" in the tag index.
    fn tag_set_symbolic(&self, ns: &str, name: &str, target: &str) -> Result<(), StoreError>;
    /// Return the raw tag value without resolution. For direct tags this
    /// is the kappa-label string. For symbolic tags this is "ref:{target}".
    fn tag_get_raw(&self, ns: &str, name: &str) -> Result<Option<String>, StoreError>;

    // edge (scoped to namespace)
    #[allow(clippy::too_many_arguments)]
    fn edge_put(
        &self,
        ns: &str,
        edge_kappa: &str,
        src: &str,
        rel: &str,
        tgt: &str,
        canon: &[u8],
        metadata: serde_json::Value,
    ) -> Result<bool, StoreError>;
    fn edge_query(
        &self,
        ns: &str,
        node: &str,
        dir: Direction,
        rel: Option<&str>,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<Vec<EdgeRecord>, StoreError>;
    fn edge_find(
        &self,
        ns: &str,
        node: &str,
        dir: Direction,
        rel: Option<&str>,
    ) -> Result<Vec<EdgeRecord>, StoreError> {
        self.edge_query(ns, node, dir, rel, None, None)
    }
    fn edge_remove(&self, ns: &str, edge_kappa: &str) -> Result<bool, StoreError>;
    fn edge_remove_by_node(&self, ns: &str, kappa: &str) -> Result<(), StoreError>;
    fn edge_walk(
        &self,
        ns: &str,
        roots: &[String],
        rels: &[&str],
    ) -> Result<HashSet<String>, StoreError>;
    /// Compute graph set difference: kappa-labels reachable from `want`
    /// roots but NOT reachable from `have` roots, along the given
    /// relation types. The `have` walk prunes at common ancestors.
    fn edge_diff(
        &self,
        ns: &str,
        have: &[String],
        want: &[String],
        rels: &[&str],
    ) -> Result<Vec<String>, StoreError>;

    // range-based set reconciliation (RBSR)
    /// Return the XOR-monoid fingerprint for kappa-labels in [lower, upper).
    /// If lower == upper, returns the fingerprint of the entire namespace.
    fn range_fingerprint(
        &self,
        ns: &str,
        lower: &str,
        upper: &str,
    ) -> Result<RangeFingerprint, StoreError>;
    /// Return all kappa-labels in the range [lower, upper) for a namespace.
    /// If lower == upper, returns all items.
    fn range_items(&self, ns: &str, lower: &str, upper: &str) -> Result<Vec<String>, StoreError>;

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

    // metadata query
    fn list_by_meta(&self, key: &str, value: &str) -> Result<Vec<String>, StoreError>;

    // bundle (bulk transfer)
    fn bundle_create(&self, kappas: &[String], delta: bool) -> Result<Vec<u8>, StoreError>;
    fn bundle_ingest(&self, bundle: &[u8]) -> Result<Vec<String>, StoreError>;

    // namespace root (authenticated namespace state)
    fn namespace_root(&self, ns: &str) -> Result<(Option<String>, usize), StoreError>;
    fn namespace_proof(&self, ns: &str, name: &str) -> Result<Option<NamespaceProof>, StoreError>;
}
