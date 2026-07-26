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
    RangeNotSatisfiable {
        size: u64,
    },
    /// Input validation failure (filter rejection, schema mismatch).
    /// Maps to HTTP 400 Bad Request.
    Rejected(String),
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
            StoreError::RangeNotSatisfiable { size } => {
                write!(f, "range not satisfiable, blob size: {size}")
            }
            StoreError::Conflict(msg) => write!(f, "conflict: {msg}"),
            StoreError::Io(e) => write!(f, "I/O error: {e}"),
            StoreError::Rejected(msg) => write!(f, "rejected: {msg}"),
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

/// StoreError implements HttpErrorResponse so it can be converted to
/// topcoat::Error via `From` and render with the correct HTTP status.
///
/// Handlers can now use `?` directly on StoreError-returning calls.
/// No `store_err` helper, no `.map_err`.
///
/// Status mapping:
/// - NotFound -> 404
/// - Conflict("forbidden:...") -> 403
/// - Conflict -> 409
/// - RangeNotSatisfiable -> 400 (416 with Content-Range handled in blob handler)
/// - Io -> 500
/// - Rejected -> 400
/// - Bundle/Delta errors -> 400
impl topcoat::HttpErrorResponse for StoreError {
    fn status_code(&self) -> http::StatusCode {
        use http::StatusCode;
        match self {
            StoreError::NotFound => StatusCode::NOT_FOUND,
            StoreError::Conflict(msg) if msg.starts_with("forbidden:") => StatusCode::FORBIDDEN,
            StoreError::Conflict(_) => StatusCode::CONFLICT,
            StoreError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            StoreError::RangeNotSatisfiable { .. } => StatusCode::BAD_REQUEST,
            _ => StatusCode::BAD_REQUEST,
        }
    }

    fn response_body(&self) -> String {
        match self {
            StoreError::NotFound => "not found".to_owned(),
            StoreError::Conflict(msg) if msg.starts_with("forbidden:") => "forbidden".to_owned(),
            StoreError::Io(_) => "internal server error".to_owned(),
            other => other.to_string(),
        }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime: Option<u64>,
}

/// On-disk tag index entry. The tag index is a BTreeMap<String, IndexEntry>
/// serialized as JSON. The `mtime` field records the last modification time
/// in milliseconds since the Unix epoch. The `version` field is a per-tag
/// monotonic counter incremented on each mutation of that tag (D-5).
///
/// Both `mtime` and `version` are metadata about the tag, not part of the
/// tag's identity -- the namespace root hash is computed over (name, value)
/// pairs only, excluding mtime and version.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IndexEntry {
    pub value: String,
    pub mtime: u64,
    #[serde(default)]
    pub version: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EdgeRecord {
    pub edge_kappa: String,
    /// Anchor kappa of the asserter (D-1: derived from signature, not from auth).
    #[serde(default)]
    pub asserter: String,
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

#[derive(Debug, Default, serde::Serialize)]
pub struct RemovalReport {
    pub blobs_removed: Vec<String>,
    pub edges_removed: usize,
    pub tags_removed: Vec<String>,
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
    /// Per-tag version CAS (D-5).
    /// 0 = create-if-absent (tag must not exist).
    /// N > 0 = tag's current version must equal N.
    /// None = unconditional (no CAS check).
    pub expected_version: Option<u64>,
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
    /// Read a byte range from a blob. Returns bytes in [offset..offset+length).
    fn blob_get_range(&self, kappa: &str, offset: u64, length: u64) -> Result<Vec<u8>, StoreError>;

    /// Returns the size in bytes of a blob, or None if it does not exist.
    fn blob_size(&self, kappa: &str) -> Result<Option<u64>, StoreError>;

    /// Returns a streaming reader for a blob.
    fn blob_reader(&self, kappa: &str) -> Result<Box<dyn std::io::Read + Send>, StoreError>;

    fn put_meta(&self, kappa: &str, key: &str, val: &[u8]) -> Result<(), StoreError>;
    fn get_meta(&self, kappa: &str, key: &str) -> Result<Option<Vec<u8>>, StoreError>;

    // tag (scoped to namespace)
    fn tag_set(&self, ns: &str, name: &str, kappa: &str) -> Result<(), StoreError>;
    fn tag_get(&self, ns: &str, name: &str) -> Result<Option<String>, StoreError>;
    fn tag_list(&self, ns: &str, opts: &TagListOpts) -> Result<TagPage, StoreError>;
    fn tag_delete(&self, ns: &str, name: &str) -> Result<bool, StoreError>;
    /// Conditionally set a tag if the tag's current version matches
    /// `expected_version`. Per-tag CAS (D-5), not per-namespace.
    /// `expected_version = 0` means create-if-absent (tag must not exist).
    fn tag_set_if(
        &self,
        ns: &str,
        name: &str,
        kappa: &str,
        expected_version: u64,
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

    /// List tags whose names start with `prefix`.
    fn tag_list_prefix(&self, ns: &str, prefix: &str) -> Result<Vec<TagEntry>, StoreError>;

    /// Atomically delete all tags whose names start with `prefix`.
    /// Returns the number of tags deleted.
    fn tag_delete_prefix(&self, ns: &str, prefix: &str) -> Result<usize, StoreError>;

    // edge (scoped to namespace)
    #[allow(clippy::too_many_arguments)]
    fn edge_put(
        &self,
        ns: &str,
        asserter: &str,
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

    // metadata query (global, legacy -- content-type sidecar)
    fn list_by_meta(&self, key: &str, value: &str) -> Result<Vec<String>, StoreError>;

    // namespace-scoped metadata (redb-backed)
    /// Set metadata key-value pairs on a blob within a namespace.
    fn meta_set(&self, ns: &str, kappa: &str, entries: &[(&str, &str)]) -> Result<(), StoreError>;
    /// Get a metadata value for a blob within a namespace.
    fn meta_get(&self, ns: &str, kappa: &str, key: &str) -> Result<Option<String>, StoreError>;
    /// Query blobs by metadata key-value pair within a namespace.
    fn meta_query(&self, ns: &str, key: &str, value: &str) -> Result<Vec<String>, StoreError>;
    /// Query blobs that have any value for a given metadata key within a namespace.
    fn meta_query_exists(&self, ns: &str, key: &str) -> Result<Vec<String>, StoreError>;
    /// Query blobs matching ALL of the given (key, value) pairs (intersection).
    fn meta_query_compound(
        &self,
        ns: &str,
        filters: &[(&str, &str)],
    ) -> Result<Vec<String>, StoreError>;
    /// Query blobs whose metadata value for `key` starts with `value_prefix`.
    fn meta_query_prefix(
        &self,
        ns: &str,
        key: &str,
        value_prefix: &str,
    ) -> Result<Vec<String>, StoreError>;
    /// Remove all metadata entries for `key` where value starts with `prefix`.
    fn meta_remove_by_value_prefix(
        &self,
        ns: &str,
        key: &str,
        value_prefix: &str,
    ) -> Result<usize, StoreError>;
    /// Remove all metadata for a blob within a namespace.
    fn meta_remove(&self, ns: &str, kappa: &str) -> Result<(), StoreError>;

    // bundle (bulk transfer)
    fn bundle_create(&self, kappas: &[String], delta: bool) -> Result<Vec<u8>, StoreError>;
    fn bundle_ingest(&self, bundle: &[u8]) -> Result<Vec<String>, StoreError>;

    // cascade delete
    /// Walk edges from roots along specified relation types and remove all
    /// reachable blobs, their edges, tags pointing to them, and metadata.
    /// `roots` can be blob kappa-labels. Returns a report of what was removed.
    fn remove_reachable(
        &self,
        ns: &str,
        roots: &[String],
        rels: &[&str],
    ) -> Result<RemovalReport, StoreError>;

    /// Resolve all tags matching `prefix`, cascade delete from their target
    /// blobs along `rels`, then delete the matching tags. Atomic operation
    /// for collection-level drops.
    fn remove_reachable_from_prefix(
        &self,
        ns: &str,
        prefix: &str,
        rels: &[&str],
    ) -> Result<RemovalReport, StoreError> {
        let tags = self.tag_list_prefix(ns, prefix)?;
        let roots: Vec<String> = tags.iter().map(|t| t.kappa.clone()).collect();
        let mut report = if roots.is_empty() {
            RemovalReport::default()
        } else {
            self.remove_reachable(ns, &roots, rels)?
        };
        let deleted = self.tag_delete_prefix(ns, prefix)?;
        // Tags removed by prefix that weren't already removed by cascade
        for tag in &tags {
            if !report.tags_removed.contains(&tag.name) {
                report.tags_removed.push(tag.name.clone());
            }
        }
        let _ = deleted;
        Ok(report)
    }

    // sequence (scoped to namespace)
    /// Atomically increment and return a named sequence counter.
    fn sequence_next(&self, ns: &str, name: &str) -> Result<u64, StoreError>;
    /// Return the current value of a named sequence without incrementing.
    fn sequence_current(&self, ns: &str, name: &str) -> Result<u64, StoreError>;

    // namespace root (authenticated namespace state)
    fn namespace_root(&self, ns: &str) -> Result<(Option<String>, usize), StoreError>;
    fn namespace_proof(&self, ns: &str, name: &str) -> Result<Option<NamespaceProof>, StoreError>;

    // edge query by asserter (D-8: asserter-last compound key)
    /// Query edges filtering by asserter. The default implementation
    /// post-filters on the deserialized asserter field. FsStore overrides
    /// with scan-level filtering on field 4 of the compound key.
    fn edge_query_by_asserter(
        &self,
        ns: &str,
        node: &str,
        asserter: Option<&str>,
        rel: Option<&str>,
    ) -> Result<Vec<EdgeRecord>, StoreError> {
        let edges = self.edge_query(ns, node, Direction::Outbound, rel, None, None)?;
        match asserter {
            Some(a) => Ok(edges.into_iter().filter(|e| e.asserter == a).collect()),
            None => Ok(edges),
        }
    }
}
