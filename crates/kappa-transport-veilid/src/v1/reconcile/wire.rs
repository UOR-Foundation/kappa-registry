//! Reconciliation protocol messages and blob fetch bookkeeping.

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EpochRootResponse {
    pub epoch_number: u64,
    pub root_kappa: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct MstSnapshotRequest {
    pub namespace: String,
    pub local_root_hash: [u8; 16],
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct MstSnapshotResponse {
    pub namespace: String,
    /// Page ranges from the responder's MST (`MstSnapshot::to_wire`), in
    /// tree order. Empty if the responder has no tags in this namespace.
    pub page_ranges: Vec<PageRangeWire>,
}

/// One MST page range on the wire: the start key, end key and 16-byte
/// page digest. Owned by kappa-reconcile so both ends build and read it
/// through one snapshot type.
pub use kappa_reconcile::WirePageRange as PageRangeWire;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DiffPullRequest {
    pub namespace: String,
    /// Empty means "send all tags starting from cursor, up to MAX_PULL_TAGS."
    /// Non-empty means "send only these specific tag names" (cursor is ignored).
    pub tag_names: Vec<String>,
    /// Pagination cursor. The tag name to start after (exclusive).
    /// None starts from the beginning of the tag keyspace.
    pub cursor: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DiffPullResponse {
    pub namespace: String,
    pub tags: Vec<TagEntryWire>,
    /// True if more tags exist beyond this page.
    pub truncated: bool,
    /// The cursor for the next page. The last tag name in this response.
    /// None when truncated is false.
    pub next_cursor: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TagEntryWire {
    pub name: String,
    pub kappa: String,
    pub version: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BlobPullRequest {
    pub kappa: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BlobPullResponse {
    pub kappa: String,
    /// Empty if the responder does not have this blob.
    pub data: Vec<u8>,
    /// True if the blob exists on the responder but exceeds the inline
    /// size limit. The initiator should request bulk transfer instead.
    pub too_large: bool,
    /// Blob size in bytes when too_large is true, so the initiator
    /// knows what to expect from the bulk transfer.
    pub size: u64,
}

/// A blob that is missing from the local store and needs to be fetched.
#[derive(Debug, Clone)]
pub struct MissingBlob {
    pub kappa: String,
    pub size_hint: Option<u64>,
}

/// A blob that could not be fetched during this round and should be
/// retried on the next round or by a background task.
#[derive(Debug, Clone)]
pub struct DeferredBlob {
    pub kappa: String,
    pub reason: String,
}

/// Report from a blob fetch operation.
#[derive(Debug, Clone)]
pub struct BlobFetchReport {
    pub fetched: u32,
    pub deferred: Vec<DeferredBlob>,
    pub errors: Vec<String>,
}
