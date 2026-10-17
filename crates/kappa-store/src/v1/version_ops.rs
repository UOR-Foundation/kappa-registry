//! Composed versioning operations.
//!
//! Version entries are tags under `_versions/{key}/{inverted_timestamp}`.
//! Each version entry blob is dCBOR-encoded `VersionEntry`. `DerivedFrom`
//! edges connect new versions to previous versions.
//!
//! Writers take the execution that publishes them. Current state (the
//! versioning switch and the object's tag) is read through the execution, so
//! it includes the execution's own writes. Version history is enumerated
//! from the published store: the execution holds the store's single writer,
//! so published history cannot change under it, and one execution writes
//! at most one history entry per key.

use std::sync::LazyLock;

use dcbor::prelude::*;

use crate::execution::{ExecutionReads, ExecutionWrites};
use crate::traits::blob::BlobStore;
use crate::traits::namespace::NamespaceStore;
use crate::traits::tag::TagStore;
use kappa_types::canonical::{canonical_bytes, from_canonical};
use kappa_types::clock::ClockMs;
use kappa_types::edge::{EdgeInput, EdgeRelation, SemanticRelation, semantic};
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::namespace::NamespaceRef;
use kappa_types::tag::{TagEntry, TagUpdate};
use kappa_types::verified::VerifiedContent;
use kappa_types::versioning::{DeleteResult, VersionEntry, VersioningState};

const VERSION_PREFIX: &str = "_versions/";
const VERSIONING_STATE_KEY: &str = "_versions/state";

fn history_tag_name(key: &str, now: ClockMs) -> Result<String, StoreError> {
    let timestamp = u64::try_from(now.as_i64())
        .map_err(|_| StoreError::Rejected("version timestamp predates the Unix epoch".into()))?;
    let inverted = !timestamp;
    Ok(format!("{VERSION_PREFIX}{key}/{inverted:016x}"))
}

// History tags are internal roots. Public tag-list visibility must not decide
// which versions exist. Capture names before mutations invalidate live cursors.
fn history_tags<S: TagStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    prefix: &str,
) -> Result<Vec<TagEntry>, StoreError> {
    let mut cursor = store.tag_cursor(ns, Some(prefix))?;
    let mut tags = Vec::new();
    let mut previous: Option<Vec<u8>> = None;
    while cursor.key() != kappa_cursor::TERMINATED {
        let key = cursor.key();
        if previous.as_deref().is_some_and(|previous| previous >= key) {
            return Err(StoreError::Rejected(
                "history cursor is not strictly ordered".into(),
            ));
        }
        let name = std::str::from_utf8(key)
            .map_err(|error| StoreError::Rejected(format!("history tag identity: {error}")))?;
        if !name.starts_with(prefix) {
            return Err(StoreError::Rejected(
                "history cursor escaped requested prefix".into(),
            ));
        }
        tags.push(store.tag_get_raw(ns, name)?);
        previous = Some(key.to_vec());
        cursor.advance();
    }
    Ok(tags)
}

fn decode_entry(tag: &TagEntry, blob: &[u8]) -> Result<VersionEntry, StoreError> {
    from_canonical(blob)
        .map_err(|e| StoreError::Internal(format!("version entry decode for {}: {e}", tag.name)))
}

// =========================================================================
// Sentinel kappa for delete markers
// =========================================================================

/// dCBOR-encodable struct for the delete marker sentinel blob.
#[derive(Debug, Clone, CBORCodable)]
struct DeleteMarkerSentinel {
    #[cbor(n = 0)]
    delete_marker: bool,
}

/// Computed once at process start. Same bytes on every node (FF-11).
static SENTINEL: LazyLock<(Kappa, Vec<u8>)> = LazyLock::new(|| {
    let sentinel = DeleteMarkerSentinel {
        delete_marker: true,
    };
    let bytes = canonical_bytes(&sentinel);
    let kappa = Kappa::sha256(&bytes);
    (kappa, bytes)
});

fn sentinel_kappa() -> &'static Kappa {
    &SENTINEL.0
}

fn sentinel_bytes() -> &'static [u8] {
    &SENTINEL.1
}

// =========================================================================
// Versioning state
// =========================================================================

fn parse_state(bytes: &[u8]) -> Result<VersioningState, StoreError> {
    let s = std::str::from_utf8(bytes)
        .map_err(|e| StoreError::Internal(format!("versioning state corrupt: {e}")))?;
    match s.trim() {
        "enabled" => Ok(VersioningState::Enabled),
        "suspended" => Ok(VersioningState::Suspended),
        "disabled" => Ok(VersioningState::Disabled),
        _ => Err(StoreError::Rejected(
            "unknown stored versioning state".into(),
        )),
    }
}

/// Read the published versioning state for a namespace.
pub fn versioning_get<S: NamespaceStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
) -> Result<VersioningState, StoreError> {
    crate::absent(store.namespace_get_meta(ns, VERSIONING_STATE_KEY))?
        .map_or(Ok(VersioningState::Disabled), |bytes| parse_state(&bytes))
}

/// Read the versioning state an execution observes, including its writes.
pub fn versioning_in<E: ExecutionReads + ?Sized>(
    execution: &E,
) -> Result<VersioningState, StoreError> {
    execution
        .namespace_get_meta(VERSIONING_STATE_KEY)?
        .map_or(Ok(VersioningState::Disabled), |bytes| parse_state(&bytes))
}

/// Set the versioning state of the execution's namespace.
pub fn versioning_put<E: ExecutionWrites + ?Sized>(
    execution: &mut E,
    state: VersioningState,
) -> Result<(), StoreError> {
    let value = match state {
        VersioningState::Enabled => "enabled",
        VersioningState::Suspended => "suspended",
        VersioningState::Disabled => "disabled",
    };
    execution.namespace_put_meta(VERSIONING_STATE_KEY, value.as_bytes())
}

// =========================================================================
// Version entry creation
// =========================================================================

/// Create a version entry with full provenance in `execution`.
///
/// Produces:
/// 1. Version entry blob (dCBOR `VersionEntry`, content-addressed)
/// 2. Version tag under `_versions/{key}/{inverted_timestamp}`
/// 3. Object tag update (points to the new content)
/// 4. `DerivedFrom` edge from new version to previous version
///
/// Behavior depends on versioning state:
/// - Disabled: plain tag write, no version entry, returns "null"
/// - Enabled: version entry with UUID version ID, `DerivedFrom` edge
/// - Suspended: replaces null version entry, `DerivedFrom` edge
pub fn version_put_entry<S, E>(
    store: &S,
    execution: &mut E,
    key: &str,
    content_kappa: &Kappa,
    asserter: &Kappa,
) -> Result<String, StoreError>
where
    S: TagStore + BlobStore + ?Sized,
    E: ExecutionWrites + ?Sized,
{
    let set = TagUpdate::Set {
        kappa: content_kappa.clone(),
    };
    let version_id = match versioning_in(execution)? {
        VersioningState::Disabled => {
            execution.tag_put(key, &set)?;
            return Ok("null".to_string());
        }
        VersioningState::Enabled => uuid::Uuid::new_v4().to_string(),
        VersioningState::Suspended => {
            version_remove_null(store, execution, key)?;
            "null".to_string()
        }
    };
    let previous = execution.tag_get(key)?.map(|tag| tag.kappa);
    let tag_name = history_tag_name(key, execution.now())?;
    store_version_entry(execution, &tag_name, content_kappa, &version_id, false)?;
    execution.tag_put(key, &set)?;
    if let Some(previous) = previous {
        let created_at_ms = execution.now().as_i64();
        execution.edge_put(&EdgeInput {
            source: content_kappa.clone(),
            target: previous,
            relation: EdgeRelation::Semantic(SemanticRelation(semantic::DERIVED_FROM.into())),
            asserter: asserter.clone(),
            created_at_ms,
            metadata: None,
        })?;
    }
    Ok(version_id)
}

/// Store a version entry blob and create its tag.
fn store_version_entry<E: ExecutionWrites + ?Sized>(
    execution: &mut E,
    tag_name: &str,
    content_kappa: &Kappa,
    version_id: &str,
    is_delete_marker: bool,
) -> Result<Kappa, StoreError> {
    let kappa_for_entry = if is_delete_marker {
        sentinel_kappa().clone()
    } else {
        content_kappa.clone()
    };

    let entry = VersionEntry {
        kappa: kappa_for_entry,
        version_id: version_id.to_string(),
        is_delete_marker,
        created_at_ms: execution.now().as_i64(),
    };
    let entry_bytes = canonical_bytes(&entry);
    let verified = VerifiedContent::compute(kappa_types::axis::Axis::Sha256, &entry_bytes)?;
    let entry_kappa = verified.kappa().clone();
    execution.blob_put(&verified)?;

    if is_delete_marker {
        let sentinel_verified = VerifiedContent::verify(sentinel_kappa(), sentinel_bytes())?;
        execution.blob_put(&sentinel_verified)?;
    }

    execution.tag_put(
        tag_name,
        &TagUpdate::Set {
            kappa: entry_kappa.clone(),
        },
    )?;
    Ok(entry_kappa)
}

// =========================================================================
// Version retrieval
// =========================================================================

/// Get the latest non-delete-marker version of an object.
pub fn version_get_latest<S>(
    store: &S,
    ns: &NamespaceRef,
    key: &str,
) -> Result<VersionEntry, StoreError>
where
    S: TagStore + BlobStore + NamespaceStore + ?Sized,
{
    let state = versioning_get(store, ns)?;

    if matches!(state, VersioningState::Disabled) {
        let tag = store.tag_get(ns, key)?;
        return Ok(VersionEntry {
            kappa: tag.kappa,
            version_id: "null".to_string(),
            is_delete_marker: false,
            created_at_ms: tag.updated_at_ms,
        });
    }

    let versions = version_list_entries(store, ns, key)?;
    for entry in &versions {
        if !entry.is_delete_marker {
            return Ok(entry.clone());
        }
    }

    versions.first().map_or_else(
        || Err(StoreError::NotFound(format!("{ns}/{key}"))),
        |marker| {
            Err(StoreError::NotFound(format!(
                "{ns}/{key} (delete marker: {})",
                marker.version_id
            )))
        },
    )
}

/// Get a specific version by version ID.
pub fn version_get_by_id<S>(
    store: &S,
    ns: &NamespaceRef,
    key: &str,
    version_id: &str,
) -> Result<VersionEntry, StoreError>
where
    S: TagStore + BlobStore + NamespaceStore + ?Sized,
{
    let versions = version_list_entries(store, ns, key)?;
    versions
        .into_iter()
        .find(|e| e.version_id == version_id)
        .ok_or_else(|| StoreError::NotFound(format!("version {version_id} of {ns}/{key}")))
}

/// List all versions of an object, newest first.
pub fn version_list_entries<S>(
    store: &S,
    ns: &NamespaceRef,
    key: &str,
) -> Result<Vec<VersionEntry>, StoreError>
where
    S: TagStore + BlobStore + NamespaceStore + ?Sized,
{
    let state = versioning_get(store, ns)?;
    if matches!(state, VersioningState::Disabled) {
        return Ok(Vec::new());
    }

    let prefix = format!("{VERSION_PREFIX}{key}/");
    let tags = history_tags(store, ns, &prefix)?;

    let mut entries = Vec::with_capacity(tags.len());
    for tag in &tags {
        let blob = store.blob_get_verified_in(ns, &tag.kappa)?;
        entries.push(decode_entry(tag, &blob)?);
    }
    Ok(entries)
}

// =========================================================================
// Version deletion
// =========================================================================

/// Delete with versioning semantics in `execution`.
///
/// - Disabled + no `version_id`: deletes the object tag directly
/// - Enabled/Suspended + no `version_id`: creates a delete marker
/// - Any state + `Some(version_id)`: removes that specific version tag
///
/// Deleting an absent object or an unknown version writes nothing.
pub fn version_delete_with_marker<S, E>(
    store: &S,
    execution: &mut E,
    key: &str,
    version_id: Option<&str>,
) -> Result<DeleteResult, StoreError>
where
    S: TagStore + BlobStore + ?Sized,
    E: ExecutionWrites + ?Sized,
{
    let state = versioning_in(execution)?;

    match (state, version_id) {
        (VersioningState::Disabled, None) => {
            if execution.tag_get_raw(key)?.is_some() {
                execution.tag_delete(key)?;
            }
            Ok(DeleteResult {
                version_id: None,
                is_delete_marker: false,
            })
        }

        (_, None) => {
            let marker_id = uuid::Uuid::new_v4().to_string();
            let tag_name = history_tag_name(key, execution.now())?;
            store_version_entry(execution, &tag_name, sentinel_kappa(), &marker_id, true)?;
            if execution.tag_get_raw(key)?.is_some() {
                execution.tag_delete(key)?;
            }
            Ok(DeleteResult {
                version_id: Some(marker_id),
                is_delete_marker: true,
            })
        }

        (_, Some(vid)) => {
            let prefix = format!("{VERSION_PREFIX}{key}/");
            let tags = history_tags(store, execution.namespace(), &prefix)?;
            let mut was_delete_marker = false;

            for tag in &tags {
                let blob = store.blob_get_verified_in(execution.namespace(), &tag.kappa)?;
                let entry = decode_entry(tag, &blob)?;
                if entry.version_id == vid {
                    was_delete_marker = entry.is_delete_marker;
                    execution.tag_delete(&tag.name)?;
                    break;
                }
            }

            Ok(DeleteResult {
                version_id: Some(vid.to_string()),
                is_delete_marker: was_delete_marker,
            })
        }
    }
}

// =========================================================================
// Eviction
// =========================================================================

/// Evict old version entries beyond the keep count in `execution`.
///
/// Keeps the `keep_latest` newest versions. Deletes the rest.
/// Returns the number of evicted entries. Captures internal history names.
pub fn version_evict_old<S, E>(
    store: &S,
    execution: &mut E,
    key: &str,
    keep_latest: u32,
) -> Result<u64, StoreError>
where
    S: TagStore + ?Sized,
    E: ExecutionWrites + ?Sized,
{
    let prefix = format!("{VERSION_PREFIX}{key}/");
    let tags = history_tags(store, execution.namespace(), &prefix)?;

    let mut evicted = 0u64;
    for (index, tag) in tags.iter().enumerate() {
        if (index as u64) < u64::from(keep_latest) {
            continue;
        }
        execution.tag_delete(&tag.name)?;
        evicted += 1;
    }
    Ok(evicted)
}

/// Remove all version entries with `version_id` "null" for a key.
fn version_remove_null<S, E>(store: &S, execution: &mut E, key: &str) -> Result<(), StoreError>
where
    S: TagStore + BlobStore + ?Sized,
    E: ExecutionWrites + ?Sized,
{
    let prefix = format!("{VERSION_PREFIX}{key}/");
    let tags = history_tags(store, execution.namespace(), &prefix)?;

    for tag in &tags {
        let blob = store.blob_get_verified_in(execution.namespace(), &tag.kappa)?;
        if decode_entry(tag, &blob)?.version_id == "null" {
            execution.tag_delete(&tag.name)?;
        }
    }
    Ok(())
}
