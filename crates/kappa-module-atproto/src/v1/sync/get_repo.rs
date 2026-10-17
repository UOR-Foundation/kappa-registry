use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use topcoat::context::{Cx, request_context};
use topcoat::router::{Body, StatusCode};

use crate::protocol_id;
use kappa_handler::{
    HandlerError, StreamingWriter, blocking, query_optional, query_required, store,
    streaming_response,
};
use kappa_store::{KappaStore, NamespaceRef, StoreError};

use crate::car;
use crate::cid::cid_for_cbor;
use crate::mst_node;
use crate::repo::mst_ops::parse_commit_data_cid;

/// Concurrency limit for full CAR exports (no `since` parameter).
/// Full exports at 10M records produce ~450 MB visited sets.
/// Configurable via app context. Default 10 concurrent full exports.
pub struct FullExportSemaphore(pub Arc<tokio::sync::Semaphore>);

/// GET /xrpc/com.atproto.sync.getLatestCommit
pub async fn get_latest_commit(
    cx: &Cx,
    _body: Body, // GET — body not expected
) -> Result<topcoat::router::response::Response, HandlerError> {
    let did = query_required(cx, "did")?;
    let s = store(cx);

    let result = blocking(move || -> Result<_, HandlerError> {
        let ns = s
            .namespace_resolve(&did, Some(protocol_id()))
            .map_err(|e| match e {
                StoreError::NotFound(_) => HandlerError::protocol(
                    StatusCode::NOT_FOUND,
                    "RepoNotFound",
                    format!("repository not found: {did}"),
                ),
                other => HandlerError::Store(other),
            })?;
        let entry = s.tag_get(&ns, "commit/head")?;
        let rev = match s.tag_get(&ns, "commit/rev") {
            Ok(e) => e.kappa.to_string(),
            Err(StoreError::NotFound(_)) => String::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(serde_json::json!({ "cid": entry.kappa.to_string(), "rev": rev }))
    })
    .await?;

    kappa_handler::json_response(StatusCode::OK, &result)
}

/// GET /xrpc/com.atproto.sync.getRepo
///
/// Streams a CAR export of an AT Protocol repository. Full export
/// contains the signed commit, all MST nodes, and every record blob.
/// Incremental export (with `since` parameter) contains only blocks
/// that changed since the specified revision.
pub async fn get_repo(
    cx: &Cx,
    _body: Body, // GET — body not expected
) -> Result<topcoat::router::response::Response, HandlerError> {
    let did = query_required(cx, "did")?;
    let since = query_optional(cx, "since");
    let s = store(cx);

    // Resolve commit head for ETag check.
    let head_kappa = blocking({
        let s = s.clone();
        let did = did.clone();
        move || {
            let ns = s
                .namespace_resolve(&did, Some(protocol_id()))
                .map_err(|e| match e {
                    StoreError::NotFound(_) => HandlerError::protocol(
                        StatusCode::NOT_FOUND,
                        "RepoNotFound",
                        format!("repository not found: {did}"),
                    ),
                    other => HandlerError::Store(other),
                })?;
            let entry = s.tag_get(&ns, "commit/head").map_err(|e| match e {
                StoreError::NotFound(_) => HandlerError::protocol(
                    StatusCode::NOT_FOUND,
                    "RepoNotFound",
                    format!("no commits in repository: {did}"),
                ),
                other => HandlerError::Store(other),
            })?;
            Ok::<_, HandlerError>(entry.kappa)
        }
    })
    .await?;

    // ETag conditional GET from HTTP header (not query parameter).
    let etag = head_kappa.to_string();
    let parts: &http::request::Parts = request_context(cx);
    if let Some(if_none_match) = parts.headers.get("if-none-match")
        && let Ok(value) = if_none_match.to_str()
        && value.trim_matches('"') == etag
    {
        return Ok(topcoat::router::response::Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header("etag", format!("\"{}\"", etag))
            .body(Default::default())
            .expect("valid 304 response"));
    }

    // Full export rate limiting: acquire permit or 503.
    let permit = if since.is_none() {
        match kappa_handler::try_service::<FullExportSemaphore>(cx) {
            Some(sem) => match sem.0.clone().try_acquire_owned() {
                Ok(p) => Some(p),
                Err(_) => {
                    return Err(HandlerError::protocol(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "TooManyFullExports",
                        "too many concurrent full exports, retry with incremental sync (since parameter)",
                    ));
                }
            },
            None => None,
        }
    } else {
        None
    };

    let blocks_emitted = Arc::new(AtomicU64::new(0));
    let blocks_counter = blocks_emitted.clone();

    let (mut resp, writer) = streaming_response(cx, "application/vnd.ipld.car", None, 32)?;
    resp.headers_mut().insert(
        "etag",
        format!("\"{}\"", etag).parse().expect("valid etag header"),
    );

    // Move the permit INTO the blocking closure so it is held
    // for the duration of the export, not released when the
    // handler returns.
    tokio::task::spawn_blocking(move || {
        let _permit = permit; // held until this closure returns

        let result: Result<(), HandlerError> = (|| {
            let ns = s.namespace_resolve(&did, Some(protocol_id()))?;
            let head = s.tag_get(&ns, "commit/head")?;
            let commit_bytes = s.blob_get_in(&ns, &head.kappa)?;
            let commit_cid = cid_for_cbor(&commit_bytes);

            let header = car::encode_car_header(Some(&commit_cid));
            writer.send(bytes::Bytes::from(header))?;

            let mut buf = Vec::with_capacity(4096);
            car::encode_car_block_into(&mut buf, &commit_cid, &commit_bytes);
            writer.send(bytes::Bytes::copy_from_slice(&buf))?;
            blocks_counter.fetch_add(1, Ordering::Relaxed);

            let mut visited = HashSet::new();
            let mut cid_arr = [0u8; 36];
            cid_arr.copy_from_slice(&commit_cid);
            visited.insert(cid_arr);

            if let Some(mst_root_cid) = parse_commit_data_cid(&commit_bytes) {
                match &since {
                    Some(since_rev) => {
                        let since_tag = format!("commit/rev/{}", since_rev);
                        let since_entry = s.tag_get(&ns, &since_tag).map_err(|e| match e {
                            StoreError::NotFound(_) => HandlerError::protocol(
                                StatusCode::BAD_REQUEST,
                                "InvalidSince",
                                format!("unknown revision: {since_rev}"),
                            ),
                            other => HandlerError::Store(other),
                        })?;
                        let since_bytes = s.blob_get_in(&ns, &since_entry.kappa)?;
                        if let Some(since_mst_cid) = parse_commit_data_cid(&since_bytes) {
                            walk_mst_diff_streaming(
                                &*s,
                                &ns,
                                (&mst_root_cid, &since_mst_cid),
                                &mut visited,
                                &mut buf,
                                &writer,
                                &blocks_counter,
                            )?;
                        } else {
                            walk_mst_full_streaming(
                                &*s,
                                &ns,
                                &mst_root_cid,
                                &mut visited,
                                &mut buf,
                                &writer,
                                &blocks_counter,
                            )?;
                        }
                    }
                    None => {
                        walk_mst_full_streaming(
                            &*s,
                            &ns,
                            &mst_root_cid,
                            &mut visited,
                            &mut buf,
                            &writer,
                            &blocks_counter,
                        )?;
                    }
                }
            }

            writer.mark_completed();
            Ok(())
        })();

        if let Err(e) = result {
            writer.report_error(e);
        }
    });

    Ok(resp)
}

/// CID-level MST diff for incremental sync.
///
/// Walks both MSTs simultaneously by KEY, not by position. When root
/// CIDs match, the subtree is identical — zero blocks emitted. When
/// CIDs differ, descend both and emit only the current MST's blocks
/// that differ from the since MST.
fn walk_mst_diff_streaming(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    roots: (&[u8], &[u8]),
    visited: &mut HashSet<[u8; 36]>,
    buf: &mut Vec<u8>,
    writer: &StreamingWriter,
    blocks: &AtomicU64,
) -> Result<(), HandlerError> {
    let (current_cid, since_cid) = roots;
    if current_cid == since_cid {
        return Ok(());
    }

    if current_cid.len() != 36 {
        return Err(StoreError::Internal("MST CID not 36 bytes".into()).into());
    }
    let mut cid_arr = [0u8; 36];
    cid_arr.copy_from_slice(current_cid);
    if !visited.insert(cid_arr) {
        return Ok(());
    }

    let cid_hex = hex::encode(current_cid);
    let current_tag = store.tag_get(ns, &format!("mst/{}", cid_hex))?;
    let current_bytes = store.blob_get_in(ns, &current_tag.kappa)?;

    buf.clear();
    car::encode_car_block_into(buf, current_cid, &current_bytes);
    writer.send(bytes::Bytes::copy_from_slice(buf))?;
    blocks.fetch_add(1, Ordering::Relaxed);

    let (current_left, current_entries) = mst_node::decode_node(&current_bytes)
        .map_err(|e| StoreError::Internal(format!("MST decode: {e}")))?;

    let since_hex = hex::encode(since_cid);
    let since_node = match store.tag_get(ns, &format!("mst/{}", since_hex)) {
        Ok(tag) => {
            let bytes = store.blob_get_in(ns, &tag.kappa)?;
            Some(
                mst_node::decode_node(&bytes)
                    .map_err(|e| StoreError::Internal(format!("since MST decode: {e}")))?,
            )
        }
        Err(StoreError::NotFound(_)) => None,
        Err(e) => return Err(e.into()),
    };

    // Left subtree diff
    if let Some(ref left_cid) = current_left {
        let left_bytes = left_cid.as_slice();
        let since_left = since_node.as_ref().and_then(|(l, _)| l.as_deref());
        match since_left {
            Some(sl) if sl == left_bytes => {}
            Some(sl) => {
                walk_mst_diff_streaming(store, ns, (left_bytes, sl), visited, buf, writer, blocks)?
            }
            None => walk_mst_full_streaming(store, ns, left_bytes, visited, buf, writer, blocks)?,
        }
    }

    // Entry diff by KEY, not by position.
    // Build a lookup of since entries by their reconstructed key.
    let since_entries_by_key: HashMap<&[u8], &mst_node::DecodedEntry> = match &since_node {
        Some((_, entries)) => entries.iter().map(|e| (e.key.as_slice(), e)).collect(),
        None => HashMap::new(),
    };

    for entry in &current_entries {
        let since_entry = since_entries_by_key.get(entry.key.as_slice());
        let value_differs = since_entry.is_none_or(|se| se.value != entry.value);

        if value_differs {
            emit_record_block(store, ns, &entry.value, visited, buf, writer, blocks)?;
        }

        if let Some(ref right_cid) = entry.tree {
            let right_bytes = right_cid.as_slice();
            let since_right = since_entry.and_then(|se| se.tree.as_ref().map(|t| t.as_slice()));
            match since_right {
                Some(sr) if sr == right_bytes => {}
                Some(sr) => walk_mst_diff_streaming(
                    store,
                    ns,
                    (right_bytes, sr),
                    visited,
                    buf,
                    writer,
                    blocks,
                )?,
                None => {
                    walk_mst_full_streaming(store, ns, right_bytes, visited, buf, writer, blocks)?
                }
            }
        }
    }

    Ok(())
}

/// Full MST export — no since parameter.
fn walk_mst_full_streaming(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    cid: &[u8],
    visited: &mut HashSet<[u8; 36]>,
    buf: &mut Vec<u8>,
    writer: &StreamingWriter,
    blocks: &AtomicU64,
) -> Result<(), HandlerError> {
    if cid.len() != 36 {
        return Err(StoreError::Internal("MST CID not 36 bytes".into()).into());
    }
    let mut cid_arr = [0u8; 36];
    cid_arr.copy_from_slice(cid);
    if !visited.insert(cid_arr) {
        return Ok(());
    }

    let cid_hex = hex::encode(cid);
    let tag = store.tag_get(ns, &format!("mst/{}", cid_hex))?;
    let data = store.blob_get_in(ns, &tag.kappa)?;

    buf.clear();
    car::encode_car_block_into(buf, cid, &data);
    writer.send(bytes::Bytes::copy_from_slice(buf))?;
    blocks.fetch_add(1, Ordering::Relaxed);

    let (left, entries) = mst_node::decode_node(&data)
        .map_err(|e| StoreError::Internal(format!("MST decode: {e}")))?;

    if let Some(ref left_cid) = left {
        walk_mst_full_streaming(store, ns, left_cid.as_slice(), visited, buf, writer, blocks)?;
    }

    for entry in &entries {
        emit_record_block(store, ns, &entry.value, visited, buf, writer, blocks)?;

        if let Some(ref right_cid) = entry.tree {
            walk_mst_full_streaming(
                store,
                ns,
                right_cid.as_slice(),
                visited,
                buf,
                writer,
                blocks,
            )?;
        }
    }

    Ok(())
}

fn emit_record_block(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    value_cid: &[u8; 36],
    visited: &mut HashSet<[u8; 36]>,
    buf: &mut Vec<u8>,
    writer: &StreamingWriter,
    blocks: &AtomicU64,
) -> Result<(), HandlerError> {
    if !visited.insert(*value_cid) {
        return Ok(());
    }

    let val_hex = hex::encode(value_cid);
    let bridge = store.tag_get(ns, &format!("blob/{}", val_hex))?;
    let blob = store.blob_get_in(ns, &bridge.kappa)?;

    buf.clear();
    car::encode_car_block_into(buf, value_cid, &blob);
    writer.send(bytes::Bytes::copy_from_slice(buf))?;
    blocks.fetch_add(1, Ordering::Relaxed);

    Ok(())
}
