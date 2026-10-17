//! Inbound reconciliation request handler. Read-only against the store.

use kappa_reconcile::NamespaceMst;
use kappa_store::traits::{BlobStore, EpochStore, NamespaceStore, TagStore};
use kappa_types::kappa::Kappa;
use kappa_types::page::PageRequest;

use super::wire::{
    BlobPullRequest, BlobPullResponse, DiffPullRequest, DiffPullResponse, EpochRootResponse,
    MstSnapshotRequest, MstSnapshotResponse, PageRangeWire, TagEntryWire,
};
use super::{
    MAX_INLINE_BLOB_SIZE, MAX_PULL_TAGS, PROTO_BLOB_PULL_REQ, PROTO_BLOB_PULL_RESP,
    PROTO_DIFF_PULL_REQ, PROTO_DIFF_PULL_RESP, PROTO_EPOCH_ROOT_REQ, PROTO_EPOCH_ROOT_RESP,
    PROTO_MST_SNAPSHOT_REQ, PROTO_MST_SNAPSHOT_RESP, PROTO_PING,
};

/// Handle an inbound reconciliation request.
/// Called from the dispatch loop when an AppCall arrives.
/// Returns response bytes for the transport to send back.
pub fn handle_reconcile_request<S>(store: &S, request: &[u8]) -> Result<Vec<u8>, String>
where
    S: NamespaceStore + TagStore + EpochStore + BlobStore + ?Sized,
{
    if request.is_empty() {
        return Err("empty request".into());
    }

    match request[0] {
        PROTO_PING => Ok(vec![PROTO_PING]),
        PROTO_EPOCH_ROOT_REQ => epoch_root(store, &request[1..]),
        PROTO_MST_SNAPSHOT_REQ => mst_snapshot(store, &request[1..]),
        PROTO_DIFF_PULL_REQ => diff_pull(store, &request[1..]),
        PROTO_BLOB_PULL_REQ => blob_pull(store, &request[1..]),
        proto => Err(format!("unknown protocol byte 0x{proto:02x}")),
    }
}

fn epoch_root<S>(store: &S, payload: &[u8]) -> Result<Vec<u8>, String>
where
    S: NamespaceStore + EpochStore + ?Sized,
{
    let namespace_str =
        std::str::from_utf8(payload).map_err(|e| format!("invalid namespace utf8: {e}"))?;

    let Ok(ns_ref) = store.namespace_resolve(namespace_str, None) else {
        return encode_response(
            PROTO_EPOCH_ROOT_RESP,
            &EpochRootResponse {
                epoch_number: 0,
                root_kappa: String::new(),
            },
        );
    };

    let (epoch_number, root_kappa) = match store.epoch_current(&ns_ref) {
        Ok((n, k)) => (n, k.to_string()),
        Err(_) => (0, String::new()),
    };

    encode_response(
        PROTO_EPOCH_ROOT_RESP,
        &EpochRootResponse {
            epoch_number,
            root_kappa,
        },
    )
}

fn mst_snapshot<S>(store: &S, payload: &[u8]) -> Result<Vec<u8>, String>
where
    S: NamespaceStore + TagStore + ?Sized,
{
    let req: MstSnapshotRequest =
        postcard::from_bytes(payload).map_err(|e| format!("decode mst snapshot req: {e}"))?;

    let Ok(ns_ref) = store.namespace_resolve(&req.namespace, None) else {
        return encode_response(
            PROTO_MST_SNAPSHOT_RESP,
            &MstSnapshotResponse {
                namespace: req.namespace,
                page_ranges: Vec::new(),
            },
        );
    };

    let tags_page = store
        .tag_list(&ns_ref, None, &PageRequest::first(100_000))
        .map_err(|e| format!("tag_list: {e}"))?;
    let mut mst = NamespaceMst::new(req.namespace.clone());
    for tag in &tags_page.items {
        mst.upsert(&tag.name, &tag.kappa.to_string());
    }

    let snapshot = mst.snapshot().map_err(|e| format!("mst snapshot: {e}"))?;

    let page_ranges: Vec<PageRangeWire> = snapshot
        .snapshot
        .iter()
        .map(|pr| PageRangeWire {
            start: pr.start().clone(),
            end: pr.end().clone(),
            hash: *pr.hash().as_bytes(),
        })
        .collect();

    encode_response(
        PROTO_MST_SNAPSHOT_RESP,
        &MstSnapshotResponse {
            namespace: req.namespace,
            page_ranges,
        },
    )
}

fn diff_pull<S>(store: &S, payload: &[u8]) -> Result<Vec<u8>, String>
where
    S: NamespaceStore + TagStore + ?Sized,
{
    let req: DiffPullRequest =
        postcard::from_bytes(payload).map_err(|e| format!("decode pull req: {e}"))?;

    let ns_ref = store
        .namespace_resolve(&req.namespace, None)
        .map_err(|e| format!("namespace resolve: {e}"))?;

    let (tags, truncated, next_cursor) = if req.tag_names.is_empty() {
        // Paginated full pull. Use cursor as the PageRequest.after value.
        let page = store
            .tag_list(&ns_ref, None, &PageRequest::new(MAX_PULL_TAGS, req.cursor))
            .map_err(|e| format!("tag_list: {e}"))?;

        let truncated = page.has_more();
        let next_cursor = page.next_after.clone();
        let tags: Vec<TagEntryWire> = page
            .items
            .into_iter()
            .map(|t| TagEntryWire {
                name: t.name,
                kappa: t.kappa.to_string(),
                version: t.version,
            })
            .collect();
        (tags, truncated, next_cursor)
    } else {
        // Selective pull for specific tag names. No pagination needed.
        let mut tags = Vec::with_capacity(req.tag_names.len());
        for name in &req.tag_names {
            if let Ok(t) = store.tag_get(&ns_ref, name) {
                tags.push(TagEntryWire {
                    name: t.name,
                    kappa: t.kappa.to_string(),
                    version: t.version,
                });
            }
        }
        (tags, false, None)
    };

    encode_response(
        PROTO_DIFF_PULL_RESP,
        &DiffPullResponse {
            namespace: req.namespace,
            tags,
            truncated,
            next_cursor,
        },
    )
}

fn blob_pull<S: BlobStore + ?Sized>(store: &S, payload: &[u8]) -> Result<Vec<u8>, String> {
    let req: BlobPullRequest =
        postcard::from_bytes(payload).map_err(|e| format!("decode blob pull req: {e}"))?;

    let parsed =
        Kappa::parse(&req.kappa).map_err(|e| format!("invalid kappa in blob pull: {e}"))?;

    let Ok(data) = store.blob_get(&parsed) else {
        return encode_response(
            PROTO_BLOB_PULL_RESP,
            &BlobPullResponse {
                kappa: req.kappa,
                data: Vec::new(),
                too_large: false,
                size: 0,
            },
        );
    };

    if data.len() > MAX_INLINE_BLOB_SIZE {
        return encode_response(
            PROTO_BLOB_PULL_RESP,
            &BlobPullResponse {
                kappa: req.kappa,
                data: Vec::new(),
                too_large: true,
                size: data.len() as u64,
            },
        );
    }

    encode_response(
        PROTO_BLOB_PULL_RESP,
        &BlobPullResponse {
            kappa: req.kappa,
            data,
            too_large: false,
            size: 0,
        },
    )
}

fn encode_response<T: serde::Serialize>(proto_byte: u8, payload: &T) -> Result<Vec<u8>, String> {
    let encoded = postcard::to_stdvec(payload).map_err(|e| format!("encode: {e}"))?;
    let mut resp = Vec::with_capacity(1 + encoded.len());
    resp.push(proto_byte);
    resp.extend_from_slice(&encoded);
    Ok(resp)
}
