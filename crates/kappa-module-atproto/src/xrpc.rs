//! XRPC endpoint dispatch for AT Protocol.
//!
//! Registers all com.atproto.* routes on the topcoat router.
//! Each handler resolves the DID namespace internally (the namespace
//! interceptor returns NoNamespace for /xrpc/ paths).
//!
//! XRPC error envelope: { "error": "ErrorName", "message": "detail" }

use std::borrow::Cow;
use std::sync::Arc;

use topcoat::context::{app_context, try_app_context, Cx};
use topcoat::router::{
    Body, Method, Path, RouteFn, RouteFuture, RouterBuilder, StatusCode,
};
use topcoat::router::request::FromRequest;
use topcoat::router::response::IntoResponse;

use sha2::Digest;

use kappa_core::store::KappaStore;

/// Register all AT Protocol XRPC routes.
pub fn register(builder: RouterBuilder) -> RouterBuilder {
    fn p(s: &'static str) -> Cow<'static, Path> {
        Cow::Borrowed(Path::new(s))
    }

    builder
        // Server
        .route(RouteFn::new(Method::GET, p("/xrpc/com.atproto.server.describeServer"), describe_server))
        .route(RouteFn::new(Method::GET, p("/xrpc/com.atproto.sync.getLatestCommit"), get_latest_commit))
        .route(RouteFn::new(Method::GET, p("/xrpc/com.atproto.sync.listRepos"), list_repos))
        .route(RouteFn::new(Method::GET, p("/xrpc/com.atproto.identity.resolveHandle"), resolve_handle))
        .route(RouteFn::new(Method::GET, p("/xrpc/com.atproto.repo.describeRepo"), describe_repo))
        .route(RouteFn::new(Method::GET, p("/xrpc/com.atproto.repo.getRecord"), get_record))
        .route(RouteFn::new(Method::GET, p("/xrpc/com.atproto.repo.listRecords"), list_records))
        .route(RouteFn::new(Method::POST, p("/xrpc/com.atproto.repo.createRecord"), create_record))
        .route(RouteFn::new(Method::POST, p("/xrpc/com.atproto.repo.putRecord"), put_record))
        .route(RouteFn::new(Method::POST, p("/xrpc/com.atproto.repo.deleteRecord"), delete_record))
        .route(RouteFn::new(Method::POST, p("/xrpc/com.atproto.repo.uploadBlob"), upload_blob))
        .route(RouteFn::new(Method::POST, p("/xrpc/com.atproto.repo.applyWrites"), apply_writes))
        .route(RouteFn::new(Method::GET, p("/xrpc/com.atproto.sync.getRepo"), get_repo))
        .route(RouteFn::new(Method::GET, p("/xrpc/com.atproto.sync.getBlob"), get_blob))
        // Session endpoints
        .route(RouteFn::new(Method::POST, p("/xrpc/com.atproto.server.createSession"), create_session))
        .route(RouteFn::new(Method::POST, p("/xrpc/com.atproto.server.refreshSession"), refresh_session))
        .route(RouteFn::new(Method::POST, p("/xrpc/com.atproto.server.deleteSession"), delete_session))
        .route(RouteFn::new(Method::GET, p("/xrpc/com.atproto.server.getSession"), get_session))
        .route(RouteFn::new(Method::POST, p("/xrpc/com.atproto.server.createAccount"), create_account))
        // Sync firehose + crawl
        .route(RouteFn::new(Method::GET, p("/xrpc/com.atproto.sync.subscribeRepos"), subscribe_repos))
        .route(RouteFn::new(Method::POST, p("/xrpc/com.atproto.sync.requestCrawl"), request_crawl))
        // Identity
        .route(RouteFn::new(Method::POST, p("/xrpc/com.atproto.identity.updateHandle"), update_handle))
}

fn xrpc_error(cx: &Cx, status: StatusCode, error: &str, message: &str) -> Result<topcoat::router::response::Response, topcoat::Error> {
    let body = serde_json::json!({
        "error": error,
        "message": message,
    });
    (status, [("content-type", "application/json")], body.to_string()).into_response(cx)
}

/// Extract a query parameter from the request URI.
fn query_param(cx: &Cx, key: &str) -> Option<String> {
    use topcoat::context::request_context;
    let parts: &http::request::Parts = request_context(cx);
    parts.uri.query().and_then(|q| {
        q.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            if k == key { Some(v.to_string()) } else { None }
        })
    })
}

// -- Server endpoints ---------------------------------------------------------

fn describe_server(cx: &Cx, _body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let response = serde_json::json!({
            "availableUserDomains": [],
            "inviteCodeRequired": false,
            "phoneVerificationRequired": false,
            "did": "did:web:kappa-registry",
            "links": {}
        });
        (StatusCode::OK, [("content-type", "application/json")], response.to_string()).into_response(cx)
    })
}

// -- Sync endpoints -----------------------------------------------------------

fn get_latest_commit(cx: &Cx, _body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let did = match query_param(cx, "did") {
            Some(d) => d,
            None => return xrpc_error(cx, StatusCode::BAD_REQUEST, "InvalidRequest", "missing did parameter"),
        };
        let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
        let result = tokio::task::spawn_blocking(move || {
            let ns = store.namespace_resolve(&did, Some("atproto"))?;
            let entry = store.tag_get(&ns, "commit/head")?;
            let rev_entry = store.tag_get(&ns, "commit/rev");
            let rev = rev_entry.map(|e| e.kappa).unwrap_or_default();
            Ok::<(String, String), kappa_core::types::StoreError>((entry.kappa, rev))
        }).await;
        match result {
            Ok(Ok((cid, rev))) => {
                let body = serde_json::json!({ "cid": cid, "rev": rev });
                (StatusCode::OK, [("content-type", "application/json")], body.to_string()).into_response(cx)
            }
            _ => xrpc_error(cx, StatusCode::NOT_FOUND, "RepoNotFound", "repository not found"),
        }
    })
}

fn list_repos(cx: &Cx, _body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
        let limit: usize = query_param(cx, "limit")
            .and_then(|s| s.parse().ok())
            .unwrap_or(50);
        let cursor = query_param(cx, "cursor");
        let result = tokio::task::spawn_blocking(move || {
            let records = store.namespace_list(Some("atproto"))?;
            let repos: Vec<serde_json::Value> = records.iter()
                .filter(|r| !r.tombstoned)
                .skip_while(|r| {
                    if let Some(ref c) = cursor {
                        r.uuid_hex < *c
                    } else {
                        false
                    }
                })
                .take(limit)
                .map(|r| {
                    serde_json::json!({
                        "did": r.aliases.first().map(|a| a.as_str()).unwrap_or(""),
                        "head": "",
                        "rev": "",
                        "active": true,
                    })
                })
                .collect();
            Ok::<Vec<serde_json::Value>, kappa_core::types::StoreError>(repos)
        }).await;
        match result {
            Ok(Ok(repos)) => {
                let body = serde_json::json!({ "repos": repos });
                (StatusCode::OK, [("content-type", "application/json")], body.to_string()).into_response(cx)
            }
            _ => xrpc_error(cx, StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", "list repos failed"),
        }
    })
}

fn get_repo(cx: &Cx, _body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let did = match query_param(cx, "did") {
            Some(d) => d,
            None => return xrpc_error(cx, StatusCode::BAD_REQUEST, "InvalidRequest", "missing did parameter"),
        };
        let since = query_param(cx, "since");
        let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
        let result = tokio::task::spawn_blocking(move || {
            let ns = store.namespace_resolve(&did, Some("atproto"))?;
            let head = store.tag_get(&ns, "commit/head")?;
            let commit_bytes = store.blob_get(&head.kappa)?;
            let commit_cid = crate::cid::cid_for_cbor(&commit_bytes);

            // Build exclusion set from `since` commit if provided
            let mut visited = std::collections::HashSet::new();
            if let Some(ref since_rev) = since {
                // Try to find the since commit via commit/rev/{rev} tag
                let since_tag = format!("commit/rev/{}", since_rev);
                if let Ok(since_entry) = store.tag_get(&ns, &since_tag) {
                    if let Ok(since_commit_bytes) = store.blob_get(&since_entry.kappa) {
                        if let Some(since_mst_cid) = parse_commit_data_cid(&since_commit_bytes) {
                            // Walk the since MST to populate exclusion set
                            walk_mst_cids(&store, &ns, &since_mst_cid, &mut visited);
                        }
                    }
                }
            }

            let mut blocks = Vec::new();

            // 1. Commit block
            if visited.insert(commit_cid) {
                blocks.push(crate::car::CarBlock {
                    cid: commit_cid.to_vec(),
                    bytes: commit_bytes.clone(),
                });
            }

            // 2. Parse commit data CID (MST root) and walk
            if let Some(mst_root_cid) = parse_commit_data_cid(&commit_bytes) {
                walk_mst_node(&store, &ns, &mst_root_cid, &mut blocks, &mut visited);
            }

            let car = crate::car::encode_car(Some(&commit_cid), &blocks);
            Ok::<Vec<u8>, kappa_core::types::StoreError>(car)
        }).await;
        match result {
            Ok(Ok(car)) => {
                (StatusCode::OK, [("content-type", "application/vnd.ipld.car")], car).into_response(cx)
            }
            _ => xrpc_error(cx, StatusCode::NOT_FOUND, "RepoNotFound", "repository not found"),
        }
    })
}

/// Parse the "data" field CID from a DAG-CBOR encoded commit.
///
/// The commit is a CBOR map. We find the "data" key and read its
/// Tag 42 byte string value, stripping the 0x00 multibase prefix.
fn parse_commit_data_cid(commit_bytes: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    if pos >= commit_bytes.len() { return None; }
    let major = commit_bytes[pos] >> 5;
    if major != 5 { return None; } // not a map
    let map_len = (commit_bytes[pos] & 0x1F) as usize;
    pos += 1;

    for _ in 0..map_len {
        // Read key (text string)
        if pos >= commit_bytes.len() { return None; }
        let key_major = commit_bytes[pos] >> 5;
        let key_len = (commit_bytes[pos] & 0x1F) as usize;
        if key_major != 3 { return None; }
        pos += 1;
        if pos + key_len > commit_bytes.len() { return None; }
        let key = std::str::from_utf8(&commit_bytes[pos..pos + key_len]).ok()?;
        pos += key_len;

        if key == "data" {
            // Expect Tag 42 (0xD8 0x2A) then byte string
            if pos + 1 >= commit_bytes.len() { return None; }
            if commit_bytes[pos] == 0xD8 && commit_bytes[pos + 1] == 42 {
                pos += 2;
                if pos >= commit_bytes.len() { return None; }
                let bs_major = commit_bytes[pos] >> 5;
                let bs_len = (commit_bytes[pos] & 0x1F) as usize;
                if bs_major != 2 { return None; }
                pos += 1;
                let actual_len = if bs_len < 24 {
                    bs_len
                } else if bs_len == 24 {
                    if pos >= commit_bytes.len() { return None; }
                    let l = commit_bytes[pos] as usize;
                    pos += 1;
                    l
                } else { return None; };
                if pos + actual_len > commit_bytes.len() { return None; }
                let cid_bytes = &commit_bytes[pos..pos + actual_len];
                // Strip 0x00 identity multibase prefix
                if !cid_bytes.is_empty() && cid_bytes[0] == 0x00 {
                    return Some(cid_bytes[1..].to_vec());
                }
                return Some(cid_bytes.to_vec());
            }
            return None;
        } else {
            // Skip value
            skip_cbor_value(commit_bytes, &mut pos)?;
        }
    }
    None
}

/// Skip a single CBOR value at the given position.
fn skip_cbor_value(data: &[u8], pos: &mut usize) -> Option<()> {
    if *pos >= data.len() { return None; }
    let major = data[*pos] >> 5;
    let additional = data[*pos] & 0x1F;
    *pos += 1;
    match major {
        0 | 1 => {
            if additional >= 24 && additional <= 27 {
                *pos += 1usize << (additional - 24);
            }
        }
        2 | 3 => {
            let len = if additional < 24 { additional as usize }
                else if additional == 24 { let l = *data.get(*pos)? as usize; *pos += 1; l }
                else { return None; };
            *pos += len;
        }
        4 => {
            let len = additional as usize;
            for _ in 0..len { skip_cbor_value(data, pos)?; }
        }
        5 => {
            let len = additional as usize;
            for _ in 0..len { skip_cbor_value(data, pos)?; skip_cbor_value(data, pos)?; }
        }
        6 => {
            if additional >= 24 && additional <= 27 {
                *pos += 1usize << (additional - 24);
            }
            skip_cbor_value(data, pos)?;
        }
        7 => {
            if additional >= 24 && additional <= 27 {
                *pos += 1usize << (additional - 24);
            }
        }
        _ => {}
    }
    Some(())
}

/// Walk an MST tree depth-first, collecting CIDs into the visited set.
/// Does not collect blocks -- used for building exclusion sets.
fn walk_mst_cids(
    store: &Arc<dyn KappaStore>,
    ns: &kappa_core::types::NamespaceRef,
    node_cid: &[u8],
    visited: &mut std::collections::HashSet<[u8; 36]>,
) {
    if node_cid.len() != 36 { return; }
    let mut cid_arr = [0u8; 36];
    cid_arr.copy_from_slice(node_cid);
    if !visited.insert(cid_arr) { return; }

    let cid_hex = hex::encode(node_cid);
    let tag_name = format!("mst/{}", cid_hex);
    let kappa = match store.tag_get(ns, &tag_name) {
        Ok(e) => e.kappa,
        Err(_) => return,
    };
    let node_bytes = match store.blob_get(&kappa) {
        Ok(b) => b,
        Err(_) => return,
    };

    if let Ok((left, entries)) = crate::mst::decode_node(&node_bytes) {
        if let Some(left_cid) = left {
            walk_mst_cids(store, ns, &left_cid, visited);
        }
        for entry in &entries {
            visited.insert(entry.value);
            if let Some(right_cid) = &entry.tree {
                walk_mst_cids(store, ns, right_cid, visited);
            }
        }
    }
}

/// Walk an MST tree depth-first, collecting blocks for CAR export.
fn walk_mst_node(
    store: &Arc<dyn KappaStore>,
    ns: &kappa_core::types::NamespaceRef,
    node_cid: &[u8],
    blocks: &mut Vec<crate::car::CarBlock>,
    visited: &mut std::collections::HashSet<[u8; 36]>,
) {
    if node_cid.len() != 36 { return; }
    let mut cid_arr = [0u8; 36];
    cid_arr.copy_from_slice(node_cid);
    if !visited.insert(cid_arr) { return; }

    // Look up node blob via CID->kappa bridge tag
    let cid_hex = hex::encode(node_cid);
    let tag_name = format!("mst/{}", cid_hex);
    let kappa = match store.tag_get(ns, &tag_name) {
        Ok(e) => e.kappa,
        Err(_) => return,
    };
    let node_bytes = match store.blob_get(&kappa) {
        Ok(b) => b,
        Err(_) => return,
    };
    blocks.push(crate::car::CarBlock {
        cid: node_cid.to_vec(),
        bytes: node_bytes.clone(),
    });

    // Decode the MST node to find children
    if let Ok((left, entries)) = crate::mst::decode_node(&node_bytes) {
        // Walk left subtree
        if let Some(left_cid) = left {
            walk_mst_node(store, ns, &left_cid, blocks, visited);
        }

        // Walk each entry's value (record blob) and right subtree
        for entry in &entries {
            // Record blob via CID->kappa bridge tag
            let value_cid_hex = hex::encode(&entry.value);
            let blob_tag = format!("blob/{}", value_cid_hex);
            if let Ok(blob_entry) = store.tag_get(ns, &blob_tag) {
                if let Ok(blob_data) = store.blob_get(&blob_entry.kappa) {
                    if visited.insert(entry.value) {
                        blocks.push(crate::car::CarBlock {
                            cid: entry.value.to_vec(),
                            bytes: blob_data,
                        });
                    }
                }
            }

            // Right subtree
            if let Some(right_cid) = &entry.tree {
                walk_mst_node(store, ns, right_cid, blocks, visited);
            }
        }
    }
}

/// Rebuild the MST from all record tags, create a new commit, update
/// commit/head, commit/rev, and commit/rev/{rev} tags.
///
/// Called after every record mutation (create, update, delete) to keep
/// the commit chain consistent with the record state.
fn rebuild_mst_and_commit(
    store: &Arc<dyn KappaStore>,
    ns: &kappa_core::types::NamespaceRef,
    repo_did: &str,
) -> Result<String, kappa_core::types::StoreError> {
    // 1. Load all record tags into an MST
    let record_tags = store.tag_prefix(ns, "record/")?;
    let mut mst = crate::mst::Mst::new();
    for tag in &record_tags {
        let record_bytes = store.blob_get(&tag.kappa)?;
        let record_cid = crate::cid::cid_for_cbor(&record_bytes);
        // MST key = collection/rkey (strip "record/" prefix)
        let mst_key = tag.name.strip_prefix("record/").unwrap_or(&tag.name);
        // insert returns Err on duplicate -- skip silently
        let _ = mst.insert(mst_key, record_cid);
    }

    // 2. Serialize MST and store all node blocks with CID->kappa bridge tags
    let mut mst_store = crate::mst::MemoryBlockStore::new();
    let (mst_root, mst_blocks) = mst.write_to_store(&mut mst_store);
    for (block_cid, block_bytes) in &mst_blocks {
        let ingest = store.ingest_compute(kappa_core::kappa::Axis::Sha256, block_bytes)?;
        let cid_hex = hex::encode(block_cid);
        store.tag_set(ns, &format!("mst/{}", cid_hex), &ingest.kappa)?;
    }

    // 3. Get previous commit CID for prev field
    let prev_commit_cid = store.tag_get(ns, "commit/head").ok().and_then(|entry| {
        let bytes = store.blob_get(&entry.kappa).ok()?;
        Some(crate::cid::cid_for_cbor(&bytes).to_vec())
    });

    // 4. Create new commit
    let tid_gen = crate::tid::TidGenerator::with_clock_id(0);
    let rev = tid_gen.next();

    let commit = crate::commit::UnsignedCommit {
        did: repo_did.to_string(),
        version: 3,
        data: mst_root.to_vec(),
        rev: rev.clone(),
        prev: prev_commit_cid,
    };
    let commit_bytes = commit.to_cbor();
    let commit_result = store.ingest_compute(kappa_core::kappa::Axis::Sha256, &commit_bytes)?;

    // 5. Update commit tags
    store.tag_set(ns, "commit/head", &commit_result.kappa)?;
    store.tag_set(ns, "commit/rev", &rev)?;
    // Indexed by rev for incremental sync (getRepo ?since=)
    store.tag_set(ns, &format!("commit/rev/{}", rev), &commit_result.kappa)?;

    Ok(rev)
}

fn get_blob(cx: &Cx, _body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let did = match query_param(cx, "did") {
            Some(d) => d,
            None => return xrpc_error(cx, StatusCode::BAD_REQUEST, "InvalidRequest", "missing did parameter"),
        };
        let cid_param = match query_param(cx, "cid") {
            Some(c) => c,
            None => return xrpc_error(cx, StatusCode::BAD_REQUEST, "InvalidRequest", "missing cid parameter"),
        };
        let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
        let result = tokio::task::spawn_blocking(move || {
            let ns = store.namespace_resolve(&did, Some("atproto"))?;
            // Look up blob by CID tag
            let tag_name = format!("blob/{}", cid_param);
            let entry = store.tag_get(&ns, &tag_name)?;
            store.blob_get(&entry.kappa)
        }).await;
        match result {
            Ok(Ok(data)) => {
                (StatusCode::OK, [("content-type", "application/octet-stream")], data).into_response(cx)
            }
            _ => StatusCode::NOT_FOUND.into_response(cx),
        }
    })
}

// -- Identity endpoints -------------------------------------------------------

fn resolve_handle(cx: &Cx, _body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let handle = match query_param(cx, "handle") {
            Some(h) => h,
            None => return xrpc_error(cx, StatusCode::BAD_REQUEST, "InvalidRequest", "missing handle parameter"),
        };
        // Use the ResolverRegistry to resolve the handle to a DID
        let registry = try_app_context::<Arc<kappa_core::identity::ResolverRegistry>>(cx).cloned();
        if let Some(reg) = registry {
            match reg.resolve(&handle).await {
                Ok(Some(identity)) => {
                    // The anchor resolves but we need the DID, not the anchor.
                    // For atproto, the handle maps to a DID via WebFinger.
                    // If the resolver returned evidence (the DID document), extract the DID.
                    // Otherwise return the anchor as a placeholder.
                    let did = identity.handle.clone();
                    let body = serde_json::json!({ "did": did });
                    return (StatusCode::OK, [("content-type", "application/json")], body.to_string()).into_response(cx);
                }
                _ => {}
            }
        }
        // Fallback: check handle tags in _handles namespace
        let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
        let result = tokio::task::spawn_blocking(move || {
            let handles_ns = store.namespace_resolve("_handles", None)?;
            let tag_name = format!("handle:atproto:{}", handle);
            let entry = store.tag_get(&handles_ns, &tag_name)?;
            store.blob_get(&entry.kappa)
        }).await;
        match result {
            Ok(Ok(data)) => {
                let record: serde_json::Value = serde_json::from_slice(&data).unwrap_or_default();
                let did = record.get("anchor").and_then(|a| a.as_str()).unwrap_or("");
                let body = serde_json::json!({ "did": did });
                (StatusCode::OK, [("content-type", "application/json")], body.to_string()).into_response(cx)
            }
            _ => xrpc_error(cx, StatusCode::NOT_FOUND, "HandleNotFound", "handle not found"),
        }
    })
}

// -- Repo endpoints -----------------------------------------------------------

fn describe_repo(cx: &Cx, _body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let repo = match query_param(cx, "repo") {
            Some(r) => r,
            None => return xrpc_error(cx, StatusCode::BAD_REQUEST, "InvalidRequest", "missing repo parameter"),
        };
        let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
        let repo_owned = repo.clone();
        let result = tokio::task::spawn_blocking(move || {
            let ns = store.namespace_resolve(&repo_owned, Some("atproto"))?;
            let ns_name = ns.display_name().unwrap_or("");
            let info = store.namespace_info(ns_name, Some("atproto"))?;
            // List collections by scanning tag prefixes
            let tags = store.tag_list(&ns)?;
            let mut collections: Vec<String> = tags.iter()
                .filter_map(|t| {
                    let key = t.name.strip_prefix("record/")?;
                    let collection = key.split('/').next()?;
                    Some(collection.to_string())
                })
                .collect();
            collections.sort();
            collections.dedup();
            Ok::<(kappa_core::store::NamespaceRecord, Vec<String>), kappa_core::types::StoreError>((info, collections))
        }).await;
        match result {
            Ok(Ok((info, collections))) => {
                let did = info.aliases.first().map(|a| a.as_str()).unwrap_or(&repo);
                let body = serde_json::json!({
                    "handle": did,
                    "did": did,
                    "didDoc": {},
                    "collections": collections,
                    "handleIsCorrect": true,
                });
                (StatusCode::OK, [("content-type", "application/json")], body.to_string()).into_response(cx)
            }
            _ => xrpc_error(cx, StatusCode::NOT_FOUND, "RepoNotFound", "repository not found"),
        }
    })
}

fn get_record(cx: &Cx, _body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let repo = match query_param(cx, "repo") {
            Some(r) => r,
            None => return xrpc_error(cx, StatusCode::BAD_REQUEST, "InvalidRequest", "missing repo parameter"),
        };
        let collection = match query_param(cx, "collection") {
            Some(c) => c,
            None => return xrpc_error(cx, StatusCode::BAD_REQUEST, "InvalidRequest", "missing collection parameter"),
        };
        let rkey = match query_param(cx, "rkey") {
            Some(r) => r,
            None => return xrpc_error(cx, StatusCode::BAD_REQUEST, "InvalidRequest", "missing rkey parameter"),
        };
        let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
        let result = tokio::task::spawn_blocking(move || {
            let ns = store.namespace_resolve(&repo, Some("atproto"))?;
            let tag_name = format!("record/{}/{}", collection, rkey);
            let entry = store.tag_get(&ns, &tag_name)?;
            let data = store.blob_get(&entry.kappa)?;
            Ok::<(String, Vec<u8>, String), kappa_core::types::StoreError>(
                (entry.kappa, data, format!("at://{}/{}/{}", repo, collection, rkey))
            )
        }).await;
        match result {
            Ok(Ok((cid, data, uri))) => {
                let value: serde_json::Value = serde_json::from_slice(&data).unwrap_or_default();
                let body = serde_json::json!({
                    "uri": uri,
                    "cid": cid,
                    "value": value,
                });
                (StatusCode::OK, [("content-type", "application/json")], body.to_string()).into_response(cx)
            }
            _ => xrpc_error(cx, StatusCode::NOT_FOUND, "RecordNotFound", "record not found"),
        }
    })
}

fn list_records(cx: &Cx, _body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let repo = match query_param(cx, "repo") {
            Some(r) => r,
            None => return xrpc_error(cx, StatusCode::BAD_REQUEST, "InvalidRequest", "missing repo parameter"),
        };
        let collection = match query_param(cx, "collection") {
            Some(c) => c,
            None => return xrpc_error(cx, StatusCode::BAD_REQUEST, "InvalidRequest", "missing collection parameter"),
        };
        let limit: usize = query_param(cx, "limit")
            .and_then(|s| s.parse().ok())
            .unwrap_or(50);
        let cursor = query_param(cx, "cursor");
        let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
        let result = tokio::task::spawn_blocking(move || {
            let ns = store.namespace_resolve(&repo, Some("atproto"))?;
            let prefix = format!("record/{}/", collection);
            let tags = store.tag_prefix(&ns, &prefix)?;
            let mut records: Vec<serde_json::Value> = Vec::new();
            let mut skipping = cursor.is_some();
            for tag in &tags {
                if skipping {
                    if let Some(ref c) = cursor {
                        if tag.name.ends_with(c.as_str()) {
                            skipping = false;
                        }
                    }
                    continue;
                }
                if records.len() >= limit { break; }
                let rkey = tag.name.strip_prefix(&prefix).unwrap_or(&tag.name);
                let uri = format!("at://{}/{}/{}", repo, collection, rkey);
                let value: serde_json::Value = match store.blob_get(&tag.kappa) {
                    Ok(data) => serde_json::from_slice(&data).unwrap_or_default(),
                    Err(_) => serde_json::Value::Null,
                };
                records.push(serde_json::json!({
                    "uri": uri,
                    "cid": tag.kappa,
                    "value": value,
                }));
            }
            Ok::<Vec<serde_json::Value>, kappa_core::types::StoreError>(records)
        }).await;
        match result {
            Ok(Ok(records)) => {
                let body = serde_json::json!({ "records": records });
                (StatusCode::OK, [("content-type", "application/json")], body.to_string()).into_response(cx)
            }
            _ => xrpc_error(cx, StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", "list records failed"),
        }
    })
}

fn create_record(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
        let request_bytes = {
            use topcoat::router::to_bytes;
            to_bytes(body, 1024 * 1024).await.map(|b| b.to_vec()).unwrap_or_default()
        };
        // Pre-parse repo for auth check before spawn_blocking
        let pre_req: serde_json::Value = serde_json::from_slice(&request_bytes)
            .map_err(|e| topcoat::router::error::bad_request(format!("invalid JSON: {e}")))?;
        if let Some(repo_val) = pre_req.get("repo").and_then(|r| r.as_str()) {
            if let Err(resp) = verify_repo_auth(cx, repo_val) { return Ok(resp); }
        }
        let result = tokio::task::spawn_blocking(move || {
            let req: serde_json::Value = serde_json::from_slice(&request_bytes)
                .map_err(|e| kappa_core::types::StoreError::Rejected(format!("invalid JSON: {e}")))?;
            let repo = req.get("repo").and_then(|r| r.as_str())
                .ok_or_else(|| kappa_core::types::StoreError::Rejected("missing repo".into()))?;
            let collection = req.get("collection").and_then(|c| c.as_str())
                .ok_or_else(|| kappa_core::types::StoreError::Rejected("missing collection".into()))?;
            let record = req.get("record")
                .ok_or_else(|| kappa_core::types::StoreError::Rejected("missing record".into()))?;

            let ns = store.namespace_resolve_or_create(repo, repo, Some("atproto"))?;

            // Generate rkey (TID)
            let rkey = req.get("rkey").and_then(|r| r.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    let gen = crate::tid::TidGenerator::with_clock_id(0);
                    gen.next()
                });

            // Store record as blob
            let record_bytes = serde_json::to_vec(record)
                .map_err(|e| kappa_core::types::StoreError::Rejected(format!("record serialize: {e}")))?;
            let ingest = store.ingest_compute(kappa_core::kappa::Axis::Sha256, &record_bytes)?;

            // CID->kappa bridge tag for MST tree walk in getRepo
            let record_cid = crate::cid::cid_for_cbor(&record_bytes);
            let blob_cid_hex = hex::encode(record_cid);
            store.tag_set(&ns, &format!("blob/{}", blob_cid_hex), &ingest.kappa)?;

            // Tag: record/{collection}/{rkey} -> record kappa
            let tag_name = format!("record/{}/{}", collection, rkey);
            store.tag_set(&ns, &tag_name, &ingest.kappa)?;

            // Rebuild MST and create new commit
            rebuild_mst_and_commit(&store, &ns, repo)?;

            let uri = format!("at://{}/{}/{}", repo, collection, rkey);
            Ok::<(String, String, String), kappa_core::types::StoreError>((uri, ingest.kappa, rkey))
        }).await;
        match result {
            Ok(Ok((uri, cid, _rkey))) => {
                let body = serde_json::json!({
                    "uri": uri,
                    "cid": cid,
                });
                (StatusCode::OK, [("content-type", "application/json")], body.to_string()).into_response(cx)
            }
            Ok(Err(kappa_core::types::StoreError::Rejected(msg))) => {
                xrpc_error(cx, StatusCode::BAD_REQUEST, "InvalidRequest", &msg)
            }
            _ => xrpc_error(cx, StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", "create record failed"),
        }
    })
}

fn put_record(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
        let request_bytes = {
            use topcoat::router::to_bytes;
            to_bytes(body, 1024 * 1024).await.map(|b| b.to_vec()).unwrap_or_default()
        };
        let pre_req: serde_json::Value = serde_json::from_slice(&request_bytes)
            .map_err(|e| topcoat::router::error::bad_request(format!("invalid JSON: {e}")))?;
        if let Some(repo_val) = pre_req.get("repo").and_then(|r| r.as_str()) {
            if let Err(resp) = verify_repo_auth(cx, repo_val) { return Ok(resp); }
        }
        let result = tokio::task::spawn_blocking(move || {
            let req: serde_json::Value = serde_json::from_slice(&request_bytes)
                .map_err(|e| kappa_core::types::StoreError::Rejected(format!("invalid JSON: {e}")))?;
            let repo = req.get("repo").and_then(|r| r.as_str())
                .ok_or_else(|| kappa_core::types::StoreError::Rejected("missing repo".into()))?;
            let collection = req.get("collection").and_then(|c| c.as_str())
                .ok_or_else(|| kappa_core::types::StoreError::Rejected("missing collection".into()))?;
            let rkey = req.get("rkey").and_then(|r| r.as_str())
                .ok_or_else(|| kappa_core::types::StoreError::Rejected("missing rkey".into()))?;
            let record = req.get("record")
                .ok_or_else(|| kappa_core::types::StoreError::Rejected("missing record".into()))?;

            let ns = store.namespace_resolve_or_create(repo, repo, Some("atproto"))?;

            let record_bytes = serde_json::to_vec(record)
                .map_err(|e| kappa_core::types::StoreError::Rejected(format!("record serialize: {e}")))?;
            let ingest = store.ingest_compute(kappa_core::kappa::Axis::Sha256, &record_bytes)?;

            // CID->kappa bridge tag for MST tree walk
            let record_cid = crate::cid::cid_for_cbor(&record_bytes);
            let blob_cid_hex = hex::encode(record_cid);
            store.tag_set(&ns, &format!("blob/{}", blob_cid_hex), &ingest.kappa)?;

            let tag_name = format!("record/{}/{}", collection, rkey);
            store.tag_set(&ns, &tag_name, &ingest.kappa)?;

            // Rebuild MST and create new commit
            rebuild_mst_and_commit(&store, &ns, repo)?;

            let uri = format!("at://{}/{}/{}", repo, collection, rkey);
            Ok::<(String, String), kappa_core::types::StoreError>((uri, ingest.kappa))
        }).await;
        match result {
            Ok(Ok((uri, cid))) => {
                let body = serde_json::json!({ "uri": uri, "cid": cid });
                (StatusCode::OK, [("content-type", "application/json")], body.to_string()).into_response(cx)
            }
            Ok(Err(kappa_core::types::StoreError::Rejected(msg))) => {
                xrpc_error(cx, StatusCode::BAD_REQUEST, "InvalidRequest", &msg)
            }
            _ => xrpc_error(cx, StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", "put record failed"),
        }
    })
}

fn delete_record(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
        let request_bytes = {
            use topcoat::router::to_bytes;
            to_bytes(body, 64 * 1024).await.map(|b| b.to_vec()).unwrap_or_default()
        };
        let pre_req: serde_json::Value = serde_json::from_slice(&request_bytes)
            .map_err(|e| topcoat::router::error::bad_request(format!("invalid JSON: {e}")))?;
        if let Some(repo_val) = pre_req.get("repo").and_then(|r| r.as_str()) {
            if let Err(resp) = verify_repo_auth(cx, repo_val) { return Ok(resp); }
        }
        let result = tokio::task::spawn_blocking(move || {
            let req: serde_json::Value = serde_json::from_slice(&request_bytes)
                .map_err(|e| kappa_core::types::StoreError::Rejected(format!("invalid JSON: {e}")))?;
            let repo = req.get("repo").and_then(|r| r.as_str())
                .ok_or_else(|| kappa_core::types::StoreError::Rejected("missing repo".into()))?;
            let collection = req.get("collection").and_then(|c| c.as_str())
                .ok_or_else(|| kappa_core::types::StoreError::Rejected("missing collection".into()))?;
            let rkey = req.get("rkey").and_then(|r| r.as_str())
                .ok_or_else(|| kappa_core::types::StoreError::Rejected("missing rkey".into()))?;

            let ns = store.namespace_resolve(repo, Some("atproto"))?;
            let tag_name = format!("record/{}/{}", collection, rkey);
            store.tag_delete(&ns, &tag_name)?;

            // Rebuild MST and create new commit
            rebuild_mst_and_commit(&store, &ns, repo)?;

            Ok::<(), kappa_core::types::StoreError>(())
        }).await;
        match result {
            Ok(Ok(())) => StatusCode::OK.into_response(cx),
            _ => xrpc_error(cx, StatusCode::NOT_FOUND, "RecordNotFound", "record not found"),
        }
    })
}

fn upload_blob(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
        let blob_bytes = {
            use topcoat::router::to_bytes;
            to_bytes(body, 10 * 1024 * 1024).await.map(|b| b.to_vec()).unwrap_or_default()
        };
        let result = tokio::task::spawn_blocking(move || {
            let ingest = store.ingest_compute(kappa_core::kappa::Axis::Sha256, &blob_bytes)?;
            Ok::<(String, usize), kappa_core::types::StoreError>((ingest.kappa, blob_bytes.len()))
        }).await;
        match result {
            Ok(Ok((cid, size))) => {
                let body = serde_json::json!({
                    "blob": {
                        "$type": "blob",
                        "ref": { "$link": cid },
                        "mimeType": "application/octet-stream",
                        "size": size,
                    }
                });
                (StatusCode::OK, [("content-type", "application/json")], body.to_string()).into_response(cx)
            }
            _ => xrpc_error(cx, StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", "upload blob failed"),
        }
    })
}

fn apply_writes(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
        let request_bytes = {
            use topcoat::router::to_bytes;
            to_bytes(body, 10 * 1024 * 1024).await.map(|b| b.to_vec()).unwrap_or_default()
        };
        let pre_req: serde_json::Value = serde_json::from_slice(&request_bytes)
            .map_err(|e| topcoat::router::error::bad_request(format!("invalid JSON: {e}")))?;
        if let Some(repo_val) = pre_req.get("repo").and_then(|r| r.as_str()) {
            if let Err(resp) = verify_repo_auth(cx, repo_val) { return Ok(resp); }
        }
        let result = tokio::task::spawn_blocking(move || {
            let req: serde_json::Value = serde_json::from_slice(&request_bytes)
                .map_err(|e| kappa_core::types::StoreError::Rejected(format!("invalid JSON: {e}")))?;
            let repo = req.get("repo").and_then(|r| r.as_str())
                .ok_or_else(|| kappa_core::types::StoreError::Rejected("missing repo".into()))?;
            let writes = req.get("writes").and_then(|w| w.as_array())
                .ok_or_else(|| kappa_core::types::StoreError::Rejected("missing writes array".into()))?;

            let ns = store.namespace_resolve_or_create(repo, repo, Some("atproto"))?;

            for write in writes {
                let action = write.get("$type").or(write.get("action"))
                    .and_then(|a| a.as_str()).unwrap_or("");
                let collection = write.get("collection").and_then(|c| c.as_str()).unwrap_or("");
                let rkey = write.get("rkey").and_then(|r| r.as_str()).unwrap_or("");

                match action {
                    "com.atproto.repo.applyWrites#create" | "create" => {
                        let record = write.get("value").or(write.get("record"))
                            .ok_or_else(|| kappa_core::types::StoreError::Rejected("missing record in create".into()))?;
                        let record_bytes = serde_json::to_vec(record)
                            .map_err(|e| kappa_core::types::StoreError::Rejected(format!("record serialize: {e}")))?;
                        let ingest = store.ingest_compute(kappa_core::kappa::Axis::Sha256, &record_bytes)?;

                        // CID->kappa bridge tag
                        let record_cid = crate::cid::cid_for_cbor(&record_bytes);
                        let blob_cid_hex = hex::encode(record_cid);
                        store.tag_set(&ns, &format!("blob/{}", blob_cid_hex), &ingest.kappa)?;

                        let rkey = if rkey.is_empty() {
                            let gen = crate::tid::TidGenerator::with_clock_id(0);
                            gen.next()
                        } else {
                            rkey.to_string()
                        };
                        let tag_name = format!("record/{}/{}", collection, rkey);
                        store.tag_set(&ns, &tag_name, &ingest.kappa)?;
                    }
                    "com.atproto.repo.applyWrites#update" | "update" => {
                        let record = write.get("value").or(write.get("record"))
                            .ok_or_else(|| kappa_core::types::StoreError::Rejected("missing record in update".into()))?;
                        let record_bytes = serde_json::to_vec(record)
                            .map_err(|e| kappa_core::types::StoreError::Rejected(format!("record serialize: {e}")))?;
                        let ingest = store.ingest_compute(kappa_core::kappa::Axis::Sha256, &record_bytes)?;

                        // CID->kappa bridge tag
                        let record_cid = crate::cid::cid_for_cbor(&record_bytes);
                        let blob_cid_hex = hex::encode(record_cid);
                        store.tag_set(&ns, &format!("blob/{}", blob_cid_hex), &ingest.kappa)?;

                        let tag_name = format!("record/{}/{}", collection, rkey);
                        store.tag_set(&ns, &tag_name, &ingest.kappa)?;
                    }
                    "com.atproto.repo.applyWrites#delete" | "delete" => {
                        let tag_name = format!("record/{}/{}", collection, rkey);
                        let _ = store.tag_delete(&ns, &tag_name);
                    }
                    _ => {
                        return Err(kappa_core::types::StoreError::Rejected(
                            format!("unknown write action: {}", action)
                        ));
                    }
                }
            }

            // Rebuild MST and create new commit after all writes
            rebuild_mst_and_commit(&store, &ns, repo)?;

            Ok::<(), kappa_core::types::StoreError>(())
        }).await;
        match result {
            Ok(Ok(())) => StatusCode::OK.into_response(cx),
            Ok(Err(kappa_core::types::StoreError::Rejected(msg))) => {
                xrpc_error(cx, StatusCode::BAD_REQUEST, "InvalidRequest", &msg)
            }
            _ => xrpc_error(cx, StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", "apply writes failed"),
        }
    })
}

// -- Session endpoints --------------------------------------------------------

fn create_session(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let request_bytes = {
            use topcoat::router::to_bytes;
            to_bytes(body, 64 * 1024).await.map(|b| b.to_vec()).unwrap_or_default()
        };
        let req: serde_json::Value = serde_json::from_slice(&request_bytes)
            .map_err(|e| topcoat::router::error::bad_request(format!("invalid JSON: {e}")))?;

        let identifier = req.get("identifier").and_then(|v| v.as_str()).unwrap_or("");
        let password = req.get("password").and_then(|v| v.as_str()).unwrap_or("");

        if identifier.is_empty() || password.is_empty() {
            return xrpc_error(cx, StatusCode::BAD_REQUEST, "InvalidRequest", "missing identifier or password");
        }

        // Extract DPoP JKT from request (or use empty for non-DPoP clients)
        let dpop_jkt = req.get("dpopJkt").and_then(|v| v.as_str()).unwrap_or("");

        let session_store = try_app_context::<Arc<crate::session::SessionStore>>(cx);
        match session_store {
            Some(store) => {
                match store.create_session(identifier, password, identifier, dpop_jkt) {
                    Ok(session) => {
                        let body = serde_json::json!({
                            "accessJwt": session.access_token,
                            "refreshJwt": session.refresh_token,
                            "handle": session.handle,
                            "did": session.did,
                            "dpopJkt": session.dpop_jkt,
                        });
                        (StatusCode::OK, [("content-type", "application/json")], body.to_string()).into_response(cx)
                    }
                    Err(e) => {
                        let status = StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::UNAUTHORIZED);
                        xrpc_error(cx, status, e.xrpc_error(), &e.to_string())
                    }
                }
            }
            None => xrpc_error(cx, StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", "session store not configured"),
        }
    })
}

fn refresh_session(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        // Refresh token comes from Authorization header
        let refresh_token = {
            use topcoat::context::request_context;
            let parts: &http::request::Parts = request_context(cx);
            parts.headers.get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .unwrap_or("")
                .to_string()
        };

        if refresh_token.is_empty() {
            return xrpc_error(cx, StatusCode::UNAUTHORIZED, "AuthenticationRequired", "missing refresh token");
        }

        let session_store = try_app_context::<Arc<crate::session::SessionStore>>(cx);
        match session_store {
            Some(store) => {
                match store.refresh_session(&refresh_token) {
                    Ok(session) => {
                        let body = serde_json::json!({
                            "accessJwt": session.access_token,
                            "refreshJwt": session.refresh_token,
                            "handle": session.handle,
                            "did": session.did,
                        });
                        (StatusCode::OK, [("content-type", "application/json")], body.to_string()).into_response(cx)
                    }
                    Err(e) => {
                        let status = StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::UNAUTHORIZED);
                        xrpc_error(cx, status, e.xrpc_error(), &e.to_string())
                    }
                }
            }
            None => xrpc_error(cx, StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", "session store not configured"),
        }
    })
}

fn delete_session(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let access_token = extract_bearer_token(cx);
        if access_token.is_empty() {
            return xrpc_error(cx, StatusCode::UNAUTHORIZED, "AuthenticationRequired", "missing access token");
        }

        let session_store = try_app_context::<Arc<crate::session::SessionStore>>(cx);
        match session_store {
            Some(store) => {
                match store.delete_session(&access_token) {
                    Ok(()) => StatusCode::OK.into_response(cx),
                    Err(e) => xrpc_error(cx, StatusCode::UNAUTHORIZED, e.xrpc_error(), &e.to_string()),
                }
            }
            None => xrpc_error(cx, StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", "session store not configured"),
        }
    })
}

fn get_session(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let access_token = extract_bearer_token(cx);
        if access_token.is_empty() {
            return xrpc_error(cx, StatusCode::UNAUTHORIZED, "AuthenticationRequired", "missing access token");
        }

        let session_store = try_app_context::<Arc<crate::session::SessionStore>>(cx);
        match session_store {
            Some(store) => {
                match store.get_session(&access_token) {
                    Ok(session) => {
                        let body = serde_json::json!({
                            "handle": session.handle,
                            "did": session.did,
                            "active": true,
                        });
                        (StatusCode::OK, [("content-type", "application/json")], body.to_string()).into_response(cx)
                    }
                    Err(e) => xrpc_error(cx, StatusCode::UNAUTHORIZED, e.xrpc_error(), &e.to_string()),
                }
            }
            None => xrpc_error(cx, StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", "session store not configured"),
        }
    })
}

// -- createAccount ------------------------------------------------------------

fn create_account(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let request_bytes = {
            use topcoat::router::to_bytes;
            to_bytes(body, 64 * 1024).await.map(|b| b.to_vec()).unwrap_or_default()
        };
        let req: serde_json::Value = serde_json::from_slice(&request_bytes)
            .map_err(|e| topcoat::router::error::bad_request(format!("invalid JSON: {e}")))?;

        let handle = req.get("handle").and_then(|v| v.as_str()).unwrap_or("");
        let password = req.get("password").and_then(|v| v.as_str()).unwrap_or("");
        let did = req.get("did").and_then(|v| v.as_str()).map(|s| s.to_string());

        if handle.is_empty() || password.is_empty() {
            return xrpc_error(cx, StatusCode::BAD_REQUEST, "InvalidRequest", "missing handle or password");
        }

        let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
        let handle_owned = handle.to_string();
        let password_owned = password.to_string();

        // Generate DID if not provided
        let account_did = did.unwrap_or_else(|| {
            // Generate a deterministic DID from the handle
            let hash = sha2::Sha256::digest(handle_owned.as_bytes());
            format!("did:plc:{}", &hex::encode(&hash[..16]))
        });

        let did_for_ns = account_did.clone();
        // Create namespace and initial repo state
        let result = tokio::task::spawn_blocking(move || {
            // Create namespace for this DID
            let ns = store.namespace_resolve_or_create(&did_for_ns, &did_for_ns, Some("atproto"))?;

            // Initialize empty MST root
            let mut mst_store = crate::mst::MemoryBlockStore::new();
            let mst = crate::mst::Mst::new();
            let (mst_root, mst_blocks) = mst.write_to_store(&mut mst_store);

            // Store all MST node blocks and create CID->kappa bridge tags
            for (block_cid, block_bytes) in &mst_blocks {
                let ingest = store.ingest_compute(
                    kappa_core::kappa::Axis::Sha256,
                    block_bytes,
                )?;
                let cid_hex = hex::encode(block_cid);
                store.tag_set(&ns, &format!("mst/{}", cid_hex), &ingest.kappa)?;
            }

            // Create initial commit
            let tid_gen = crate::tid::TidGenerator::with_clock_id(0);
            let rev = tid_gen.next();

            let commit = crate::commit::UnsignedCommit {
                did: did_for_ns.clone(),
                version: 3,
                data: mst_root.to_vec(),
                rev: rev.clone(),
                prev: None,
            };
            let commit_bytes = commit.to_cbor();
            let commit_result = store.ingest_compute(
                kappa_core::kappa::Axis::Sha256, &commit_bytes,
            )?;

            // Tag: commit/head -> commit kappa
            store.tag_set(&ns, "commit/head", &commit_result.kappa)?;
            store.tag_set(&ns, "commit/rev", &rev)?;
            // Indexed by rev for incremental sync (getRepo ?since=)
            store.tag_set(&ns, &format!("commit/rev/{}", rev), &commit_result.kappa)?;

            Ok::<(String, String), kappa_core::types::StoreError>((did_for_ns, rev))
        }).await;

        match result {
            Ok(Ok((did, _rev))) => {
                // Register credentials and create initial session
                let mut access_jwt = String::new();
                let mut refresh_jwt = String::new();
                if let Some(session_store) = try_app_context::<Arc<crate::session::SessionStore>>(cx) {
                    session_store.register_credentials(&did, &password_owned);
                    if let Ok(session) = session_store.create_session(&did, &password_owned, &handle_owned, "") {
                        access_jwt = session.access_token;
                        refresh_jwt = session.refresh_token;
                    }
                }

                let body = serde_json::json!({
                    "handle": handle_owned,
                    "did": did,
                    "accessJwt": access_jwt,
                    "refreshJwt": refresh_jwt,
                });
                (StatusCode::OK, [("content-type", "application/json")], body.to_string()).into_response(cx)
            }
            Ok(Err(e)) => xrpc_error(cx, StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", &e.to_string()),
            Err(e) => xrpc_error(cx, StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", &e.to_string()),
        }
    })
}

// -- Helpers ------------------------------------------------------------------

// -- subscribeRepos firehose --------------------------------------------------

/// Firehose delivery mode.
#[derive(Debug, Clone, Copy)]
pub enum FirehoseMode {
    /// Subscribe to broadcast channel. Zero-latency push.
    /// Requires EventBroadcaster in app context.
    Broadcast,
    /// Poll sequence counter at configurable interval.
    /// Works without EventBroadcaster. Higher latency.
    Poll { interval_ms: u64 },
}

impl Default for FirehoseMode {
    fn default() -> Self {
        Self::Broadcast
    }
}

/// Configurable firehose settings registered in app context.
pub struct FirehoseConfig {
    pub mode: FirehoseMode,
    pub max_lag: u64,
    pub heartbeat_interval_ms: u64,
    /// When true, send JSON text frames instead of DAG-CBOR binary frames.
    /// For debugging and clients that don't implement DAG-CBOR parsing.
    pub force_json: bool,
}

impl Default for FirehoseConfig {
    fn default() -> Self {
        Self {
            mode: FirehoseMode::Broadcast,
            max_lag: 10000,
            heartbeat_interval_ms: 30000,
            force_json: false,
        }
    }
}

fn subscribe_repos(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        use topcoat::router::content::websocket::{Message, WebSocketUpgrade};

        let cursor: Option<u64> = query_param(cx, "cursor")
            .and_then(|s| s.parse().ok());

        let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
        let config = try_app_context::<Arc<FirehoseConfig>>(cx)
            .cloned()
            .unwrap_or_else(|| Arc::new(FirehoseConfig::default()));

        // Broadcast sender registered in app context by kappa-server.
        // The atproto module subscribes to it for zero-latency push delivery.
        let event_sender = try_app_context::<
            Arc<tokio::sync::broadcast::Sender<kappa_core::events::TagEvent>>
        >(cx).cloned();

        let upgrade = WebSocketUpgrade::from_request(cx, body).await?;
        upgrade
            .protocols(["atproto-sync.v1"])
            .on_upgrade(move |mut socket| async move {
                let mut seq = cursor.unwrap_or(0);
                let max_lag = config.max_lag;
                let force_json = config.force_json;

                match (config.mode, &event_sender) {
                    // Broadcast mode: subscribe to the event channel
                    (FirehoseMode::Broadcast, Some(sender)) => {
                        let mut rx = sender.subscribe();
                        let mut heartbeat = tokio::time::interval(
                            std::time::Duration::from_millis(config.heartbeat_interval_ms),
                        );

                        loop {
                            tokio::select! {
                                event = rx.recv() => {
                                    match event {
                                        Ok(tag_event) => {
                                            seq += 1;
                                            let msg = if force_json {
                                                let frame = firehose_frame_json(&tag_event, seq);
                                                Message::text(frame.to_string())
                                            } else {
                                                let frame = firehose_frame_cbor(&tag_event, seq);
                                                Message::binary(bytes::Bytes::from(frame))
                                            };
                                            if socket.send(msg).await.is_err() {
                                                return; // client disconnected
                                            }
                                        }
                                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                            if n > max_lag {
                                                let msg = if force_json {
                                                    let info = serde_json::json!({
                                                        "$type": "#info",
                                                        "name": "OutdatedCursor",
                                                        "message": format!("lagged {} events, closing", n),
                                                    });
                                                    Message::text(info.to_string())
                                                } else {
                                                    let frame = crate::dag_cbor::frame(
                                                        crate::dag_cbor::encode_header(-1, "#info"),
                                                        crate::dag_cbor::encode_info_body("OutdatedCursor", &format!("lagged {} events, closing", n)),
                                                    );
                                                    Message::binary(bytes::Bytes::from(frame))
                                                };
                                                let _ = socket.send(msg).await;
                                                return;
                                            }
                                            seq += n;
                                        }
                                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                            return;
                                        }
                                    }
                                }
                                _ = heartbeat.tick() => {
                                    if socket.send(Message::Ping(bytes::Bytes::new())).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    }

                    // Poll mode: check sequence counter at interval
                    _ => {
                        let poll_ms = match config.mode {
                            FirehoseMode::Poll { interval_ms } => interval_ms,
                            _ => 500,
                        };
                        let mut interval = tokio::time::interval(
                            std::time::Duration::from_millis(poll_ms),
                        );
                        let system_ns = match store.namespace_resolve("_system", None) {
                            Ok(ns) => ns,
                            Err(_) => return,
                        };

                        loop {
                            interval.tick().await;

                            let current_seq = match store.sequence_current(&system_ns, "_atproto_seq") {
                                Ok(s) => s,
                                Err(_) => continue,
                            };

                            if current_seq <= seq {
                                if socket.send(Message::Ping(bytes::Bytes::new())).await.is_err() {
                                    break;
                                }
                                continue;
                            }

                            while seq < current_seq {
                                seq += 1;
                                let msg = if force_json {
                                    let event = serde_json::json!({
                                        "$type": "#info",
                                        "name": "SequenceAdvance",
                                        "seq": seq,
                                    });
                                    Message::text(event.to_string())
                                } else {
                                    let frame = crate::dag_cbor::frame(
                                        crate::dag_cbor::encode_header(1, "#info"),
                                        crate::dag_cbor::encode_info_body("SequenceAdvance", &format!("{}", seq)),
                                    );
                                    Message::binary(bytes::Bytes::from(frame))
                                };
                                if socket.send(msg).await.is_err() {
                                    return;
                                }
                            }

                            if current_seq.saturating_sub(seq) > max_lag {
                                let msg = if force_json {
                                    let info = serde_json::json!({
                                        "$type": "#info",
                                        "name": "OutdatedCursor",
                                        "message": "cursor too far behind",
                                    });
                                    Message::text(info.to_string())
                                } else {
                                    let frame = crate::dag_cbor::frame(
                                        crate::dag_cbor::encode_header(-1, "#info"),
                                        crate::dag_cbor::encode_info_body("OutdatedCursor", "cursor too far behind"),
                                    );
                                    Message::binary(bytes::Bytes::from(frame))
                                };
                                let _ = socket.send(msg).await;
                                break;
                            }
                        }
                    }
                }
            })
            .into_response(cx)
    })
}

// -- Frame type dispatch for subscribeRepos -----------------------------------

/// Classify a TagEvent into a firehose frame type.
///
/// Rule table (deterministic, one entry per frame type):
///   _handles namespace + handle: prefix  -> #handle
///   any namespace + binding/ prefix      -> #identity
///   any namespace + succession/ prefix   -> #identity
///   any namespace + tombstone flag       -> #tombstone
///   everything else                      -> #commit
fn classify_frame(event: &kappa_core::events::TagEvent) -> &'static str {
    if event.namespace == "_handles" && event.name.starts_with("handle:") {
        "#handle"
    } else if event.name.starts_with("binding/") || event.name.starts_with("succession/") {
        "#identity"
    } else if event.name == "_tombstone" || event.name.starts_with("_tombstone/") {
        "#tombstone"
    } else {
        "#commit"
    }
}

/// Encode a firehose frame as DAG-CBOR binary (spec-correct wire format).
fn firehose_frame_cbor(event: &kappa_core::events::TagEvent, seq: u64) -> Vec<u8> {
    let frame_type = classify_frame(event);
    let header = crate::dag_cbor::encode_header(1, frame_type);
    let body = match frame_type {
        "#handle" => {
            let handle = event.name.strip_prefix("handle:")
                .and_then(|s| s.split_once(':').map(|(_, h)| h))
                .unwrap_or("");
            crate::dag_cbor::encode_handle_body(seq, &event.namespace, handle)
        }
        "#identity" => crate::dag_cbor::encode_identity_body(seq, &event.namespace),
        "#tombstone" => crate::dag_cbor::encode_tombstone_body(seq, &event.namespace),
        _ => {
            let action = match event.operation {
                kappa_core::events::TagEventOp::Set => "create",
                kappa_core::events::TagEventOp::Delete => "delete",
                _ => "update",
            };
            crate::dag_cbor::encode_commit_body(
                seq, &event.namespace,
                &[], // commit CID -- populated when MST-backed commits are real
                "",  // rev
                None, // since
                &[], // blocks CAR -- populated with MST-aware export
                &[(action, &event.name, None)],
            )
        }
    };
    crate::dag_cbor::frame(header, body)
}

/// Encode a firehose frame as JSON (debug/fallback format).
fn firehose_frame_json(event: &kappa_core::events::TagEvent, seq: u64) -> serde_json::Value {
    let frame_type = classify_frame(event);
    match frame_type {
        "#handle" => {
            let handle = event.name.strip_prefix("handle:")
                .and_then(|s| s.split_once(':').map(|(_, h)| h))
                .unwrap_or("");
            serde_json::json!({
                "$type": "#handle",
                "seq": seq,
                "did": event.namespace,
                "handle": handle,
            })
        }
        "#identity" => {
            serde_json::json!({
                "$type": "#identity",
                "seq": seq,
                "did": event.namespace,
            })
        }
        "#tombstone" => {
            serde_json::json!({
                "$type": "#tombstone",
                "seq": seq,
                "did": event.namespace,
            })
        }
        _ => {
            let action = match event.operation {
                kappa_core::events::TagEventOp::Set => "create",
                kappa_core::events::TagEventOp::Delete => "delete",
                _ => "update",
            };
            serde_json::json!({
                "$type": "#commit",
                "seq": seq,
                "repo": event.namespace,
                "ops": [{
                    "action": action,
                    "path": event.name,
                    "cid": event.value.as_deref().unwrap_or(""),
                }],
            })
        }
    }
}

// -- updateHandle -------------------------------------------------------------

fn update_handle(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let access_token = extract_bearer_token(cx);
        if access_token.is_empty() {
            return xrpc_error(cx, StatusCode::UNAUTHORIZED, "AuthenticationRequired", "missing access token");
        }

        // Validate session
        let session_store = try_app_context::<Arc<crate::session::SessionStore>>(cx);
        let did = match session_store {
            Some(store) => match store.validate_token(&access_token) {
                Some(d) => d,
                None => return xrpc_error(cx, StatusCode::UNAUTHORIZED, "ExpiredToken", "invalid token"),
            },
            None => return xrpc_error(cx, StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", "no session store"),
        };

        let request_bytes = {
            use topcoat::router::to_bytes;
            to_bytes(body, 64 * 1024).await.map(|b| b.to_vec()).unwrap_or_default()
        };
        let req: serde_json::Value = serde_json::from_slice(&request_bytes)
            .map_err(|e| topcoat::router::error::bad_request(format!("invalid JSON: {e}")))?;

        let new_handle = req.get("handle").and_then(|v| v.as_str()).unwrap_or("");
        if new_handle.is_empty() {
            return xrpc_error(cx, StatusCode::BAD_REQUEST, "InvalidRequest", "missing handle");
        }

        let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
        let did_owned = did.clone();
        let handle_owned = new_handle.to_string();

        let result = tokio::task::spawn_blocking(move || {
            let handles_ns = store.namespace_resolve("_handles", None)?;

            // Find and remove old handle via reverse tag
            let reverse_key = format!("anchor:{}", did_owned);
            if let Ok(rev_entry) = store.tag_get(&handles_ns, &reverse_key) {
                if let Ok(old_keys_blob) = store.blob_get(&rev_entry.kappa) {
                    let old_keys = String::from_utf8(old_keys_blob).unwrap_or_default();
                    for old_key in old_keys.split(',') {
                        if old_key.starts_with("handle:atproto:") {
                            let _ = store.tag_delete(&handles_ns, old_key);
                        }
                    }
                }
            }

            // Create new handle record
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;

            let record = kappa_core::identity::handle::HandleRecord {
                anchor: did_owned.clone(),
                handle: handle_owned.clone(),
                protocol: "atproto".to_string(),
                claimed_at_ms: now_ms,
                verified_at_ms: None,
                verification_method: "unverified".to_string(),
                liveness: kappa_core::identity::handle::HandleLiveness::Unverified,
            };

            let record_bytes = serde_json::to_vec(&record)
                .map_err(|e| kappa_core::types::StoreError::Io(std::io::Error::other(e.to_string())))?;
            let ingest = store.ingest_compute(kappa_core::kappa::Axis::Sha256, &record_bytes)?;

            let tag_key = format!("handle:atproto:{}", handle_owned);
            store.tag_set(&handles_ns, &tag_key, &ingest.kappa)?;

            // Update reverse tag
            let reverse_bytes = tag_key.as_bytes();
            let reverse_ingest = store.ingest_compute(kappa_core::kappa::Axis::Sha256, reverse_bytes)?;
            store.tag_set(&handles_ns, &reverse_key, &reverse_ingest.kappa)?;

            Ok::<(), kappa_core::types::StoreError>(())
        }).await;

        match result {
            Ok(Ok(())) => StatusCode::OK.into_response(cx),
            Ok(Err(e)) => xrpc_error(cx, StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", &e.to_string()),
            Err(e) => xrpc_error(cx, StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", &e.to_string()),
        }
    })
}

// -- requestCrawl -------------------------------------------------------------

fn request_crawl(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let request_bytes = {
            use topcoat::router::to_bytes;
            to_bytes(body, 64 * 1024).await.map(|b| b.to_vec()).unwrap_or_default()
        };
        let req: serde_json::Value = serde_json::from_slice(&request_bytes)
            .map_err(|e| topcoat::router::error::bad_request(format!("invalid JSON: {e}")))?;

        let hostname = req.get("hostname").and_then(|v| v.as_str()).unwrap_or("");
        if hostname.is_empty() {
            return xrpc_error(cx, StatusCode::BAD_REQUEST, "InvalidRequest", "missing hostname");
        }

        // Fire-and-forget: notify the relay via OutboundClient
        let our_hostname = std::env::var("KAPPA_PDS_HOSTNAME")
            .unwrap_or_else(|_| "http://localhost:5000".to_string());
        let relay_url = format!("{}/xrpc/com.atproto.sync.requestCrawl", hostname.trim_end_matches('/'));

        if let Some(outbound) = try_app_context::<Arc<topcoat::router::outbound::OutboundClient>>(cx) {
            let outbound = outbound.clone();
            let cx_clone = cx.clone();
            tokio::spawn(async move {
                let body = serde_json::json!({ "hostname": our_hostname });
                match outbound.post_json(&cx_clone, &relay_url, &body).await {
                    Ok(resp) => {
                        tracing::debug!(relay = %relay_url, status = %resp.status(), "requestCrawl sent");
                    }
                    Err(e) => {
                        tracing::warn!(relay = %relay_url, error = %e, "requestCrawl failed");
                    }
                }
            });
        } else {
            tracing::warn!("OutboundClient not configured, skipping requestCrawl");
        }

        StatusCode::OK.into_response(cx)
    })
}

// -- Helpers ------------------------------------------------------------------

/// Verify the caller's session DID matches the target repo.
///
/// Write endpoints (createRecord, putRecord, deleteRecord, applyWrites)
/// must verify that the authenticated user owns the repo they're writing to.
/// Returns Ok(did) if authorized, Err(Response) if not.
fn verify_repo_auth(
    cx: &Cx,
    repo: &str,
) -> Result<String, topcoat::router::response::Response> {
    use topcoat::context::request_context;
    let parts: &http::request::Parts = request_context(cx);
    let auth_header = parts.headers.get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if auth_header.is_empty() {
        return Err(xrpc_error(cx, StatusCode::UNAUTHORIZED, "AuthenticationRequired", "missing access token")
            .unwrap_or_else(|_| topcoat::router::response::Response::default()));
    }

    let session_store = try_app_context::<Arc<crate::session::SessionStore>>(cx);
    let Some(store) = session_store else {
        // No session store = auth not enforced (unauthenticated mode)
        return Ok(repo.to_string());
    };

    // DPoP path: Authorization: DPoP {access_token} + DPoP header with proof JWT
    if let Some(access_token) = auth_header.strip_prefix("DPoP ") {
        let dpop_proof = parts.headers.get("dpop")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if dpop_proof.is_empty() {
            return Err(xrpc_error(cx, StatusCode::UNAUTHORIZED, "InvalidToken", "DPoP proof header missing")
                .unwrap_or_else(|_| topcoat::router::response::Response::default()));
        }
        // Parse and verify the DPoP proof JWT (ES256 signature verification)
        let claims = crate::session::parse_and_verify_dpop_proof(dpop_proof)
            .map_err(|e| xrpc_error(cx, StatusCode::UNAUTHORIZED, e.xrpc_error(), &e.to_string())
                .unwrap_or_else(|_| topcoat::router::response::Response::default()))?;

        // Full 7-step DPoP verification against the session
        let method = parts.method.as_str();
        let uri = parts.uri.to_string();
        let did = store.verify_dpop_request(access_token, &claims, method, &uri)
            .map_err(|e| xrpc_error(cx, StatusCode::UNAUTHORIZED, e.xrpc_error(), &e.to_string())
                .unwrap_or_else(|_| topcoat::router::response::Response::default()))?;

        if did != repo {
            return Err(xrpc_error(cx, StatusCode::FORBIDDEN, "Forbidden",
                &format!("session DID {} does not match repo {}", did, repo))
                .unwrap_or_else(|_| topcoat::router::response::Response::default()));
        }
        return Ok(did);
    }

    // Bearer path: Authorization: Bearer {access_token}
    if let Some(access_token) = auth_header.strip_prefix("Bearer ") {
        match store.validate_token(access_token) {
            Some(did) => {
                if did != repo {
                    return Err(xrpc_error(cx, StatusCode::FORBIDDEN, "Forbidden",
                        &format!("session DID {} does not match repo {}", did, repo))
                        .unwrap_or_else(|_| topcoat::router::response::Response::default()));
                }
                return Ok(did);
            }
            None => return Err(xrpc_error(cx, StatusCode::UNAUTHORIZED, "ExpiredToken", "invalid or expired token")
                .unwrap_or_else(|_| topcoat::router::response::Response::default())),
        }
    }

    Err(xrpc_error(cx, StatusCode::UNAUTHORIZED, "AuthenticationRequired", "unsupported authorization scheme")
        .unwrap_or_else(|_| topcoat::router::response::Response::default()))
}

fn extract_bearer_token(cx: &Cx) -> String {
    use topcoat::context::request_context;
    let parts: &http::request::Parts = request_context(cx);
    parts.headers.get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("DPoP ")))
        .unwrap_or("")
        .to_string()
}
