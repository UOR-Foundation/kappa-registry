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
use crate::mst::BlockStore as _;

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
        // Sync firehose
        .route(RouteFn::new(Method::GET, p("/xrpc/com.atproto.sync.subscribeRepos"), subscribe_repos))
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
        let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
        let result = tokio::task::spawn_blocking(move || {
            let ns = store.namespace_resolve(&did, Some("atproto"))?;
            // Export the entire repo as a CAR file
            let head = store.tag_get(&ns, "commit/head")?;
            // Collect all blocks reachable from the commit
            let commit_bytes = store.blob_get(&head.kappa)?;
            let mut blocks = vec![crate::car::CarBlock {
                cid: hex::decode(&head.kappa.replace("sha256:", "")).unwrap_or_default(),
                bytes: commit_bytes,
            }];
            // Walk tags for record blobs
            let tags = store.tag_list(&ns)?;
            for tag in &tags {
                if tag.name.starts_with("record/") || tag.name.starts_with("mst/") {
                    if let Ok(data) = store.blob_get(&tag.kappa) {
                        blocks.push(crate::car::CarBlock {
                            cid: hex::decode(&tag.kappa.replace("sha256:", "")).unwrap_or_default(),
                            bytes: data,
                        });
                    }
                }
            }
            let root_cid = hex::decode(&head.kappa.replace("sha256:", "")).unwrap_or_default();
            let car = crate::car::encode_car(Some(&root_cid), &blocks);
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

            // Tag: record/{collection}/{rkey} -> record kappa
            let tag_name = format!("record/{}/{}", collection, rkey);
            store.tag_set(&ns, &tag_name, &ingest.kappa)?;

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

            let tag_name = format!("record/{}/{}", collection, rkey);
            store.tag_set(&ns, &tag_name, &ingest.kappa)?;

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
            let mst_root = mst.write_to_store(&mut mst_store);

            // Store MST root block
            let empty_vec = Vec::new();
            let mst_root_bytes = mst_store.get(&mst_root).unwrap_or(empty_vec);
            let mst_root_kappa = store.ingest_compute(
                kappa_core::kappa::Axis::Sha256,
                &mst_root_bytes,
            )?.kappa;

            // Tag: CID -> kappa bridge so getRepo can walk the commit tree
            let mst_cid_hex = hex::encode(mst_root);
            store.tag_set(&ns, &format!("mst/{}", mst_cid_hex), &mst_root_kappa)?;

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
}

impl Default for FirehoseConfig {
    fn default() -> Self {
        Self {
            mode: FirehoseMode::Broadcast,
            max_lag: 10000,
            heartbeat_interval_ms: 30000,
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
                                            let action = match tag_event.operation {
                                                kappa_core::events::TagEventOp::Set => "create",
                                                kappa_core::events::TagEventOp::Delete => "delete",
                                                _ => "update",
                                            };
                                            let frame = serde_json::json!({
                                                "$type": "#commit",
                                                "seq": seq,
                                                "repo": tag_event.namespace,
                                                "ops": [{
                                                    "action": action,
                                                    "path": tag_event.name,
                                                    "cid": tag_event.value.as_deref().unwrap_or(""),
                                                }],
                                            });
                                            if socket.send(Message::text(frame.to_string())).await.is_err() {
                                                return; // client disconnected
                                            }
                                        }
                                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                            if n > max_lag {
                                                let info = serde_json::json!({
                                                    "$type": "#info",
                                                    "name": "OutdatedCursor",
                                                    "message": format!("lagged {} events, closing", n),
                                                });
                                                let _ = socket.send(Message::text(info.to_string())).await;
                                                return;
                                            }
                                            // Recoverable lag: continue receiving
                                            seq += n;
                                        }
                                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                            return; // broadcaster dropped
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
                                let event = serde_json::json!({
                                    "$type": "#info",
                                    "name": "SequenceAdvance",
                                    "seq": seq,
                                });
                                if socket.send(Message::text(event.to_string())).await.is_err() {
                                    return;
                                }
                            }

                            if current_seq.saturating_sub(seq) > max_lag {
                                let info = serde_json::json!({
                                    "$type": "#info",
                                    "name": "OutdatedCursor",
                                    "message": "cursor too far behind",
                                });
                                let _ = socket.send(Message::text(info.to_string())).await;
                                break;
                            }
                        }
                    }
                }
            })
            .into_response(cx)
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
    let token = extract_bearer_token(cx);
    if token.is_empty() {
        return Err(xrpc_error(cx, StatusCode::UNAUTHORIZED, "AuthenticationRequired", "missing access token")
            .unwrap_or_else(|_| topcoat::router::response::Response::default()));
    }

    let session_store = try_app_context::<Arc<crate::session::SessionStore>>(cx);
    match session_store {
        Some(store) => {
            match store.validate_token(&token) {
                Some(did) => {
                    // Session DID must match the repo parameter
                    if did != repo {
                        return Err(xrpc_error(cx, StatusCode::FORBIDDEN, "Forbidden",
                            &format!("session DID {} does not match repo {}", did, repo))
                            .unwrap_or_else(|_| topcoat::router::response::Response::default()));
                    }
                    Ok(did)
                }
                None => Err(xrpc_error(cx, StatusCode::UNAUTHORIZED, "ExpiredToken", "invalid or expired token")
                    .unwrap_or_else(|_| topcoat::router::response::Response::default())),
            }
        }
        // No session store = auth not enforced (unauthenticated mode)
        None => Ok(repo.to_string()),
    }
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
