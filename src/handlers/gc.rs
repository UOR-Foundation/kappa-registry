use std::sync::Arc;

use topcoat::context::{app_context, Cx};
use topcoat::router::error::{bad_request, not_found};
use topcoat::router::{Body, IntoResponse, Response, RouteFuture, StatusCode};

use crate::auth::authorize;
use crate::ratelimit::OpClass;
use crate::store::fs::FsStore;
use crate::store::{KappaStore, StoreError};

use super::path_param;

fn store(cx: &Cx) -> &Arc<FsStore> {
    app_context::<Arc<FsStore>>(cx)
}

pub fn pin_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = super::read_body(body).await?;
        let ns = path_param(cx, "ns");
        pin(cx, ns, &bytes).await
    })
}

pub fn unpin_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = super::read_body(body).await?;
        let ns = path_param(cx, "ns");
        unpin(cx, ns, &bytes).await
    })
}

pub fn sweep_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        sweep(cx, ns).await
    })
}

pub fn status_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        status(cx, ns).await
    })
}

async fn pin(cx: &Cx, ns: &str, body: &[u8]) -> topcoat::Result<Response> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad_request(format!("invalid JSON: {e}")))?;
    let kappa = v["kappa"]
        .as_str()
        .ok_or_else(|| bad_request("missing kappa"))?;
    let ttl = v["ttl"].as_u64().unwrap_or(0);
    let controller = v["controller"].as_str().unwrap_or("");

    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    let k = kappa.to_string();
    let ctrl = controller.to_string();
    let pin_kappa = tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        move || {
            authorize(&*s, &n, OpClass::Write, &asserter)?;
            s.pin(&k, ttl, &ctrl)
        }
    })
    .await??;

    let pk = pin_kappa.clone();
    tokio::task::spawn_blocking(move || s.meta_set(&n, &pk, &[("object-type", "pin")])).await??;

    (
        StatusCode::CREATED,
        [
            ("x-kappa-label", pin_kappa),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response(cx)
}

async fn unpin(cx: &Cx, ns: &str, body: &[u8]) -> topcoat::Result<Response> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad_request(format!("invalid JSON: {e}")))?;
    let pin_kappa = v["pin_kappa"]
        .as_str()
        .ok_or_else(|| bad_request("missing pin_kappa"))?;
    let release = v["release"].as_str() == Some("true");

    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    let pk = pin_kappa.to_string();
    let result = tokio::task::spawn_blocking(move || {
        authorize(&*s, &n, OpClass::Write, &asserter)?;
        s.unpin(&pk, release)
    })
    .await?;

    match result {
        Ok(()) => StatusCode::OK.into_response(cx),
        Err(StoreError::Conflict(msg)) => (
            StatusCode::CONFLICT,
            format!("finalizer {msg} blocks unpin"),
        )
            .into_response(cx),
        Err(StoreError::NotFound) => Err(not_found().into()),
        Err(e) => Err(e.into()),
    }
}

async fn sweep(cx: &Cx, ns: &str) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let ns_owned = ns.to_string();
    let store_root = store(cx).root().to_path_buf();

    tokio::task::spawn_blocking({
        let s = s.clone();
        let n = ns_owned.clone();
        let a = asserter;
        move || authorize(&*s, &n, OpClass::Admin, &a)
    })
    .await??;

    let sweep_id = uuid::Uuid::new_v4().to_string();
    let sid = sweep_id.clone();

    tokio::task::spawn(async move {
        let result =
            tokio::task::spawn_blocking(move || run_sweep(&*s, &ns_owned, &store_root, &sid)).await;
        if let Err(e) = result {
            tracing::error!("sweep task failed: {e}");
        }
    });

    let body = serde_json::json!({"sweep_id": sweep_id});
    (
        StatusCode::ACCEPTED,
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn status(cx: &Cx, ns: &str) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    let store_root = store(cx).root().to_path_buf();
    let body = tokio::task::spawn_blocking(move || {
        authorize(&*s, &n, OpClass::Read, &asserter)?;

        let status_path = store_root.join("gc").join("status.json");
        let mut status: serde_json::Value = if status_path.exists() {
            std::fs::read(&status_path)
                .ok()
                .and_then(|d| serde_json::from_slice(&d).ok())
                .unwrap_or_else(|| serde_json::json!({}))
        } else {
            serde_json::json!({})
        };

        let finalizers = s.pin_finalizers().unwrap_or_default();
        let fin_json: Vec<serde_json::Value> = finalizers
            .iter()
            .map(|(k, c)| serde_json::json!({"kappa": k, "controller": c}))
            .collect();
        status["pending_finalizers"] = serde_json::json!(fin_json);

        if status.get("objects_scanned").is_none() {
            status["objects_scanned"] = serde_json::json!(0);
            status["objects_reachable"] = serde_json::json!(0);
            status["objects_evicted"] = serde_json::json!(0);
        }

        Ok::<_, StoreError>(serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string()))
    })
    .await??;

    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        body,
    )
        .into_response(cx)
}

/// D-7: GC walk relations include identity relations.
const GC_WALK_RELATIONS: &[&str] = &[
    "owns",
    "composed-of",
    "assertion",
    "revocation",
    "recovery-share",
    "capability",
];

fn run_sweep(
    store: &dyn KappaStore,
    ns: &str,
    store_root: &std::path::Path,
    sweep_id: &str,
) -> Result<(), StoreError> {
    let pin_roots = store.pin_roots()?;
    let tag_roots = store.tag_all_kappas_global()?;

    let mut roots: Vec<String> = pin_roots.clone();
    roots.extend(tag_roots.clone());
    roots.sort();
    roots.dedup();

    let reachable = store.edge_walk(ns, &roots, GC_WALK_RELATIONS)?;

    let mut all_blobs = Vec::new();
    for axis in &[
        "sha1",
        "sha256",
        "blake3",
        "sha3-256",
        "keccak256",
        "sha512",
    ] {
        let prefix = format!("{axis}:");
        if let Ok(keys) = store.list(&prefix) {
            all_blobs.extend(keys);
        }
    }

    let mut reachable_bitmap = roaring::RoaringBitmap::new();
    for (i, kappa) in all_blobs.iter().enumerate() {
        if reachable.contains(kappa) {
            reachable_bitmap.insert(i as u32);
        }
    }

    let scanned = all_blobs.len();
    let mut evicted = 0usize;
    let mut evicted_set = Vec::new();
    for (i, kappa) in all_blobs.iter().enumerate() {
        if !reachable_bitmap.contains(i as u32) {
            let _ = store.remove(kappa);
            evicted_set.push(kappa.clone());
            evicted += 1;
        }
    }

    for kappa in &evicted_set {
        let _ = store.edge_remove_by_node(ns, kappa);
    }

    let reachable_count = scanned - evicted;
    let finalizers = store.pin_finalizers().unwrap_or_default();
    let fin_json: Vec<serde_json::Value> = finalizers
        .iter()
        .map(|(k, c)| serde_json::json!({"kappa": k, "controller": c}))
        .collect();

    let reachable_list: Vec<&String> = reachable.iter().collect();

    let status = serde_json::json!({
        "last_sweep": sweep_id,
        "objects_scanned": scanned,
        "objects_reachable": reachable_count,
        "objects_evicted": evicted,
        "pending_finalizers": fin_json,
        "debug_pin_roots": pin_roots,
        "debug_tag_roots": tag_roots,
        "debug_roots": roots,
        "debug_reachable": reachable_list,
        "debug_evicted": evicted_set,
        "debug_all_blobs": all_blobs,
    });

    let gc_dir = store_root.join("gc");
    std::fs::create_dir_all(&gc_dir)?;

    let data =
        serde_json::to_vec_pretty(&status).map_err(|e| StoreError::Io(std::io::Error::other(e)))?;

    let snapshot_path = gc_dir.join(format!("status-{sweep_id}.json"));
    crate::store::fs::atomic_write(&snapshot_path, &data)?;

    let status_path = gc_dir.join("status.json");
    crate::store::fs::atomic_write(&status_path, &data)?;

    Ok(())
}
