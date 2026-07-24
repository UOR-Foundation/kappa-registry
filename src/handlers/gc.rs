use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::auth;
use crate::error::AppError;
use crate::store::{KappaStore, StoreError};
use crate::AppState;

pub async fn pin(state: &AppState, ns: &str, body: &[u8]) -> Result<Response, AppError> {
    auth::authorize(ns, "gc.pin")?;

    let v: serde_json::Value = serde_json::from_slice(body)?;
    let kappa = v["kappa"]
        .as_str()
        .ok_or_else(|| AppError::NameInvalid("missing kappa".to_string()))?;
    let ttl = v["ttl"].as_u64().unwrap_or(0);
    let controller = v["controller"].as_str().unwrap_or("");

    let s = state.store.clone();
    let k = kappa.to_string();
    let ctrl = controller.to_string();
    let pin_kappa = tokio::task::spawn_blocking(move || s.pin(&k, ttl, &ctrl)).await??;

    Ok((
        StatusCode::CREATED,
        [
            ("x-kappa-label", pin_kappa),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response())
}

pub async fn unpin(state: &AppState, ns: &str, body: &[u8]) -> Result<Response, AppError> {
    auth::authorize(ns, "gc.unpin")?;

    let v: serde_json::Value = serde_json::from_slice(body)?;
    let pin_kappa = v["pin_kappa"]
        .as_str()
        .ok_or_else(|| AppError::NameInvalid("missing pin_kappa".to_string()))?;
    let release = v["release"].as_str() == Some("true");

    let s = state.store.clone();
    let pk = pin_kappa.to_string();
    let result = tokio::task::spawn_blocking(move || s.unpin(&pk, release)).await?;

    match result {
        Ok(()) => Ok(StatusCode::OK.into_response()),
        Err(StoreError::Conflict(msg)) => Err(AppError::FinalizerOutstanding(msg)),
        Err(StoreError::NotFound) => Err(AppError::BlobUnknown),
        Err(e) => Err(AppError::Store(e)),
    }
}

pub async fn sweep(state: &AppState, ns: &str) -> Result<Response, AppError> {
    auth::authorize(ns, "gc.sweep")?;

    let s = state.store.clone();
    let ns_owned = ns.to_string();
    let store_root = state.store.root().to_path_buf();

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
    Ok((StatusCode::ACCEPTED, Json(body)).into_response())
}

pub async fn status(state: &AppState, ns: &str) -> Result<Response, AppError> {
    auth::authorize(ns, "gc.status")?;

    let s = state.store.clone();
    let store_root = state.store.root().to_path_buf();
    let body = tokio::task::spawn_blocking(move || {
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

        serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string())
    })
    .await?;

    Ok((
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        body,
    )
        .into_response())
}

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

    let reachable = store.edge_walk(ns, &roots, &["owns", "composed-of"])?;

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

    // Build a roaring bitmap of reachable blob positions for O(1) eviction checks.
    // At scale (millions of objects), this replaces O(n) HashSet::contains per blob
    // with a bitmap test that fits in cache.
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

    // Clean up edge index entries referencing evicted blobs
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

    // Write per-sweep snapshot for post-mortem
    let snapshot_path = gc_dir.join(format!("status-{sweep_id}.json"));
    crate::store::fs::atomic_write(&snapshot_path, &data)?;

    // Write current status (latest sweep wins)
    let status_path = gc_dir.join("status.json");
    crate::store::fs::atomic_write(&status_path, &data)?;

    Ok(())
}
