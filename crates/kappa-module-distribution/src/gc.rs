//! GC (garbage collection) HTTP handlers.
//!
//! POST /v2/{*ns}/gc/pin    -- pin a blob from collection
//! POST /v2/{*ns}/gc/unpin  -- unpin (with finalizer support)
//! POST /v2/{*ns}/gc/sweep  -- trigger synchronous GC sweep
//! GET  /v2/{*ns}/gc/status -- GC status with finalizer listing

use std::borrow::Cow;

use topcoat::context::Cx;
use topcoat::router::error::bad_request;
use topcoat::router::{
    Body, IntoResponse, Method, Path, Response, RouteFn, RouteFuture, RouterBuilder, StatusCode,
};

use kappa_core::store::{blob_put_computed, KappaStore};
use kappa_core::types::{Direction, EdgeQuery};

use crate::{path_param, read_body, store};

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/v2/{*ns}/gc/pin")),
            pin_route,
        ))
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/v2/{*ns}/gc/unpin")),
            unpin_route,
        ))
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/v2/{*ns}/gc/sweep")),
            sweep_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/gc/status")),
            status_route,
        ))
}

fn pin_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let ns = path_param(cx, "ns");
        pin(cx, ns, &bytes).await
    })
}

fn unpin_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let ns = path_param(cx, "ns");
        unpin(cx, ns, &bytes).await
    })
}

fn sweep_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        sweep(cx, ns).await
    })
}

fn status_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
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

    let s = store(cx).clone();
    let n = ns.to_string();
    let k = kappa.to_string();
    let ctrl = controller.to_string();

    let pin_content = serde_json::to_vec(&serde_json::json!({
        "kappa": k,
        "ttl": ttl,
        "controller": ctrl,
    }))
    .unwrap_or_default();

    let pin_kappa = tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        let k = k.clone();
        let pc = pin_content;
        move || {
            let pk = blob_put_computed(&*s, &pc)?;
            s.tag_set(&n, &format!("_pin/{}", k), &pk)?;
            Ok::<String, kappa_core::StoreError>(pk)
        }
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    // Store object-type metadata (global + namespace-indexed)
    let pk = pin_kappa.clone();
    let n = ns.to_string();
    tokio::task::spawn_blocking({
        let s = s.clone();
        move || {
            s.blob_put_meta(&pk, "object-type", b"pin")?;
            s.meta_set(&n, &pk, "object-type", "pin")
        }
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

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

    let s = store(cx).clone();
    let n = ns.to_string();
    let pk = pin_kappa.to_string();

    let result = tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        move || {
            let released_tag = format!("_released/{}", pk);
            let was_released = s.tag_get(&n, &released_tag).is_ok();

            let pins = s.tag_prefix(&n, "_pin/")?;
            for pin_tag in &pins {
                if pin_tag.kappa != pk {
                    continue;
                }

                if let Ok(pin_bytes) = s.blob_get(&pk) {
                    if let Ok(pin_meta) = serde_json::from_slice::<serde_json::Value>(&pin_bytes) {
                        let ctrl = pin_meta["controller"].as_str().unwrap_or("");

                        if !ctrl.is_empty() && !release && !was_released {
                            return Err(kappa_core::StoreError::Conflict(ctrl.to_string()));
                        }

                        if !ctrl.is_empty() && release {
                            let marker = blob_put_computed(&*s, b"released")?;
                            s.tag_set(&n, &released_tag, &marker)?;
                            return Ok(());
                        }
                    }
                }

                s.tag_delete(&n, &pin_tag.name)?;
                let _ = s.tag_delete(&n, &released_tag);
                return Ok(());
            }
            Err(kappa_core::StoreError::NotFound(pk))
        }
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?;

    match result {
        Ok(()) => StatusCode::OK.into_response(cx),
        Err(kappa_core::StoreError::Conflict(msg)) => crate::error_response(
            StatusCode::CONFLICT,
            "FINALIZER_OUTSTANDING",
            &format!("finalizer {msg} blocks unpin"),
        ),
        Err(kappa_core::StoreError::NotFound(_)) => {
            crate::error_response(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", "pin not found")
        }
        Err(e) => Err(bad_request(e.to_string()).into()),
    }
}

async fn sweep(cx: &Cx, ns: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let ns_owned = ns.to_string();

    let sweep_id = uuid::Uuid::new_v4().to_string();
    let sid = sweep_id.clone();

    tracing::info!(ns = ns, sweep_id = %sid, "gc sweep starting");

    let result = tokio::task::spawn_blocking(move || run_sweep(&*s, &ns_owned, &sid))
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;

    tracing::info!(
        sweep_id = %sweep_id,
        objects_scanned = result.objects_scanned,
        objects_reachable = result.objects_reachable,
        objects_evicted = result.objects_evicted,
        "gc sweep complete"
    );

    let body = serde_json::json!({
        "sweep_id": sweep_id,
        "objects_scanned": result.objects_scanned,
        "objects_reachable": result.objects_reachable,
        "objects_evicted": result.objects_evicted,
    });
    (
        StatusCode::ACCEPTED,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn status(cx: &Cx, ns: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let n = ns.to_string();

    let status = tokio::task::spawn_blocking(move || {
        let pins = s.tag_prefix(&n, "_pin/").unwrap_or_default();
        let mut finalizers = Vec::new();
        for pin_tag in &pins {
            if let Ok(pin_bytes) = s.blob_get(&pin_tag.kappa) {
                if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&pin_bytes) {
                    let ctrl = meta["controller"].as_str().unwrap_or("");
                    let kappa = meta["kappa"].as_str().unwrap_or("");
                    if !ctrl.is_empty() {
                        finalizers.push(serde_json::json!({
                            "kappa": kappa,
                            "controller": ctrl,
                        }));
                    }
                }
            }
        }

        let sweep_result = s
            .tag_get(&n, "_gc/last_sweep")
            .ok()
            .and_then(|entry| s.blob_get(&entry.kappa).ok())
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());

        let mut result = sweep_result.unwrap_or_else(|| {
            serde_json::json!({
                "objects_scanned": 0,
                "objects_reachable": 0,
                "objects_evicted": 0,
            })
        });

        result["pin_count"] = serde_json::json!(pins.len());
        result["pending_finalizers"] = serde_json::json!(finalizers);

        result
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?;

    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&status).unwrap_or_default(),
    )
        .into_response(cx)
}

struct SweepResult {
    objects_scanned: usize,
    objects_reachable: usize,
    objects_evicted: usize,
}

fn run_sweep(
    store: &dyn KappaStore,
    ns: &str,
    sweep_id: &str,
) -> Result<SweepResult, kappa_core::StoreError> {
    let _span = tracing::info_span!("store_mutation", op = "gc_sweep", ns = %ns, sweep_id = %sweep_id).entered();
    tracing::debug!("run_sweep: collecting root set");

    let mut roots = std::collections::HashSet::new();

    let tags = store.tag_list(ns)?;
    for tag in &tags {
        roots.insert(tag.kappa.clone());
    }

    let pins = store.tag_prefix(ns, "_pin/")?;
    for pin_tag in &pins {
        if let Ok(pin_bytes) = store.blob_get(&pin_tag.kappa) {
            if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&pin_bytes) {
                if let Some(k) = meta["kappa"].as_str() {
                    roots.insert(k.to_string());
                }
            }
        }
        roots.insert(pin_tag.kappa.clone());
    }

    if let Ok(Some(current)) = store.epoch_current(ns) {
        roots.insert(current);
    }

    let reachable = kappa_core::gc::compute_reachable(
        &roots.iter().cloned().collect::<Vec<_>>(),
        &|kappa: &str| {
            let query = EdgeQuery {
                anchor: kappa.to_string(),
                direction: Direction::Outbound,
                relation: None,
                asserter: None,
            };
            store
                .edge_query(ns, &query)
                .unwrap_or_default()
                .into_iter()
                .filter(|e| e.relation.gc_reachable())
                .map(|e| e.target)
                .collect()
        },
    );

    let all_blobs = store.blob_list()?;

    let mut evicted = 0usize;
    for kappa in &all_blobs {
        if !reachable.contains(kappa) {
            let _ = store.blob_delete(kappa);
            evicted += 1;
        }
    }

    let result = SweepResult {
        objects_scanned: all_blobs.len(),
        objects_reachable: reachable.len(),
        objects_evicted: evicted,
    };

    // Persist sweep results
    let status_json = serde_json::json!({
        "last_sweep": sweep_id,
        "objects_scanned": result.objects_scanned,
        "objects_reachable": result.objects_reachable,
        "objects_evicted": result.objects_evicted,
    });
    if let Ok(status_bytes) = serde_json::to_vec(&status_json) {
        if let Ok(status_kappa) = blob_put_computed(store, &status_bytes) {
            let _ = store.tag_set(ns, "_gc/last_sweep", &status_kappa);
        }
    }

    Ok(result)
}
