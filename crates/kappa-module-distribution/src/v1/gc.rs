use topcoat::context::Cx;
use topcoat::router::{Body, Method, RouterBuilder, StatusCode};

use std::sync::Arc;

use kappa_handler::{
    Clock, HandlerError, Outcome, blocking, empty_response, execute, json_response, principal,
    read_json_with_bytes, resolve_ns_read, service, store, write_target,
};
use kappa_store::Execution;
use kappa_store::gc::{GcConfig, blob_snapshot, gc_sweep};
use kappa_store::kappa::Kappa;

const PIN_PREFIX: &str = "_pin/";
/// Namespace metadata holding the most recent sweep report.
const LAST_SWEEP_KEY: &str = "_gc/last_sweep";

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(dist_route!(Method::POST, "/v2/{*ns}/gc/pin", pin))
        .route(dist_route!(Method::POST, "/v2/{*ns}/gc/unpin", unpin))
        .route(dist_route!(Method::POST, "/v2/{*ns}/gc/sweep", sweep))
        .route(dist_route!(Method::GET, "/v2/{*ns}/gc/status", gc_status))
}

fn pinned_kappa(req: &serde_json::Value) -> Result<Kappa, HandlerError> {
    let kappa_str = req["kappa"]
        .as_str()
        .ok_or_else(|| HandlerError::BadRequest {
            reason: "missing kappa field".into(),
        })?;
    Ok(Kappa::parse(kappa_str)?)
}

/// Execution work recording a pin of `kappa` held by `controller` (empty for
/// none) for `ttl` seconds, stamped with the execution's time.
pub fn record_pin(
    kappa: &Kappa,
    ttl: u64,
    controller: String,
) -> impl FnMut(&mut dyn Execution) -> Result<Outcome<()>, HandlerError> + Send + 'static {
    let meta_key = format!("{PIN_PREFIX}{kappa}");
    move |execution| {
        let pin_value = serde_json::to_vec(&serde_json::json!({
            "ttl": ttl,
            "controller": controller,
            "created_at_ms": execution.now().as_i64(),
        }))
        .map_err(|e| HandlerError::Internal {
            reason: format!("json: {e}"),
        })?;
        execution.namespace_put_meta(&meta_key, &pin_value)?;
        Ok(Outcome::Publish(()))
    }
}

/// Execution work removing the pin of `kappa`. A missing pin is `NotFound`;
/// a pin held by a controller is removed only when `release` is set.
pub fn release_pin(
    kappa: &Kappa,
    release: bool,
) -> impl FnMut(&mut dyn Execution) -> Result<Outcome<()>, HandlerError> + Send + 'static {
    let meta_key = format!("{PIN_PREFIX}{kappa}");
    let kappa = kappa.clone();
    move |execution| {
        let Some(pin_bytes) = execution.namespace_get_meta(&meta_key)? else {
            return Err(HandlerError::NotFound {
                reason: format!("pin {kappa} not found"),
            });
        };
        let meta: serde_json::Value =
            serde_json::from_slice(&pin_bytes).map_err(|e| HandlerError::Internal {
                reason: format!("pin metadata corrupt: {e}"),
            })?;
        if let Some(ctrl) = meta["controller"].as_str()
            && !ctrl.is_empty()
            && !release
        {
            return Err(HandlerError::Conflict {
                reason: format!("finalizer {ctrl} blocks unpin"),
            });
        }
        execution.namespace_delete_meta(&meta_key)?;
        Ok(Outcome::Publish(()))
    }
}

async fn pin(cx: &Cx, body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (serde_json::Value, _) = read_json_with_bytes(body, 64 * 1024).await?;
    let target = write_target(cx)?;

    let kappa = pinned_kappa(&req)?;
    let ttl: u64 = req["ttl"].as_u64().unwrap_or(0);
    let controller = req["controller"].as_str().unwrap_or("").to_string();

    let committed = execute(cx, target, &raw, record_pin(&kappa, ttl, controller)).await?;

    let mut response = empty_response(StatusCode::CREATED);
    committed.annotate(&mut response);
    Ok(response)
}

async fn unpin(cx: &Cx, body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (serde_json::Value, _) = read_json_with_bytes(body, 64 * 1024).await?;
    let target = write_target(cx)?;

    let kappa = pinned_kappa(&req)?;
    let release = req["release"].as_bool().unwrap_or(false);

    let committed = execute(cx, target, &raw, release_pin(&kappa, release)).await?;

    let mut response = empty_response(StatusCode::OK);
    committed.annotate(&mut response);
    Ok(response)
}

/// Execution work recording the outcome of one sweep in the requesting
/// namespace, where `gc/status` reports it.
fn record_sweep(
    report: Vec<u8>,
) -> impl FnMut(&mut dyn Execution) -> Result<Outcome<()>, HandlerError> + Send + 'static {
    move |execution| {
        execution.namespace_put_meta(LAST_SWEEP_KEY, &report)?;
        Ok(Outcome::Publish(()))
    }
}

/// Identities retired per publication during a sweep.
const RETIRE_BATCH: usize = 256;

/// Run one store-wide sweep and report it.
///
/// Content is shared across namespaces, so reachability is computed from
/// every namespace's epoch-committed roots (tags, epoch chain heads, live
/// pins; staged resources are reached through their heads); a blob
/// reachable from any namespace survives. Unreachable identities are
/// retired through executions in each namespace that admitted them, so
/// every retirement is epoch-committed; the backend reclaims physical
/// storage after the retirements settle, subject to reader and
/// preparation protection.
/// The sweep runs to completion before the response, and its counts are
/// recorded in the requesting namespace for `gc/status`.
async fn sweep(cx: &Cx, _body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let target = write_target(cx)?;
    let sweep_id = uuid::Uuid::new_v4().to_string();
    tracing::info!(sweep_id = %sweep_id, requester = %principal(cx), "gc sweep starting");

    let s = store(cx);
    let clock = service::<Arc<dyn Clock>>(cx).clone();
    let result = blocking(move || -> Result<_, HandlerError> {
        let snapshot = blob_snapshot(&*s)?;
        let config = GcConfig {
            max_blob_count: 0,
            retire_batch: RETIRE_BATCH,
        };
        Ok(gc_sweep(&*s, &snapshot, &config, &*clock, clock.now()?)?)
    })
    .await?;
    tracing::info!(
        sweep_id = %sweep_id,
        objects_scanned = result.objects_scanned,
        objects_reachable = result.objects_reachable,
        objects_retired = result.objects_retired,
        objects_skipped = result.objects_skipped,
        objects_absent = result.objects_absent,
        bytes_retired = result.bytes_retired,
        "gc sweep complete"
    );

    // Logical retirement only: the bytes of a retired representation are
    // reclaimed by the backend after reader and preparation protection
    // drain, so no physical figure is reported here.
    let report = serde_json::json!({
        "sweep_id": sweep_id,
        "objects_scanned": result.objects_scanned,
        "objects_reachable": result.objects_reachable,
        "objects_retired": result.objects_retired,
        "objects_skipped": result.objects_skipped,
        "objects_absent": result.objects_absent,
        "bytes_retired": result.bytes_retired,
    });
    let encoded = serde_json::to_vec(&report).map_err(|e| HandlerError::Internal {
        reason: format!("json: {e}"),
    })?;
    let committed = execute(cx, target, &[], record_sweep(encoded)).await?;

    let mut response = json_response(StatusCode::ACCEPTED, &report)?;
    committed.annotate(&mut response);
    Ok(response)
}

async fn gc_status(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let ns = resolve_ns_read(cx)?;

    let s = store(cx);
    let status = blocking(move || -> Result<_, HandlerError> {
        let mut request = kappa_store::PageRequest::first(1024);
        let mut pin_count = 0;
        let mut finalizers = Vec::new();
        loop {
            let page = s.namespace_list_meta_keys(&ns, PIN_PREFIX, &request)?;
            pin_count += page.items.len();
            for pin_key in &page.items {
                let kappa_str = pin_key.strip_prefix(PIN_PREFIX).unwrap_or(pin_key);
                let pin_bytes = s.namespace_get_meta(&ns, pin_key)?;
                let meta: serde_json::Value =
                    serde_json::from_slice(&pin_bytes).map_err(|e| HandlerError::Internal {
                        reason: format!("pin metadata corrupt: {e}"),
                    })?;
                if let Some(ctrl) = meta["controller"].as_str()
                    && !ctrl.is_empty()
                {
                    finalizers.push(serde_json::json!({
                        "kappa": kappa_str,
                        "controller": ctrl,
                    }));
                }
            }
            let Some(next) = page.next_after else {
                break;
            };
            if request
                .after
                .as_ref()
                .is_some_and(|previous| previous >= &next)
            {
                return Err(HandlerError::internal("pin pagination did not advance"));
            }
            request.after = Some(next);
        }
        let mut status = match kappa_store::absent(s.namespace_get_meta(&ns, LAST_SWEEP_KEY))? {
            Some(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|e| {
                HandlerError::Internal {
                    reason: format!("sweep record corrupt: {e}"),
                }
            })?,
            None => serde_json::json!({
                "objects_scanned": 0,
                "objects_reachable": 0,
                "objects_retired": 0,
                "objects_skipped": 0,
                "objects_absent": 0,
                "bytes_retired": 0,
            }),
        };
        status["pin_count"] = serde_json::json!(pin_count);
        status["pending_finalizers"] = serde_json::json!(finalizers);
        Ok(status)
    })
    .await?;

    json_response(StatusCode::OK, &status)
}
