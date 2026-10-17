//! Cascade retirement of content reachable from roots.
//!
//! The namespace scopes the edge walk that finds the content; each
//! identity found is retired through an execution in that namespace, so
//! every retirement is epoch-committed and refused while any committed
//! reference (in this or another namespace) still names it. The backend
//! reclaims physical storage after publication, subject to reader and
//! preparation protection. Nothing here deletes directly.

use topcoat::context::Cx;
use topcoat::router::{Body, Method, RouterBuilder, StatusCode};

use kappa_handler::{
    HandlerError, Outcome, blocking, execute, json_response, principal, read_json, store,
    write_target,
};
use kappa_store::StoreError;
use kappa_store::edge::EdgeRelation;
use kappa_store::execution::Retirement;
use kappa_store::kappa::Kappa;

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder.route(dist_route!(
        Method::POST,
        "/v2/{*ns}/blobs/_cascade",
        cascade_delete
    ))
}

/// Identities retired per publication.
const RETIRE_BATCH: usize = 256;

async fn cascade_delete(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let req: serde_json::Value = read_json(body, 1024 * 1024).await?;
    let target = write_target(cx)?;
    let ns = target.namespace().clone();
    tracing::info!(namespace = %ns, requester = %principal(cx), "cascade retirement requested");

    let roots_arr = req["roots"]
        .as_array()
        .ok_or_else(|| HandlerError::BadRequest {
            reason: "roots must be an array".into(),
        })?;
    let roots: Vec<Kappa> = roots_arr
        .iter()
        .map(|v| {
            let s = v.as_str().ok_or_else(|| HandlerError::BadRequest {
                reason: "each root must be a string".into(),
            })?;
            Kappa::parse(s).map_err(HandlerError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;

    if roots.is_empty() {
        return Err(HandlerError::BadRequest {
            reason: "empty roots list".into(),
        });
    }

    let all_relations: Vec<EdgeRelation> = kappa_store::gc::gc_reachable_relations();

    let s = store(cx);
    // The walk reads committed state; a namespace not yet created holds
    // no edges and the walk reaches only the roots.
    let candidates: Vec<(Kappa, u64)> = blocking({
        let s = s.clone();
        let ns = ns.clone();
        let roots = roots.clone();
        move || -> Result<_, StoreError> {
            let reachable = s.edge_diff(&ns, &[], &roots, &all_relations)?;
            let mut candidates = Vec::with_capacity(reachable.len() + roots.len());
            for kappa in reachable.into_iter().chain(roots) {
                if candidates.iter().any(|(known, _)| known == &kappa) {
                    continue;
                }
                if let Some(size) = kappa_store::absent(s.blob_size_in(&ns, &kappa))? {
                    candidates.push((kappa, size));
                }
            }
            Ok(candidates)
        }
    })
    .await?;
    let reachable = candidates.len();

    let mut retired: u64 = 0;
    let mut retained: u64 = 0;
    let mut bytes_retired: u64 = 0;
    for batch in candidates.chunks(RETIRE_BATCH) {
        let batch = batch.to_vec();
        let committed = execute(cx, target.clone(), &[], move |execution| {
            let mut tally = (0u64, 0u64, 0u64);
            for (kappa, size) in &batch {
                match execution.content_retire(kappa)? {
                    Retirement::Retired => {
                        tally.0 += 1;
                        tally.2 = tally.2.saturating_add(*size);
                    }
                    Retirement::Retained => tally.1 += 1,
                    Retirement::Absent => {}
                }
            }
            let encoded = format!("{} {} {}", tally.0, tally.1, tally.2);
            Ok(if tally.0 == 0 {
                Outcome::Discard(encoded)
            } else {
                Outcome::Publish(encoded)
            })
        })
        .await?;
        let mut parts = committed.value.split(' ').map(|part| part.parse::<u64>());
        let (a, b, c) = (parts.next(), parts.next(), parts.next());
        let (Some(Ok(a)), Some(Ok(b)), Some(Ok(c))) = (a, b, c) else {
            return Err(HandlerError::internal("cascade tally encoding"));
        };
        retired += a;
        retained += b;
        bytes_retired = bytes_retired.saturating_add(c);
    }
    let _ = s;

    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "retired": retired,
            "retained": retained,
            "reachable": reachable,
            "bytes_retired": bytes_retired,
        }),
    )
}
