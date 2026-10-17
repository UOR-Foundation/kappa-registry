use std::sync::Arc;

use topcoat::context::Cx;
use topcoat::router::{Body, Method, RouterBuilder, StatusCode};

use kappa_handler::{
    HandlerError, MaxBlobSize, Outcome, binary_response, blocking, execute, json_response,
    prepare_body, read_body, read_json, service, store, take_prepared, write_target,
};
use kappa_store::bundle::{self, BundleError};
use kappa_store::delta::{DeltaBudget, DeltaError, DeltaReservation};
use kappa_store::kappa::Kappa;
use kappa_store::{ContentIdentity, StoreError, absent};

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(dist_route!(
            Method::POST,
            "/v2/{*ns}/_bundle/create",
            create
        ))
        .route(dist_route!(
            Method::POST,
            "/v2/{*ns}/_bundle/ingest",
            ingest
        ))
}

async fn create(cx: &Cx, body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let req: serde_json::Value = read_json(body, 1024 * 1024).await?;
    // Export reads the namespace's admitted content and writes nothing;
    // the target names the namespace.
    let ns = write_target(cx)?.namespace().clone();

    let kappa_arr = req["kappas"]
        .as_array()
        .ok_or_else(|| HandlerError::BadRequest {
            reason: "kappas must be an array".into(),
        })?;
    let kappas: Vec<Kappa> = kappa_arr
        .iter()
        .map(|v| {
            let s = v.as_str().ok_or_else(|| HandlerError::BadRequest {
                reason: "each kappa must be a string".into(),
            })?;
            Kappa::parse(s).map_err(HandlerError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;

    if kappas.is_empty() {
        return Err(HandlerError::BadRequest {
            reason: "empty kappas list".into(),
        });
    }

    let delta = req["delta"].as_bool().unwrap_or(false);

    let s = store(cx);
    let encoded = blocking(move || -> Result<_, StoreError> {
        let mut objects: Vec<(Kappa, Vec<u8>)> = Vec::with_capacity(kappas.len());
        for k in &kappas {
            let content = s.blob_get_in(&ns, k)?;
            objects.push((k.clone(), content));
        }
        let labeled: Vec<(String, &[u8])> = objects
            .iter()
            .map(|(k, c)| (k.to_string(), c.as_slice()))
            .collect();
        let refs: Vec<(&str, &[u8])> = labeled.iter().map(|(s, c)| (s.as_str(), *c)).collect();
        bundle::encode(&refs, delta).map_err(|error| StoreError::Rejected(error.to_string()))
    })
    .await?;

    binary_response(StatusCode::OK, "application/x-kappa-bundle", encoded)
}

/// A bundle refused for its size is a capacity condition; any other
/// decoding failure is a malformed request.
fn decode_error(error: BundleError) -> StoreError {
    match error {
        BundleError::DecodeLimitExceeded { .. }
        | BundleError::Delta(
            DeltaError::BudgetExhausted { .. } | DeltaError::ResultTooLarge { .. },
        ) => StoreError::CapacityExceeded(error.to_string()),
        other => StoreError::Rejected(other.to_string()),
    }
}

async fn ingest(cx: &Cx, body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let max_bytes = service::<MaxBlobSize>(cx).0;
    let bytes = read_body(body, max_bytes).await?;
    let target = write_target(cx)?;
    let ns = target.namespace().clone();

    let s = store(cx);
    let data = bytes.to_vec();
    // Decoded content is bounded by the blob limit in total and reserved
    // against the node's shared delta budget, held until every entry is
    // prepared outside the writer. Decoding reads delta bases from the
    // namespace's admitted content and writes nothing.
    let budget = service::<Arc<DeltaBudget>>(cx).clone();
    let (entries, reservation): (Vec<(Kappa, Vec<u8>)>, DeltaReservation) =
        blocking(move || -> Result<_, StoreError> {
            let resolve_base = |kappa_str: &str| -> Option<Vec<u8>> {
                let kappa = Kappa::parse(kappa_str).ok()?;
                match absent(s.blob_get_in(&ns, &kappa)) {
                    Ok(content) => content,
                    // The decoder's base resolver reports only presence; a
                    // failed read surfaces as an unresolved base, which
                    // rejects the bundle.
                    Err(error) => {
                        tracing::warn!(%error, base = kappa_str, "bundle delta base unreadable");
                        None
                    }
                }
            };
            let decoded = bundle::decode(&data, Some(&resolve_base), max_bytes, &budget)
                .map_err(decode_error)?;
            let entries = decoded
                .entries
                .into_iter()
                .map(|entry| {
                    let kappa = Kappa::parse(&entry.kappa)
                        .map_err(|e| StoreError::Rejected(e.to_string()))?;
                    Ok((kappa, entry.content))
                })
                .collect::<Result<Vec<_>, StoreError>>()?;
            Ok((entries, decoded.reservation))
        })
        .await?;

    // Every entry is prepared outside the writer, then all publish in one
    // epoch, or none does. The budget is released once every entry is
    // prepared into the store.
    let mut prepared = Vec::with_capacity(entries.len());
    for (kappa, content) in entries {
        prepared.push((
            kappa.to_string(),
            prepare_body(cx, ContentIdentity::Verified(kappa), content).await?,
        ));
    }
    drop(reservation);
    let committed = execute(cx, target, &bytes, move |execution| {
        let mut ingested = Vec::with_capacity(prepared.len());
        for (kappa, prepared) in &prepared {
            execution.content_install(take_prepared(prepared)?)?;
            ingested.push(kappa.clone());
        }
        Ok(if ingested.is_empty() {
            Outcome::Discard(ingested)
        } else {
            Outcome::Publish(ingested)
        })
    })
    .await?;

    let mut response = json_response(
        StatusCode::OK,
        &serde_json::json!({"ingested": committed.value}),
    )?;
    committed.annotate(&mut response);
    Ok(response)
}
