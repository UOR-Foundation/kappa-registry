use std::sync::Arc;

use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_handler::resolver::ResolverRegistry;
use kappa_handler::{HandlerError, blocking, query_required, store, try_service};
use kappa_store::{HandleRecord, StoreError};

/// GET /xrpc/com.atproto.identity.resolveHandle
///
/// Two-phase resolution: async resolver registry first (PLC directory,
/// WebFinger, DNS TXT), local _handles namespace second. The resolver
/// registry handles network calls outside spawn_blocking. The local
/// fallback runs inside spawn_blocking for store access.
///
/// The response DID comes from ResolvedIdentity.handle (the DID string
/// from the WebFinger/PLC resolution path) or from the anchor kappa
/// formatted as a DID-like string. The anchor is NOT a DID — it is a
/// content-addressed key hash. The resolver trait should carry the DID
/// as a dedicated field. Until then, the anchor string is the best
/// available identifier.
pub async fn resolve_handle(
    cx: &Cx,
    _body: Body, // GET — body not expected
) -> Result<topcoat::router::response::Response, HandlerError> {
    let handle = query_required(cx, "handle")?;

    // Phase 1: resolver registry (async — PLC, WebFinger, DNS)
    if let Some(registry) = try_service::<Arc<ResolverRegistry>>(cx) {
        match registry.resolve(&handle).await {
            Ok(Some(identity)) => {
                // The DID is the intermediate value from WebFinger/PLC.
                // ResolvedIdentity carries it in the handle field when
                // the resolver found the DID document's alsoKnownAs.
                // Falls back to anchor string when handle is absent.
                let did = identity
                    .handle
                    .unwrap_or_else(|| identity.anchor.to_string());
                return kappa_handler::json_response(
                    StatusCode::OK,
                    &serde_json::json!({ "did": did }),
                );
            }
            Ok(None) => {}
            Err(e) => {
                tracing::debug!(
                    handle = %handle,
                    error = %e,
                    "resolver registry failed, trying local",
                );
            }
        }
    }

    // Phase 2: local _handles namespace
    let s = store(cx);
    let h = handle.clone();
    let protocol_str = crate::protocol_id().as_str().to_string();
    let result = blocking(move || {
        let handles_ns = s.namespace_resolve("_handles", None)?;
        let tag_name = format!("handle:{}:{}", protocol_str, h);
        let entry = s.tag_get(&handles_ns, &tag_name)?;
        let data = s.blob_get_in(&handles_ns, &entry.kappa)?;
        let record: HandleRecord = kappa_store::from_canonical(&data)
            .map_err(|e| StoreError::Internal(format!("handle record decode: {e}")))?;
        Ok::<_, StoreError>(record.anchor.to_string())
    })
    .await;

    match result {
        Ok(did) => kappa_handler::json_response(StatusCode::OK, &serde_json::json!({ "did": did })),
        Err(HandlerError::Store(StoreError::NotFound(_))) => Err(HandlerError::protocol(
            StatusCode::NOT_FOUND,
            "HandleNotFound",
            format!("handle '{}' not found", handle),
        )),
        Err(e) => Err(e),
    }
}
