/// Namespace resolution interceptor layer.
///
/// Three responsibilities, zero protocol-specific logic:
/// 1. Run the DetectorRegistry against the request
/// 2. Apply URI rewrite if the matched detector requested one
/// 3. Resolve namespace via store and store result in context
///
/// Protocol-specific detection, path parsing, and rewriting live
/// in the protocol module detector implementations, not here.
use std::sync::Arc;

use topcoat::context::Cx;
use topcoat::router::error::rewrite;
use topcoat::router::request::{headers, uri};
use topcoat::router::{Body, Next};

use kappa_handler::detect::{BodyClass, DetectedOperation, DetectorRegistry, ProtocolMatch};
use kappa_handler::{HandlerError, ResolvedNamespace, blocking};
use kappa_store::StoreError;
use kappa_store::namespace::ProtocolId;

pub fn namespace_layer<'a>(
    cx: &'a Cx,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let registry = kappa_handler::service::<Arc<DetectorRegistry>>(cx);
        let request_uri = uri(cx).clone();
        let path = request_uri.path();
        let query = request_uri.query().unwrap_or("");
        let hdrs = headers(cx);
        let host = hdrs.get("host").and_then(|v| v.to_str().ok());

        let matched = registry.detect(path, query, hdrs, host);

        // Apply URI rewrite if the detector requested one
        if let Some(ref m) = matched
            && let Some(ref target) = m.rewrite
        {
            return Err(rewrite(target, body).into());
        }

        // Store detected operation and body class in context. A request no
        // detector claims carries at most a control document.
        let op = matched
            .as_ref()
            .map_or(DetectedOperation::Read, |m| m.operation);
        let body_class = matched.as_ref().map_or(BodyClass::Control, |m| m.body);
        let cx = cx.with(op);
        let cx = cx.with(body_class);

        // Resolve namespace. Only an absent namespace becomes `NotFound`;
        // a store that cannot answer fails the request with its own status.
        let resolved = match &matched {
            Some(m) => match resolve(&cx, m).await {
                Ok(resolved) => resolved,
                Err(error) => {
                    tracing::error!(%error, path, "namespace resolution failed");
                    return Ok(kappa_handler::error_response(&error));
                }
            },
            None => ResolvedNamespace::NoNamespace,
        };
        let cx = cx.with(resolved);

        next.run(&cx, body).await
    })
}

async fn resolve(cx: &Cx, m: &ProtocolMatch) -> Result<ResolvedNamespace, HandlerError> {
    let Some(ref ns_name) = m.namespace else {
        return Ok(ResolvedNamespace::NoNamespace);
    };
    // Detector protocol ids are compile-time constants; an invalid one is
    // a module bug, never a reason to resolve without protocol scoping.
    let protocol = ProtocolId::new(m.protocol).map_err(|error| {
        HandlerError::internal(format!("detector protocol {:?}: {error}", m.protocol))
    })?;

    // A name is visible to a protocol through its protocol-scoped alias or
    // its global alias. Alias admission (`validate_alias_admission`) makes
    // the two mutually exclusive, so at most one lookup succeeds and the
    // resolution is unique; both succeeding is a corrupted alias table.
    let store = kappa_handler::store(cx);
    let name = ns_name.clone();
    let scope = protocol.clone();
    let (scoped, global) = blocking(move || {
        let scoped = kappa_store::absent(store.namespace_resolve(&name, Some(&scope)))?;
        let global = kappa_store::absent(store.namespace_resolve(&name, None))?;
        Ok::<_, StoreError>((scoped, global))
    })
    .await?;
    match (scoped, global) {
        (Some(ns), None) | (None, Some(ns)) => Ok(ResolvedNamespace::Exists(ns)),
        (None, None) => Ok(ResolvedNamespace::NotFound {
            name: ns_name.clone(),
            protocol: Some(protocol),
        }),
        (Some(_), Some(_)) => Err(HandlerError::internal(format!(
            "namespace '{ns_name}' has both a global and a {protocol}-scoped alias"
        ))),
    }
}
