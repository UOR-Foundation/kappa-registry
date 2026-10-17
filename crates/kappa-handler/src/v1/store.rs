use std::sync::Arc;

use topcoat::context::{Cx, app_context, try_app_context, try_request_context};

use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::traits::KappaStore;

use crate::clock::Clock;
use crate::error::HandlerError;
use crate::namespace::ResolvedNamespace;

/// Get a required value from app context by type.
///
/// Panics if not registered. A missing registration is a server
/// bootstrap bug, not a request-time recoverable error.
pub fn service<T: Send + Sync + 'static>(cx: &Cx) -> &T {
    app_context::<T>(cx)
}

/// Try to get a value from app context. Returns None if not registered.
pub fn try_service<T: Send + Sync + 'static>(cx: &Cx) -> Option<&T> {
    try_app_context::<T>(cx)
}

/// Get the store Arc.
pub fn store(cx: &Cx) -> Arc<dyn KappaStore> {
    service::<Arc<dyn KappaStore>>(cx).clone()
}

/// Get the current time from the clock.
pub fn clock_now(cx: &Cx) -> Result<kappa_store::clock::ClockMs, HandlerError> {
    service::<Arc<dyn Clock>>(cx)
        .now()
        .map_err(HandlerError::from)
}

/// Physical acquisition from the same injected authority, separate from
/// causal issuance and its admitted-history/recovery floor.
pub fn physical_now(cx: &Cx) -> Result<kappa_store::clock::UnixTimeMs, HandlerError> {
    service::<Arc<dyn Clock>>(cx)
        .physical_now()
        .map_err(HandlerError::from)
}

/// Resolve namespace for read operations. Returns `NotFound` if absent.
pub fn resolve_ns_read(cx: &Cx) -> Result<NamespaceRef, HandlerError> {
    let resolved: &ResolvedNamespace = topcoat::context::request_context(cx);
    match resolved {
        ResolvedNamespace::Exists(ns) => Ok(ns.clone()),
        ResolvedNamespace::NotFound { name, .. } => Err(HandlerError::NotFound {
            reason: format!("namespace '{name}' not found"),
        }),
        ResolvedNamespace::NoNamespace => Err(HandlerError::BadRequest {
            reason: "no namespace in request path".into(),
        }),
    }
}

/// Resolve the identity namespace for `anchor` by name through the store.
///
/// The node's identity namespace is created by `namespace_ensure` with the
/// anchor's string representation as its name. Every consumer that reads or
/// writes the identity namespace must resolve it through the store, never
/// through `NamespaceRef::for_anchor` which constructs a phantom UUID.
pub fn resolve_anchor_ns(
    store: &dyn KappaStore,
    anchor: &Kappa,
) -> Result<NamespaceRef, kappa_store::StoreError> {
    store.namespace_resolve(&anchor.to_string(), None)
}

/// Async wrapper: ensure `anchor`'s identity namespace exists and return
/// the `WriteTarget` an identity handler publishes into. Creates the
/// namespace on first use (an asserter's first identity operation).
pub async fn anchor_write_target(
    cx: &Cx,
    anchor: &Kappa,
) -> Result<crate::execute::WriteTarget, HandlerError> {
    let s = store(cx);
    let clock = service::<Arc<dyn crate::clock::Clock>>(cx).clone();
    let owner = anchor.clone();
    let ns = crate::blocking::blocking(move || {
        kappa_store::namespace_ensure(&*s, &owner.to_string(), Some(&owner), None, &*clock)
    })
    .await?;
    Ok(crate::execute::WriteTarget::existing(ns))
}

/// Extract the caller's anchor from request context.
///
/// Returns None for anonymous (unauthenticated) callers.
/// Callers that require an anchor for edge/assertion/binding
/// creation must handle None explicitly — anonymous callers
/// cannot create identity-bearing records.
pub fn caller_anchor(cx: &Cx) -> Option<Kappa> {
    try_request_context::<crate::auth::CallerIdentity>(cx).and_then(|caller| caller.anchor.clone())
}

/// Anchor attributing writes made by unauthenticated callers.
///
/// Derived from a domain-separated label, so it never equals an anchor
/// derived from a public key (`Kappa::from_key` frames algorithm and key)
/// and never names the node's own identity. It holds no authority: grants
/// and delegations name key-derived anchors only.
pub fn anonymous_principal() -> Kappa {
    Kappa::sha256(b"kappa-registry\0anonymous-principal\0v1")
}

/// Principal a write is attributed to.
///
/// The authenticated caller, or the anonymous principal when the server
/// admits unauthenticated writes. Whether the write is permitted is the
/// authorization layer's decision.
pub fn principal(cx: &Cx) -> Kappa {
    caller_anchor(cx).unwrap_or_else(anonymous_principal)
}

/// Construct a `PageRequest` from the request's query parameters.
///
/// Reads `limit` and `cursor` from the query string. Clamps
/// limit to `max_limit`. Every handler that calls a list method
/// calls this function — one validation point, one clamp,
/// zero per-handler pagination logic.
///
/// The protocol-specific cursor parameter name (OCI `last`,
/// S3 `continuation-token`, AT Protocol `cursor`) is mapped
/// to the substrate's `cursor` by the route definition or
/// the handler before calling this function.
pub fn page_request_from(
    cx: &Cx,
    max_limit: usize,
) -> Result<kappa_store::PageRequest, HandlerError> {
    let limit: usize = crate::query::query_optional_parsed(cx, "limit")?.unwrap_or(max_limit);
    let limit = limit.min(max_limit);
    let after = crate::query::query_optional(cx, "cursor");
    Ok(kappa_store::PageRequest::new(limit, after))
}
