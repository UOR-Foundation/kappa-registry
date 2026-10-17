use std::borrow::Cow;

use topcoat::router::{Method, Path, RouterBuilder, StatusCode};

use kappa_handler::{HandlerError, WriteTarget, blocking, resolve_ns_read};
use kappa_store::StoreError;
use kappa_store::namespace::NamespaceRef;

pub mod cache_info;
pub mod nar;
pub mod narinfo;

fn p(s: &'static str) -> Cow<'static, Path> {
    Cow::Borrowed(Path::new(s))
}

/// Convert HandlerError to a plain-text Nix error response.
/// Nix clients expect plain text, not JSON or XML.
/// Returns a minimal 500 if response construction fails.
pub(crate) fn nix_error(e: &HandlerError) -> topcoat::router::response::Response {
    let status = e.status();
    let body = e.to_string();
    kappa_handler::binary_response(status, "text/plain", body.into_bytes())
        .unwrap_or_else(|_| kappa_handler::empty_response(StatusCode::INTERNAL_SERVER_ERROR))
}

/// Nix route macro. Wraps async handlers with plain-text error conversion
/// via the shared handler_route! infrastructure.
macro_rules! nix_route {
    ($method:expr, $path:expr, $handler:path) => {
        kappa_handler::handler_route!($method, p($path), $handler, $crate::handlers::nix_error)
    };
}

/// Extract the resolved _nix namespace from request context.
pub(crate) fn nix_ns(cx: &topcoat::context::Cx) -> Result<NamespaceRef, HandlerError> {
    resolve_ns_read(cx).map_err(|e| match e {
        HandlerError::NotFound { .. } => HandlerError::internal(
            "_nix namespace not resolved by interceptor; system bootstrap may have failed",
        ),
        other => other,
    })
}

/// System namespace holding the binary cache, created by server bootstrap.
pub(crate) const NIX_NAMESPACE: &str = "_nix";

/// Write target for the `_nix` namespace. Bootstrap creates it under the
/// nix protocol scope, so writes resolve it and never create it.
pub(crate) async fn nix_target(cx: &topcoat::context::Cx) -> Result<WriteTarget, HandlerError> {
    let store = kappa_handler::store(cx);
    let resolved =
        blocking(move || store.namespace_resolve(NIX_NAMESPACE, Some(crate::protocol_id()))).await;
    match resolved {
        Ok(namespace) => Ok(WriteTarget::existing(namespace)),
        Err(HandlerError::Store(StoreError::NotFound(_))) => Err(HandlerError::internal(
            "_nix namespace does not exist; system bootstrap may have failed",
        )),
        Err(error) => Err(error),
    }
}

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(nix_route!(
            Method::GET,
            "/_nix/nix-cache-info",
            cache_info::handler
        ))
        .route(nix_route!(
            Method::GET,
            "/_nix/narinfo/{hash}",
            narinfo::get
        ))
        .route(nix_route!(
            Method::HEAD,
            "/_nix/narinfo/{hash}",
            narinfo::head
        ))
        .route(nix_route!(
            Method::PUT,
            "/_nix/narinfo/{hash}",
            narinfo::put
        ))
        .route(nix_route!(Method::GET, "/_nix/nar/{*path}", nar::get))
        .route(nix_route!(Method::PUT, "/_nix/nar/{*path}", nar::put))
}
