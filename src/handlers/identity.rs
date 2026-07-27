//! Identity endpoints -- whoami.
//!
//! OpClass::Read, unauthenticated. Someone curling a strange registry
//! should understand what they're talking to in one request.

use std::sync::Arc;

use topcoat::context::{app_context, try_app_context, Cx};
use topcoat::router::{Body, IntoResponse, RouteFuture, StatusCode};

use crate::identity::NodeIdentity;
use crate::store::fs::FsStore;

/// GET /v2/{*ns}/_identity/whoami
///
/// Returns the node's anchor, algorithm, trust position, epoch, and
/// self-assertions as plain JSON. No auth, no client library required.
pub fn whoami_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        match try_app_context::<Arc<NodeIdentity>>(cx) {
            Some(identity) => {
                let s = app_context::<Arc<FsStore>>(cx).clone();
                let id = identity.clone();
                let info = tokio::task::spawn_blocking(move || id.whoami(&*s)).await?;
                (
                    StatusCode::OK,
                    [("content-type", "application/json".to_string())],
                    serde_json::to_string(&info).unwrap_or_else(|_| "{}".to_owned()),
                )
                    .into_response(cx)
            }
            None => {
                let body = serde_json::json!({
                    "error": "node identity not bootstrapped"
                });
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::to_string(&body).unwrap_or_default(),
                )
                    .into_response(cx)
            }
        }
    })
}
