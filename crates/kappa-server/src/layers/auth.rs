//! Authentication and authorization layer.
//!
//! Two checks, in order:
//! 1. Bearer token: rejects unauthenticated requests when auth is required.
//!    Resolves the token to an asserter anchor for authorization.
//! 2. Authorization: checks capability edges and delegation chains using
//!    the ResolvedNamespace from the interceptor layer's context.

use std::sync::Arc;

use topcoat::context::{app_context, try_app_context, try_request_context, Cx};
use topcoat::router::response::Response;
use topcoat::router::{Body, Next, StatusCode};

use kappa_core::store::KappaStore;
use kappa_core::types::ResolvedNamespace;

use crate::auth::{authorize, AuthDecision, AuthError, BearerAuth};
use crate::ratelimit::{classify_request, OpClass};


pub fn auth_layer<'a>(
    cx: &'a Cx,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let path = topcoat::router::request::uri(cx).path().to_string();
        let method = topcoat::router::request::method(cx).to_string();

        // 1. Bearer token authentication -> resolved asserter identity
        let asserter = if let Some(bearer) = try_app_context::<Arc<BearerAuth>>(cx) {
            let hdrs = topcoat::router::request::headers(cx);
            match bearer.check(&path, hdrs) {
                Ok(identity) => identity.asserter,
                Err(rejection) => return Ok(rejection),
            }
        } else {
            "anonymous".to_string()
        };

        // Store caller identity in request context for downstream handlers
        let cx = cx.with(kappa_core::types::CallerIdentity(asserter.clone()));

        // 2. Authorization using ResolvedNamespace from interceptor
        let resolved = try_request_context::<ResolvedNamespace>(&cx)
            .cloned()
            .unwrap_or(ResolvedNamespace::NoNamespace);

        let op = classify_request(&method, &path);
        if !matches!(op, OpClass::Exempt) {
            let store = app_context::<Arc<dyn KappaStore>>(&cx);
            let s = store.clone();
            let resolved_owned = resolved.clone();
            let asserter_owned = asserter.clone();
            let result = tokio::task::spawn_blocking(move || {
                authorize(&*s, &resolved_owned, op, &asserter_owned)
            })
            .await;

            match result {
                Ok(Ok(AuthDecision::Allowed | AuthDecision::AllowedViaDelegation)) => {}
                Ok(Ok(AuthDecision::AllowCreateNew)) => {}
                Ok(Err(AuthError::NotFound)) => {
                    return Err(topcoat::router::error::not_found().into());
                }
                Ok(Err(AuthError::Forbidden { reason })) => {
                    let body_str = format!(
                        r#"{{"errors":[{{"code":"DENIED","message":"{reason}"}}]}}"#
                    );
                    let mut response = Response::new(Body::from(body_str));
                    *response.status_mut() = StatusCode::FORBIDDEN;
                    response
                        .headers_mut()
                        .insert("content-type", "application/json".parse().unwrap());
                    return Ok(response);
                }
                Ok(Err(AuthError::Store(_))) | Err(_) => {
                    let mut response = Response::new(Body::from("internal server error"));
                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    return Ok(response);
                }
            }
        }

        next.run(&cx, body).await
    })
}
