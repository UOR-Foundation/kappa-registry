use std::sync::Arc;

use topcoat::context::{Cx, try_request_context};
use topcoat::router::response::Response;
use topcoat::router::{Body, Next, StatusCode};

use kappa_handler::detect::DetectedOperation;
use kappa_handler::{ResolvedNamespace, store};

use crate::auth::{AuthDecision, AuthError, BearerAuth, authorize};
use crate::ratelimit::{OpClass, classify_request};

pub fn auth_layer<'a>(cx: &'a Cx, body: Body, next: Next<'a>) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let path = topcoat::router::request::uri(cx).path().to_string();
        let method = topcoat::router::request::method(cx).to_string();

        // Bearer authentication is registered unconditionally at bootstrap;
        // a missing registration must fail loudly, never degrade every
        // caller to anonymous.
        let bearer = kappa_handler::service::<Arc<BearerAuth>>(cx);
        let asserter = match bearer.check(&path, topcoat::router::request::headers(cx)) {
            Ok(identity) => identity.asserter,
            Err(rejection) => return Ok((*rejection).map(Body::from)),
        };

        let auth_method = if asserter.is_some() {
            kappa_handler::auth::AuthMethod::Bearer
        } else {
            kappa_handler::auth::AuthMethod::Anonymous
        };
        let cx = cx.with(kappa_handler::CallerIdentity {
            anchor: asserter.clone(),
            method: auth_method,
        });

        let resolved = try_request_context::<ResolvedNamespace>(&cx)
            .cloned()
            .unwrap_or(ResolvedNamespace::NoNamespace);

        let mut op = classify_request(&method, &path);
        if let Some(detected) = try_request_context::<DetectedOperation>(&cx)
            && detected.is_write()
            && op == OpClass::Read
        {
            op = OpClass::Write;
        }

        if !matches!(op, OpClass::Exempt) {
            let s = store(&cx);
            let r = resolved.clone();
            let a = asserter.clone();
            // Grant validity windows are Unix milliseconds; the physical
            // reading, not the encoded causal timestamp, is compared.
            let now_ms = match kappa_handler::physical_now(&cx) {
                Ok(now) => now.as_millis(),
                Err(error) => {
                    tracing::error!(%error, "authorization time unavailable");
                    let mut response = Response::new(Body::from("time authority unavailable"));
                    *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                    return Ok(response);
                }
            };
            let result =
                tokio::task::spawn_blocking(move || authorize(&*s, &r, op, a.as_ref(), now_ms))
                    .await;

            match result {
                Ok(Ok(AuthDecision::Allowed | AuthDecision::AllowedViaDelegation)) => {}
                Ok(Ok(AuthDecision::AllowCreateNew)) => {}
                Ok(Err(AuthError::NotFound)) => {
                    tracing::info!(%method, %path, ?op, "authorization: namespace not found");
                    let mut resp = Response::new(Body::from("not found"));
                    *resp.status_mut() = StatusCode::NOT_FOUND;
                    return Ok(resp);
                }
                Ok(Err(AuthError::Forbidden(reason))) => {
                    tracing::info!(
                        %method, %path, ?op, caller = ?asserter, %reason,
                        "authorization denied"
                    );
                    let body =
                        format!(r#"{{"errors":[{{"code":"DENIED","message":"{reason}"}}]}}"#);
                    let mut resp = Response::new(Body::from(body));
                    *resp.status_mut() = StatusCode::FORBIDDEN;
                    resp.headers_mut()
                        .insert("content-type", "application/json".parse().unwrap());
                    return Ok(resp);
                }
                Ok(Err(AuthError::Store(e))) => {
                    tracing::error!(error = %e, "store error during authorization");
                    let mut resp = Response::new(Body::from("internal server error"));
                    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    return Ok(resp);
                }
                Err(e) => {
                    tracing::error!(error = %e, "authorization task failed");
                    let mut resp = Response::new(Body::from("internal server error"));
                    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    return Ok(resp);
                }
            }
        }

        next.run(&cx, body).await
    })
}
