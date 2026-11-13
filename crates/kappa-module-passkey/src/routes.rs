//! HTTP routes under `/passkey/` and the Prism mailbox under `/prism/topic/`.
//!
//! Thin: decode the body, run the service call off the async executor, and
//! turn a `PasskeyError` into its typed JSON response.

use std::borrow::Cow;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use kappa_core::store::KappaStore;
use topcoat::context::{app_context, Cx};
use topcoat::router::response::{IntoResponse, Response};
use topcoat::router::{
    raw_path_params, to_bytes, Body, Method, Path, RouteFn, RouteFuture, RouterBuilder, StatusCode,
};

use crate::error::PasskeyError;
use crate::mailbox;
use crate::service::{self, Registration, Revocation};
use crate::PasskeyState;

/// Largest request body a passkey route reads. A registration is a few KiB.
const MAX_BODY_BYTES: usize = 64 * 1024;

fn json(cx: &Cx, status: StatusCode, body: String) -> topcoat::Result<Response> {
    (
        status,
        [
            ("content-type", "application/json".to_string()),
            ("cache-control", "no-store".to_string()),
        ],
        body,
    )
        .into_response(cx)
}

fn failure(cx: &Cx, error: &PasskeyError) -> topcoat::Result<Response> {
    if let PasskeyError::Store(detail) = error {
        tracing::error!(error = %detail, "passkey store failure");
    }
    json(cx, error.status(), error.body())
}

fn path_param(cx: &Cx, key: &str) -> String {
    raw_path_params(cx)
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.as_str().to_string())
        .unwrap_or_default()
}

async fn read_json<T: serde::de::DeserializeOwned>(body: Body) -> Result<T, PasskeyError> {
    let bytes = to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| PasskeyError::Request("the request body is too large or unreadable".into()))?;
    serde_json::from_slice(&bytes).map_err(|e| PasskeyError::Request(format!("invalid JSON: {e}")))
}

/// Run `work` with the store and passkey state on a blocking thread.
async fn blocking<T: Send + 'static>(
    cx: &Cx,
    work: impl FnOnce(&dyn KappaStore, &PasskeyState) -> Result<T, PasskeyError> + Send + 'static,
) -> Result<T, PasskeyError> {
    let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
    let state = app_context::<Arc<PasskeyState>>(cx).clone();
    tokio::task::spawn_blocking(move || work(&*store, &state))
        .await
        .map_err(|e| {
            PasskeyError::Store(kappa_core::StoreError::Io(std::io::Error::other(
                e.to_string(),
            )))
        })?
}

fn challenge_handler(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        drop(body);
        let state = app_context::<Arc<PasskeyState>>(cx);
        match state.challenges.issue(service::now_ms()) {
            Ok((challenge, expires)) => json(
                cx,
                StatusCode::OK,
                serde_json::json!({ "challenge": challenge, "expires": expires }).to_string(),
            ),
            Err(e) => failure(cx, &e),
        }
    })
}

fn register_handler(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let request: Registration = match read_json(body).await {
            Ok(r) => r,
            Err(e) => return failure(cx, &e),
        };
        let result = blocking(cx, move |store, state| {
            service::register(
                store,
                &state.namespace,
                &state.config,
                &state.challenges,
                request,
                service::now_ms(),
            )
        })
        .await;
        match result {
            Ok(record) => json(
                cx,
                StatusCode::CREATED,
                serde_json::json!({ "key": record.key, "account": record.account, "record": record })
                    .to_string(),
            ),
            Err(e) => failure(cx, &e),
        }
    })
}

fn credential_handler(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        drop(body);
        let credential = path_param(cx, "credential");
        let result = blocking(cx, move |store, state| {
            service::credential(store, &state.namespace, &credential)
        })
        .await;
        match result {
            Ok(bytes) => json(
                cx,
                StatusCode::OK,
                String::from_utf8_lossy(&bytes).into_owned(),
            ),
            Err(e) => failure(cx, &e),
        }
    })
}

fn account_handler(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        drop(body);
        let account = path_param(cx, "account");
        let result = blocking(cx, move |store, state| {
            service::account(store, &state.namespace, &account)
        })
        .await;
        match result {
            Ok(value) => json(cx, StatusCode::OK, value.to_string()),
            Err(e) => failure(cx, &e),
        }
    })
}

fn revoke_handler(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let request: Revocation = match read_json(body).await {
            Ok(r) => r,
            Err(e) => return failure(cx, &e),
        };
        let account = request.account.clone();
        let key = request.key.clone();
        let result = blocking(cx, move |store, state| {
            service::revoke(store, &state.namespace, &state.config, &request)
        })
        .await;
        match result {
            Ok(newly) => json(
                cx,
                StatusCode::OK,
                serde_json::json!({ "account": account, "key": key, "revoked": true, "newly": newly })
                    .to_string(),
            ),
            Err(e) => failure(cx, &e),
        }
    })
}

fn topic_post_handler(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let topic = path_param(cx, "topic");
        let message = match to_bytes(body, mailbox::MAX_MESSAGE_BYTES).await {
            Ok(bytes) => bytes.to_vec(),
            Err(_) => {
                return failure(
                    cx,
                    &PasskeyError::Request(format!(
                        "a message is at most {} bytes",
                        mailbox::MAX_MESSAGE_BYTES
                    )),
                )
            }
        };
        let name = topic.clone();
        let result = blocking(cx, move |store, state| {
            mailbox::post(store, &state.mailbox, &name, &message)
        })
        .await;
        match result {
            Ok(newly) => json(
                cx,
                if newly {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
                },
                serde_json::json!({ "topic": topic, "newly": newly }).to_string(),
            ),
            Err(e) => failure(cx, &e),
        }
    })
}

fn topic_get_handler(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        drop(body);
        let topic = path_param(cx, "topic");
        let name = topic.clone();
        let result = blocking(cx, move |store, state| {
            mailbox::messages(store, &state.mailbox, &name)
        })
        .await;
        match result {
            Ok(messages) => {
                let encoded: Vec<String> =
                    messages.iter().map(|m| URL_SAFE_NO_PAD.encode(m)).collect();
                json(
                    cx,
                    StatusCode::OK,
                    serde_json::json!({ "topic": topic, "messages": encoded }).to_string(),
                )
            }
            Err(e) => failure(cx, &e),
        }
    })
}

/// CORS preflight target. The server's CORS layer answers preflights for
/// `/passkey/` before this runs; the route exists because the router answers
/// a method no route accepts with 405 before any path layer sees it.
fn preflight_handler(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        drop(body);
        StatusCode::NO_CONTENT.into_response(cx)
    })
}

/// Paths of every `/passkey/` and `/prism/` route, for the server's router policies.
pub const PATHS: [&str; 6] = [
    "/passkey/challenge",
    "/passkey/register",
    "/passkey/credential/{credential}",
    "/passkey/account/{account}",
    "/passkey/revoke",
    "/prism/topic/{topic}",
];

/// Register the `/passkey/` and `/prism/` routes. The server must also put an
/// `Arc<PasskeyState>` in the app context.
pub fn register(builder: RouterBuilder) -> RouterBuilder {
    let builder = PATHS.into_iter().fold(builder, |builder, path| {
        builder.route(RouteFn::new(
            Method::OPTIONS,
            Cow::Borrowed(Path::new(path)),
            preflight_handler,
        ))
    });
    builder
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/passkey/challenge")),
            challenge_handler,
        ))
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/passkey/register")),
            register_handler,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/passkey/credential/{credential}")),
            credential_handler,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/passkey/account/{account}")),
            account_handler,
        ))
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/passkey/revoke")),
            revoke_handler,
        ))
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/prism/topic/{topic}")),
            topic_post_handler,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/prism/topic/{topic}")),
            topic_get_handler,
        ))
}
