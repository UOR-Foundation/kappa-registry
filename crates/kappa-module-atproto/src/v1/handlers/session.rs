use std::sync::Arc;

use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{HandlerError, clock_now, read_json};

use crate::session::SessionStore;
use crate::session::dpop;

fn session_store(cx: &Cx) -> Result<Arc<SessionStore>, HandlerError> {
    kappa_handler::try_service::<Arc<SessionStore>>(cx)
        .cloned()
        .ok_or_else(|| HandlerError::internal("session store not configured"))
}

fn extract_bearer(cx: &Cx) -> Result<String, HandlerError> {
    let parts: &http::request::Parts = topcoat::context::request_context(cx);
    parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("DPoP "))
        })
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| HandlerError::unauthorized("missing access token"))
}

fn require_field<'a>(req: &'a serde_json::Value, field: &str) -> Result<&'a str, HandlerError> {
    req.get(field)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| HandlerError::bad_request(format!("missing required field: {field}")))
}

pub async fn create_session(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let req: serde_json::Value = read_json(body, 64 * 1024).await?;
    let identifier = require_field(&req, "identifier")?;
    let password = require_field(&req, "password")?;
    let dpop_jkt = req.get("dpopJkt").and_then(|v| v.as_str()).unwrap_or("");
    let handle = req
        .get("handle")
        .and_then(|v| v.as_str())
        .unwrap_or(identifier);

    let store = session_store(cx)?;
    let now = clock_now(cx)?;

    let identifier = identifier.to_string();
    let password = password.to_string();
    let handle = handle.to_string();
    let dpop_jkt = dpop_jkt.to_string();
    let session = kappa_handler::blocking(move || {
        let anchor = store.account_anchor(&identifier, &password, now)?;
        store.create_session(&identifier, &password, &handle, &anchor, &dpop_jkt, now)
    })
    .await?;
    kappa_handler::json_response(
        StatusCode::OK,
        &serde_json::json!({
            "accessJwt": session.access_token,
            "refreshJwt": session.refresh_token,
            "handle": session.handle,
            "did": session.did,
            "dpopJkt": session.dpop_jkt,
        }),
    )
}

pub async fn refresh_session(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let refresh_token = extract_bearer(cx)?;
    let store = session_store(cx)?;
    let now = clock_now(cx)?;

    let session =
        kappa_handler::blocking(move || store.refresh_session(&refresh_token, now)).await?;
    kappa_handler::json_response(
        StatusCode::OK,
        &serde_json::json!({
            "accessJwt": session.access_token,
            "refreshJwt": session.refresh_token,
            "handle": session.handle,
            "did": session.did,
        }),
    )
}

pub async fn delete_session(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let token = extract_bearer(cx)?;
    let store = session_store(cx)?;

    kappa_handler::blocking(move || store.delete_session(&token)).await?;
    Ok(kappa_handler::empty_response(StatusCode::OK))
}

pub async fn get_session(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let token = extract_bearer(cx)?;
    let store = session_store(cx)?;
    let now = clock_now(cx)?;

    let session = kappa_handler::blocking(move || store.get_session(&token, now)).await?;
    kappa_handler::json_response(
        StatusCode::OK,
        &serde_json::json!({
            "handle": session.handle,
            "did": session.did,
            "active": true,
        }),
    )
}

/// The caller's proof of authority over `repo`, as the request carries it:
/// the bearer token, or the DPoP-bound token with its verified proof
/// claims.
pub enum RepoAuth {
    Bearer(String),
    Dpop {
        access_token: String,
        claims: dpop::DpopClaims,
        method: String,
        uri: String,
    },
}

/// Verify repo auth for write endpoints.
///
/// Returns Ok(did) if auth passes. Dispatches DPoP vs Bearer based on the
/// Authorization header prefix. The session read runs on a blocking
/// worker: it reaches the store.
pub async fn verify_repo_auth(cx: &Cx, repo: &str) -> Result<String, HandlerError> {
    let parts: &http::request::Parts = topcoat::context::request_context(cx);
    let store = session_store(cx)?;

    let auth_header = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .filter(|h| !h.is_empty())
        .ok_or_else(|| HandlerError::unauthorized("missing access token"))?;

    let now = clock_now(cx)?;
    let auth = if let Some(access_token) = auth_header.strip_prefix("DPoP ") {
        let dpop_proof = parts
            .headers
            .get("dpop")
            .and_then(|v| v.to_str().ok())
            .filter(|p| !p.is_empty())
            .ok_or_else(|| HandlerError::unauthorized("DPoP proof header missing"))?;
        let claims = dpop::parse_and_verify_dpop_proof(dpop_proof)?;
        RepoAuth::Dpop {
            access_token: access_token.to_string(),
            claims,
            method: parts.method.as_str().to_string(),
            uri: parts.uri.to_string(),
        }
    } else if let Some(access_token) = auth_header.strip_prefix("Bearer ") {
        RepoAuth::Bearer(access_token.to_string())
    } else {
        return Err(HandlerError::unauthorized(
            "unsupported authorization scheme",
        ));
    };

    let repo = repo.to_string();
    kappa_handler::blocking(move || -> Result<String, HandlerError> {
        let did = match auth {
            RepoAuth::Dpop {
                access_token,
                claims,
                method,
                uri,
            } => store.verify_dpop_request(&access_token, &claims, &method, &uri, now)?,
            RepoAuth::Bearer(access_token) => {
                store
                    .validate_token(&access_token, now)?
                    .ok_or_else(|| HandlerError::unauthorized("invalid or expired token"))?
                    .0
            }
        };
        if did != repo {
            return Err(HandlerError::forbidden("session DID does not match repo"));
        }
        Ok(did)
    })
    .await
}
