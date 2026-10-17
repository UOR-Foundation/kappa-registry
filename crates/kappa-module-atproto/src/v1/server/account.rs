use sha2::Digest;
use std::sync::Arc;

use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{
    HandlerError, Outcome, WriteTarget, blocking, clock_now, execute, read_json_with_bytes, store,
};

use crate::protocol_id;
use crate::repo::mst_ops::{RecordChanges, commit_repo};
use crate::repo::write::resolve_repo;
use crate::session::SessionStore;

fn require_field<'a>(req: &'a serde_json::Value, field: &str) -> Result<&'a str, HandlerError> {
    req.get(field)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| HandlerError::bad_request(format!("missing required field: {field}")))
}

pub async fn create_account(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (serde_json::Value, _) = read_json_with_bytes(body, 64 * 1024).await?;
    let handle = require_field(&req, "handle")?.to_string();
    let password = require_field(&req, "password")?.to_string();

    let account_did = match req.get("did").and_then(|v| v.as_str()) {
        Some(d) => d.to_string(),
        None => {
            let hash = sha2::Sha256::digest(handle.as_bytes());
            format!("did:plc:{}", hex::encode(&hash[..16]))
        }
    };

    let now = clock_now(cx)?;

    let session_store = kappa_handler::try_service::<Arc<SessionStore>>(cx)
        .cloned()
        .ok_or_else(|| HandlerError::internal("session store not configured"))?;

    let anchor = blocking({
        let did = account_did.clone();
        let password = password.clone();
        let session_store = session_store.clone();
        move || -> Result<_, HandlerError> {
            session_store.register_credentials(&did, &password)?;
            Ok(session_store.account_anchor(&did, &password, now)?)
        }
    })
    .await?;

    // The repository namespace and its initial commit publish together; a
    // failed commit leaves no empty repository behind.
    let target = match resolve_repo(cx, &account_did).await? {
        Some(namespace) => WriteTarget::existing(namespace),
        None => WriteTarget::create(
            &account_did,
            Some(anchor.clone()),
            Some(protocol_id().clone()),
            now,
        )?,
    };
    let s = store(cx);
    let repo = account_did.clone();
    let committed = execute(cx, target, &raw, move |execution| {
        commit_repo(&*s, execution, &repo, &RecordChanges::new())?;
        Ok(Outcome::Publish(()))
    })
    .await?;

    // The session publishes after the repository: its epoch follows the
    // account's creation in the same clock domain.
    let session_now = clock_now(cx)?;
    let (did, access_jwt, refresh_jwt) = blocking({
        let handle = handle.clone();
        move || -> Result<_, HandlerError> {
            let session = session_store.create_session(
                &account_did,
                &password,
                &handle,
                &anchor,
                "",
                session_now,
            )?;
            Ok((account_did, session.access_token, session.refresh_token))
        }
    })
    .await?;

    let mut response = kappa_handler::json_response(
        StatusCode::OK,
        &serde_json::json!({
            "handle": handle,
            "did": did,
            "accessJwt": access_jwt,
            "refreshJwt": refresh_jwt,
        }),
    )?;
    committed.annotate(&mut response);
    Ok(response)
}
