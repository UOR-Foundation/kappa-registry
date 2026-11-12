//! Node authority routes: rotation, and the status an operator reads to
//! learn which authority is current and which guarantees hold.
//!
//! Responses speak to the caller (an administrator or automation): a stable
//! code, what state the node is in, and what to do. Causes, which name key
//! records, storage errors and internal steps, go to the server log with
//! the request identifier the response also carries in `x-request-id`.

use std::sync::Arc;

use topcoat::context::Cx;
use topcoat::router::response::Response;
use topcoat::router::{Body, StatusCode};

use kappa_crypto::CryptoError;
use kappa_crypto::node::Availability;
use kappa_handler::{HandlerError, json_response};
use kappa_store::StoreError;

use crate::layers::request_id::RequestId;
use crate::node_authority::NodeAuthority;
use crate::node_completion::{Completion, chain};
use crate::node_outcome::{AuthorityStatus, Precommit, Residual, RotationError};

/// Signing algorithms a rotation may name.
pub const ALGORITHMS: [&str; 3] = ["ed25519", "p256", "k256"];

fn request_id(cx: &Cx) -> String {
    topcoat::context::try_request_context::<RequestId>(cx)
        .map_or_else(|| "none".to_owned(), |id| id.0.clone())
}

fn completion_json(completion: Completion) -> serde_json::Value {
    serde_json::json!({
        "custody": completion.custody,
        "key_removal": completion.key_removal,
        "authorization": completion.authorization,
        "revocation": completion.revocation,
        "activation": completion.activation,
    })
}

/// The availability an operator acts on, and the anchor it concerns.
/// `diverged`: the live authority is not the established one, which only a
/// restart resolves.
fn availability(status: &AuthorityStatus) -> (&'static str, Option<String>) {
    match &status.availability {
        Availability::Active(live) if status.commit_known && live == &status.established => {
            ("active", None)
        }
        Availability::Active(live) if live == &status.established => {
            ("unresolved", Some(live.to_string()))
        }
        Availability::Active(live) | Availability::Diverged { live, .. } => {
            ("diverged", Some(live.to_string()))
        }
        Availability::Unresolved { last } => ("unresolved", Some(last.to_string())),
        Availability::Interrupted => ("interrupted", None),
    }
}

/// Whether the node's authority is fully established: signing under the
/// committed authority and every follow-up guarantee holding for it. While
/// a guarantee is incomplete and the authority is otherwise sound, this
/// runs reconciliation, so each readiness probe retries the failed steps.
/// Both steps run on a blocking worker: they wait for a running rotation.
pub async fn ready(authority: &Arc<NodeAuthority>, cx: &Cx) -> bool {
    let observed = Arc::clone(authority);
    let status = match tokio::task::spawn_blocking(move || observed.status()).await {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => {
            tracing::warn!(request_id = %request_id(cx), error = %chain(&error), "node authority status unavailable");
            return false;
        }
        Err(error) => {
            tracing::error!(request_id = %request_id(cx), %error, "node authority status worker failed");
            return false;
        }
    };
    if availability(&status).0 != "active" {
        return false;
    }
    if status.completion.is_complete() {
        return true;
    }
    let reconciling = Arc::clone(authority);
    match tokio::task::spawn_blocking(move || reconciling.reconcile()).await {
        Ok(Ok(follow_up)) => {
            for (guarantee, error) in follow_up.failures() {
                tracing::warn!(request_id = %request_id(cx), guarantee, %error, "node authority guarantee still incomplete");
            }
            follow_up.completion().is_complete()
        }
        Ok(Err(error)) => {
            tracing::warn!(request_id = %request_id(cx), error = %chain(&error), "node authority reconciliation could not run");
            false
        }
        Err(error) => {
            tracing::error!(request_id = %request_id(cx), %error, "node authority reconciliation worker failed");
            false
        }
    }
}

// GET /_node/authority. Body: not consumed. Read on `_root`. The authority
// the store established and whether its commit is known, whether the node
// signs with it, every retired authority, and which follow-up guarantees
// hold, all observed in one instant of the lifecycle. After an unresolved
// rotation and a restart, this is how an operator learns which authority
// the store committed.
pub async fn authority_status(cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    let authority = Arc::clone(kappa_handler::service::<Arc<NodeAuthority>>(cx));
    let status = tokio::task::spawn_blocking(move || authority.status())
        .await
        .map_err(|error| HandlerError::internal(format!("authority status worker: {error}")))?
        .map_err(|error| {
            tracing::error!(request_id = %request_id(cx), error = %chain(&error), "node authority status unavailable");
            HandlerError::Protocol {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "AUTHORITY_INTERRUPTED".into(),
                message: "An authority change was interrupted, so the node's authority cannot be observed. Restart the node, then read GET /_node/authority.".into(),
            }
        })?;
    let (availability, live) = availability(&status);
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "current": status.established.to_string(),
            "commit": if status.commit_known { "known" } else { "unknown" },
            "availability": availability,
            "live": live,
            "retired": status.retired.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "completion": completion_json(status.completion),
        }),
    )
}

const NEW_ROTATION: &str = "Another rotation request performs a new rotation.";

/// What became of key material a rotation that did not commit generated or
/// found.
fn residual_sentence(residual: &Residual) -> &'static str {
    match (residual.custody.is_ok(), residual.key_removal.is_ok()) {
        (true, true) => "No generated key remains.",
        (true, false) => {
            "A generated key could not be removed yet; reconciliation removes it, and GET /_node/authority reports key_removal false until it has."
        }
        (false, _) => {
            "The key store could not be settled to the current authority; reconciliation retries it, and GET /_node/authority reports custody false until it has."
        }
    }
}

fn not_committed(reason: &str, residual: &Residual) -> String {
    format!(
        "No authority rotation committed; the current authority remains active. {reason} {} {NEW_ROTATION}",
        residual_sentence(residual)
    )
}

const UNAVAILABLE: &str = "Restart the node, then read GET /_node/authority to learn which authority the store committed.";

/// A rotation failure as the caller sees it, logged with its cause chain.
fn failure(cx: &Cx, error: &RotationError) -> HandlerError {
    let (status, code, message) = match error {
        RotationError::Staging {
            cause: CryptoError::UnsupportedAlgorithm { algorithm },
            residual,
        } => (
            StatusCode::BAD_REQUEST,
            "UNSUPPORTED_ALGORITHM",
            not_committed(
                &format!(
                    "Unsupported signing algorithm {algorithm}; supported: {}.",
                    ALGORITHMS.join(", ")
                ),
                residual,
            ),
        ),
        RotationError::KeyStore(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "ROTATION_FAILED",
            format!(
                "The key store's lifecycle is unavailable, so nothing was attempted; the current authority remains active. {UNAVAILABLE}"
            ),
        ),
        RotationError::Custody(residual) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "ROTATION_FAILED",
            not_committed(
                "The key store could not first be brought into agreement with the current authority, so no successor key was generated.",
                residual,
            ),
        ),
        RotationError::Staging { residual, .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "ROTATION_FAILED",
            not_committed("Generating the successor key failed.", residual),
        ),
        RotationError::NotCommitted {
            cause: Precommit::Witness(cause),
            residual,
        } => (
            StatusCode::CONFLICT,
            "ROTATION_UNWITNESSED",
            not_committed(
                &format!("No qualifying rotation witness countersigned it: {cause}. Configure KAPPA_ROTATION_WITNESS_KEY_FILE with a key other than the node's."),
                residual,
            ),
        ),
        RotationError::NotCommitted {
            cause: Precommit::Store(StoreError::Rejected(reason) | StoreError::Conflict(reason)),
            residual,
        } => (
            StatusCode::CONFLICT,
            "ROTATION_REJECTED",
            not_committed(&format!("The store refused it: {reason}."), residual),
        ),
        RotationError::NotCommitted {
            cause: Precommit::Store(StoreError::AuthorityUnresolved { .. }),
            ..
        }
        | RotationError::Unavailable(CryptoError::AuthorityUnresolved { .. }) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTHORITY_UNRESOLVED",
            format!(
                "An earlier rotation's outcome is unknown, so the node signs nothing; no rotation was committed. {UNAVAILABLE}"
            ),
        ),
        RotationError::Unavailable(CryptoError::AuthorityDiverged { .. }) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTHORITY_DIVERGED",
            format!(
                "The node's live signing authority differs from the store's committed authority, so the node signs nothing; nothing was attempted. {UNAVAILABLE}"
            ),
        ),
        RotationError::Unavailable(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTHORITY_INTERRUPTED",
            format!(
                "An earlier authority change was interrupted, so the node signs nothing; nothing was attempted. {UNAVAILABLE}"
            ),
        ),
        RotationError::NotCommitted { residual, .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "ROTATION_FAILED",
            not_committed("Preparing the rotation failed.", residual),
        ),
        RotationError::Indeterminate(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "ROTATION_UNRESOLVED",
            "Whether the rotation committed is unknown. The node signs nothing until it restarts; on restart it selects whichever authority the store committed and keeps both keys until then. Do not request another rotation: restart the node, then read GET /_node/authority to learn which authority is current.".to_owned(),
        ),
        RotationError::Retained(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "ROTATION_RETAINED",
            "The rotation's governing epoch is retained unpublished: its signing coordinate is consumed, and resolving it either publishes it and installs the incoming authority or finds it terminal. The node signs nothing until then and keeps both keys. Do not request another rotation: read GET /_node/authority to learn which authority is current.".to_owned(),
        ),
        RotationError::Diverged { .. } => (
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTHORITY_DIVERGED",
            format!(
                "The node's live signing authority differs from the store's committed authority; nothing was attempted and the node now signs nothing. {UNAVAILABLE}"
            ),
        ),
    };
    let id = request_id(cx);
    if status.is_server_error() {
        tracing::error!(request_id = %id, code, error = %chain(error), "node rotation failed");
    } else {
        tracing::warn!(request_id = %id, code, error = %chain(error), "node rotation refused");
    }
    HandlerError::Protocol {
        status,
        code: code.into(),
        message,
    }
}

/// The algorithm a rotation request names: `None` for an empty body or an
/// object without `algorithm`. Anything but a JSON object whose only member
/// is an `algorithm` string from [`ALGORITHMS`] is refused before any
/// lifecycle effect.
///
/// # Errors
///
/// `BadRequest` describing what the body must be.
pub fn rotation_request(bytes: &[u8]) -> Result<Option<String>, HandlerError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let request: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| HandlerError::bad_request(format!("invalid JSON: {error}")))?;
    let serde_json::Value::Object(members) = request else {
        return Err(HandlerError::bad_request(
            "the body must be a JSON object, optionally with an \"algorithm\" member",
        ));
    };
    if let Some(unknown) = members.keys().find(|key| key.as_str() != "algorithm") {
        return Err(HandlerError::bad_request(format!(
            "unknown member \"{unknown}\"; the only member is \"algorithm\""
        )));
    }
    match members.get("algorithm") {
        None => Ok(None),
        Some(serde_json::Value::String(algorithm)) if ALGORITHMS.contains(&algorithm.as_str()) => {
            Ok(Some(algorithm.clone()))
        }
        Some(serde_json::Value::String(algorithm)) => Err(HandlerError::bad_request(format!(
            "unsupported signing algorithm: {algorithm}; supported: {}",
            ALGORITHMS.join(", ")
        ))),
        Some(_) => Err(HandlerError::bad_request("algorithm must be a string")),
    }
}

// POST /_node/authority/rotate. Body: optional {"algorithm": "ed25519" |
// "p256" | "k256"}; absent, the configured algorithm. Admin on `_root`.
// Not idempotent: every accepted request is a new rotation. After a lost
// response, read GET /_node/authority before submitting another.
pub async fn rotate_authority(cx: &Cx, body: Body) -> Result<Response, HandlerError> {
    match topcoat::context::try_request_context::<kappa_handler::ResolvedNamespace>(cx) {
        Some(kappa_handler::ResolvedNamespace::Exists(ns))
            if ns.display_name() == kappa_handler::authority::ROOT_NAMESPACE => {}
        _ => {
            return Err(HandlerError::internal(
                "node rotation did not resolve to the root namespace",
            ));
        }
    }
    let bytes = kappa_handler::read_body(body, 4 * 1024).await?;
    let algorithm = rotation_request(&bytes)?;
    let authority = Arc::clone(kappa_handler::service::<Arc<NodeAuthority>>(cx));
    // No deadline: an abandoned rotation could commit after its request
    // reported failure. The outcome is known only when it returns.
    let outcome = tokio::task::spawn_blocking(move || authority.rotate(algorithm.as_deref()))
        .await
        .map_err(|error| HandlerError::internal(format!("rotation worker: {error}")))?;
    let rotation = outcome.map_err(|error| failure(cx, &error))?;
    for (guarantee, error) in rotation.follow_up.failures() {
        tracing::warn!(
            request_id = %request_id(cx),
            guarantee,
            %error,
            retired = %rotation.retired,
            current = %rotation.current,
            "node rotation committed; follow-up guarantee incomplete"
        );
    }
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "retired": rotation.retired.to_string(),
            "current": rotation.current.to_string(),
            "completion": completion_json(rotation.follow_up.completion()),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::rotation_request;

    #[test]
    fn rotation_requests_admit_only_an_object_naming_a_supported_algorithm()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(rotation_request(b"")?, None);
        assert_eq!(rotation_request(b"{}")?, None);
        assert_eq!(
            rotation_request(br#"{"algorithm":"p256"}"#)?,
            Some("p256".to_owned())
        );
        for refused in [
            &b"[]"[..],
            b"null",
            b"7",
            b"\"ed25519\"",
            br#"{"algorithm":1}"#,
            br#"{"algorithm":null}"#,
            br#"{"algorithm":"rsa"}"#,
            br#"{"algorithm":"ed25519","extra":true}"#,
            b"{",
        ] {
            assert!(
                rotation_request(refused).is_err(),
                "{} admitted",
                String::from_utf8_lossy(refused)
            );
        }
        Ok(())
    }
}
