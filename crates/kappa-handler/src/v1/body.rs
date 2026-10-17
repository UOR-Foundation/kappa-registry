use crate::error::HandlerError;
use bytes::Bytes;
use topcoat::router::{Body, to_bytes};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BodyError {
    #[error("body exceeds {limit} byte limit")]
    TooLarge { limit: usize },
    #[error("failed to read body: {0}")]
    ReadFailed(String),
}

/// Read the full request body, enforcing a byte limit.
pub async fn read_body(body: Body, max_bytes: usize) -> Result<Bytes, BodyError> {
    to_bytes(body, max_bytes).await.map_err(|e| {
        let msg = e.to_string();
        if msg.contains("limit") || msg.contains("too large") {
            BodyError::TooLarge { limit: max_bytes }
        } else {
            BodyError::ReadFailed(msg)
        }
    })
}

/// Read body and deserialize as JSON.
pub async fn read_json<T: serde::de::DeserializeOwned>(
    body: Body,
    max_bytes: usize,
) -> Result<T, HandlerError> {
    read_json_with_bytes(body, max_bytes)
        .await
        .map(|(value, _)| value)
}

/// Read body, deserialize as JSON, and keep the exact bytes received.
///
/// A write binds its operation identity to these bytes, so a retried request
/// is recognised even when the server fills omitted fields differently.
pub async fn read_json_with_bytes<T: serde::de::DeserializeOwned>(
    body: Body,
    max_bytes: usize,
) -> Result<(T, Bytes), HandlerError> {
    let bytes = read_body(body, max_bytes).await?;
    let value = serde_json::from_slice(&bytes).map_err(|e| HandlerError::BadRequest {
        reason: format!("invalid JSON: {e}"),
    })?;
    Ok((value, bytes))
}
