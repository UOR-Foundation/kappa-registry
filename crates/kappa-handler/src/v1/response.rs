use http::StatusCode;
use http::header::HeaderValue;

use crate::error::HandlerError;

static JSON_CT: HeaderValue = HeaderValue::from_static("application/json");

/// Build a JSON success response.
pub fn json_response<T: serde::Serialize>(
    status: StatusCode,
    body: &T,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let bytes = serde_json::to_vec(body).map_err(|e| HandlerError::Internal {
        reason: format!("response serialize: {e}"),
    })?;
    let mut resp = topcoat::router::response::Response::new(topcoat::router::Body::from(bytes));
    *resp.status_mut() = status;
    resp.headers_mut().insert("content-type", JSON_CT.clone());
    Ok(resp)
}

/// Build a JSON error response from a `HandlerError`.
pub fn error_response(err: &HandlerError) -> topcoat::router::response::Response {
    let status = err.status();
    let body = format!(r#"{{"error":"{err}"}}"#);
    let mut resp =
        topcoat::router::response::Response::new(topcoat::router::Body::from(body.into_bytes()));
    *resp.status_mut() = status;
    resp.headers_mut().insert("content-type", JSON_CT.clone());
    resp
}

/// Build an empty response with just a status code.
pub fn empty_response(status: StatusCode) -> topcoat::router::response::Response {
    let mut resp = topcoat::router::response::Response::new(topcoat::router::Body::default());
    *resp.status_mut() = status;
    resp
}

/// Build a binary response.
pub fn binary_response(
    status: StatusCode,
    content_type: &str,
    data: Vec<u8>,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let ct = HeaderValue::from_str(content_type).map_err(|e| HandlerError::Internal {
        reason: format!("invalid content-type header: {e}"),
    })?;
    let len = HeaderValue::from(data.len() as u64);
    let mut resp = topcoat::router::response::Response::new(topcoat::router::Body::from(data));
    *resp.status_mut() = status;
    resp.headers_mut().insert("content-type", ct);
    resp.headers_mut().insert("content-length", len);
    Ok(resp)
}
