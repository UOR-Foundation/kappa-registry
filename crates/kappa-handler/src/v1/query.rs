use crate::error::HandlerError;
use topcoat::context::Cx;
use topcoat::router::request;

/// Extract a required query parameter by name.
pub fn query_required(cx: &Cx, name: &str) -> Result<String, HandlerError> {
    let uri = request::uri(cx);
    let query = uri.query().ok_or_else(|| HandlerError::BadRequest {
        reason: format!("missing required query parameter: {name}"),
    })?;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == name
        {
            return Ok(crate::util::percent_decode(v));
        }
    }
    Err(HandlerError::BadRequest {
        reason: format!("missing required query parameter: {name}"),
    })
}

/// Extract an optional query parameter by name.
pub fn query_optional(cx: &Cx, name: &str) -> Option<String> {
    let uri = request::uri(cx);
    let query = uri.query()?;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == name
        {
            return Some(crate::util::percent_decode(v));
        }
    }
    None
}

/// Extract an optional query parameter and parse it.
pub fn query_optional_parsed<T: std::str::FromStr>(
    cx: &Cx,
    name: &str,
) -> Result<Option<T>, HandlerError>
where
    T::Err: std::fmt::Display,
{
    query_optional(cx, name).map_or_else(
        || Ok(None),
        |s| {
            s.parse::<T>()
                .map(Some)
                .map_err(|e| HandlerError::BadRequest {
                    reason: format!("invalid query parameter '{name}': {e}"),
                })
        },
    )
}
