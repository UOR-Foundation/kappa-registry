use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{HandlerError, blocking, path_param};

use crate::directory::{audit_json, directory, directory_error};

/// Append-only proof of the directory's evolution between two epochs:
/// the earlier log is a prefix of the later, and the transitions appended
/// between them, one page from `offset`.
pub async fn handler(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let start: u64 = path_param(cx, "start")?
        .parse()
        .map_err(|e| HandlerError::bad_request(format!("invalid start epoch: {e}")))?;
    let end: u64 = path_param(cx, "end")?
        .parse()
        .map_err(|e| HandlerError::bad_request(format!("invalid end epoch: {e}")))?;
    let offset: Option<u64> = kappa_handler::query::query_optional_parsed(cx, "offset")?;
    let directory = directory(cx);
    let proof = blocking(move || {
        directory
            .audit(start, Some(end), offset)
            .map_err(directory_error)
    })
    .await?;
    kappa_handler::json_response(StatusCode::OK, &audit_json(cx, &proof)?)
}
