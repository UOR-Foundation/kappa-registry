use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{HandlerError, blocking, path_param};

use crate::directory::{directory, directory_error, history_json, label};

/// Verified history of (subject, facet): never asserted, active, or
/// retracted, bound to the node's signed epoch.
pub async fn handler(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let subject = path_param(cx, "subject")?;
    let facet = path_param(cx, "facet")?;
    let directory = directory(cx);
    let key = label(&subject, &facet);
    let proof = blocking(move || directory.history(&key).map_err(directory_error)).await?;
    let mut body = history_json(cx, &proof)?;
    body["subject"] = subject.into();
    body["facet"] = facet.into();
    kappa_handler::json_response(StatusCode::OK, &body)
}
