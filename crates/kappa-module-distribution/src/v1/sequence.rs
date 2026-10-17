use topcoat::context::Cx;
use topcoat::router::{Body, Method, RouterBuilder, StatusCode};

use kappa_handler::{
    HandlerError, OperationResult, Outcome, blocking, execute, json_response, path_param,
    resolve_ns_read, store, write_target,
};
use kappa_store::Execution;

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(dist_route!(
            Method::POST,
            "/v2/{*ns}/_sequence/{name}/next",
            sequence_next
        ))
        .route(dist_route!(
            Method::GET,
            "/v2/{*ns}/_sequence/{name}",
            sequence_current
        ))
}

/// A reserved sequence value, persisted in an operation receipt as eight
/// big-endian bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequenceValue(pub u64);

impl OperationResult for SequenceValue {
    fn encode(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, HandlerError> {
        let bytes: [u8; 8] = bytes.try_into().map_err(|_| {
            HandlerError::internal("operation receipt carries an invalid sequence value")
        })?;
        Ok(Self(u64::from_be_bytes(bytes)))
    }
}

/// Execution work reserving the next value of sequence `name`. The
/// reservation publishes its `SequenceUpdate` evidence with the epoch.
pub fn reserve_next(
    name: String,
) -> impl FnMut(&mut dyn Execution) -> Result<Outcome<SequenceValue>, HandlerError> + Send + 'static
{
    move |execution| {
        Ok(Outcome::Publish(SequenceValue(
            execution.sequence_next(&name)?,
        )))
    }
}

async fn sequence_next(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let target = write_target(cx)?;
    let name = path_param(cx, "name")?;

    let committed = execute(cx, target, &[], reserve_next(name.clone())).await?;

    let mut response = json_response(
        StatusCode::OK,
        &serde_json::json!({"name": name, "value": committed.value.0}),
    )?;
    committed.annotate(&mut response);
    Ok(response)
}

async fn sequence_current(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let ns = resolve_ns_read(cx)?;
    let name = path_param(cx, "name")?;

    let s = store(cx);
    let val = blocking(move || s.sequence_current(&ns, &name)).await?;

    json_response(
        StatusCode::OK,
        &serde_json::json!({"name": path_param(cx, "name")?, "value": val}),
    )
}
