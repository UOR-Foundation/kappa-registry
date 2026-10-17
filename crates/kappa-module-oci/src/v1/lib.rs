use std::borrow::Cow;
use topcoat::context::Cx;
use topcoat::router::{Method, Path, RouterBuilder, StatusCode};

const fn p(s: &'static str) -> Cow<'static, Path> {
    Cow::Borrowed(Path::new(s))
}

/// OCI error envelope response from a `HandlerError`.
pub(crate) fn oci_error_response(
    e: &kappa_handler::HandlerError,
) -> topcoat::router::response::Response {
    let (code, message) = match e {
        kappa_handler::HandlerError::NotFound { reason } => ("BLOB_UNKNOWN", reason.as_str()),
        kappa_handler::HandlerError::BadRequest { reason } => ("DIGEST_INVALID", reason.as_str()),
        kappa_handler::HandlerError::BodyTooLarge { .. } => ("SIZE_EXCEEDED", "body too large"),
        kappa_handler::HandlerError::Unauthorized { reason } => ("UNAUTHORIZED", reason.as_str()),
        kappa_handler::HandlerError::Forbidden { reason } => ("DENIED", reason.as_str()),
        kappa_handler::HandlerError::Conflict { reason } => ("TAG_INVALID", reason.as_str()),
        kappa_handler::HandlerError::Protocol { code, message, .. } => {
            (code.as_str(), message.as_str())
        }
        kappa_handler::HandlerError::Store(se) => match se {
            kappa_store::StoreError::NotFound(ctx) => ("BLOB_UNKNOWN", ctx.as_str()),
            kappa_store::StoreError::Conflict(msg) => ("TAG_INVALID", msg.as_str()),
            kappa_store::StoreError::Rejected(msg) => ("DIGEST_INVALID", msg.as_str()),
            kappa_store::StoreError::CapacityExceeded(msg) => ("SIZE_EXCEEDED", msg.as_str()),
            kappa_store::StoreError::Unavailable(msg) => ("UNAVAILABLE", msg.as_str()),
            _ => ("UNKNOWN", "internal error"),
        },
        _ => ("UNKNOWN", "internal error"),
    };
    let status = e.status();
    let body = serde_json::json!({"errors": [{"code": code, "message": message}]});
    serde_json::to_vec(&body)
        .ok()
        .and_then(|bytes| kappa_handler::binary_response(status, "application/json", bytes).ok())
        .unwrap_or_else(|| kappa_handler::empty_response(StatusCode::INTERNAL_SERVER_ERROR))
}

/// OCI error envelope from code and message.
pub(crate) fn oci_error(
    status: StatusCode,
    code: &str,
    message: &str,
) -> Result<topcoat::router::response::Response, kappa_handler::HandlerError> {
    let body = serde_json::json!({"errors": [{"code": code, "message": message}]});
    kappa_handler::json_response(status, &body)
}

/// Response header value from text the handler built (digests, paths,
/// numbers). Text that is not a valid header value is a server failure.
pub(crate) fn header(value: &str) -> Result<http::HeaderValue, kappa_handler::HandlerError> {
    http::HeaderValue::from_str(value)
        .map_err(|e| kappa_handler::HandlerError::internal(format!("invalid header value: {e}")))
}

/// Repository a blob upload writes into, created on first write.
///
/// A missing repository is created, owned by the caller, in its own
/// execution and epoch; an existing one publishes nothing. Blob content and
/// upload sessions themselves are content-addressed and stay outside
/// executions.
pub(crate) async fn ensure_repository(
    cx: &Cx,
) -> Result<kappa_handler::Committed<()>, kappa_handler::HandlerError> {
    let target = kappa_handler::write_target(cx)?;
    let created = target.creates().then(|| *target.namespace().id());
    kappa_handler::execute(cx, target, &[], move |execution| {
        // After a concurrent creation the execution runs against the
        // resolved repository, whose identity differs from the generated one.
        Ok(if created.as_ref() == Some(execution.namespace().id()) {
            kappa_handler::Outcome::Publish(())
        } else {
            kappa_handler::Outcome::Discard(())
        })
    })
    .await
}

/// Route registration with OCI error envelope wrapping via the shared
/// `handler_route!` infrastructure, which logs every handler failure.
/// Handlers are async fn returning `Result<Response, HandlerError>`.
macro_rules! oci_route {
    ($method:expr, $path:expr, $handler:path) => {
        kappa_handler::handler_route!($method, p($path), $handler, oci_error_response)
    };
}

use kappa_types::ProtocolId;
use std::sync::LazyLock;

static PROTOCOL_ID: LazyLock<ProtocolId> = LazyLock::new(|| {
    ProtocolId::new("oci")
        .unwrap_or_else(|_| unreachable!("\"oci\" is lowercase ASCII alphanumeric"))
});

/// OCI distribution protocol surface identifier.
pub fn protocol_id() -> &'static ProtocolId {
    &PROTOCOL_ID
}

mod admission;
pub mod blob;
pub mod detect;
pub mod manifests;
pub mod referrers;
mod tag_writes;
pub mod tags;
pub mod upload;

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    register_tags(register_manifests(register_blobs(builder)))
}

fn register_blobs(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(oci_route!(
            Method::GET,
            "/v2/{*ns}/blobs/_meta",
            blob::meta_list
        ))
        .route(oci_route!(Method::GET, "/v2/{*ns}/blobs/", blob::list))
        .route(oci_route!(
            Method::PUT,
            "/v2/{*ns}/blobs/{kappa}",
            blob::put
        ))
        .route(oci_route!(
            Method::GET,
            "/v2/{*ns}/blobs/{kappa}",
            blob::get
        ))
        .route(oci_route!(
            Method::HEAD,
            "/v2/{*ns}/blobs/{kappa}",
            blob::head
        ))
        .route(oci_route!(
            Method::DELETE,
            "/v2/{*ns}/blobs/{kappa}",
            blob::delete
        ))
        .route(oci_route!(
            Method::POST,
            "/v2/{*ns}/blobs/uploads/",
            upload::start
        ))
        .route(oci_route!(
            Method::PATCH,
            "/v2/_uploads/{id}",
            upload::chunk
        ))
        .route(oci_route!(
            Method::PUT,
            "/v2/_uploads/{id}",
            upload::complete
        ))
        .route(oci_route!(
            Method::GET,
            "/v2/_uploads/{id}",
            upload::recovery
        ))
        .route(oci_route!(
            Method::DELETE,
            "/v2/_uploads/{id}",
            upload::cancel
        ))
}

fn register_manifests(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(oci_route!(
            Method::PUT,
            "/v2/{*ns}/manifests/{reference}",
            manifests::put
        ))
        .route(oci_route!(
            Method::GET,
            "/v2/{*ns}/manifests/{reference}",
            manifests::get
        ))
        .route(oci_route!(
            Method::HEAD,
            "/v2/{*ns}/manifests/{reference}",
            manifests::head
        ))
        .route(oci_route!(
            Method::DELETE,
            "/v2/{*ns}/manifests/{reference}",
            manifests::delete
        ))
        .route(oci_route!(
            Method::GET,
            "/v2/{*ns}/referrers/{digest}",
            referrers::list
        ))
}

fn register_tags(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(oci_route!(
            Method::GET,
            "/v2/{*ns}/tags/list",
            tags::tag_list
        ))
        .route(oci_route!(
            Method::POST,
            "/v2/{*ns}/tags/_batch",
            tag_writes::batch
        ))
        .route(oci_route!(
            Method::DELETE,
            "/v2/{*ns}/tags/_prefix",
            tag_writes::delete_prefix
        ))
        .route(oci_route!(Method::POST, "/v2/{*ns}/tags/", tags::crud))
        .route(oci_route!(Method::GET, "/v2/{*ns}/tags/", tags::crud))
        .route(oci_route!(Method::DELETE, "/v2/{*ns}/tags/", tags::crud))
        .route(oci_route!(
            Method::GET,
            "/v2/{*ns}/tags/{name}",
            tags::get_by_name
        ))
        .route(oci_route!(
            Method::PUT,
            "/v2/{*ns}/tags/{name}",
            tag_writes::put_by_name
        ))
}
