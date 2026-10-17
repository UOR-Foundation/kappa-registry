pub mod auth;
pub mod authority;
pub mod blocking;
pub mod body;
pub mod clock;
pub mod detect;
pub mod error;
pub mod event_feed;
pub mod event_stream;
pub mod events;
pub mod execute;
pub mod namespace;
pub mod prepare;
pub mod query;
pub mod resolver;
pub mod response;
pub mod staging;
pub mod store;
pub mod streaming;
pub mod util;

pub use auth::{AuthError, AuthScope, AuthValidator, CallerIdentity, Operation, require_auth};
pub use blocking::{blocking, with_deadline};
pub use body::{BodyError, read_body, read_json, read_json_with_bytes};
pub use clock::{
    Clock, ClockError, WallClock, epoch_ms_to_datetime, epoch_ms_to_http_date, epoch_ms_to_iso8601,
    epoch_secs_to_datetime, parse_datetime_to_epoch_secs,
};
#[cfg(any(test, feature = "test-util"))]
pub use clock::{ControlledSource, clock_at};
pub use detect::{BodyClass, DetectedOperation, DetectorRegistry, ProtocolDetector, ProtocolMatch};
pub use error::{HandlerError, status_for_store_error};
pub use event_feed::{Notice, NoticeBatch, PublicationFeed};
pub use event_stream::{
    Delivery, EventStream, Gap, Position, READ_BATCH, Read, head_position, read_events,
};
pub use events::{MutationEvent, MutationEventOp, events_from_ledger};
pub use execute::{
    Committed, IDEMPOTENCY_KEY, IDEMPOTENT_REPLAYED, KAPPA_EPOCH, KAPPA_EPOCH_ROOT,
    OperationResult, Outcome, RequestDeadline, WRITE_DEADLINE, WriteTarget, committed_ledger,
    execute, execute_phase, request_deadline, write_target,
};
pub use namespace::ResolvedNamespace;
pub use prepare::{PREPARATION_DEADLINE, Prepared, prepare_body, take_prepared};
pub use query::{query_optional, query_optional_parsed, query_required};
pub use resolver::{ExternalIdentifierResolver, ResolveError, ResolvedIdentity, ResolverRegistry};
pub use response::{binary_response, empty_response, error_response, json_response};
pub use staging::{
    ByteAdmission, OpenAdmission, StagingBudget, scan_namespace_resources, scan_resources,
    staging_budget,
};
pub use store::{
    anchor_write_target, anonymous_principal, caller_anchor, clock_now, page_request_from,
    physical_now, principal, resolve_anchor_ns, resolve_ns_read, service, store, try_service,
};
pub use streaming::{StreamingErrorSlot, StreamingWriter, stream_blob, streaming_response};
pub use util::{
    base64_decode, base64_encode, base64url_decode, base64url_encode, base64url_sha256,
    extract_bearer_token, generate_session_token, is_valid_session_token, parse_query_map,
    path_param, percent_decode,
};

/// Shared route macro for all protocol modules and kappa-server.
///
/// Wraps an `async fn(cx, body) -> Result<Response, HandlerError>` in
/// the `Box::pin` + match pattern that every route registration needs.
/// The error formatter is protocol-specific — OCI produces
/// `{"errors":[...]}`, XRPC produces `{"error":"...","message":"..."}`,
/// Git produces plain text, S3 produces XML. Each module defines a
/// one-line wrapper macro that passes its formatter.
///
/// Usage:
/// ```ignore
/// handler_route!(Method::GET, p("/path"), my_handler, my_error_fn)
/// ```
#[macro_export]
macro_rules! handler_route {
    ($method:expr, $path:expr, $handler:path, $error_fn:expr) => {
        topcoat::router::RouteFn::new($method, $path, |cx, body| {
            Box::pin(async move {
                match $handler(cx, body).await {
                    Ok(resp) => Ok(resp),
                    Err(e) => {
                        $crate::log_handler_error(stringify!($handler), &e);
                        Ok($error_fn(&e))
                    }
                }
            })
        })
    };
}

/// Record why a handler failed. The wire response carries only the
/// protocol's error envelope; the cause belongs in the server log. Server
/// failures log at error, client errors at info.
pub fn log_handler_error(handler: &str, error: &HandlerError) {
    let status = error.status();
    if status.is_server_error() {
        tracing::error!(handler, status = status.as_u16(), %error, "handler failed");
    } else {
        tracing::info!(handler, status = status.as_u16(), %error, "handler rejected request");
    }
}

#[derive(Clone)]
pub struct MaxBlobSize(pub usize);
