use std::borrow::Cow;
use std::collections::HashMap;

use topcoat::context::{Cx, try_request_context};
use topcoat::router::{Body, Method, Path, RouterBuilder, StatusCode};

use kappa_handler::{HandlerError, Outcome, ResolvedNamespace, WriteTarget};
use kappa_store::namespace::NamespaceRef;

mod bucket;
mod multipart;
mod multipart_list;
mod multipart_xml;
mod object;

// -- S3 spec constants --------------------------------------------------------

pub(crate) const DEFAULT_MAX_KEYS: u32 = 1000;
pub(crate) const MAX_TAGS_PER_OBJECT: usize = 10;
pub(crate) const MAX_CONFIG_BODY: usize = 256 * 1024;
pub(crate) const MAX_TAGGING_BODY: usize = 128 * 1024;
pub(crate) const MAX_BATCH_DELETE_BODY: usize = 10 * 1024 * 1024;
pub(crate) const MAX_VERSIONING_BODY: usize = 64 * 1024;
pub(crate) const OBJ_META_PREFIX: &str = "obj:";

fn p(s: &'static str) -> Cow<'static, Path> {
    Cow::Borrowed(Path::new(s))
}

/// Convert HandlerError to S3 XML error response.
/// Takes &HandlerError for handler_route! macro compatibility.
pub(crate) fn s3_error_response(e: &HandlerError) -> topcoat::router::response::Response {
    match e {
        HandlerError::Protocol {
            status,
            code,
            message,
        } => s3_error(*status, code, message),
        HandlerError::Store(se) => store_err_to_s3(se),
        HandlerError::Timeout { deadline_ms } => s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("operation timed out after {deadline_ms}ms"),
        ),
        HandlerError::NotFound { reason } => s3_error(StatusCode::NOT_FOUND, "NoSuchKey", reason),
        HandlerError::BadRequest { reason } => {
            s3_error(StatusCode::BAD_REQUEST, "InvalidRequest", reason)
        }
        HandlerError::BodyTooLarge { limit } => s3_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "EntityTooLarge",
            &format!("body exceeds {limit} byte limit"),
        ),
        HandlerError::Conflict { reason } => {
            s3_error(StatusCode::CONFLICT, "BucketAlreadyOwnedByYou", reason)
        }
        HandlerError::Unauthorized { reason } => {
            s3_error(StatusCode::FORBIDDEN, "AccessDenied", reason)
        }
        HandlerError::Forbidden { reason } => {
            s3_error(StatusCode::FORBIDDEN, "AccessDenied", reason)
        }
        other => s3_error(other.status(), "InternalError", &other.to_string()),
    }
}

fn store_err_to_s3(e: &kappa_store::StoreError) -> topcoat::router::response::Response {
    use kappa_store::StoreError;
    match e {
        StoreError::NotFound(ctx) if ctx == "NoSuchUpload" => s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "The specified upload does not exist.",
        ),
        StoreError::NotFound(ctx) => s3_error(StatusCode::NOT_FOUND, "NoSuchKey", ctx),
        StoreError::Conflict(msg) => s3_error(StatusCode::CONFLICT, "Conflict", msg),
        StoreError::Rejected(msg) => {
            if let Some((code, message)) = msg.split_once(": ")
                && matches!(
                    code,
                    "InvalidPart" | "InvalidPartOrder" | "EntityTooSmall" | "InvalidArgument"
                )
            {
                return s3_error(StatusCode::BAD_REQUEST, code, message);
            }
            s3_error(StatusCode::BAD_REQUEST, "InvalidRequest", msg)
        }
        StoreError::CapacityExceeded(msg) => {
            s3_error(StatusCode::INSUFFICIENT_STORAGE, "InternalError", msg)
        }
        // Deadline and indeterminate publication keep their retryable
        // status; S3 clients retry 503 ServiceUnavailable.
        _ => {
            let status = kappa_handler::status_for_store_error(e);
            let code = if status == StatusCode::INTERNAL_SERVER_ERROR {
                "InternalError"
            } else {
                "ServiceUnavailable"
            };
            s3_error(status, code, &e.to_string())
        }
    }
}

/// S3 route macro. Wraps async handlers with S3 XML error conversion
/// via the shared handler_route! infrastructure.
macro_rules! s3_route {
    ($method:expr, $path:expr, $handler:path) => {
        kappa_handler::handler_route!($method, p($path), $handler, s3_error_response)
    };
}

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(s3_route!(
            Method::PUT,
            "/{bucket}/{*key}",
            object::put_or_copy_or_part
        ))
        .route(s3_route!(Method::GET, "/{bucket}/{*key}", object::get))
        .route(s3_route!(Method::HEAD, "/{bucket}/{*key}", object::head))
        .route(s3_route!(
            Method::DELETE,
            "/{bucket}/{*key}",
            object::delete_or_abort
        ))
        .route(s3_route!(
            Method::POST,
            "/{bucket}/{*key}",
            object::post_dispatch
        ))
        .route(s3_route!(Method::GET, "/{bucket}", bucket::get_dispatch))
        .route(s3_route!(Method::PUT, "/{bucket}", bucket::put_dispatch))
        .route(s3_route!(Method::HEAD, "/{bucket}", bucket::head))
        .route(s3_route!(
            Method::DELETE,
            "/{bucket}",
            bucket::delete_dispatch
        ))
        .route(s3_route!(Method::POST, "/{bucket}", object::batch_delete))
        .route(s3_route!(Method::GET, "/", bucket::list_buckets))
}

// -- S3-specific helpers ------------------------------------------------------

pub(crate) fn max_object_body(cx: &Cx) -> usize {
    kappa_handler::try_service::<kappa_handler::MaxBlobSize>(cx)
        .map(|m| m.0)
        .unwrap_or(256 * 1024 * 1024)
}

fn no_such_bucket() -> HandlerError {
    HandlerError::protocol(
        StatusCode::NOT_FOUND,
        "NoSuchBucket",
        "The specified bucket does not exist.",
    )
}

/// Resolve an existing bucket. A missing bucket is S3 `NoSuchBucket`.
pub(crate) fn bucket_read(cx: &Cx) -> Result<NamespaceRef, HandlerError> {
    match try_request_context::<ResolvedNamespace>(cx) {
        Some(ResolvedNamespace::Exists(ns)) => Ok(ns.clone()),
        _ => Err(no_such_bucket()),
    }
}

/// Write target for an existing bucket. A missing bucket is S3
/// `NoSuchBucket`; operations that must not create a bucket use this.
pub(crate) fn bucket_existing(cx: &Cx) -> Result<WriteTarget, HandlerError> {
    bucket_read(cx).map(WriteTarget::existing)
}

/// Write target that creates the bucket on first write, owned by the caller.
/// The creation publishes in the same epoch as the write.
pub(crate) fn bucket_write(cx: &Cx) -> Result<WriteTarget, HandlerError> {
    match try_request_context::<ResolvedNamespace>(cx) {
        Some(ResolvedNamespace::Exists(ns)) => Ok(WriteTarget::existing(ns.clone())),
        Some(ResolvedNamespace::NotFound { name, protocol }) => WriteTarget::create(
            name,
            kappa_handler::caller_anchor(cx),
            protocol.clone(),
            kappa_handler::clock_now(cx)?,
        ),
        _ => Err(no_such_bucket()),
    }
}

/// Ensure the bucket exists, creating it in its own execution when the
/// request is its first write. An existing bucket publishes nothing.
pub(crate) async fn ensure_bucket(cx: &Cx) -> Result<kappa_handler::Committed<()>, HandlerError> {
    let target = bucket_write(cx)?;
    let created = target.creates().then(|| *target.namespace().id());
    kappa_handler::execute(cx, target, &[], move |execution| {
        // After a concurrent creation the execution runs against the
        // resolved bucket, whose identity differs from the generated one.
        Ok(if created.as_ref() == Some(execution.namespace().id()) {
            Outcome::Publish(())
        } else {
            Outcome::Discard(())
        })
    })
    .await
}

pub(crate) fn s3_response(
    status: StatusCode,
    xml_body: Vec<u8>,
) -> topcoat::router::response::Response {
    let mut resp = topcoat::router::response::Response::new(Body::from(xml_body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        "content-type",
        http::header::HeaderValue::from_static("application/xml"),
    );
    resp
}

pub(crate) fn s3_error(
    status: StatusCode,
    code: &str,
    message: &str,
) -> topcoat::router::response::Response {
    s3_response(status, crate::xml::encode_s3_error_xml(code, message))
}

/// Object metadata written with the object in the same execution. The
/// object's identity is the key's tag target; its metadata is keyed by the
/// object key, so no field here names the content.
pub(crate) struct NewObjectMeta<'a> {
    pub content_type: Option<&'a str>,
    pub etag: &'a str,
    /// Serialized object tag set; `None` writes an object without tags.
    pub tags: Option<&'a [u8]>,
}

/// Replace an object's metadata. Every field is rewritten, so nothing from
/// a previous object under the same key survives the new write.
pub(crate) fn set_object_meta(
    execution: &mut dyn kappa_store::Execution,
    object_key: &str,
    meta: &NewObjectMeta<'_>,
) -> Result<(), kappa_store::StoreError> {
    execution.namespace_put_meta(&obj_meta_key(object_key, "etag"), meta.etag.as_bytes())?;
    let created_ms = execution.now().physical_ms().to_string();
    execution.namespace_put_meta(
        &obj_meta_key(object_key, "created_ms"),
        created_ms.as_bytes(),
    )?;
    // The content type is the bucket's description of its object, not a
    // property of the shared bytes: namespace metadata only.
    let content_type_key = obj_meta_key(object_key, "content-type");
    match meta.content_type {
        Some(ct) => execution.namespace_put_meta(&content_type_key, ct.as_bytes())?,
        None => execution.namespace_delete_meta(&content_type_key)?,
    }
    let tags_key = obj_meta_key(object_key, "tags");
    match meta.tags {
        Some(tags) => execution.namespace_put_meta(&tags_key, tags),
        None => execution.namespace_delete_meta(&tags_key),
    }
}

/// Remove every metadata field of a deleted object.
pub(crate) fn clear_object_meta(
    execution: &mut dyn kappa_store::Execution,
    object_key: &str,
) -> Result<(), kappa_store::StoreError> {
    for field in OBJECT_META_FIELDS {
        execution.namespace_delete_meta(&obj_meta_key(object_key, field))?;
    }
    Ok(())
}

const OBJECT_META_FIELDS: [&str; 4] = ["etag", "created_ms", "content-type", "tags"];

pub(crate) fn get_object_meta<S: kappa_store::traits::namespace::NamespaceStore + ?Sized>(
    s: &S,
    ns: &NamespaceRef,
    object_key: &str,
) -> Result<ObjectMeta, kappa_store::StoreError> {
    let field = |name: &str| {
        kappa_store::absent(s.namespace_get_meta(ns, &obj_meta_key(object_key, name)))?
            .map(|bytes| {
                String::from_utf8(bytes).map_err(|error| {
                    kappa_store::StoreError::Internal(format!("object {name} metadata: {error}"))
                })
            })
            .transpose()
    };
    Ok(ObjectMeta {
        ct: field("content-type")?,
        etag: field("etag")?,
        created_ms: field("created_ms")?,
    })
}

pub(crate) struct ObjectMeta {
    pub ct: Option<String>,
    pub etag: Option<String>,
    pub created_ms: Option<String>,
}

pub(crate) fn obj_meta_key(object_key: &str, field: &str) -> String {
    format!("{}{}:{}", OBJ_META_PREFIX, object_key, field)
}

pub(crate) fn store(cx: &Cx) -> std::sync::Arc<dyn kappa_store::traits::KappaStore> {
    kappa_handler::store(cx)
}

/// S3-specific query parameter extraction. Returns the full HashMap
/// because S3 dispatch decisions (tagging, versioning, uploadId,
/// partNumber) depend on which query keys are present, not just
/// their values. Protocol-specific — kappa-handler's query_optional
/// extracts single named params, S3 dispatch needs the full set.
pub(crate) fn parse_query(cx: &Cx) -> HashMap<String, String> {
    let parts: &http::request::Parts = topcoat::context::request_context(cx);
    let mut map = HashMap::new();
    if let Some(query) = parts.uri.query() {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                map.insert(
                    kappa_handler::percent_decode(k),
                    kappa_handler::percent_decode(v),
                );
            } else if !pair.is_empty() {
                map.insert(kappa_handler::percent_decode(pair), String::new());
            }
        }
    }
    map
}

pub(crate) fn path_param(cx: &Cx, name: &str) -> Result<String, HandlerError> {
    kappa_handler::path_param(cx, name)
}

/// Set S3-standard response headers on an object response.
pub(crate) fn object_headers(
    resp: &mut topcoat::router::response::Response,
    meta: &ObjectMeta,
    kappa: &kappa_store::kappa::Kappa,
    content_length: u64,
) -> Result<(), HandlerError> {
    let h = resp.headers_mut();
    h.insert(
        "content-type",
        meta.ct
            .as_deref()
            .unwrap_or("application/octet-stream")
            .parse()
            .map_err(|error| {
                HandlerError::internal(format!("invalid stored content type: {error}"))
            })?,
    );
    let etag_val = meta
        .etag
        .clone()
        .unwrap_or_else(|| format!("\"{}\"", kappa));
    h.insert(
        "etag",
        etag_val
            .parse()
            .map_err(|error| HandlerError::internal(format!("invalid stored ETag: {error}")))?,
    );
    h.insert(
        "content-length",
        http::header::HeaderValue::from(content_length),
    );
    if let Some(ref ms_str) = meta.created_ms {
        let ms = ms_str.parse::<u64>().map_err(|error| {
            HandlerError::internal(format!("invalid stored timestamp: {error}"))
        })?;
        let http_date = kappa_handler::epoch_ms_to_http_date(ms)?;
        let value = http_date
            .parse()
            .map_err(|error| HandlerError::internal(format!("invalid HTTP date: {error}")))?;
        h.insert("last-modified", value);
    }
    Ok(())
}
