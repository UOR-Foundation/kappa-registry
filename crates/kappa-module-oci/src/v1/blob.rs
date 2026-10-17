//! Blob endpoints over repository-scoped references.
//!
//! Content is global and content-addressed; a repository's claim on it is
//! namespace state. A push prepares the body outside the writer, then one
//! execution installs the content and publishes the repository's reference
//! to it (the tag `_blob/{kappa}`) with its content type as namespace
//! metadata. Reads resolve that reference first, so a repository serves
//! only content it published. Delete retires the reference; the content
//! stays until nothing in any namespace names it and the collector retires
//! it. Nothing here writes or deletes global state directly.

use topcoat::context::Cx;
use topcoat::router::response::Response;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{
    HandlerError, Outcome, WriteTarget, binary_response, blocking, empty_response, execute,
    json_response, path_param, prepare_body, query_optional, read_body, resolve_ns_read, store,
    take_prepared,
};
use kappa_store::kappa::Kappa;
use kappa_store::tag::TagUpdate;
use kappa_store::traits::KappaStore;
use kappa_store::verified::VerifiedContent;
use kappa_store::{ContentIdentity, NamespaceRef, StoreError};

use crate::header;

pub(crate) const STREAM_CHUNK_SIZE: usize = 65536;

/// Tag naming a blob the repository published.
pub(crate) fn reference_tag(kappa: &Kappa) -> String {
    format!("_blob/{kappa}")
}

/// Namespace metadata key of a blob's content type in the repository.
pub(crate) fn content_type_key(kappa: &Kappa) -> String {
    format!("_blob/{kappa}/content-type")
}

/// Whether `ns` publishes a reference to `kappa`.
pub(crate) fn referenced(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    kappa: &Kappa,
) -> Result<bool, StoreError> {
    Ok(kappa_store::absent(store.tag_get_raw(ns, &reference_tag(kappa)))?.is_some())
}

/// Content type the repository recorded for a blob;
/// `application/octet-stream` when unset or not UTF-8.
pub(crate) fn content_type(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    kappa: &Kappa,
) -> Result<String, HandlerError> {
    Ok(
        kappa_store::absent(store.namespace_get_meta(ns, &content_type_key(kappa)))?
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap_or_else(|| "application/octet-stream".into()),
    )
}

/// Digest, label, and axis headers every blob response carries.
fn identity_headers(resp: &mut Response, kappa: &Kappa) -> Result<(), HandlerError> {
    let label = header(&kappa.to_string())?;
    let h = resp.headers_mut();
    h.insert("docker-content-digest", label.clone());
    h.insert("x-kappa-label", label);
    h.insert("x-kappa-axis", header(&kappa.axis().to_string())?);
    Ok(())
}

fn blob_unknown() -> Result<Response, HandlerError> {
    crate::oci_error(
        StatusCode::NOT_FOUND,
        "BLOB_UNKNOWN",
        "blob unknown to repository",
    )
}

/// Execution work publishing the repository's reference to `kappa` with
/// its content type. Returns whether the reference was new.
pub(crate) fn publish_reference(
    execution: &mut dyn kappa_store::Execution,
    kappa: &Kappa,
    content_type: Option<&[u8]>,
) -> Result<bool, StoreError> {
    let name = reference_tag(kappa);
    let new = execution.tag_get_raw(&name)?.is_none();
    if new {
        execution.tag_put(
            &name,
            &TagUpdate::CreateIfAbsent {
                kappa: kappa.clone(),
            },
        )?;
    }
    if let Some(ct) = content_type {
        execution.namespace_put_meta(&content_type_key(kappa), ct)?;
    }
    Ok(new)
}

pub async fn put(cx: &Cx, body: Body) -> Result<Response, HandlerError> {
    let s = store(cx);
    let repository = crate::ensure_repository(cx).await?;
    let ns = repository.namespace.clone();
    let bytes = read_body(body, usize::MAX).await?;
    let client_kappa = Kappa::parse(&path_param(cx, "kappa")?)?;
    let content = bytes.to_vec();

    // Verify digest matches content BEFORE any storage
    VerifiedContent::verify(&client_kappa, &content)?;

    // Filter evaluation and schema validation BEFORE storing
    blocking({
        let s = s.clone();
        let ns = ns.clone();
        let content = content.clone();
        move || crate::admission::admit(&*s, &ns, &content)
    })
    .await?;

    // Verify alternate axis digest if provided
    let also_kappa = match query_optional(cx, "also") {
        Some(also_str) => {
            let also = Kappa::parse(&also_str)?;
            if !also.verify(&content)? {
                return crate::oci_error(
                    StatusCode::BAD_REQUEST,
                    "DIGEST_INVALID",
                    "also digest mismatch",
                );
            }
            Some(also)
        }
        None => None,
    };
    let content_type = topcoat::router::request::headers(cx)
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.as_bytes().to_vec());

    // Prepared outside the writer under the client's axis and every
    // mandatory axis; an `also` axis is a second verified preparation of
    // the same bytes, installed as an alias of the same representation.
    let prepared = prepare_body(
        cx,
        ContentIdentity::Verified(client_kappa.clone()),
        content.clone(),
    )
    .await?;
    let also_prepared = match &also_kappa {
        Some(also) => {
            Some(prepare_body(cx, ContentIdentity::Verified(also.clone()), content).await?)
        }
        None => None,
    };
    let committed = execute(cx, WriteTarget::existing(ns.clone()), &bytes, {
        let kappa = client_kappa.clone();
        move |execution| {
            let installed = execution.content_install(take_prepared(&prepared)?)?;
            if let Some(also) = &also_prepared {
                execution.content_install(take_prepared(also)?)?;
            }
            let new_reference = publish_reference(execution, &kappa, content_type.as_deref())?;
            Ok(Outcome::Publish(
                if installed.newly_stored || new_reference {
                    "created".to_string()
                } else {
                    "exists".to_string()
                },
            ))
        }
    })
    .await?;

    let status = if committed.value == "created" {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let mut resp = empty_response(status);
    identity_headers(&mut resp, &client_kappa)?;
    let h = resp.headers_mut();
    h.insert(
        "location",
        header(&format!("/v2/{}/blobs/{client_kappa}", ns.display_name()))?,
    );
    h.insert("content-length", http::HeaderValue::from_static("0"));
    repository.annotate(&mut resp);
    committed.annotate(&mut resp);
    Ok(resp)
}

/// Resolve the repository's reference and the blob's size and content type.
async fn resolve_blob(
    cx: &Cx,
    kappa: &Kappa,
) -> Result<Option<(NamespaceRef, u64, String)>, HandlerError> {
    let s = store(cx);
    let ns = resolve_ns_read(cx)?;
    let kappa = kappa.clone();
    blocking(move || {
        if !referenced(&*s, &ns, &kappa)? {
            return Ok::<_, HandlerError>(None);
        }
        let size = s.blob_size_in(&ns, &kappa)?;
        let ct = content_type(&*s, &ns, &kappa)?;
        Ok(Some((ns, size, ct)))
    })
    .await
}

pub async fn get(cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    let s = store(cx);
    let kappa = Kappa::parse(&path_param(cx, "kappa")?)?;
    let Some((ns, total, ct)) = resolve_blob(cx, &kappa).await? else {
        return blob_unknown();
    };

    // Range request
    if let Some(range_header) = topcoat::router::request::headers(cx)
        .get("range")
        .and_then(|v| v.to_str().ok())
        && let Some(spec) = parse_range_header(range_header)
    {
        let (offset, length) = resolve_range(&spec, total);
        if offset >= total || length == 0 {
            return crate::oci_error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "RANGE_NOT_SATISFIABLE",
                &format!("bytes */{total}"),
            );
        }
        let end = offset + length - 1;
        let slice = blocking({
            let k = kappa.clone();
            let ns = ns.clone();
            move || s.blob_get_range_in(&ns, &k, offset, length)
        })
        .await?;

        let mut resp = binary_response(StatusCode::PARTIAL_CONTENT, &ct, slice)?;
        identity_headers(&mut resp, &kappa)?;
        let h = resp.headers_mut();
        h.insert(
            "content-range",
            header(&format!("bytes {offset}-{end}/{total}"))?,
        );
        h.insert("accept-ranges", http::HeaderValue::from_static("bytes"));
        return Ok(resp);
    }

    let mut response = kappa_handler::stream_blob(cx, s, &ns, &kappa, &ct).await?;
    identity_headers(&mut response, &kappa)?;
    response
        .headers_mut()
        .insert("accept-ranges", http::HeaderValue::from_static("bytes"));
    Ok(response)
}

pub async fn head(cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    let kappa = Kappa::parse(&path_param(cx, "kappa")?)?;
    let Some((_, size, ct)) = resolve_blob(cx, &kappa).await? else {
        return blob_unknown();
    };
    let mut resp = empty_response(StatusCode::OK);
    identity_headers(&mut resp, &kappa)?;
    let h = resp.headers_mut();
    h.insert("content-type", header(&ct)?);
    h.insert("content-length", http::HeaderValue::from(size));
    h.insert("accept-ranges", http::HeaderValue::from_static("bytes"));
    Ok(resp)
}

/// Retire the repository's reference to the blob. The content itself is
/// shared and is collected only when no namespace names it.
pub async fn delete(cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    let kappa = Kappa::parse(&path_param(cx, "kappa")?)?;
    let ns = resolve_ns_read(cx)?;
    let committed = execute(cx, WriteTarget::existing(ns), &[], move |execution| {
        let name = reference_tag(&kappa);
        if execution.tag_get_raw(&name)?.is_none() {
            return Ok(Outcome::Discard("unknown".to_string()));
        }
        execution.tag_delete(&name)?;
        execution.namespace_delete_meta(&content_type_key(&kappa))?;
        Ok(Outcome::Publish("retired".to_string()))
    })
    .await?;
    if committed.value != "retired" {
        return blob_unknown();
    }
    let mut resp = empty_response(StatusCode::ACCEPTED);
    committed.annotate(&mut resp);
    Ok(resp)
}

/// Blobs of the namespace indexed with metadata `key = value`, paginated by
/// `limit` and `cursor`. A pair no blob carries is an empty list.
pub async fn meta_list(cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    let ns = resolve_ns_read(cx)?;
    let key = kappa_handler::query_required(cx, "key")?;
    let value = kappa_handler::query_required(cx, "value")?;
    let page_request = kappa_handler::page_request_from(cx, 1000)?;
    let s = store(cx);
    let page =
        blocking(move || kappa_store::meta_query(&*s, &ns, &key, &value, &page_request)).await?;

    let labels: Vec<String> = page.items.iter().map(ToString::to_string).collect();
    json_response(
        StatusCode::OK,
        &serde_json::json!({"kappas": labels, "next_after": page.next_after}),
    )
}

/// Blobs the repository references, paginated.
pub async fn list(cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    let ns = resolve_ns_read(cx)?;
    let prefix = query_optional(cx, "prefix");
    let s = store(cx);
    let page_request = kappa_handler::page_request_from(cx, 1000)?;
    let page = blocking(move || s.tag_list(&ns, Some("_blob/"), &page_request)).await?;
    let labels: Vec<String> = page
        .items
        .iter()
        .filter(|entry| !entry.name.ends_with("/content-type"))
        .filter(|entry| {
            prefix
                .as_deref()
                .is_none_or(|prefix| entry.kappa.to_string().starts_with(prefix))
        })
        .map(|entry| entry.kappa.to_string())
        .collect();
    json_response(
        StatusCode::OK,
        &serde_json::json!({"kappas": labels, "next_after": page.next_after}),
    )
}

// -- Range parsing ------------------------------------------------------------

enum RangeSpec {
    Range(u64, Option<u64>),
    Suffix(u64),
}

fn parse_range_header(header: &str) -> Option<RangeSpec> {
    let range = header.strip_prefix("bytes=")?;
    let (start_str, end_str) = range.split_once('-')?;
    if start_str.is_empty() {
        return Some(RangeSpec::Suffix(end_str.parse().ok()?));
    }
    let start: u64 = start_str.parse().ok()?;
    let end: Option<u64> = if end_str.is_empty() {
        None
    } else {
        Some(end_str.parse().ok()?)
    };
    Some(RangeSpec::Range(start, end))
}

fn resolve_range(spec: &RangeSpec, total: u64) -> (u64, u64) {
    if total == 0 {
        return (0, 0);
    }
    match spec {
        RangeSpec::Range(start, end) => {
            let end = end.map_or(total - 1, |e| std::cmp::min(e, total - 1));
            if end < *start {
                return (*start, 0);
            }
            (*start, end - start + 1)
        }
        RangeSpec::Suffix(n) => {
            let start = total.saturating_sub(*n);
            (start, total - start)
        }
    }
}
