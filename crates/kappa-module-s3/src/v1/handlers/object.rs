use topcoat::context::{Cx, request_context};
use topcoat::router::{Body, StatusCode};

use md5::Digest as _;

use kappa_handler::{HandlerError, Outcome, blocking};
use kappa_store::axis::Axis;
use kappa_store::error::StoreError;
use kappa_store::tag::TagUpdate;

use super::{
    NewObjectMeta, bucket_existing, bucket_read, bucket_write, clear_object_meta, get_object_meta,
    obj_meta_key, object_headers, parse_query, path_param, s3_response, set_object_meta, store,
};
use crate::xml::{encode_tagging_xml, parse_delete_keys, parse_tagging};

// -- Dispatch handlers --------------------------------------------------------

pub async fn get(
    cx: &Cx,
    _body: Body, // GET — body not expected
) -> Result<topcoat::router::response::Response, HandlerError> {
    let ns = bucket_read(cx)?;
    let key = path_param(cx, "key")?;
    let query = parse_query(cx);

    if query.contains_key("uploadId") {
        return super::multipart_list::list(cx).await;
    }

    if query.contains_key("tagging") {
        return get_tagging(cx, ns, &key).await;
    }

    let s = store(cx);
    let (size, meta, kappa) = blocking({
        let s = s.clone();
        let ns = ns.clone();
        move || {
            let entry = s.tag_get(&ns, &key)?;
            let size = s.blob_size_in(&ns, &entry.kappa)?;
            let meta = get_object_meta(&*s, &ns, &key)?;
            Ok::<_, StoreError>((size, meta, entry.kappa))
        }
    })
    .await?;

    // The shared blob stream verifies the declared length and reports
    // producer failure as a body error rather than a clean end of stream.
    let ct = meta.ct.as_deref().unwrap_or("application/octet-stream");
    let mut resp = kappa_handler::stream_blob(cx, s, &ns, &kappa, ct).await?;
    object_headers(&mut resp, &meta, &kappa, size)?;
    Ok(resp)
}

pub async fn head(
    cx: &Cx,
    _body: Body, // HEAD — body not expected
) -> Result<topcoat::router::response::Response, HandlerError> {
    let ns = bucket_read(cx)?;
    let key = path_param(cx, "key")?;
    let s = store(cx);
    let (size, meta, kappa) = blocking(move || {
        let entry = s.tag_get(&ns, &key)?;
        let size = s.blob_size_in(&ns, &entry.kappa)?;
        let meta = get_object_meta(&*s, &ns, &key)?;
        Ok::<_, StoreError>((size, meta, entry.kappa))
    })
    .await?;

    let mut resp = kappa_handler::empty_response(StatusCode::OK);
    object_headers(&mut resp, &meta, &kappa, size)?;
    Ok(resp)
}

pub async fn put_or_copy_or_part(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let query = parse_query(cx);
    let parts: &http::request::Parts = request_context(cx);
    let has_copy_source = parts.headers.contains_key("x-amz-copy-source");
    let has_tagging = query.contains_key("tagging");
    let has_part_number = query.contains_key("partNumber");

    if has_tagging {
        put_tagging(cx, body).await
    } else if has_copy_source {
        copy_object(cx).await
    } else if has_part_number {
        super::multipart::upload_part(cx, body).await
    } else {
        put_object(cx, body).await
    }
}

pub async fn delete_or_abort(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let query = parse_query(cx);
    if query.contains_key("tagging") {
        delete_tagging(cx).await
    } else if query.contains_key("uploadId") {
        super::multipart::abort(cx).await
    } else {
        delete_object(cx).await
    }
}

pub async fn post_dispatch(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let query = parse_query(cx);
    if query.contains_key("uploads") {
        super::multipart::initiate(cx).await
    } else if query.contains_key("uploadId") {
        super::multipart::complete(cx, body).await
    } else {
        Err(HandlerError::bad_request("unsupported POST operation"))
    }
}

/// DeleteObjects. All deletions publish in one epoch. Keys that do not
/// exist are reported as deleted, as S3 does; a request deleting no
/// existing object publishes nothing.
pub async fn batch_delete(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let target = bucket_existing(cx)?;
    let body_bytes = kappa_handler::read_body(body, super::MAX_BATCH_DELETE_BODY).await?;
    let keys_to_delete = parse_delete_keys(&body_bytes).map_err(HandlerError::bad_request)?;

    let committed = kappa_handler::execute(cx, target, &body_bytes, move |execution| {
        let mut removed_any = false;
        for key in &keys_to_delete {
            if execution.tag_get_raw(key)?.is_some() {
                execution.tag_delete(key)?;
                clear_object_meta(execution, key)?;
                removed_any = true;
            }
        }
        let deleted = keys_to_delete.clone();
        Ok(if removed_any {
            Outcome::Publish(deleted)
        } else {
            Outcome::Discard(deleted)
        })
    })
    .await?;

    let xml = crate::xml::encode_delete_result_xml(&committed.value, &[]);
    let mut response = s3_response(StatusCode::OK, xml);
    committed.annotate(&mut response);
    Ok(response)
}

// -- Internal handlers --------------------------------------------------------

fn header_value(cx: &Cx, name: &str) -> Option<String> {
    let parts: &http::request::Parts = request_context(cx);
    parts
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn etag_header(etag: &str) -> Result<http::HeaderValue, HandlerError> {
    etag.parse()
        .map_err(|error| HandlerError::internal(format!("invalid ETag: {error}")))
}

/// PutObject. The content, its tag, and its metadata publish in one epoch,
/// so no reader observes an object without its metadata.
async fn put_object(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let target = bucket_write(cx)?;
    let key = path_param(cx, "key")?;
    let content_type = header_value(cx, "content-type");
    let content = kappa_handler::read_body(body, super::max_object_body(cx)).await?;
    let etag = format!("\"{}\"", hex::encode(md5::Md5::digest(&content)));

    // The body is prepared outside the writer; the execution installs it.
    let prepared = kappa_handler::prepare_body(
        cx,
        kappa_store::ContentIdentity::Computed(Axis::Sha256),
        content.to_vec(),
    )
    .await?;
    let committed = kappa_handler::execute(cx, target, &content, move |execution| {
        let ingest = execution.content_install(kappa_handler::take_prepared(&prepared)?)?;
        execution.tag_put(
            &key,
            &TagUpdate::Set {
                kappa: ingest.kappa.clone(),
            },
        )?;
        set_object_meta(
            execution,
            &key,
            &NewObjectMeta {
                content_type: content_type.as_deref(),
                etag: &etag,
                tags: None,
            },
        )?;
        Ok(Outcome::Publish(etag.clone()))
    })
    .await?;

    let mut resp = kappa_handler::empty_response(StatusCode::OK);
    resp.headers_mut()
        .insert("etag", etag_header(&committed.value)?);
    committed.annotate(&mut resp);
    Ok(resp)
}

/// DeleteObject. Deleting an absent key succeeds and publishes nothing.
async fn delete_object(cx: &Cx) -> Result<topcoat::router::response::Response, HandlerError> {
    let target = bucket_existing(cx)?;
    let key = path_param(cx, "key")?;
    let committed = kappa_handler::execute(cx, target, &[], move |execution| {
        if execution.tag_get_raw(&key)?.is_none() {
            return Ok(Outcome::Discard(()));
        }
        execution.tag_delete(&key)?;
        clear_object_meta(execution, &key)?;
        Ok(Outcome::Publish(()))
    })
    .await?;
    let mut response = kappa_handler::empty_response(StatusCode::NO_CONTENT);
    committed.annotate(&mut response);
    Ok(response)
}

/// CopyObject. Content type and tag set are copied from the source, as with
/// S3's default `COPY` metadata and tagging directives.
async fn copy_object(cx: &Cx) -> Result<topcoat::router::response::Response, HandlerError> {
    let target = bucket_write(cx)?;
    let key = path_param(cx, "key")?;
    let copy_source = header_value(cx, "x-amz-copy-source")
        .filter(|source| !source.is_empty())
        .map(|source| kappa_handler::percent_decode(&source))
        .ok_or_else(|| HandlerError::bad_request("Missing or empty x-amz-copy-source header"))?;
    let source = copy_source
        .strip_prefix('/')
        .unwrap_or(&copy_source)
        .to_string();
    let (src_bucket, src_key) = source
        .split_once('/')
        .map(|(bucket, key)| (bucket.to_string(), key.to_string()))
        .ok_or_else(|| HandlerError::bad_request("invalid copy source format"))?;
    let s = store(cx);
    let s3_protocol = crate::protocol_id().clone();

    let committed = kappa_handler::execute(cx, target, source.as_bytes(), move |execution| {
        // Source reads run while the execution holds the store's writer, so
        // the copied object cannot change before this copy publishes.
        let src_ns = s.namespace_resolve(&src_bucket, Some(&s3_protocol))?;
        let src_entry = s.tag_get(&src_ns, &src_key)?;
        let src_meta = get_object_meta(&*s, &src_ns, &src_key)?;
        let src_tags =
            kappa_store::absent(s.namespace_get_meta(&src_ns, &obj_meta_key(&src_key, "tags")))?;
        let etag = match src_meta.etag {
            Some(etag) => etag,
            None => {
                let content = s.blob_get_in(&src_ns, &src_entry.kappa)?;
                format!("\"{}\"", hex::encode(md5::Md5::digest(&content)))
            }
        };
        execution.tag_put(
            &key,
            &TagUpdate::Set {
                kappa: src_entry.kappa.clone(),
            },
        )?;
        set_object_meta(
            execution,
            &key,
            &NewObjectMeta {
                content_type: src_meta.ct.as_deref(),
                etag: &etag,
                tags: src_tags.as_deref(),
            },
        )?;
        let modified_ms = execution.now().physical_ms().to_string();
        Ok(Outcome::Publish(vec![etag, modified_ms]))
    })
    .await?;

    let [etag, modified_ms] = committed.value.as_slice() else {
        return Err(HandlerError::internal(
            "copy result must carry ETag and modification time",
        ));
    };
    let modified_ms = modified_ms
        .parse::<u64>()
        .map_err(|error| HandlerError::internal(format!("copy modification time: {error}")))?;
    let last_modified = kappa_handler::epoch_ms_to_iso8601(modified_ms)?;
    let xml = crate::xml::encode_copy_result_xml(etag, &last_modified);
    let mut response = s3_response(StatusCode::OK, xml);
    committed.annotate(&mut response);
    Ok(response)
}

// -- Tagging ------------------------------------------------------------------

async fn put_tagging(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let target = bucket_existing(cx)?;
    let key = path_param(cx, "key")?;
    let body_bytes = kappa_handler::read_body(body, super::MAX_TAGGING_BODY).await?;
    let tags = parse_tagging(&body_bytes, super::MAX_TAGS_PER_OBJECT)
        .map_err(HandlerError::bad_request)?;
    let encoded = serde_json::to_vec(&tags)
        .map_err(|error| HandlerError::internal(format!("tag set encoding: {error}")))?;

    let committed = kappa_handler::execute(cx, target, &body_bytes, move |execution| {
        if execution.tag_get_raw(&key)?.is_none() {
            return Err(HandlerError::not_found(format!("object {key} not found")));
        }
        execution.namespace_put_meta(&obj_meta_key(&key, "tags"), &encoded)?;
        Ok(Outcome::Publish(()))
    })
    .await?;

    let mut response = kappa_handler::empty_response(StatusCode::OK);
    committed.annotate(&mut response);
    Ok(response)
}

async fn get_tagging(
    cx: &Cx,
    ns: kappa_store::namespace::NamespaceRef,
    key: &str,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let s = store(cx);
    let k = key.to_string();
    let tags = blocking(move || {
        s.tag_get(&ns, &k)?;
        match s.namespace_get_meta(&ns, &obj_meta_key(&k, "tags")) {
            Ok(raw) => {
                let tags: Vec<(String, String)> = serde_json::from_slice(&raw)
                    .map_err(|e| StoreError::Internal(format!("tag metadata corrupted: {e}")))?;
                Ok(tags)
            }
            Err(StoreError::NotFound(_)) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    })
    .await?;

    let xml = encode_tagging_xml(&tags);
    Ok(s3_response(StatusCode::OK, xml))
}

/// DeleteObjectTagging. An absent object or an object without tags
/// succeeds and publishes nothing.
async fn delete_tagging(cx: &Cx) -> Result<topcoat::router::response::Response, HandlerError> {
    let target = bucket_existing(cx)?;
    let key = path_param(cx, "key")?;
    let committed = kappa_handler::execute(cx, target, &[], move |execution| {
        let tags_key = obj_meta_key(&key, "tags");
        if execution.tag_get_raw(&key)?.is_none()
            || execution.namespace_get_meta(&tags_key)?.is_none()
        {
            return Ok(Outcome::Discard(()));
        }
        execution.namespace_delete_meta(&tags_key)?;
        Ok(Outcome::Publish(()))
    })
    .await?;
    let mut response = kappa_handler::empty_response(StatusCode::NO_CONTENT);
    committed.annotate(&mut response);
    Ok(response)
}
