use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{HandlerError, Outcome, blocking, page_request_from};
use kappa_store::page::{NamespaceFilter, PageRequest};

use super::{
    bucket_existing, bucket_read, bucket_write, ensure_bucket, parse_query, path_param,
    s3_response, store,
};

// ---------------------------------------------------------------------------
// HEAD /{bucket}
// ---------------------------------------------------------------------------

pub async fn head(
    cx: &Cx,
    _body: Body, // HEAD — no body expected
) -> Result<topcoat::router::response::Response, HandlerError> {
    bucket_read(cx)?;
    Ok(kappa_handler::empty_response(StatusCode::OK))
}

// ---------------------------------------------------------------------------
// GET / — ListBuckets
// ---------------------------------------------------------------------------

pub async fn list_buckets(
    cx: &Cx,
    _body: Body, // GET — no body expected
) -> Result<topcoat::router::response::Response, HandlerError> {
    let page_req = page_request_from(cx, 1000)?;
    let filter = NamespaceFilter {
        protocol: Some(crate::protocol_id().clone()),
        ..Default::default()
    };
    let s = store(cx);
    let page = blocking(move || s.namespace_list(&filter, &page_req)).await?;

    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Buckets>",
    );
    for rec in &page.items {
        let created_ms = kappa_store::clock::ClockMs::from_raw(rec.created_at_ms).physical_ms();
        let created = kappa_handler::epoch_ms_to_iso8601(created_ms)?;
        xml.push_str("<Bucket><Name>");
        xml.push_str(&rec.name);
        xml.push_str("</Name><CreationDate>");
        xml.push_str(&created);
        xml.push_str("</CreationDate></Bucket>");
    }
    xml.push_str("</Buckets></ListAllMyBucketsResult>");
    Ok(s3_response(StatusCode::OK, xml.into_bytes()))
}

// ---------------------------------------------------------------------------
// PUT /{bucket} — dispatch: versioning | config | create
// ---------------------------------------------------------------------------

const BUCKET_CONFIG_KEYS: &[&str] = &["versioning", "lifecycle", "cors", "policy", "acl"];

fn match_config_key(query: &std::collections::HashMap<String, String>) -> Option<&'static str> {
    BUCKET_CONFIG_KEYS
        .iter()
        .copied()
        .find(|key| query.contains_key(*key))
}

pub async fn put_dispatch(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let query = parse_query(cx);
    match match_config_key(&query) {
        Some("versioning") => put_versioning(cx, body).await,
        Some(key) => put_config(cx, body, key).await,
        None => create_bucket(cx).await,
    }
}

// ---------------------------------------------------------------------------
// GET /{bucket} — dispatch: versioning | config | list objects
// ---------------------------------------------------------------------------

pub async fn get_dispatch(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let query = parse_query(cx);
    match match_config_key(&query) {
        Some("versioning") => get_versioning(cx).await,
        Some(key) => get_config(cx, key).await,
        None => list_objects(cx, body).await,
    }
}

// ---------------------------------------------------------------------------
// DELETE /{bucket} — dispatch: config | delete bucket
// ---------------------------------------------------------------------------

pub async fn delete_dispatch(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let query = parse_query(cx);
    match match_config_key(&query) {
        Some(key) if key != "versioning" => delete_config(cx, key).await,
        _ => delete_bucket(cx).await,
    }
}

// ---------------------------------------------------------------------------
// Internal: create bucket
// ---------------------------------------------------------------------------

/// The bucket's creation publishes in its own epoch so federation peers
/// observe it. Creating an existing bucket publishes nothing.
async fn create_bucket(cx: &Cx) -> Result<topcoat::router::response::Response, HandlerError> {
    let committed = ensure_bucket(cx).await?;
    let mut response = kappa_handler::empty_response(StatusCode::OK);
    committed.annotate(&mut response);
    Ok(response)
}

// ---------------------------------------------------------------------------
// Internal: delete bucket
// ---------------------------------------------------------------------------

async fn delete_bucket(cx: &Cx) -> Result<topcoat::router::response::Response, HandlerError> {
    let target = bucket_existing(cx)?;
    let s = store(cx);
    let committed = kappa_handler::execute(cx, target, &[], move |execution| {
        // The execution holds the store's single writer, so no object can
        // publish between this emptiness check and the deletion.
        let check = s.tag_list(
            execution.namespace(),
            None,
            &PageRequest {
                limit: 1,
                after: None,
            },
        )?;
        if !check.items.is_empty() {
            return Err(HandlerError::protocol(
                StatusCode::CONFLICT,
                "BucketNotEmpty",
                "The bucket you tried to delete is not empty.",
            ));
        }
        execution.namespace_delete()?;
        Ok(Outcome::Publish(()))
    })
    .await?;
    let mut response = kappa_handler::empty_response(StatusCode::NO_CONTENT);
    committed.annotate(&mut response);
    Ok(response)
}

// ---------------------------------------------------------------------------
// Internal: list objects (ListObjectsV2)
// ---------------------------------------------------------------------------

async fn list_objects(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let ns = bucket_read(cx)?;
    let bucket_name = path_param(cx, "bucket")?;
    let query = parse_query(cx);
    let s = store(cx);

    let max_keys: u32 = match query.get("max-keys") {
        Some(v) => v
            .parse::<u32>()
            .map_err(|_| HandlerError::bad_request("max-keys must be a non-negative integer"))?,
        None => super::DEFAULT_MAX_KEYS,
    };

    let req = crate::list::ListObjectsV2Request {
        bucket: bucket_name,
        prefix: query.get("prefix").cloned(),
        delimiter: query.get("delimiter").cloned(),
        max_keys,
        continuation_token: query.get("continuation-token").cloned(),
        start_after: query.get("start-after").cloned(),
        encoding_type: query.get("encoding-type").cloned(),
        fetch_owner: false,
    };

    let xml = blocking(move || {
        let resp = crate::list::list_objects_v2(&*s, &ns, &req)?;
        Ok::<_, kappa_store::StoreError>(crate::xml::encode_list_objects_v2_xml(&resp))
    })
    .await?;

    Ok(s3_response(StatusCode::OK, xml))
}

// ---------------------------------------------------------------------------
// Internal: versioning
// ---------------------------------------------------------------------------

/// The `Status` of a PutBucketVersioning body: `Enabled` or `Suspended`,
/// surrounding whitespace ignored. A body without `Status` leaves the bucket
/// unversioned.
fn parse_versioning_status(xml_bytes: &[u8]) -> Result<&'static str, HandlerError> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_reader(xml_bytes);
    let mut buf = Vec::new();
    let mut status: Option<String> = None;

    loop {
        let event = reader
            .read_event_into(&mut buf)
            .map_err(|_| HandlerError::bad_request("invalid XML in versioning body"))?;
        match event {
            Event::Start(ref e) if e.name().as_ref() == "Status" => status = Some(String::new()),
            Event::End(ref e) if e.name().as_ref() == "Status" => {
                let text = status.take().unwrap_or_default();
                return match text.trim() {
                    "Enabled" => Ok("enabled"),
                    "Suspended" => Ok("suspended"),
                    _ => Err(HandlerError::bad_request(
                        "Status must be Enabled or Suspended",
                    )),
                };
            }
            Event::Eof => break,
            ref other => {
                if let Some(text) = status.as_mut() {
                    crate::xml::push_character_data(text, other).map_err(|_| {
                        HandlerError::bad_request("invalid XML encoding in versioning body")
                    })?;
                }
            }
        }
        buf.clear();
    }
    Ok("unversioned")
}

async fn put_versioning(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let target = bucket_write(cx)?;
    let body_bytes = kappa_handler::read_body(body, super::MAX_VERSIONING_BODY).await?;
    let status_value = parse_versioning_status(&body_bytes)?;
    let committed = kappa_handler::execute(cx, target, &body_bytes, move |execution| {
        execution.namespace_put_meta("versioning", status_value.as_bytes())?;
        Ok(Outcome::Publish(()))
    })
    .await?;
    let mut response = kappa_handler::empty_response(StatusCode::OK);
    committed.annotate(&mut response);
    Ok(response)
}

async fn get_versioning(cx: &Cx) -> Result<topcoat::router::response::Response, HandlerError> {
    let ns = bucket_read(cx)?;
    let s = store(cx);
    let status_str = blocking(move || match s.namespace_get_meta(&ns, "versioning") {
        Ok(bytes) => String::from_utf8(bytes).map_err(|e| {
            kappa_store::StoreError::Internal(format!("versioning metadata corrupted: {e}"))
        }),
        Err(kappa_store::StoreError::NotFound(_)) => Ok(String::new()),
        Err(e) => Err(e),
    })
    .await?;

    let xml_status = match status_str.as_str() {
        "enabled" => "<Status>Enabled</Status>",
        "suspended" => "<Status>Suspended</Status>",
        _ => "",
    };
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         {}\
         </VersioningConfiguration>",
        xml_status
    );
    Ok(s3_response(StatusCode::OK, xml.into_bytes()))
}

// ---------------------------------------------------------------------------
// Internal: generic config (lifecycle, cors, policy, acl)
// ---------------------------------------------------------------------------

async fn put_config(
    cx: &Cx,
    body: Body,
    config_key: &str,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let target = bucket_write(cx)?;
    let body_bytes = kappa_handler::read_body(body, super::MAX_CONFIG_BODY).await?;
    let key = config_key.to_string();
    let config = body_bytes.clone();
    let committed = kappa_handler::execute(cx, target, &body_bytes, move |execution| {
        execution.namespace_put_meta(&key, &config)?;
        Ok(Outcome::Publish(()))
    })
    .await?;
    let mut response = kappa_handler::empty_response(StatusCode::OK);
    committed.annotate(&mut response);
    Ok(response)
}

async fn get_config(
    cx: &Cx,
    config_key: &str,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let ns = bucket_read(cx)?;
    let s = store(cx);
    let key = config_key.to_string();
    let content = blocking(move || match s.namespace_get_meta(&ns, &key) {
        Ok(content) => Ok(content),
        Err(kappa_store::StoreError::NotFound(_)) => Err(HandlerError::not_found(format!(
            "{} configuration not found",
            key
        ))),
        Err(e) => Err(e.into()),
    })
    .await?;
    Ok(s3_response(StatusCode::OK, content))
}

async fn delete_config(
    cx: &Cx,
    config_key: &str,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let target = bucket_existing(cx)?;
    let key = config_key.to_string();
    let committed = kappa_handler::execute(cx, target, &[], move |execution| {
        // Deleting an absent configuration is idempotent and publishes
        // nothing.
        if execution.namespace_get_meta(&key)?.is_none() {
            return Ok(Outcome::Discard(()));
        }
        execution.namespace_delete_meta(&key)?;
        Ok(Outcome::Publish(()))
    })
    .await?;
    let mut response = kappa_handler::empty_response(StatusCode::NO_CONTENT);
    committed.annotate(&mut response);
    Ok(response)
}
