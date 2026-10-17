use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use crate::protocol_id;
use kappa_handler::{HandlerError, blocking, page_request_from, query_required, store};
use kappa_store::StoreError;

pub async fn describe_repo(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let repo = query_required(cx, "repo")?;
    let s = store(cx);

    let result = blocking(move || {
        let ns = s.namespace_resolve(&repo, Some(protocol_id()))?;
        let mut cursor = s.tag_cursor(&ns, Some("record/"))?;
        let mut collections = Vec::new();
        while cursor.key() != kappa_cursor::TERMINATED {
            let key = std::str::from_utf8(cursor.key())
                .map_err(|e| StoreError::Internal(format!("non-utf8 tag: {e}")))?;
            let collection = key
                .strip_prefix("record/")
                .ok_or_else(|| {
                    StoreError::Internal(format!("tag '{}' missing record/ prefix", key))
                })?
                .split('/')
                .next()
                .ok_or_else(|| {
                    StoreError::Internal(format!("tag '{}' has no collection segment", key))
                })?
                .to_string();
            if collections
                .last()
                .is_none_or(|last: &String| *last != collection)
            {
                collections.push(collection);
            }
            cursor.advance();
        }
        Ok::<_, StoreError>((repo, collections))
    })
    .await?;

    kappa_handler::json_response(
        StatusCode::OK,
        &serde_json::json!({
            "handle": result.0,
            "did": result.0,
            "didDoc": {},
            "collections": result.1,
            "handleIsCorrect": true,
        }),
    )
}

pub async fn get_record(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let repo = query_required(cx, "repo")?;
    let collection = query_required(cx, "collection")?;
    let rkey = query_required(cx, "rkey")?;
    let s = store(cx);

    let result = blocking(move || {
        let ns = s.namespace_resolve(&repo, Some(protocol_id()))?;
        let tag_name = format!("record/{}/{}", collection, rkey);
        let entry = s.tag_get(&ns, &tag_name)?;
        let data = s.blob_get_in(&ns, &entry.kappa)?;
        let value: serde_json::Value = serde_json::from_slice(&data).map_err(|e| {
            StoreError::Internal(format!("record at {} is not valid JSON: {e}", tag_name))
        })?;
        let uri = format!("at://{}/{}/{}", repo, collection, rkey);
        Ok::<_, StoreError>(serde_json::json!({
            "uri": uri,
            "cid": entry.kappa.to_string(),
            "value": value,
        }))
    })
    .await?;

    kappa_handler::json_response(StatusCode::OK, &result)
}

const MAX_LIST_LIMIT: usize = 100;

pub async fn list_records(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let repo = query_required(cx, "repo")?;
    let collection = query_required(cx, "collection")?;
    let page_req = page_request_from(cx, MAX_LIST_LIMIT)?;
    let s = store(cx);

    let result = blocking(move || {
        let ns = s.namespace_resolve(&repo, Some(protocol_id()))?;
        let prefix = format!("record/{}/", collection);
        let page = s.tag_list(&ns, Some(&prefix), &page_req)?;
        let mut records = Vec::with_capacity(page.items.len());
        let mut skipped = 0u64;
        for tag in &page.items {
            let rkey = tag.name.strip_prefix(&prefix).ok_or_else(|| {
                StoreError::Internal(format!(
                    "tag '{}' missing expected prefix '{}'",
                    tag.name, prefix
                ))
            })?;
            let uri = format!("at://{}/{}/{}", repo, collection, rkey);
            match s.blob_get_in(&ns, &tag.kappa) {
                Ok(data) => {
                    let value: serde_json::Value = serde_json::from_slice(&data).map_err(|e| {
                        StoreError::Internal(format!(
                            "record at {} is not valid JSON: {e}",
                            tag.name
                        ))
                    })?;
                    records.push(serde_json::json!({
                        "uri": uri,
                        "cid": tag.kappa.to_string(),
                        "value": value,
                    }));
                }
                Err(StoreError::NotFound(_)) => {
                    skipped += 1;
                }
                Err(e) => return Err(e),
            }
        }
        Ok((records, skipped, page.next_after))
    })
    .await?;

    let (records, skipped, next_cursor) = result;
    let status = if skipped > 0 {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    let mut body = serde_json::json!({ "records": records });
    if let Some(c) = next_cursor {
        body["cursor"] = serde_json::Value::String(c);
    }
    if skipped > 0 {
        body["skipped"] = serde_json::json!(skipped);
    }
    kappa_handler::json_response(status, &body)
}
