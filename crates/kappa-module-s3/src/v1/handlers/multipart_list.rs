//! ListParts over the committed members of a multipart resource.

use super::{bucket_read, parse_query, path_param, s3_response, store};
use kappa_handler::{HandlerError, blocking};
use kappa_store::resource;
use kappa_store::{Page, PartReceipt};
use quick_xml::{
    Writer,
    events::{BytesEnd, BytesStart, BytesText, Event},
};
use topcoat::{context::Cx, router::StatusCode};

fn element(writer: &mut Writer<Vec<u8>>, name: &str, value: &str) -> Result<(), HandlerError> {
    let write = |error: std::io::Error| HandlerError::internal(error.to_string());
    writer
        .write_event(Event::Start(BytesStart::new(name)))
        .map_err(write)?;
    writer
        .write_event(Event::Text(BytesText::new(value)))
        .map_err(write)?;
    writer
        .write_event(Event::End(BytesEnd::new(name)))
        .map_err(write)?;
    Ok(())
}

fn encode(
    bucket: &str,
    key: &str,
    upload: &str,
    marker: &str,
    limit: usize,
    page: &Page<PartReceipt>,
) -> Result<Vec<u8>, HandlerError> {
    let mut writer = Writer::new(Vec::new());
    let mut root = BytesStart::new("ListPartsResult");
    root.push_attribute(("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/"));
    writer
        .write_event(Event::Start(root))
        .map_err(|error| HandlerError::internal(error.to_string()))?;
    for (name, value) in [
        ("Bucket", bucket),
        ("Key", key),
        ("UploadId", upload),
        ("PartNumberMarker", marker),
    ] {
        element(&mut writer, name, value)?;
    }
    element(&mut writer, "MaxParts", &limit.to_string())?;
    element(
        &mut writer,
        "IsTruncated",
        if page.next_after.is_some() {
            "true"
        } else {
            "false"
        },
    )?;
    if let Some(after) = &page.next_after {
        element(&mut writer, "NextPartNumberMarker", after)?;
    }
    for part in &page.items {
        writer
            .write_event(Event::Start(BytesStart::new("Part")))
            .map_err(|error| HandlerError::internal(error.to_string()))?;
        element(&mut writer, "PartNumber", &part.part_number.to_string())?;
        element(&mut writer, "ETag", &part.etag)?;
        element(&mut writer, "Size", &part.size.to_string())?;
        writer
            .write_event(Event::End(BytesEnd::new("Part")))
            .map_err(|error| HandlerError::internal(error.to_string()))?;
    }
    writer
        .write_event(Event::End(BytesEnd::new("ListPartsResult")))
        .map_err(|error| HandlerError::internal(error.to_string()))?;
    Ok(writer.into_inner())
}

/// Receipts of the upload's members after `marker`, in slot order,
/// `limit + 1` at most so the page reports truncation.
fn receipts_after(
    members: &[resource::Member],
    marker: u64,
    limit: usize,
) -> Result<Page<PartReceipt>, HandlerError> {
    let mut receipts: Vec<PartReceipt> = Vec::new();
    let mut ordered: Vec<&resource::Member> = members.iter().collect();
    ordered.sort_by_key(|member| member.coordinate.position);
    for member in ordered {
        if member.coordinate.position <= marker {
            continue;
        }
        let md5 = member
            .coordinate
            .receipt
            .as_deref()
            .ok_or_else(|| HandlerError::internal("multipart member without an MD5 receipt"))?;
        let part_number = u32::try_from(member.coordinate.position)
            .map_err(|_| HandlerError::internal("part number exceeds u32"))?;
        receipts.push(PartReceipt {
            part_number,
            etag: format!("\"{}\"", hex::encode(md5)),
            size: member.coordinate.length,
        });
        if receipts.len() > limit {
            break;
        }
    }
    Ok(Page::from_oversized(receipts, limit, |receipt| {
        receipt.part_number.to_string()
    }))
}

pub(super) async fn list(cx: &Cx) -> Result<topcoat::router::response::Response, HandlerError> {
    let ns = bucket_read(cx)?;
    let key = path_param(cx, "key")?;
    let bucket = path_param(cx, "bucket")?;
    let query = parse_query(cx);
    let upload = query
        .get("uploadId")
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            HandlerError::protocol(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "uploadId is required",
            )
        })?
        .clone();
    let limit = query
        .get("max-parts")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| {
            HandlerError::protocol(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "invalid max-parts",
            )
        })?
        .unwrap_or(1000)
        .min(1000);
    let marker = query
        .get("part-number-marker")
        .cloned()
        .unwrap_or_else(|| "0".into());
    let marker_value: u64 = marker.parse().map_err(|_| {
        HandlerError::protocol(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "invalid part marker",
        )
    })?;
    if marker_value > super::multipart::MAX_PART_NUMBER {
        return Err(HandlerError::protocol(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "invalid part marker",
        ));
    }
    let s = store(cx);
    let page = blocking({
        let key = key.clone();
        let upload = upload.clone();
        move || -> Result<_, HandlerError> {
            // The upload's key is its head's context, committed at open.
            let resource = resource::resolve(&*s, &ns, &upload)?
                .filter(|resource| resource.head.context.as_deref() == Some(key.as_bytes()))
                .ok_or_else(no_such_upload)?;
            let members = resource::members(&*s, &ns, &resource.head)?;
            receipts_after(&members, marker_value, limit)
        }
    })
    .await?;
    Ok(s3_response(
        StatusCode::OK,
        encode(&bucket, &key, &upload, &marker, limit, &page)?,
    ))
}

fn no_such_upload() -> HandlerError {
    HandlerError::protocol(StatusCode::NOT_FOUND, "NoSuchUpload", "upload not found")
}
