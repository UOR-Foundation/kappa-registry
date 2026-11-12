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

/// One current receipt format: MD5 followed by big-endian CRC32C and
/// CRC64-NVME. The resource commits it with the exact part bytes.
pub(super) fn part_receipt(bytes: &[u8]) -> Vec<u8> {
    use md5::Digest;
    let mut receipt = md5::Md5::digest(bytes).to_vec();
    for algorithm in [
        crc_fast::CrcAlgorithm::Crc32Iscsi,
        crc_fast::CrcAlgorithm::Crc64Nvme,
    ] {
        let mut digest = crc_fast::Digest::new(algorithm);
        digest.update(bytes);
        let value = digest.finalize();
        if matches!(algorithm, crc_fast::CrcAlgorithm::Crc32Iscsi) {
            receipt.extend_from_slice(&(value as u32).to_be_bytes());
        } else {
            receipt.extend_from_slice(&value.to_be_bytes());
        }
    }
    receipt
}

pub(super) fn part_md5(receipt: &[u8]) -> Result<&[u8], HandlerError> {
    if receipt.len() != 28 {
        return Err(HandlerError::internal(
            "malformed multipart checksum receipt",
        ));
    }
    Ok(&receipt[..16])
}

/// Preserve the selected part manifest and full-object CRCs in the same
/// execution as completion. Selection comes from the frozen generation.
pub(super) fn persist_manifest(
    execution: &mut dyn kappa_store::Execution,
    identity: &kappa_store::Kappa,
    asserter: &kappa_store::Kappa,
    members: &[resource::Member],
) -> Result<(), HandlerError> {
    let mut crc32 = 0;
    let mut crc64 = 0;
    let mut offset = 0u64;
    let mut parts = Vec::with_capacity(members.len());
    for member in members {
        let receipt = member
            .coordinate
            .receipt
            .as_deref()
            .ok_or_else(|| HandlerError::internal("multipart member without checksums"))?;
        let md5 = part_md5(receipt)?;
        let part32 = u32::from_be_bytes(
            receipt[16..20]
                .try_into()
                .map_err(|_| HandlerError::internal("invalid CRC32C receipt"))?,
        );
        let part64 = u64::from_be_bytes(
            receipt[20..28]
                .try_into()
                .map_err(|_| HandlerError::internal("invalid CRC64-NVME receipt"))?,
        );
        let size = member.coordinate.length;
        crc32 = crc_fast::checksum_combine(
            crc_fast::CrcAlgorithm::Crc32Iscsi,
            crc32,
            u64::from(part32),
            size,
        );
        crc64 = crc_fast::checksum_combine(crc_fast::CrcAlgorithm::Crc64Nvme, crc64, part64, size);
        parts.push(
            serde_json::json!({"part_number": member.coordinate.position,
            "offset": offset, "size": size, "md5": hex::encode(md5),
            "crc32c": part32, "crc64nvme": part64}),
        );
        offset = offset
            .checked_add(size)
            .ok_or_else(|| HandlerError::internal("multipart manifest size overflow"))?;
    }
    let bytes =
        serde_json::to_vec(&serde_json::json!({"total_parts": parts.len(), "parts": parts}))
            .map_err(|error| HandlerError::internal(error.to_string()))?;
    let manifest = kappa_store::VerifiedContent::compute(kappa_store::Axis::Sha256, &bytes)
        .map_err(kappa_store::StoreError::from)?;
    execution.blob_put(&manifest)?;
    execution.blob_meta_put(
        identity,
        "_s3_checksum_crc32c",
        &(crc32 as u32).to_be_bytes(),
    )?;
    execution.blob_meta_put(identity, "_s3_checksum_crc64nvme", &crc64.to_be_bytes())?;
    execution.edge_put(&kappa_store::EdgeInput {
        source: identity.clone(),
        target: manifest.kappa().clone(),
        relation: kappa_store::edge::EdgeRelation::Builtin(
            kappa_store::edge::BuiltinRelation::ChunkManifest,
        ),
        asserter: asserter.clone(),
        created_at_ms: execution.now().as_i64(),
        metadata: None,
    })?;
    Ok(())
}

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
            etag: format!("\"{}\"", hex::encode(part_md5(md5)?)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_store::{BlobStore, EdgeStore, ExecutionStore, Kappa, NamespaceRef};

    #[test]
    fn receipts_match_independent_check_vectors_and_reject_truncation() -> Result<(), HandlerError>
    {
        let receipt = part_receipt(b"123456789");
        assert_eq!(
            hex::encode(part_md5(&receipt)?),
            "25f9e794323b453885f5181f1b624d0b"
        );
        assert_eq!(hex::encode(&receipt[16..20]), "e3069283");
        assert_eq!(hex::encode(&receipt[20..]), "ae8b14860a799888");
        for end in 0..28 {
            assert!(part_md5(&receipt[..end]).is_err());
        }
        let mut oversized = receipt;
        oversized.push(0);
        assert!(part_md5(&oversized).is_err());
        Ok(())
    }

    #[test]
    fn combined_checksums_match_streaming_for_every_split_including_empty_parts() {
        let bytes: Vec<u8> = (0..=255).cycle().take(1025).collect();
        for algorithm in [
            crc_fast::CrcAlgorithm::Crc32Iscsi,
            crc_fast::CrcAlgorithm::Crc64Nvme,
        ] {
            let expected = crc_fast::checksum(algorithm, &bytes);
            for split in 0..=bytes.len() {
                let (first, second) = bytes.split_at(split);
                let combined = crc_fast::checksum_combine(
                    algorithm,
                    crc_fast::checksum(algorithm, first),
                    crc_fast::checksum(algorithm, second),
                    second.len() as u64,
                );
                assert_eq!(combined, expected, "split={split}");
            }
        }
    }

    #[test]
    fn listing_pages_expanded_receipts_in_slot_order_and_rejects_corruption()
    -> Result<(), HandlerError> {
        let mut members: Vec<_> = [9, 2, 5]
            .into_iter()
            .map(|position| resource::Member {
                identity: Kappa::sha256(b"123456789"),
                edge: Kappa::sha256(&[position as u8]),
                coordinate: kappa_store::MemberCoordinate {
                    position,
                    length: 9,
                    receipt: Some(part_receipt(b"123456789")),
                },
            })
            .collect();
        let page = receipts_after(&members, 0, 2)?;
        assert_eq!(
            page.items
                .iter()
                .map(|part| part.part_number)
                .collect::<Vec<_>>(),
            [2, 5]
        );
        assert_eq!(page.next_after.as_deref(), Some("5"));
        for part in &page.items {
            assert_eq!(part.etag, "\"25f9e794323b453885f5181f1b624d0b\"");
            assert_eq!(part.size, 9);
        }
        let last = receipts_after(&members, 5, 2)?;
        assert_eq!(last.items.len(), 1);
        assert_eq!(last.items[0].part_number, 9);
        assert!(last.next_after.is_none());
        members[0].coordinate.receipt = Some(vec![0; 16]);
        assert!(receipts_after(&members, 5, 2).is_err());
        members[0].coordinate.receipt = None;
        assert!(receipts_after(&members, 5, 2).is_err());
        Ok(())
    }

    #[test]
    fn manifest_and_combined_checksums_publish_with_selected_parts()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = kappa_store_memory::test_support::test_store()?;
        let store = fixture.store();
        let ns = NamespaceRef::deterministic("multipart-checksums");
        let owner = Kappa::sha256(b"owner");
        let content =
            kappa_store::VerifiedContent::compute(kappa_store::Axis::Sha256, b"123456789")?;
        let members: Vec<_> = [(2, &b"1234"[..]), (9, &b"56789"[..])]
            .into_iter()
            .map(|(position, bytes)| resource::Member {
                identity: Kappa::sha256(bytes),
                edge: Kappa::sha256(bytes),
                coordinate: kappa_store::MemberCoordinate {
                    position,
                    length: bytes.len() as u64,
                    receipt: Some(part_receipt(bytes)),
                },
            })
            .collect();
        let clock = kappa_handler::clock_at(kappa_store::ClockMs::from_raw(1000))?;
        let mut execution = store.begin_execution(&ns, &clock)?;
        execution.blob_put(&content)?;
        persist_manifest(&mut *execution, content.kappa(), &owner, &members)?;
        assert!(
            store
                .blob_meta_get(content.kappa(), "_s3_checksum_crc32c")
                .is_err()
        );
        execution.publish()?;
        assert_eq!(
            hex::encode(store.blob_meta_get(content.kappa(), "_s3_checksum_crc32c")?),
            "e3069283"
        );
        assert_eq!(
            hex::encode(store.blob_meta_get(content.kappa(), "_s3_checksum_crc64nvme")?),
            "ae8b14860a799888"
        );
        let edges = store.edge_query(
            &ns,
            &kappa_store::edge::EdgeQuery {
                anchor: content.kappa().clone(),
                direction: kappa_store::edge::Direction::Outbound,
                relation: Some(kappa_store::edge::EdgeRelation::Builtin(
                    kappa_store::edge::BuiltinRelation::ChunkManifest,
                )),
                asserter: Some(owner),
            },
            &kappa_store::PageRequest::first(10),
        )?;
        assert_eq!(edges.items.len(), 1);
        let manifest: serde_json::Value =
            serde_json::from_slice(&store.blob_get(edges.items[0].target())?)?;
        assert_eq!(manifest["total_parts"], 2);
        assert_eq!(manifest["parts"][0]["part_number"], 2);
        assert_eq!(manifest["parts"][1]["part_number"], 9);
        assert_eq!(manifest["parts"][1]["offset"], 4);
        assert_eq!(manifest["parts"][1]["size"], 5);
        Ok(())
    }
}
