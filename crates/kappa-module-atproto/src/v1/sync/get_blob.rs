use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use crate::protocol_id;
use kappa_handler::{HandlerError, blocking, query_required, store, stream_blob};
use kappa_store::error::StoreError;

/// GET /xrpc/com.atproto.sync.getBlob
///
/// Streams a blob by DID + CID. The CID is an AT Protocol content
/// identifier that maps to a kappa via the blob/{cid_hex} bridge tag.
/// The blob is streamed via streaming_response with 64 KB chunks.
/// Content-type comes from blob metadata stored at upload time.
pub async fn get_blob(
    cx: &Cx,
    _body: Body, // GET — body not expected
) -> Result<topcoat::router::response::Response, HandlerError> {
    let did = query_required(cx, "did")?;
    let cid_param = query_required(cx, "cid")?;
    let s = store(cx);

    // Phase 1: resolve DID namespace, CID bridge tag, blob metadata.
    // All blocking IO in one spawn_blocking call.
    let (ns, kappa, content_type) = blocking({
        let s = s.clone();
        move || {
            let ns = s
                .namespace_resolve(&did, Some(protocol_id()))
                .map_err(|e| match e {
                    StoreError::NotFound(_) => HandlerError::protocol(
                        StatusCode::NOT_FOUND,
                        "RepoNotFound",
                        format!("repository not found: {did}"),
                    ),
                    other => HandlerError::Store(other),
                })?;
            let tag_name = format!("blob/{}", cid_param);
            let entry = s.tag_get(&ns, &tag_name).map_err(|e| match e {
                StoreError::NotFound(_) => HandlerError::protocol(
                    StatusCode::NOT_FOUND,
                    "BlobNotFound",
                    format!("blob not found: {cid_param}"),
                ),
                other => HandlerError::Store(other),
            })?;
            let ct = match s.blob_meta_get_in(&ns, &entry.kappa, "content-type") {
                Ok(bytes) => String::from_utf8(bytes).map_err(|error| {
                    HandlerError::internal(format!("blob content-type is not UTF-8: {error}"))
                })?,
                Err(StoreError::NotFound(_)) => "application/octet-stream".to_string(),
                Err(error) => return Err(HandlerError::Store(error)),
            };
            Ok::<_, HandlerError>((ns, entry.kappa, ct))
        }
    })
    .await?;

    stream_blob(cx, s, &ns, &kappa, &content_type).await
}
