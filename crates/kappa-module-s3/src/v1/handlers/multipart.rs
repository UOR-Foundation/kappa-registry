//! Multipart uploads over staged resources.
//!
//! A multipart upload is a numbered resource in the bucket's namespace
//! (`kappa_store::resource`) whose head binds the object key, so every
//! request addressing the upload, including a replay of its completed
//! outcome, is checked against the key the upload was created for. Each
//! part is prepared outside the writer and staged in its slot in one
//! epoch, with MD5 and CRC checksums in the member receipt so the ETag the client echoes
//! back is validated against committed state.
//!
//! Completion validates the client's part list (ascending, matching ETags,
//! S3's 5 MiB minimum for nonfinal parts) inside the execution that
//! freezes the selection, against the very membership it freezes, so the
//! parts the client's ETags named are the parts the generation holds: a
//! concurrent part replacement is serialized by the store's writer either
//! before this execution (and is what it validates) or after it (and is
//! refused, admission having closed). The composite ETag (MD5 of the
//! concatenated part MD5s, followed by the part count) is recorded in the
//! completion binding, so a retry replays it from committed state. The
//! assembly, the object's tag and its metadata publish in one epoch.

use md5::Digest;
use topcoat::context::{Cx, request_context};
use topcoat::router::{Body, StatusCode};

use kappa_handler::{HandlerError, Outcome, WriteTarget, blocking, prepare_body, principal};
use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::resource::{self, Member};
use kappa_store::tag::TagUpdate;
use kappa_store::{ContentIdentity, ResourceKind};

use super::{
    NewObjectMeta, bucket_read, ensure_bucket, parse_query, path_param, s3_response,
    set_object_meta, store,
};

pub const MAX_PART_NUMBER: u64 = 10_000;
pub const MIN_NONFINAL_PART_SIZE: u64 = 5 * 1024 * 1024;
/// Multipart uploads not completed within this window expire.
const UPLOAD_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;

fn upload_id(cx: &Cx) -> Result<String, HandlerError> {
    parse_query(cx).get("uploadId").cloned().ok_or_else(|| {
        HandlerError::protocol(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "missing uploadId",
        )
    })
}

fn no_such_upload() -> HandlerError {
    HandlerError::protocol(StatusCode::NOT_FOUND, "NoSuchUpload", "upload not found")
}

fn part_etag(md5: &[u8]) -> String {
    format!("\"{}\"", hex::encode(md5))
}

/// The composite ETag a completion binding recorded.
fn receipt_text(binding: &kappa_store::ResourceCompletion) -> Result<String, HandlerError> {
    String::from_utf8(
        binding
            .receipt
            .clone()
            .ok_or_else(|| HandlerError::internal("completed multipart without its ETag"))?,
    )
    .map_err(|_| HandlerError::internal("completed multipart ETag is not text"))
}

/// Resolve the upload and check it was created for `key`: the key is the
/// head's context, committed at open and carried through completion, so
/// an upload cannot complete or replay under another key.
async fn resolve_upload(
    cx: &Cx,
    ns: &kappa_store::NamespaceRef,
    key: &str,
    id: &str,
) -> Result<resource::Resource, HandlerError> {
    let s = store(cx);
    let ns = ns.clone();
    let key = key.to_string();
    let id = id.to_string();
    blocking(move || {
        let resource = resource::resolve(&*s, &ns, &id)?
            .filter(|resource| resource.head.context.as_deref() == Some(key.as_bytes()))
            .ok_or_else(|| StoreError::NotFound("NoSuchUpload".into()))?;
        Ok::<_, StoreError>(resource)
    })
    .await
    .map_err(|error| match error {
        HandlerError::Store(StoreError::NotFound(_)) => no_such_upload(),
        error => error,
    })
}

/// CreateMultipartUpload. The first write to a missing bucket creates it in
/// its own epoch before the upload opens against it.
pub async fn initiate(cx: &Cx) -> Result<topcoat::router::response::Response, HandlerError> {
    let bucket = path_param(cx, "bucket")?;
    let key = path_param(cx, "key")?;
    let ns = ensure_bucket(cx).await?.namespace;
    let now = kappa_handler::clock_now(cx)?;
    let max_size = super::max_object_body(cx) as u64;
    let asserter = principal(cx);
    let expires_at = now.add_physical_ms(UPLOAD_TTL_MS);
    let object_key = key.clone().into_bytes();
    // Reserved while the open publishes. The work holds the reservation,
    // so it is returned on the worker after `execute` projected the
    // published head, never by a dropped request.
    let admission = kappa_handler::staging_budget(cx)?.admit_open()?;
    let committed = kappa_handler::execute(
        cx,
        WriteTarget::existing(ns),
        &[],
        admission.held_by(move |execution| {
            let head = resource::open(
                execution,
                &asserter,
                ResourceKind::Numbered,
                max_size,
                expires_at,
                Some(object_key.clone()),
            )?;
            Ok(Outcome::Publish(head.id()))
        }),
    )
    .await?;
    let xml = crate::xml::encode_initiate_multipart_xml(&bucket, &key, &committed.value);
    let mut response = s3_response(StatusCode::OK, xml);
    committed.annotate(&mut response);
    Ok(response)
}

pub async fn upload_part(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let ns = bucket_read(cx)?;
    let key = path_param(cx, "key")?;
    let number = parse_query(cx)
        .get("partNumber")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|number| (1..=MAX_PART_NUMBER).contains(number))
        .ok_or_else(|| {
            HandlerError::protocol(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "partNumber must be between 1 and 10000",
            )
        })?;
    let id = upload_id(cx)?;
    let data = kappa_handler::read_body(body, super::max_object_body(cx)).await?;
    let resource = resolve_upload(cx, &ns, &key, &id).await?;
    // Reserved from preparation until the stage publishes. The work holds
    // the reservation, so it is returned on the worker after `execute`
    // projected the staged total, never by a dropped request.
    let admission = kappa_handler::staging_budget(cx)?.admit_bytes(data.len() as u64)?;
    let receipt = blocking({
        let data = data.clone();
        move || Ok::<_, StoreError>(super::multipart_list::part_receipt(&data))
    })
    .await?;
    let etag = part_etag(super::multipart_list::part_md5(&receipt)?);
    let prepared = prepare_body(
        cx,
        ContentIdentity::Computed(kappa_store::Axis::Sha256),
        data.to_vec(),
    )
    .await?;
    let asserter = principal(cx);
    let resource_id = resource.head.id();
    let committed = kappa_handler::execute(
        cx,
        WriteTarget::existing(ns),
        &[],
        admission.held_by(move |execution| {
            resource::stage(
                execution,
                &asserter,
                &resource_id,
                kappa_handler::take_prepared(&prepared)?,
                number,
                Some(receipt.clone()),
            )?;
            Ok(Outcome::Publish(etag.clone()))
        }),
    )
    .await?;
    let mut resp = topcoat::router::response::Response::new(Body::empty());
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        "etag",
        committed
            .value
            .parse()
            .map_err(|error| HandlerError::internal(format!("invalid part ETag: {error}")))?,
    );
    committed.annotate(&mut resp);
    Ok(resp)
}

/// Validate the client's part list against the members the execution
/// sees: ascending distinct numbers, ETags equal to the committed receipts,
/// every nonfinal part at least 5 MiB. Returns the selected members in
/// order and the composite ETag. Runs inside the execution that freezes the
/// selection, over the membership it freezes.
fn select_parts<'a>(
    members: &'a [Member],
    requested: &[(u32, String)],
) -> Result<(Vec<&'a Member>, String), HandlerError> {
    let invalid =
        |code: &str, message: &str| HandlerError::protocol(StatusCode::BAD_REQUEST, code, message);
    if requested.is_empty() || requested.len() as u64 > MAX_PART_NUMBER {
        return Err(invalid(
            "InvalidPart",
            "completion requires 1 to 10000 parts",
        ));
    }
    let mut selected = Vec::with_capacity(requested.len());
    let mut ordered: Vec<_> = members.iter().collect();
    ordered.sort_unstable_by_key(|member| member.coordinate.position);
    let mut digest = md5::Md5::new();
    let mut previous = 0u64;
    for (index, (number, etag)) in requested.iter().enumerate() {
        let number = u64::from(*number);
        if !(1..=MAX_PART_NUMBER).contains(&number) {
            return Err(invalid(
                "InvalidArgument",
                "part number must be between 1 and 10000",
            ));
        }
        if number <= previous {
            return Err(invalid("InvalidPartOrder", "parts must be ascending"));
        }
        let index_in_members = ordered
            .binary_search_by_key(&number, |member| member.coordinate.position)
            .map_err(|_| invalid("InvalidPart", &format!("missing part {number}")))?;
        let member = ordered[index_in_members];
        let receipt = member
            .coordinate
            .receipt
            .as_deref()
            .ok_or_else(|| HandlerError::internal("multipart member without an MD5 receipt"))?;
        let md5 = super::multipart_list::part_md5(receipt)?;
        if part_etag(md5).trim_matches('"') != etag.trim_matches('"') {
            return Err(invalid(
                "InvalidPart",
                &format!("ETag mismatch for part {number}"),
            ));
        }
        if index + 1 < requested.len() && member.coordinate.length < MIN_NONFINAL_PART_SIZE {
            return Err(invalid(
                "EntityTooSmall",
                "nonfinal part is smaller than 5 MiB",
            ));
        }
        digest.update(md5);
        selected.push(member);
        previous = number;
    }
    let etag = format!("\"{}-{}\"", hex::encode(digest.finalize()), selected.len());
    Ok((selected, etag))
}

/// Outcome of the freezing phase, decided against the head the execution
/// sees: the request's completion already committed by another execution
/// (replayed, nothing to do), or the generation frozen for it with the
/// composite ETag derived from the frozen members' receipts.
enum Phase {
    Replay(String),
    Frozen { generation: Kappa, etag: String },
}

/// CompleteMultipartUpload. Part assembly, the object's tag, and its
/// metadata publish together in one epoch. A completion whose request
/// already bound the head replays its result.
pub async fn complete(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let ns = bucket_read(cx)?;
    let bucket = path_param(cx, "bucket")?;
    let key = path_param(cx, "key")?;
    let id = upload_id(cx)?;
    let content_type = {
        let parts: &http::request::Parts = request_context(cx);
        parts
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let body_bytes = kappa_handler::read_body(body, super::MAX_BATCH_DELETE_BODY).await?;
    let client_parts = super::multipart_xml::parse(&body_bytes)?;
    let resource = resolve_upload(cx, &ns, &key, &id).await?;
    let s = store(cx);
    let resource_id = resource.head.id();
    // The completion request is the client's part list. Its committed
    // outcome is resolved first; a retry replays the committed ETag.
    let request = Kappa::sha256(&body_bytes);
    let resolution = blocking({
        let s = s.clone();
        let ns = ns.clone();
        let resource_id = resource_id.clone();
        let request = request.clone();
        move || resource::resolve_completion(&*s, &ns, &resource_id, &request)
    })
    .await?
    .ok_or_else(no_such_upload)?;
    let etag = match resolution {
        resource::Resolution::Replay(binding) => receipt_text(&binding)?,
        resource::Resolution::Pending(_) => {
            // Validate the part list against the membership the execution
            // sees and freeze exactly that selection with the request, in
            // one epoch: the ETags validated are the receipts of the
            // members frozen. A phase of this request: the request's
            // operation identity binds the completing execution below.
            let asserter = principal(cx);
            let phase = kappa_handler::execute_phase(cx, WriteTarget::existing(ns.clone()), {
                let client_parts = client_parts.clone();
                let resource_id = resource_id.clone();
                let request = request.clone();
                move |execution| {
                    let head = resource::resolve_in(execution, &resource_id)?
                        .ok_or_else(no_such_upload)?
                        .head;
                    // The resolution above this execution is not
                    // authoritative: the request may have completed since.
                    // The head this execution sees decides.
                    if let (kappa_store::ResourcePhase::Completed, Some(binding)) =
                        (&head.phase, &head.completion)
                    {
                        if binding.request != request {
                            return Err(HandlerError::Store(StoreError::Conflict(format!(
                                "resource {resource_id} was completed by another request"
                            ))));
                        }
                        return Ok(Outcome::Discard(Phase::Replay(receipt_text(binding)?)));
                    }
                    let members = resource::members_in(execution, &head)?;
                    let (selected, etag) = select_parts(&members, &client_parts)?;
                    let positions: Vec<u64> =
                        selected.iter().map(|m| m.coordinate.position).collect();
                    let prepared = resource::prepare(
                        execution,
                        &asserter,
                        &resource_id,
                        &request,
                        &positions,
                    )?;
                    let frozen = Phase::Frozen {
                        generation: prepared.generation,
                        etag,
                    };
                    // A generation already frozen for this request is
                    // reused; nothing was written and nothing publishes.
                    Ok(if prepared.frozen {
                        Outcome::Publish(frozen)
                    } else {
                        Outcome::Discard(frozen)
                    })
                }
            })
            .await?
            .value;
            let (generation, etag) = match phase {
                Phase::Replay(etag) => {
                    let xml = crate::xml::encode_complete_multipart_xml(&bucket, &key, &etag);
                    return Ok(s3_response(StatusCode::OK, xml));
                }
                Phase::Frozen { generation, etag } => (generation, etag),
            };
            // Stream and verify exactly that generation outside the writer,
            // bounded like every other preparation and by the request.
            let deadline = kappa_handler::request_deadline(cx, kappa_handler::PREPARATION_DEADLINE);
            let evidence = blocking({
                let s = s.clone();
                let ns = ns.clone();
                let resource_id = resource_id.clone();
                move || {
                    resource::prepare_composition(
                        &*s,
                        &ns,
                        &resource_id,
                        &generation,
                        kappa_store::Axis::Sha256,
                        deadline,
                    )
                }
            })
            .await?;
            let asserter = principal(cx);
            let object_key = key.clone();
            let receipt = etag.clone();
            let committed = kappa_handler::execute(
                cx,
                WriteTarget::existing(ns.clone()),
                &body_bytes,
                move |execution| {
                    let head = resource::resolve_in(execution, &resource_id)?
                        .ok_or_else(no_such_upload)?
                        .head;
                    let selected = if head.phase == kappa_store::ResourcePhase::Completed {
                        Vec::new()
                    } else {
                        let members = resource::members_in(execution, &head)?;
                        select_parts(&members, &client_parts)?
                            .0
                            .into_iter()
                            .cloned()
                            .collect()
                    };
                    let completed = resource::complete(
                        execution,
                        &asserter,
                        &resource_id,
                        &evidence,
                        Some(receipt.clone().into_bytes()),
                    )?;
                    // Completed concurrently by the same request: its
                    // committed ETag is returned and the object is not
                    // written again, so an overwrite since then stands.
                    if completed.replayed {
                        return Ok(Outcome::Discard(receipt_text(&completed.binding)?));
                    }
                    super::multipart_list::persist_manifest(
                        execution,
                        &completed.installed.kappa,
                        &asserter,
                        &selected,
                    )?;
                    execution.tag_put(
                        &object_key,
                        &TagUpdate::Set {
                            kappa: completed.installed.kappa.clone(),
                        },
                    )?;
                    set_object_meta(
                        execution,
                        &object_key,
                        &NewObjectMeta {
                            content_type: content_type.as_deref(),
                            etag: &receipt,
                            tags: None,
                        },
                    )?;
                    Ok(Outcome::Publish(receipt.clone()))
                },
            )
            .await?;
            committed.value
        }
    };

    let xml = crate::xml::encode_complete_multipart_xml(&bucket, &key, &etag);
    Ok(s3_response(StatusCode::OK, xml))
}

/// AbortMultipartUpload. Aborting an unknown upload succeeds.
pub async fn abort(cx: &Cx) -> Result<topcoat::router::response::Response, HandlerError> {
    let ns = bucket_read(cx)?;
    let key = path_param(cx, "key")?;
    let id = upload_id(cx)?;
    let resource = match resolve_upload(cx, &ns, &key, &id).await {
        Ok(resource) => resource,
        Err(HandlerError::Protocol { .. }) | Err(HandlerError::NotFound { .. }) => {
            return Ok(kappa_handler::empty_response(StatusCode::NO_CONTENT));
        }
        Err(error) => return Err(error),
    };
    let asserter = principal(cx);
    let resource_id = resource.head.id();
    kappa_handler::execute(cx, WriteTarget::existing(ns), &[], move |execution| {
        Ok(if resource::discard(execution, &asserter, &resource_id)? {
            Outcome::Publish(())
        } else {
            Outcome::Discard(())
        })
    })
    .await?;
    Ok(kappa_handler::empty_response(StatusCode::NO_CONTENT))
}
