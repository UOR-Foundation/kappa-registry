//! Blob upload sessions over staged resources.
//!
//! An upload is a sequential resource in the repository's namespace
//! (`kappa_store::resource`). Start publishes its head; each chunk is
//! prepared outside the writer, then staged at its offset in one epoch;
//! completion assembles the members, verifies the claimed digest against
//! the assembled identity, and publishes the repository's reference to it
//! (`_blob/{kappa}`, as a monolithic push does) in the completing epoch;
//! cancel discards the resource. Progress and retries read the committed head, so a lost
//! response never duplicates bytes: a chunk whose offset the head already
//! passed is refused as out of order.

use topcoat::context::Cx;
use topcoat::router::response::Response;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{
    HandlerError, Outcome, WriteTarget, blocking, clock_now, empty_response, execute, path_param,
    prepare_body, principal, query_optional, read_body, store,
};
use kappa_store::kappa::Kappa;
use kappa_store::resource::{self, Resource};
use kappa_store::{ContentIdentity, ResourceKind, StoreError};

use crate::header;

/// Uploads not completed within this window expire; the expiry task
/// discards them in an epoch.
const UPLOAD_TTL_MS: u64 = 24 * 60 * 60 * 1000;

fn session_unknown(id: &str) -> HandlerError {
    HandlerError::NotFound {
        reason: format!("upload session {id} not found or expired"),
    }
}

fn zero_length(resp: &mut Response) {
    resp.headers_mut()
        .insert("content-length", http::HeaderValue::from_static("0"));
}

/// The repository namespace of an upload is encoded in its id:
/// `{namespace display name}:{resource id}`.
fn parse_id(id: &str) -> Result<(String, String), HandlerError> {
    id.rsplit_once(':')
        .map(|(ns, resource)| (ns.to_string(), resource.to_string()))
        .ok_or_else(|| session_unknown(id))
}

async fn resolve_upload(
    cx: &Cx,
    id: &str,
) -> Result<(kappa_store::NamespaceRef, Resource), HandlerError> {
    let (ns_name, resource_id) = parse_id(id)?;
    let s = store(cx);
    let ns = blocking({
        let s = s.clone();
        move || s.namespace_resolve(&ns_name, Some(crate::protocol_id()))
    })
    .await
    .map_err(|_| session_unknown(id))?;
    let resource = blocking({
        let ns = ns.clone();
        let s = s.clone();
        move || resource::resolve(&*s, &ns, &resource_id)
    })
    .await?
    .ok_or_else(|| session_unknown(id))?;
    Ok((ns, resource))
}

pub async fn start(cx: &Cx, body: Body) -> Result<Response, HandlerError> {
    let bytes = read_body(body, usize::MAX).await?;
    let now = clock_now(cx)?;
    let digest = query_optional(cx, "digest");
    let mount = query_optional(cx, "mount");

    // Single-POST monolithic upload: digest provided + non-empty body
    if digest.is_some() && !bytes.is_empty() {
        return crate::blob::put(cx, Body::from(bytes.to_vec())).await;
    }
    let repository = crate::ensure_repository(cx).await?;
    let ns = repository.namespace.clone();
    let s = store(cx);

    // Mount: blob already exists, 201 with location, no session
    if let Some(kappa_str) = mount {
        let exists = match Kappa::parse(&kappa_str) {
            Ok(kappa) => {
                let s = s.clone();
                let ns = ns.clone();
                blocking(move || s.blob_exists_in(&ns, &kappa)).await?
            }
            Err(_) => false,
        };
        if exists {
            let mut resp = empty_response(StatusCode::CREATED);
            let h = resp.headers_mut();
            h.insert(
                "location",
                header(&format!("/v2/{}/blobs/{kappa_str}", ns.display_name()))?,
            );
            h.insert("docker-content-digest", header(&kappa_str)?);
            zero_length(&mut resp);
            repository.annotate(&mut resp);
            return Ok(resp);
        }
    }

    let max_size = kappa_handler::try_service::<kappa_handler::MaxBlobSize>(cx)
        .map_or(256 * 1024 * 1024, |m| m.0 as u64);
    let asserter = principal(cx);
    let expires_at = now.add_physical_ms(UPLOAD_TTL_MS);
    // One more open resource is reserved against the node's budget while
    // the session publishes. The work holds the reservation, so it is
    // returned on the worker after `execute` projected the published head
    // from the epoch's ledger, never by a dropped request.
    let admission = kappa_handler::staging_budget(cx)?.admit_open()?;
    let committed = execute(
        cx,
        WriteTarget::existing(ns.clone()),
        &[],
        admission.held_by(move |execution| {
            let head = resource::open(
                execution,
                &asserter,
                ResourceKind::Sequential,
                max_size,
                expires_at,
                None,
            )?;
            Ok(Outcome::Publish(head.id()))
        }),
    )
    .await?;
    let id = format!("{}:{}", ns.display_name(), committed.value);

    let mut resp = empty_response(StatusCode::ACCEPTED);
    let h = resp.headers_mut();
    h.insert("location", header(&format!("/v2/_uploads/{id}"))?);
    h.insert("x-kappa-upload-session", header(&id)?);
    h.insert(
        "x-kappa-chunk-min-length",
        http::HeaderValue::from_static("0"),
    );
    h.insert("oci-chunk-min-length", http::HeaderValue::from_static("0"));
    zero_length(&mut resp);
    repository.annotate(&mut resp);
    committed.annotate(&mut resp);
    Ok(resp)
}

/// Stage `data` at `offset` (or at the head's current length when no
/// range is given). Returns the total bytes staged.
async fn stage_chunk(
    cx: &Cx,
    ns: kappa_store::NamespaceRef,
    resource_id: String,
    offset: Option<u64>,
    data: Vec<u8>,
) -> Result<u64, HandlerError> {
    // The chunk's bytes are reserved against the node's staging budget
    // from preparation until the stage publishes. The work holds the
    // reservation, so it is returned on the worker after `execute`
    // projected the staged total, never by a dropped request.
    let admission = kappa_handler::staging_budget(cx)?.admit_bytes(data.len() as u64)?;
    let prepared = prepare_body(
        cx,
        ContentIdentity::Computed(kappa_store::Axis::Sha256),
        data,
    )
    .await?;
    let asserter = principal(cx);
    let committed = execute(
        cx,
        WriteTarget::existing(ns),
        &[],
        admission.held_by(move |execution| {
            let head = resource::resolve_in(execution, &resource_id)?
                .ok_or_else(|| HandlerError::NotFound {
                    reason: format!("upload session {resource_id} not found or expired"),
                })?
                .head;
            let position = offset.unwrap_or(head.total_bytes);
            let (head, _) = resource::stage(
                execution,
                &asserter,
                &resource_id,
                kappa_handler::take_prepared(&prepared)?,
                position,
                None,
            )?;
            Ok(Outcome::Publish(head.total_bytes.to_string()))
        }),
    )
    .await?;
    committed
        .value
        .parse::<u64>()
        .map_err(|error| HandlerError::internal(format!("staged total: {error}")))
}

pub async fn chunk(cx: &Cx, body: Body) -> Result<Response, HandlerError> {
    let bytes = read_body(body, usize::MAX).await?;
    let id_str = path_param(cx, "id")?;
    let range_start = topcoat::router::request::headers(cx)
        .get("content-range")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_range_start);
    let (ns, resource) = resolve_upload(cx, &id_str).await?;
    let result = stage_chunk(
        cx,
        ns,
        resource.head.id(),
        range_start.map(|s| s as u64),
        bytes.to_vec(),
    )
    .await;
    match result {
        Ok(total) => {
            let mut resp = empty_response(StatusCode::ACCEPTED);
            let h = resp.headers_mut();
            h.insert("range", header(&format!("0-{}", total.saturating_sub(1)))?);
            h.insert("location", header(&format!("/v2/_uploads/{id_str}"))?);
            zero_length(&mut resp);
            Ok(resp)
        }
        Err(HandlerError::Store(StoreError::NotFound(_)) | HandlerError::NotFound { .. }) => {
            crate::oci_error(
                StatusCode::NOT_FOUND,
                "BLOB_UPLOAD_UNKNOWN",
                "upload session not found",
            )
        }
        Err(HandlerError::Store(StoreError::Conflict(_))) => crate::oci_error(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "BLOB_UPLOAD_INVALID",
            "out-of-order chunk",
        ),
        Err(HandlerError::Store(StoreError::CapacityExceeded(ref msg))) => {
            crate::oci_error(StatusCode::PAYLOAD_TOO_LARGE, "SIZE_EXCEEDED", msg)
        }
        Err(e) => Err(e),
    }
}

pub async fn recovery(cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    let id_str = path_param(cx, "id")?;
    let (_, resource) = resolve_upload(cx, &id_str).await?;
    let mut resp = empty_response(StatusCode::NO_CONTENT);
    let h = resp.headers_mut();
    h.insert(
        "range",
        header(&format!(
            "0-{}",
            resource.head.total_bytes.saturating_sub(1)
        ))?,
    );
    h.insert("location", header(&format!("/v2/_uploads/{id_str}"))?);
    zero_length(&mut resp);
    Ok(resp)
}

pub async fn complete(cx: &Cx, body: Body) -> Result<Response, HandlerError> {
    let bytes = read_body(body, usize::MAX).await?;
    let id_str = path_param(cx, "id")?;
    let client_digest_str = query_optional(cx, "kappa")
        .or_else(|| query_optional(cx, "digest"))
        .ok_or_else(|| HandlerError::bad_request("missing digest or kappa query parameter"))?;
    let claimed = Kappa::parse(&client_digest_str)?;
    let content_type = topcoat::router::request::headers(cx)
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.as_bytes().to_vec());

    let (ns, resource) = resolve_upload(cx, &id_str).await?;
    let resource_id = resource.head.id();

    // The completion request is the claimed digest. Its committed outcome
    // is resolved first: a retry replays it from the head's binding and
    // never appends the final body again.
    let resolution = blocking({
        let s = store(cx);
        let ns = ns.clone();
        let resource_id = resource_id.clone();
        let claimed = claimed.clone();
        move || resource::resolve_completion(&*s, &ns, &resource_id, &claimed)
    })
    .await?
    .ok_or_else(|| session_unknown(&id_str))?;
    let result = match resolution {
        resource::Resolution::Replay(binding) => binding.result,
        resource::Resolution::Pending(pending) => {
            if !bytes.is_empty() && pending.head.phase == kappa_store::ResourcePhase::Open {
                stage_chunk(cx, ns.clone(), resource_id.clone(), None, bytes.to_vec()).await?;
            }
            complete_pending(
                cx,
                &ns,
                &resource_id,
                &claimed,
                &client_digest_str,
                content_type,
            )
            .await?
        }
    };

    let result_kappa = header(&result.to_string())?;
    let mut resp = empty_response(StatusCode::CREATED);
    let h = resp.headers_mut();
    h.insert("x-kappa-label", result_kappa.clone());
    h.insert("docker-content-digest", result_kappa);
    h.insert(
        "location",
        header(&format!("/v2/{}/blobs/{result}", ns.display_name()))?,
    );
    zero_length(&mut resp);
    Ok(resp)
}

/// Complete a pending upload whose final body, if any, is staged: freeze
/// the generation and bind `claimed` to it, stream and verify exactly that
/// generation outside the writer, then complete and publish the
/// repository's reference in one epoch. Returns the assembled identity.
async fn complete_pending(
    cx: &Cx,
    ns: &kappa_store::NamespaceRef,
    resource_id: &str,
    claimed: &Kappa,
    request: &str,
    content_type: Option<Vec<u8>>,
) -> Result<Kappa, HandlerError> {
    let s = store(cx);
    // Freeze the generation and bind the request (epoch-committed). A phase
    // of this request: the request's operation identity binds the
    // completing execution below.
    let asserter = principal(cx);
    let prepared = kappa_handler::execute_phase(cx, WriteTarget::existing(ns.clone()), {
        let resource_id = resource_id.to_string();
        let claimed = claimed.clone();
        move |execution| {
            let prepared = resource::prepare(execution, &asserter, &resource_id, &claimed, &[])?;
            // A generation already frozen for this digest is reused;
            // nothing was written and nothing publishes.
            Ok(if prepared.frozen {
                Outcome::Publish(prepared.generation)
            } else {
                Outcome::Discard(prepared.generation)
            })
        }
    })
    .await?;
    let generation = prepared.value;
    // Stream and verify exactly that generation outside the writer, bounded
    // like every other preparation and by the request.
    let deadline = kappa_handler::request_deadline(cx, kappa_handler::PREPARATION_DEADLINE);
    let evidence = blocking({
        let ns = ns.clone();
        let resource_id = resource_id.to_string();
        let claimed = claimed.clone();
        move || {
            let evidence = resource::prepare_composition(
                &*s,
                &ns,
                &resource_id,
                &generation,
                claimed.axis(),
                deadline,
            )?;
            if evidence.identity() != &claimed {
                return Err(StoreError::Rejected(format!(
                    "digest mismatch: claimed {claimed}, computed {}",
                    evidence.identity()
                )));
            }
            Ok::<_, StoreError>(evidence)
        }
    })
    .await?;
    let asserter = principal(cx);
    let resource_id = resource_id.to_string();
    let committed = execute(
        cx,
        WriteTarget::existing(ns.clone()),
        request.as_bytes(),
        move |execution| {
            let completed =
                resource::complete(execution, &asserter, &resource_id, &evidence, None)?;
            // Completed concurrently by the same request: its committed
            // outcome is returned and nothing is written again, so a
            // reference moved since then is not reverted.
            if completed.replayed {
                return Ok(Outcome::Discard(completed.binding.result));
            }
            // The repository's claim on the assembled blob, in the same
            // epoch as the completion: the reference retains the content
            // once the member edges are retired, and reads resolve through
            // it as for a monolithic push.
            crate::blob::publish_reference(
                execution,
                &completed.installed.kappa,
                content_type.as_deref(),
            )?;
            Ok(Outcome::Publish(completed.installed.kappa))
        },
    )
    .await?;
    Ok(committed.value)
}

pub async fn cancel(cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    let id_str = path_param(cx, "id")?;
    let (ns, resource) = resolve_upload(cx, &id_str).await?;
    let asserter = principal(cx);
    let resource_id = resource.head.id();
    execute(cx, WriteTarget::existing(ns), &[], move |execution| {
        Ok(if resource::discard(execution, &asserter, &resource_id)? {
            Outcome::Publish(())
        } else {
            Outcome::Discard(())
        })
    })
    .await?;
    Ok(empty_response(StatusCode::NO_CONTENT))
}

fn parse_range_start(v: &str) -> Option<usize> {
    let v = v.trim();
    let v = v.strip_prefix("bytes").map_or(v, str::trim);
    let range = v.split('/').next().unwrap_or(v);
    range.split('-').next()?.trim().parse().ok()
}
