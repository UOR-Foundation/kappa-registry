//! Manifest endpoints.
//!
//! A manifest push publishes its content, content-type metadata, tags, and
//! subject referrer edge in one execution; a repository first written by the
//! push is created inside that same execution.

use futures_util::StreamExt;
use http_body::Frame;
use http_body_util::StreamBody;
use topcoat::context::Cx;
use topcoat::router::response::Response;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{
    HandlerError, Outcome, blocking, caller_anchor, empty_response, execute, path_param,
    query_optional, read_body, resolve_ns_read, store, write_target,
};
use kappa_store::edge::{EdgeInput, EdgeRelation, SemanticRelation};
use kappa_store::kappa::Kappa;
use kappa_store::tag::TagUpdate;
use kappa_store::verified::VerifiedContent;

use crate::blob::STREAM_CHUNK_SIZE;
use crate::header;
use crate::tags::list_all_tags;

const DEFAULT_MAX_MANIFEST: usize = 256 * 1024 * 1024;

/// A manifest push as parsed from the request, before anything is stored.
struct Push {
    kappa: Kappa,
    content: Vec<u8>,
    content_type: String,
    tags: Vec<String>,
    subject: Option<(Kappa, Kappa)>,
}

pub async fn put(cx: &Cx, body: Body) -> Result<Response, HandlerError> {
    let max_size = kappa_handler::try_service::<kappa_handler::MaxBlobSize>(cx)
        .map_or(DEFAULT_MAX_MANIFEST, |m| m.0);
    let bytes = read_body(body, max_size).await?;
    let target = write_target(cx)?;
    let reference = path_param(cx, "reference")?;
    let content_type = topcoat::router::request::headers(cx)
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/vnd.oci.image.manifest.v1+json")
        .to_string();
    let content = bytes.to_vec();

    // The client chooses the digest algorithm; a tag reference is
    // addressed by sha256.
    let (kappa, reference_tag) = match Kappa::parse(&reference) {
        Ok(parsed) => {
            VerifiedContent::verify(&parsed, &content)?;
            (parsed, None)
        }
        Err(_) if looks_like_bad_digest(&reference) => {
            return crate::oci_error(
                StatusCode::BAD_REQUEST,
                "DIGEST_INVALID",
                &format!("invalid digest format: {reference}"),
            );
        }
        Err(_) => (Kappa::sha256(&content), Some(reference)),
    };
    let extra_tag = query_optional(cx, "tag");
    let subject_label = parse_oci_subject(&content);
    let subject = match &subject_label {
        Some(label) => Some((Kappa::parse(label)?, referrer_asserter(cx)?)),
        None => None,
    };
    let push = Push {
        kappa,
        content,
        content_type,
        tags: reference_tag.into_iter().chain(extra_tag.clone()).collect(),
        subject,
    };

    let s = store(cx);
    // The manifest bytes are prepared outside the writer; admission and
    // installation run inside the execution.
    let prepared = kappa_handler::prepare_body(
        cx,
        kappa_store::ContentIdentity::Verified(push.kappa.clone()),
        push.content.clone(),
    )
    .await?;
    let committed = execute(cx, target, &bytes, move |execution| {
        // Admission reads the namespace's filters and schemas while the
        // execution holds the store's writer: rejected content is never
        // stored, and no rule can change before this push publishes.
        crate::admission::admit(&*s, execution.namespace(), &push.content)?;
        execution.content_install(kappa_handler::take_prepared(&prepared)?)?;
        // The repository's reference to the manifest and its content type
        // are namespace state, published with the push.
        crate::blob::publish_reference(execution, &push.kappa, Some(push.content_type.as_bytes()))?;
        kappa_store::blob_meta_put_indexed(execution, &push.kappa, "object-type", "manifest")?;
        for tag in &push.tags {
            execution.tag_put(
                tag,
                &TagUpdate::Set {
                    kappa: push.kappa.clone(),
                },
            )?;
        }
        if let Some((target, asserter)) = &push.subject {
            execution.edge_put(&EdgeInput {
                source: push.kappa.clone(),
                target: target.clone(),
                relation: EdgeRelation::Semantic(SemanticRelation(
                    kappa_store::edge::semantic::REFERENCES.into(),
                )),
                created_at_ms: execution.now().as_i64(),
                asserter: asserter.clone(),
                metadata: None,
            })?;
        }
        Ok(Outcome::Publish(push.kappa.clone()))
    })
    .await?;
    push_response(&committed, subject_label.as_deref(), extra_tag.as_deref())
}

/// The asserter of a pushed manifest's referrer edge, which the spec
/// requires: the caller, or the node identity for an anonymous push.
fn referrer_asserter(cx: &Cx) -> Result<Kappa, HandlerError> {
    caller_anchor(cx).map_or_else(
        || {
            kappa_handler::service::<std::sync::Arc<kappa_crypto::NodeIdentity>>(cx)
                .anchor()
                .map_err(|error| HandlerError::internal(format!("node identity: {error}")))
        },
        Ok,
    )
}

/// The 201 response of a published manifest push.
fn push_response(
    committed: &kappa_handler::Committed<Kappa>,
    subject: Option<&str>,
    tag: Option<&str>,
) -> Result<Response, HandlerError> {
    let digest = header(&committed.value.to_string())?;
    let mut resp = empty_response(StatusCode::CREATED);
    let h = resp.headers_mut();
    h.insert("x-kappa-label", digest.clone());
    h.insert("docker-content-digest", digest);
    h.insert(
        "location",
        header(&format!(
            "/v2/{}/manifests/{}",
            committed.namespace.display_name(),
            committed.value
        ))?,
    );
    h.insert("content-length", http::HeaderValue::from_static("0"));
    if let Some(subject) = subject {
        h.insert("oci-subject", header(subject)?);
    }
    if let Some(tag) = tag {
        h.insert("oci-tag", header(tag)?);
    }
    committed.annotate(&mut resp);
    Ok(resp)
}

pub async fn get(cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    let ns = resolve_ns_read(cx)?;
    let reference = path_param(cx, "reference")?;
    let s = store(cx);

    let kappa = resolve_reference(&s, &ns, &reference).await?;
    let (ct, size, reader) = blocking({
        let s = s.clone();
        let k = kappa.clone();
        let ns = ns.clone();
        move || {
            let ct = crate::blob::content_type(&*s, &ns, &k)?;
            let size = s.blob_size_in(&ns, &k)?;
            Ok::<_, HandlerError>((ct, size, s.blob_open_in(&ns, &k)?))
        }
    })
    .await?;

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(2);
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut reader = reader;
        let mut buf = vec![0u8; STREAM_CHUNK_SIZE];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx
                        .blocking_send(Ok(bytes::Bytes::copy_from_slice(&buf[..n])))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) => {
                    // A send failure means the client disconnected and
                    // dropped the receiver; there is nobody to report to.
                    let _ = tx.blocking_send(Err(e));
                    break;
                }
            }
        }
    });
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body_stream = StreamBody::new(stream.map(|r| {
        r.map(Frame::data)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }));

    let mut response = Response::new(Body::new(body_stream));
    *response.status_mut() = StatusCode::OK;
    manifest_headers(&mut response, &kappa, &ct, size)?;
    Ok(response)
}

pub async fn head(cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    let ns = resolve_ns_read(cx)?;
    let reference = path_param(cx, "reference")?;
    let s = store(cx);

    let kappa = resolve_reference(&s, &ns, &reference).await?;
    let (size, ct) = blocking({
        let k = kappa.clone();
        let ns = ns.clone();
        move || {
            let size = s.blob_size_in(&ns, &k)?;
            Ok::<_, HandlerError>((size, crate::blob::content_type(&*s, &ns, &k)?))
        }
    })
    .await?;

    let mut resp = empty_response(StatusCode::OK);
    manifest_headers(&mut resp, &kappa, &ct, size)?;
    Ok(resp)
}

fn manifest_headers(
    resp: &mut Response,
    kappa: &Kappa,
    content_type: &str,
    size: u64,
) -> Result<(), HandlerError> {
    let digest = header(&kappa.to_string())?;
    let h = resp.headers_mut();
    h.insert("content-type", header(content_type)?);
    h.insert("content-length", http::HeaderValue::from(size));
    h.insert("x-kappa-label", digest.clone());
    h.insert("docker-content-digest", digest);
    Ok(())
}

fn manifest_unknown(reference: &str) -> HandlerError {
    HandlerError::protocol(
        StatusCode::NOT_FOUND,
        "MANIFEST_UNKNOWN",
        format!("manifest {reference} is not known to this repository"),
    )
}

/// Manifest delete by digest or by tag.
///
/// Delete by digest retires the repository's reference to the manifest
/// and every tag naming it in one epoch. Delete by tag removes that tag.
/// The manifest content is shared across repositories and retained by
/// whatever still names it; content nothing names is reclaimed by the
/// sweep. An unknown manifest or tag is 404 `MANIFEST_UNKNOWN` and
/// publishes nothing.
pub async fn delete(cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    let target = write_target(cx)?;
    let reference = path_param(cx, "reference")?;
    let s = store(cx);

    let committed = if let Ok(digest) = Kappa::parse(&reference) {
        let reads = s.clone();
        execute(cx, target, &[], move |execution| {
            let reference_tag = crate::blob::reference_tag(&digest);
            if execution.tag_get_raw(&reference_tag)?.is_none() {
                return Err(manifest_unknown(&digest.to_string()));
            }
            // Read through the store while the execution holds its writer,
            // so no tag naming the manifest can publish before the deletion.
            let names: Vec<String> = list_all_tags(&*reads, execution.namespace(), None)?
                .into_iter()
                .filter(|tag| tag.kappa == digest && tag.symref.is_none())
                .map(|tag| tag.name)
                .collect();
            for name in &names {
                execution.tag_delete(name)?;
            }
            execution.tag_delete(&reference_tag)?;
            execution.namespace_delete_meta(&crate::blob::content_type_key(&digest))?;
            Ok(Outcome::Publish(()))
        })
        .await?
    } else {
        execute(cx, target, &[], move |execution| {
            // Checked before deleting: a failed delete would latch the
            // execution.
            if execution.tag_get_raw(&reference)?.is_none() {
                return Err(manifest_unknown(&reference));
            }
            execution.tag_delete(&reference)?;
            Ok(Outcome::Publish(()))
        })
        .await?
    };

    let mut resp = empty_response(StatusCode::ACCEPTED);
    committed.annotate(&mut resp);
    Ok(resp)
}

// -- Shared helpers -----------------------------------------------------------

/// Resolve a reference (tag name or digest string) to a manifest the
/// repository publishes. A digest the repository never referenced is
/// unknown here even when the content exists elsewhere.
async fn resolve_reference(
    s: &std::sync::Arc<dyn kappa_store::traits::KappaStore>,
    ns: &kappa_store::NamespaceRef,
    reference: &str,
) -> Result<Kappa, HandlerError> {
    let n = ns.clone();
    let r = reference.to_string();
    let s = s.clone();
    blocking(move || {
        if let Ok(kappa) = Kappa::parse(&r) {
            if crate::blob::referenced(&*s, &n, &kappa)? {
                return Ok(kappa);
            }
            return Err(manifest_unknown(&r));
        }
        s.tag_get(&n, &r)
            .map(|entry| entry.kappa)
            .map_err(HandlerError::from)
    })
    .await
}

fn looks_like_bad_digest(reference: &str) -> bool {
    reference.split_once(':').is_some_and(|(algo, _)| {
        matches!(
            algo,
            "sha1" | "sha256" | "blake3" | "sha3-256" | "keccak256" | "sha512"
        )
    })
}

fn parse_oci_subject(manifest_bytes: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(manifest_bytes).ok()?;
    v.get("subject")?.get("digest")?.as_str().map(String::from)
}
