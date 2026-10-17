use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{
    HandlerError, Outcome, blocking, execute, path_param, read_body, streaming_response,
};
use kappa_store::axis::Axis;
use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::tag::TagUpdate;
use kappa_store::{Execution, KappaStore, absent};

use crate::handlers::{nix_ns, nix_target};
use crate::publish::{nar_identity, nar_ref_key, nar_tag};

fn extract_path(cx: &Cx) -> Result<String, HandlerError> {
    let p = path_param(cx, "path")?;
    if p.is_empty() {
        return Err(HandlerError::bad_request("missing path parameter"));
    }
    Ok(p)
}

fn max_nar_body(cx: &Cx) -> usize {
    kappa_handler::try_service::<kappa_handler::MaxBlobSize>(cx)
        .map(|m| m.0)
        .unwrap_or(256 * 1024 * 1024)
}

/// GET /_nix/nar/{*path}: stream compressed NAR.
/// Uses streaming_response for zero-materialization delivery.
pub async fn get(
    cx: &Cx,
    _body: Body, // GET: body not expected
) -> Result<topcoat::router::response::Response, HandlerError> {
    let nix_ns = nix_ns(cx)?;
    let path = extract_path(cx)?;
    let s = kappa_handler::store(cx);
    let tag_name = nar_tag(&path);

    // Phase 1: resolve tag to kappa and get compressed blob size.
    let (reader, size) = blocking({
        let s = s.clone();
        let nix_ns = nix_ns.clone();
        move || {
            let entry = s.tag_get(&nix_ns, &tag_name)?;
            let mut reader = s.blob_open_in(&nix_ns, &entry.kappa)?;
            // The retained reader addresses stored bytes, including compression.
            let size = reader.seek(std::io::SeekFrom::End(0))?;
            reader.seek(std::io::SeekFrom::Start(0))?;
            Ok::<_, StoreError>((reader, size))
        }
    })
    .await?;

    // Phase 2: stream compressed blob.
    let (resp, writer) = streaming_response(cx, "application/x-nix-nar", Some(size), 16)?;

    tokio::task::spawn_blocking(move || {
        let mut reader = reader;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match std::io::Read::read(&mut *reader, &mut buf) {
                Ok(0) => {
                    writer.mark_completed();
                    break;
                }
                Ok(n) => {
                    if let Err(e) = writer.send(bytes::Bytes::copy_from_slice(&buf[..n])) {
                        writer.report_error(e);
                        return;
                    }
                }
                Err(io_err) => {
                    writer
                        .report_error(HandlerError::internal(format!("NAR read error: {io_err}")));
                    return;
                }
            }
        }
    });

    Ok(resp)
}

/// PUT /_nix/nar/{*path}: ingest a NAR and publish its tag.
///
/// The NAR bytes are prepared outside the writer and installed by the
/// execution that publishes the tag. When a narinfo already names this
/// path, the NAR is verified against it first: a match is also prepared
/// compressed under its uncompressed identity and tagged there; a mismatch
/// removes the narinfo. Installation, the tag change, and any narinfo
/// removal publish in one execution of `_nix`.
pub async fn put(cx: &Cx, body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let path = extract_path(cx)?;
    let target = nix_target(cx).await?;
    let content = read_body(body, max_nar_body(cx)).await?;
    let s = kappa_handler::store(cx);
    let namespace = target.namespace().clone();
    let prepared = kappa_handler::prepare_body(
        cx,
        kappa_store::ContentIdentity::Computed(Axis::Sha256),
        content.to_vec(),
    )
    .await?;
    let deadline = std::time::Instant::now() + kappa_handler::PREPARATION_DEADLINE;
    let deferred = blocking({
        let content = content.clone();
        let path = path.clone();
        move || deferred_verification(&*s, &namespace, &path, &content, deadline)
    })
    .await?;

    let mut deferred = deferred;
    let committed = execute(cx, target, &content, move |execution| {
        let ingested = execution.content_install(kappa_handler::take_prepared(&prepared)?)?;
        write_nar(execution, &path, &ingested.kappa, deferred.as_mut())
    })
    .await?;

    let mut response = kappa_handler::empty_response(StatusCode::CREATED);
    committed.annotate(&mut response);
    Ok(response)
}

/// The narinfo that names a NAR path: its tag and published content.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Referrer {
    tag: String,
    narinfo: Kappa,
}

/// Outcome of verifying an uploaded NAR against its narinfo.
enum Verdict {
    /// The NAR matches; its compressed form is prepared under this
    /// uncompressed identity for the execution to install.
    Verified {
        identity: Kappa,
        prepared: Option<Box<dyn kappa_store::PreparedContent>>,
    },
    /// The NAR contradicts the narinfo, which is removed.
    Failed,
}

struct Deferred {
    referrer: Referrer,
    verdict: Verdict,
}

fn decode_ref(raw: Vec<u8>) -> Result<String, StoreError> {
    String::from_utf8(raw)
        .map_err(|error| StoreError::Internal(format!("_nar_ref index corrupt: {error}")))
}

/// Published narinfo naming `path`. A reverse index entry whose narinfo tag
/// is gone names nothing.
fn published_referrer(
    store: &dyn KappaStore,
    namespace: &NamespaceRef,
    path: &str,
) -> Result<Option<Referrer>, StoreError> {
    let Some(raw) = absent(store.namespace_get_meta(namespace, &nar_ref_key(path)))? else {
        return Ok(None);
    };
    let tag = decode_ref(raw)?;
    Ok(
        absent(store.tag_get(namespace, &tag))?.map(|entry| Referrer {
            tag,
            narinfo: entry.kappa,
        }),
    )
}

/// The same lookup through an execution, observing its writer-held view.
fn live_referrer(execution: &dyn Execution, path: &str) -> Result<Option<Referrer>, StoreError> {
    let Some(raw) = execution.namespace_get_meta(&nar_ref_key(path))? else {
        return Ok(None);
    };
    let tag = decode_ref(raw)?;
    Ok(execution.tag_get(&tag)?.map(|entry| Referrer {
        tag,
        narinfo: entry.kappa,
    }))
}

/// Verify an uploaded NAR against the narinfo naming its path, if any.
/// Runs before the execution: preparation of the compressed form happens
/// outside the writer; the execution installs it.
fn deferred_verification(
    store: &dyn KappaStore,
    namespace: &NamespaceRef,
    path: &str,
    content: &[u8],
    deadline: std::time::Instant,
) -> Result<Option<Deferred>, StoreError> {
    let Some(referrer) = published_referrer(store, namespace, path)? else {
        return Ok(None);
    };
    let narinfo_text = String::from_utf8(store.blob_get_in(namespace, &referrer.narinfo)?)
        .map_err(|error| StoreError::Internal(format!("narinfo blob not UTF-8: {error}")))?;
    let narinfo = crate::narinfo::NarInfo::parse(&narinfo_text)
        .map_err(|error| StoreError::Internal(format!("narinfo parse failed: {error}")))?;
    let verdict = match crate::refs::decompress_and_verify(
        content,
        &narinfo.compression,
        &narinfo.nar_hash,
        &narinfo.references,
    ) {
        Ok(()) => {
            let identity = nar_identity(&narinfo.nar_hash)?;
            let prepared = store.prepare_content(
                kappa_store::ContentIdentity::Compressed {
                    identity: identity.clone(),
                    algorithm: narinfo.compression.clone(),
                    uncompressed_size: narinfo.nar_size,
                },
                &mut &content[..],
                kappa_store::PreparationBounds {
                    maximum: content.len() as u64,
                    deadline,
                },
            )?;
            Verdict::Verified {
                identity,
                prepared: Some(prepared),
            }
        }
        Err(error) => {
            tracing::warn!(
                narinfo = %referrer.tag,
                error = %error,
                "deferred NAR verification failed, removing narinfo"
            );
            Verdict::Failed
        }
    };
    Ok(Some(Deferred { referrer, verdict }))
}

/// Publish the NAR tag and, after a failed verification, remove the
/// narinfo and its reverse index entry. The narinfo naming the path must be
/// the one verification observed. Re-uploading an already tagged NAR with
/// no narinfo to remove changes nothing and is discarded.
fn write_nar(
    execution: &mut dyn Execution,
    path: &str,
    ingested: &Kappa,
    deferred: Option<&mut Deferred>,
) -> Result<Outcome<()>, HandlerError> {
    let live = live_referrer(&*execution, path)?;
    if live.as_ref() != deferred.as_ref().map(|deferred| &deferred.referrer) {
        return Err(HandlerError::Conflict {
            reason: format!("narinfo for NAR {path} changed during upload; retry"),
        });
    }
    let mut changed = false;
    let kappa = match deferred {
        Some(Deferred {
            verdict: Verdict::Verified { identity, prepared },
            ..
        }) => {
            if let Some(prepared) = prepared.take() {
                let installed = execution.content_install(prepared)?;
                changed |= installed.newly_stored;
            }
            identity.clone()
        }
        Some(Deferred {
            referrer,
            verdict: Verdict::Failed,
        }) => {
            execution.tag_delete(&referrer.tag)?;
            execution.namespace_delete_meta(&nar_ref_key(path))?;
            changed = true;
            ingested.clone()
        }
        None => ingested.clone(),
    };
    let tag = nar_tag(path);
    if !execution
        .tag_get_raw(&tag)?
        .is_some_and(|entry| entry.kappa == kappa && entry.symref.is_none())
    {
        execution.tag_put(&tag, &TagUpdate::Set { kappa })?;
        changed = true;
    }
    Ok(if changed {
        Outcome::Publish(())
    } else {
        Outcome::Discard(())
    })
}
