use std::borrow::Cow;
use std::sync::Arc;
use std::time::Instant;

use topcoat::context::{Cx, try_request_context};
use topcoat::router::{Body, HeaderValue, Method, Path, RouterBuilder, StatusCode, request};

use kappa_handler::namespace::ResolvedNamespace;
use kappa_handler::{
    HandlerError, MaxBlobSize, Outcome, WriteTarget, blocking, caller_anchor, clock_now, read_body,
    store,
};
use kappa_store::{NamespaceRef, PreparationBounds, StoreError};

use crate::delta::DeltaBudget;
use crate::hooks;
use crate::lfs;
use crate::protocol;
use crate::protocol::ProtocolError;
use crate::protocol::advertisement;

/// Maximum LFS batch request body size.
const MAX_LFS_BATCH_BYTES: usize = 10 * 1024 * 1024;

fn p(s: &'static str) -> Cow<'static, Path> {
    Cow::Borrowed(Path::new(s))
}

/// Convert a HandlerError to a plain-text Git error response.
/// Git clients expect plain text error bodies, not JSON or XML.
/// Takes &HandlerError for handler_route! macro compatibility.
/// Returns a minimal 500 if response construction fails —
/// the error formatter is the last line of defense and must not panic.
fn git_error(e: &HandlerError) -> topcoat::router::response::Response {
    let status = e.status();
    let body = e.to_string();
    kappa_handler::binary_response(status, "text/plain", body.into_bytes())
        .unwrap_or_else(|_| kappa_handler::empty_response(StatusCode::INTERNAL_SERVER_ERROR))
}

/// Git route macro. Wraps async handlers with plain-text error conversion
/// via the shared handler_route! infrastructure.
macro_rules! git_route {
    ($method:expr, $path:expr, $handler:ident) => {
        kappa_handler::handler_route!($method, p($path), $handler, git_error)
    };
}

impl From<ProtocolError> for HandlerError {
    fn from(e: ProtocolError) -> Self {
        HandlerError::internal(e.to_string())
    }
}

/// Resolve an existing repository. Clone and fetch require it to exist.
fn git_read_ns(cx: &Cx) -> Result<NamespaceRef, HandlerError> {
    match try_request_context::<ResolvedNamespace>(cx) {
        Some(ResolvedNamespace::Exists(ns)) => Ok(ns.clone()),
        _ => Err(HandlerError::not_found("git namespace not found")),
    }
}

/// Write target for a push. A missing repository is created, owned by the
/// caller, by the execution that publishes its first refs; until then its
/// namespace holds no state and advertises no refs.
fn git_write_target(cx: &Cx) -> Result<WriteTarget, HandlerError> {
    match try_request_context::<ResolvedNamespace>(cx) {
        Some(ResolvedNamespace::Exists(ns)) => Ok(WriteTarget::existing(ns.clone())),
        Some(ResolvedNamespace::NotFound { name, protocol }) => {
            WriteTarget::create(name, caller_anchor(cx), protocol.clone(), clock_now(cx)?)
        }
        _ => Err(HandlerError::not_found("git namespace not found")),
    }
}

fn repo_object_hash(
    store: &dyn kappa_store::NamespaceStore,
    repo: &NamespaceRef,
) -> Result<gix_hash::Kind, HandlerError> {
    match store.namespace_get_meta(repo, "object_format") {
        Ok(bytes) => {
            if bytes == b"sha256" {
                Ok(gix_hash::Kind::Sha256)
            } else {
                Ok(gix_hash::Kind::Sha1)
            }
        }
        Err(StoreError::NotFound(_)) => Ok(gix_hash::Kind::Sha1),
        Err(e) => Err(HandlerError::Store(e)),
    }
}

/// Base URL for LFS endpoint construction.
/// Uses KAPPA_PDS_HOSTNAME from app context if available,
/// falls back to Host header, falls back to error.
fn lfs_base_url(cx: &Cx) -> Result<String, HandlerError> {
    if let Some(hostname) = kappa_handler::try_service::<String>(cx) {
        return Ok(hostname.clone());
    }
    let host = request::headers(cx)
        .get("host")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            HandlerError::bad_request("Host header required for LFS URL construction")
        })?;
    Ok(format!("http://{}", host))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn git_info_refs(
    cx: &Cx,
    _body: Body, // GET — v2 capabilities are advertised in the response,
                 // not negotiated from the request body. Body not consumed.
) -> Result<topcoat::router::response::Response, HandlerError> {
    let query = request::uri(cx).query().unwrap_or("");
    let is_upload = query.contains("service=git-upload-pack");
    let is_v2 = request::headers(cx)
        .get("git-protocol")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.contains("version=2"));
    let service = if is_upload {
        "git-upload-pack"
    } else {
        "git-receive-pack"
    };

    let repo = if is_upload {
        git_read_ns(cx)?
    } else {
        git_write_target(cx)?.namespace().clone()
    };
    let s = store(cx);

    let data = blocking(move || -> Result<_, HandlerError> {
        let object_hash = repo_object_hash(&*s, &repo)?;
        let mut out = Vec::new();
        if is_v2 {
            let caps = advertisement::default_v2_capabilities(object_hash);
            let cap_refs: Vec<&str> = caps.iter().map(|s| s.as_str()).collect();
            advertisement::write_v2_capability_advertisement(&cap_refs, &mut out)?;
        } else {
            let caps = advertisement::default_v1_capabilities(object_hash);
            let cap_refs: Vec<&str> = caps.iter().map(|s| s.as_str()).collect();
            advertisement::write_ref_advertisement(
                &*s,
                &repo,
                service,
                &cap_refs,
                object_hash,
                &mut out,
            )?;
        }
        Ok(out)
    })
    .await?;

    let ct = if is_upload {
        "application/x-git-upload-pack-advertisement"
    } else {
        "application/x-git-receive-pack-advertisement"
    };
    let mut resp = kappa_handler::binary_response(StatusCode::OK, ct, data)?;
    resp.headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-cache"));
    if is_v2 {
        resp.headers_mut()
            .insert("git-protocol", HeaderValue::from_static("version=2"));
    }
    Ok(resp)
}

async fn git_upload_pack(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let is_v2 = {
        request::headers(cx)
            .get("git-protocol")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| s.contains("version=2"))
    };
    let repo = git_read_ns(cx)?;
    let s = store(cx);
    let max_size = kappa_handler::service::<MaxBlobSize>(cx).0;
    let request_bytes = read_body(body, max_size).await?.to_vec();

    let data = blocking(move || -> Result<_, HandlerError> {
        let object_hash = repo_object_hash(&*s, &repo)?;
        let mut response_buf = Vec::new();
        if is_v2 {
            protocol::handle_v2_upload_pack(
                &*s,
                &repo,
                std::io::Cursor::new(request_bytes),
                &mut response_buf,
                object_hash,
            )?;
        } else {
            protocol::handle_upload_pack(
                &*s,
                &repo,
                std::io::Cursor::new(request_bytes),
                &mut response_buf,
                object_hash,
            )?;
        }
        Ok(response_buf)
    })
    .await?;

    kappa_handler::binary_response(StatusCode::OK, "application/x-git-upload-pack-result", data)
}

async fn git_receive_pack(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let target = git_write_target(cx)?;
    let report_namespace = target.namespace().clone();
    let s = store(cx);
    let max_size = kappa_handler::service::<MaxBlobSize>(cx).0;
    let request_bytes = read_body(body, max_size).await?;

    // The commands are parsed and the pre-receive hook runs before the
    // execution takes the store's writer; the pack is ingested inside it.
    let plan = blocking({
        let s = s.clone();
        let repo = target.namespace().clone();
        let request = request_bytes.clone();
        move || -> Result<_, HandlerError> {
            let object_hash = repo_object_hash(&*s, &repo)?;
            let plan = protocol::prepare_receive_pack(
                &*s,
                &repo,
                std::io::Cursor::new(request),
                object_hash,
            )?;
            Ok(Arc::new(plan))
        }
    })
    .await?;

    // Pack objects and accepted ref updates publish together in one epoch;
    // a push whose every command is rejected publishes nothing, installs
    // no object, and creates no repository.
    let committed = match plan.rejection() {
        Some(_) => None,
        None => {
            let applied = Arc::clone(&plan);
            let preparer = s.clone();
            let bounds = PreparationBounds {
                maximum: max_size as u64,
                deadline: Instant::now() + kappa_handler::WRITE_DEADLINE,
            };
            // The node's shared delta budget bounds every resolved delta
            // across concurrent pushes and bundle ingests.
            let budget = kappa_handler::service::<Arc<DeltaBudget>>(cx).clone();
            let committed = kappa_handler::execute(cx, target, &request_bytes, move |execution| {
                let outcomes =
                    protocol::apply_ref_updates(&*preparer, execution, &applied, bounds, &budget)?;
                Ok(if outcomes.changed() {
                    Outcome::Publish(outcomes)
                } else {
                    Outcome::Discard(outcomes)
                })
            })
            .await?;
            Some(committed)
        }
    };

    let data = blocking({
        let report = Arc::clone(&plan);
        let repo = report_namespace.clone();
        let post_receive = committed
            .as_ref()
            .filter(|committed| committed.epoch.is_some())
            .map(|committed| (committed.namespace.clone(), committed.value.accepted(&plan)));
        let outcomes = committed.as_ref().map(|committed| committed.value.clone());
        move || -> Result<_, HandlerError> {
            let mut response_buf = Vec::new();
            // The forced-update check walks the repository's own graph: a
            // namespace-bound read, never a lagging global locator.
            protocol::write_receive_report(
                &*s,
                &repo,
                &report,
                outcomes.as_ref(),
                &mut response_buf,
            )?;
            if let Some((repo, accepted)) = post_receive {
                hooks::spawn_post_receive(&*s, &repo, &accepted, 30);
            }
            Ok(response_buf)
        }
    })
    .await?;

    let mut response = kappa_handler::binary_response(
        StatusCode::OK,
        "application/x-git-receive-pack-result",
        data,
    )?;
    if let Some(committed) = &committed {
        committed.annotate(&mut response);
    }
    Ok(response)
}

async fn git_lfs_batch(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    // The batch API names transfer endpoints; it writes no repository state,
    // so a repository that does not exist yet is not created here.
    let namespace = git_write_target(cx)?.namespace().clone();
    let repo_name = namespace.display_name().to_string();
    let s = store(cx);
    let request_bytes = read_body(body, MAX_LFS_BATCH_BYTES).await?.to_vec();
    let base_url = lfs_base_url(cx)?;

    let json = blocking(move || -> Result<_, HandlerError> {
        let batch_req: lfs::BatchRequest = serde_json::from_slice(&request_bytes)
            .map_err(|error| HandlerError::bad_request(error.to_string()))?;
        let batch_resp = lfs::process_batch(&*s, &namespace, &base_url, &repo_name, &batch_req);
        let bytes = serde_json::to_vec(&batch_resp)
            .map_err(|error| HandlerError::internal(error.to_string()))?;
        Ok(bytes)
    })
    .await?;

    kappa_handler::binary_response(StatusCode::OK, "application/vnd.git-lfs+json", json)
}

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(git_route!(
            Method::GET,
            "/_git/{*repo}/info/refs",
            git_info_refs
        ))
        .route(git_route!(
            Method::POST,
            "/_git/{*repo}/git_upload_pack",
            git_upload_pack
        ))
        .route(git_route!(
            Method::POST,
            "/_git/{*repo}/git_receive_pack",
            git_receive_pack
        ))
        .route(git_route!(
            Method::POST,
            "/_git/{*repo}/info/lfs/objects/batch",
            git_lfs_batch
        ))
}
