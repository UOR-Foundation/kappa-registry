//! com.atproto.repo write endpoints.
//!
//! Each call runs as one execution of the repository namespace: record
//! blobs and tags, MST nodes, the commit object and its head tag publish
//! together in one signed epoch, or not at all.

use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use crate::protocol_id;
use kappa_handler::{
    Committed, HandlerError, OperationResult, Outcome, WriteTarget, blocking, clock_now, execute,
    read_json_with_bytes, store,
};
use kappa_store::{Axis, NamespaceRef, StoreError, absent};

use crate::handlers::session::verify_repo_auth;
use crate::repo::apply::{Applied, RecordAction, RecordOp, RecordRef, RecordSwap};
use crate::tid::TidGenerator;

const RECORD_BODY_LIMIT: usize = 1024 * 1024;
const DELETE_BODY_LIMIT: usize = 64 * 1024;
const BATCH_BODY_LIMIT: usize = 10 * 1024 * 1024;

fn required_str(req: &serde_json::Value, field: &str) -> Result<String, HandlerError> {
    req.get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| HandlerError::bad_request(format!("missing {field}")))
}

fn optional_str(req: &serde_json::Value, field: &str) -> Option<String> {
    req.get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// `swapRecord`: absent means no check, `null` means the record must not
/// exist, a string is the expected current CID.
fn record_swap(req: &serde_json::Value) -> Result<Option<RecordSwap>, HandlerError> {
    match req.get("swapRecord") {
        None => Ok(None),
        Some(serde_json::Value::Null) => Ok(Some(RecordSwap::Absent)),
        Some(serde_json::Value::String(cid)) => Ok(Some(RecordSwap::Cid(cid.clone()))),
        Some(_) => Err(HandlerError::bad_request(
            "swapRecord must be a CID string or null",
        )),
    }
}

fn next_rkey(cx: &Cx) -> Result<String, HandlerError> {
    let now = clock_now(cx)?;
    kappa_handler::service::<std::sync::Arc<TidGenerator>>(cx)
        .next(now)
        .map_err(|error| HandlerError::internal(error.to_string()))
}

/// The repository namespace named `repo`, or `None` when it does not exist.
pub(crate) async fn resolve_repo(
    cx: &Cx,
    repo: &str,
) -> Result<Option<NamespaceRef>, HandlerError> {
    let s = store(cx);
    let name = repo.to_string();
    blocking(move || absent(s.namespace_resolve(&name, Some(protocol_id())))).await
}

/// Execute `ops` against `repo` in one execution. A repository that does
/// not exist is created by the same execution when `create` is set.
async fn execute_writes<T>(
    cx: &Cx,
    repo: String,
    swap_commit: Option<String>,
    ops: Vec<RecordOp>,
    payload: &[u8],
    create: bool,
    result: fn(Applied) -> Result<T, HandlerError>,
) -> Result<Committed<T>, HandlerError>
where
    T: OperationResult + Send + 'static,
{
    let target = match resolve_repo(cx, &repo).await? {
        Some(namespace) => WriteTarget::existing(namespace),
        None if create => {
            WriteTarget::create(&repo, None, Some(protocol_id().clone()), clock_now(cx)?)?
        }
        None => {
            return Err(StoreError::NotFound(format!("repository {repo}")).into());
        }
    };
    let s = store(cx);
    execute(cx, target, payload, move |execution| {
        let applied = crate::repo::apply::apply_record_writes(
            &*s,
            execution,
            &repo,
            swap_commit.as_deref(),
            &ops,
        )?;
        let publish = applied.commit.is_some();
        let value = result(applied)?;
        Ok(if publish {
            Outcome::Publish(value)
        } else {
            Outcome::Discard(value)
        })
    })
    .await
}

fn single_record(applied: Applied) -> Result<RecordRef, HandlerError> {
    applied
        .records
        .into_iter()
        .next()
        .flatten()
        .ok_or_else(|| HandlerError::internal("record write reported no record"))
}

fn no_result(_: Applied) -> Result<(), HandlerError> {
    Ok(())
}

fn record_response(
    committed: &Committed<RecordRef>,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let mut response = kappa_handler::json_response(
        StatusCode::OK,
        &serde_json::json!({"uri": committed.value.uri, "cid": committed.value.cid}),
    )?;
    committed.annotate(&mut response);
    Ok(response)
}

fn empty_response(committed: &Committed<()>) -> topcoat::router::response::Response {
    let mut response = kappa_handler::empty_response(StatusCode::OK);
    committed.annotate(&mut response);
    response
}

pub async fn create_record(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (serde_json::Value, _) = read_json_with_bytes(body, RECORD_BODY_LIMIT).await?;
    let repo = required_str(&req, "repo")?;
    verify_repo_auth(cx, &repo).await?;
    let collection = required_str(&req, "collection")?;
    let record = req
        .get("record")
        .ok_or_else(|| HandlerError::bad_request("missing record"))?
        .clone();
    let rkey = match optional_str(&req, "rkey") {
        Some(rkey) => rkey,
        None => next_rkey(cx)?,
    };
    let op = RecordOp {
        collection,
        rkey,
        action: RecordAction::Create(record),
        swap: None,
    };
    let swap_commit = optional_str(&req, "swapCommit");
    let committed =
        execute_writes(cx, repo, swap_commit, vec![op], &raw, true, single_record).await?;
    record_response(&committed)
}

pub async fn put_record(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (serde_json::Value, _) = read_json_with_bytes(body, RECORD_BODY_LIMIT).await?;
    let repo = required_str(&req, "repo")?;
    verify_repo_auth(cx, &repo).await?;
    let op = RecordOp {
        collection: required_str(&req, "collection")?,
        rkey: required_str(&req, "rkey")?,
        action: RecordAction::Update(
            req.get("record")
                .ok_or_else(|| HandlerError::bad_request("missing record"))?
                .clone(),
        ),
        swap: record_swap(&req)?,
    };
    let swap_commit = optional_str(&req, "swapCommit");
    let committed =
        execute_writes(cx, repo, swap_commit, vec![op], &raw, true, single_record).await?;
    record_response(&committed)
}

pub async fn delete_record(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (serde_json::Value, _) = read_json_with_bytes(body, DELETE_BODY_LIMIT).await?;
    let repo = required_str(&req, "repo")?;
    verify_repo_auth(cx, &repo).await?;
    let op = RecordOp {
        collection: required_str(&req, "collection")?,
        rkey: required_str(&req, "rkey")?,
        action: RecordAction::Delete,
        swap: record_swap(&req)?,
    };
    let swap_commit = optional_str(&req, "swapCommit");
    let committed = execute_writes(cx, repo, swap_commit, vec![op], &raw, false, no_result).await?;
    Ok(empty_response(&committed))
}

pub async fn upload_blob(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let blob_bytes = kappa_handler::read_body(body, 10 * 1024 * 1024).await?;
    let size = blob_bytes.len();
    // An uploaded blob is retained by the uploader's identity namespace
    // through a pin until a record references it; the upload publishes an
    // epoch there. Unauthenticated uploads have no namespace to retain them.
    let anchor = kappa_handler::caller_anchor(cx)
        .ok_or_else(|| HandlerError::unauthorized("uploadBlob requires authentication"))?;
    let target = kappa_handler::anchor_write_target(cx, &anchor).await?;
    let prepared = kappa_handler::prepare_body(
        cx,
        kappa_store::ContentIdentity::Computed(Axis::Sha256),
        blob_bytes.to_vec(),
    )
    .await?;
    let committed = kappa_handler::execute(cx, target, &blob_bytes, move |execution| {
        let installed = execution.content_install(kappa_handler::take_prepared(&prepared)?)?;
        let pin = serde_json::json!({"created_at_ms": execution.now().as_i64(), "ttl": 0});
        execution.namespace_put_meta(
            &format!("_pin/{}", installed.kappa),
            pin.to_string().as_bytes(),
        )?;
        Ok(kappa_handler::Outcome::Publish(installed.kappa.to_string()))
    })
    .await?;
    let cid = committed.value;

    kappa_handler::json_response(
        StatusCode::OK,
        &serde_json::json!({
            "blob": {
                "$type": "blob",
                "ref": { "$link": cid },
                "mimeType": "application/octet-stream",
                "size": size,
            }
        }),
    )
}

/// Parse one element of `applyWrites.writes`. Rkeys of creates without one
/// are assigned here, before execution, so a re-run of the execution reuses
/// them.
fn parse_write(cx: &Cx, write: &serde_json::Value) -> Result<RecordOp, HandlerError> {
    let action = write
        .get("$type")
        .or_else(|| write.get("action"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| HandlerError::bad_request("missing action/$type in write"))?;
    let collection = required_str(write, "collection")
        .map_err(|_| HandlerError::bad_request("missing collection in write"))?;
    let record = |kind: &str| {
        write
            .get("value")
            .or_else(|| write.get("record"))
            .cloned()
            .ok_or_else(|| HandlerError::bad_request(format!("missing record in {kind}")))
    };
    let rkey = |kind: &str| {
        optional_str(write, "rkey")
            .ok_or_else(|| HandlerError::bad_request(format!("missing rkey in {kind}")))
    };
    let (rkey, action) = if action.contains("create") {
        let rkey = match optional_str(write, "rkey").filter(|rkey| !rkey.is_empty()) {
            Some(rkey) => rkey,
            None => next_rkey(cx)?,
        };
        (rkey, RecordAction::Create(record("create")?))
    } else if action.contains("update") {
        (rkey("update")?, RecordAction::Update(record("update")?))
    } else if action.contains("delete") {
        (rkey("delete")?, RecordAction::Delete)
    } else {
        return Err(HandlerError::bad_request(format!(
            "unknown write action: {action}"
        )));
    };
    Ok(RecordOp {
        collection,
        rkey,
        action,
        swap: None,
    })
}

pub async fn apply_writes(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (serde_json::Value, _) = read_json_with_bytes(body, BATCH_BODY_LIMIT).await?;
    let repo = required_str(&req, "repo")?;
    verify_repo_auth(cx, &repo).await?;
    let ops = req
        .get("writes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| HandlerError::bad_request("missing writes array"))?
        .iter()
        .map(|write| parse_write(cx, write))
        .collect::<Result<Vec<_>, _>>()?;
    let swap_commit = optional_str(&req, "swapCommit");
    let committed = execute_writes(cx, repo, swap_commit, ops, &raw, true, no_result).await?;
    Ok(empty_response(&committed))
}
