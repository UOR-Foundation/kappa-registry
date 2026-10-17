//! Record writes of one XRPC call, applied inside the repository execution.
//!
//! `swapCommit` and `swapRecord` are compared against the execution's own
//! view, under the writer that publishes the call, so a precondition cannot
//! be invalidated between the check and the write. Every precondition of a
//! record is checked before that record is written: an expected mismatch
//! returns an error without latching the execution, and the caller discards
//! the execution, so nothing of the call is published.

use topcoat::router::StatusCode;

use kappa_handler::{HandlerError, OperationResult};
use kappa_store::{
    Axis, ExecutionReads, ExecutionWrites, Kappa, KappaStore, StoreError, TagUpdate,
    VerifiedContent,
};

use crate::cid::cid_for_cbor;
use crate::mst::is_valid_mst_key;
use crate::repo::mst_ops::{
    HEAD_TAG, RECORD_PREFIX, RecordChanges, RepoCommit, commit_repo, put_tag_if_changed,
};

/// Expected current state of a record, from `swapRecord`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordSwap {
    /// `swapRecord: null`: the record must not exist.
    Absent,
    /// The record's current CID must equal this value.
    Cid(String),
}

/// What a write does to its record.
#[derive(Debug, Clone)]
pub enum RecordAction {
    /// Create a record that must not exist yet.
    Create(serde_json::Value),
    /// Create or replace a record.
    Update(serde_json::Value),
    /// Remove a record; removing an absent record writes nothing.
    Delete,
}

/// One record write of a call.
#[derive(Debug, Clone)]
pub struct RecordOp {
    pub collection: String,
    pub rkey: String,
    pub action: RecordAction,
    pub swap: Option<RecordSwap>,
}

impl RecordOp {
    fn key(&self) -> String {
        format!("{}/{}", self.collection, self.rkey)
    }
}

/// A written record as reported to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordRef {
    pub uri: String,
    pub cid: String,
}

/// Persisted in an operation receipt as `[uri, cid]`.
impl OperationResult for RecordRef {
    fn encode(&self) -> Vec<u8> {
        vec![self.uri.clone(), self.cid.clone()].encode()
    }

    fn decode(bytes: &[u8]) -> Result<Self, HandlerError> {
        let fields = Vec::<String>::decode(bytes)?;
        let [uri, cid] = <[String; 2]>::try_from(fields).map_err(|_| {
            HandlerError::internal("operation receipt carries an invalid record reference")
        })?;
        Ok(Self { uri, cid })
    }
}

/// Outcome of applying a call's writes.
#[derive(Debug)]
pub struct Applied {
    /// One entry per write: the record it binds, `None` for a deletion.
    pub records: Vec<Option<RecordRef>>,
    /// The new commit; `None` when no record changed and nothing must be
    /// published.
    pub commit: Option<RepoCommit>,
}

/// AT Protocol `InvalidSwap`: a compare-and-swap precondition failed.
pub fn invalid_swap(message: impl Into<String>) -> HandlerError {
    HandlerError::protocol(StatusCode::BAD_REQUEST, "InvalidSwap", message)
}

fn invalid_request(message: impl Into<String>) -> HandlerError {
    HandlerError::protocol(StatusCode::BAD_REQUEST, "InvalidRequest", message)
}

/// Apply every write of one call in `execution` and, when any record
/// changed, write the MST and the commit chained to the current head.
///
/// # Errors
///
/// `InvalidSwap` when `swap_commit` or a write's `swapRecord` does not
/// match; `InvalidRequest` for an invalid record key, an unserializable
/// record, or a create of an existing record; store failures otherwise.
pub fn apply_record_writes<E: ExecutionWrites + ?Sized>(
    store: &dyn KappaStore,
    execution: &mut E,
    repo: &str,
    swap_commit: Option<&str>,
    ops: &[RecordOp],
) -> Result<Applied, HandlerError> {
    check_swap_commit(&*execution, swap_commit)?;
    let mut changes = RecordChanges::new();
    let mut records = Vec::with_capacity(ops.len());
    for op in ops {
        records.push(apply_one(execution, repo, op, &mut changes)?);
    }
    if changes.is_empty() {
        return Ok(Applied {
            records,
            commit: None,
        });
    }
    let commit = commit_repo(store, execution, repo, &changes)?;
    Ok(Applied {
        records,
        commit: Some(commit),
    })
}

fn check_swap_commit<E: ExecutionReads + ?Sized>(
    execution: &E,
    swap_commit: Option<&str>,
) -> Result<(), HandlerError> {
    let Some(expected) = swap_commit else {
        return Ok(());
    };
    let head = execution.tag_get(HEAD_TAG)?;
    if head.is_some_and(|entry| entry.kappa.to_string() == expected) {
        Ok(())
    } else {
        Err(invalid_swap(format!(
            "repository head does not match swapCommit {expected}"
        )))
    }
}

fn check_swap_record(
    swap: Option<&RecordSwap>,
    current: Option<&Kappa>,
    key: &str,
) -> Result<(), HandlerError> {
    match (swap, current) {
        (None, _) | (Some(RecordSwap::Absent), None) => Ok(()),
        (Some(RecordSwap::Cid(expected)), Some(current)) if current.to_string() == *expected => {
            Ok(())
        }
        (Some(_), _) => Err(invalid_swap(format!(
            "record {key} does not match swapRecord"
        ))),
    }
}

fn apply_one<E: ExecutionWrites + ?Sized>(
    execution: &mut E,
    repo: &str,
    op: &RecordOp,
    changes: &mut RecordChanges,
) -> Result<Option<RecordRef>, HandlerError> {
    let key = op.key();
    if !is_valid_mst_key(&key) {
        return Err(invalid_request(format!("invalid record key: {key}")));
    }
    let tag = format!("{RECORD_PREFIX}{key}");
    let current = execution.tag_get(&tag)?.map(|entry| entry.kappa);
    check_swap_record(op.swap.as_ref(), current.as_ref(), &key)?;
    let record = match &op.action {
        RecordAction::Delete => {
            if current.is_some() {
                execution.tag_delete(&tag)?;
                changes.insert(key, None);
            }
            return Ok(None);
        }
        RecordAction::Create(_) if current.is_some() => {
            return Err(invalid_request(format!("record already exists: {key}")));
        }
        RecordAction::Create(record) | RecordAction::Update(record) => record,
    };
    let bytes = serde_json::to_vec(record)
        .map_err(|error| invalid_request(format!("record serialize: {error}")))?;
    let content = VerifiedContent::compute(Axis::Sha256, &bytes).map_err(StoreError::from)?;
    let kappa = content.kappa().clone();
    let reference = RecordRef {
        uri: format!("at://{repo}/{key}"),
        cid: kappa.to_string(),
    };
    if current.as_ref() == Some(&kappa) {
        return Ok(Some(reference));
    }
    execution.blob_put(&content)?;
    put_tag_if_changed(
        execution,
        &format!("blob/{}", hex::encode(cid_for_cbor(&bytes))),
        &kappa,
    )?;
    execution.tag_put(
        &tag,
        &TagUpdate::Set {
            kappa: kappa.clone(),
        },
    )?;
    changes.insert(key, Some(kappa));
    Ok(Some(reference))
}
