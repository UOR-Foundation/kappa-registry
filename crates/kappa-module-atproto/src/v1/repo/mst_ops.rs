use std::collections::{BTreeMap, HashSet};
use std::str;

use kappa_store::{
    Axis, ExecutionReads, ExecutionWrites, Kappa, KappaStore, PageRequest, StoreError, TagUpdate,
    VerifiedContent,
};

use crate::cid::cid_for_cbor;
use crate::commit::UnsignedCommit;
use crate::mst::{MemoryBlockStore, Mst};
use crate::tid::TidGenerator;

const RECORD_PAGE_SIZE: usize = 1024;

/// Tag naming the repository's current commit object.
pub const HEAD_TAG: &str = "commit/head";

/// Tag naming the blob that holds the current commit's revision string.
pub const REV_TAG: &str = "commit/rev";

/// Tag prefix under which every record of the repository is bound.
pub const RECORD_PREFIX: &str = "record/";

/// Upper bound on a stored record or commit read back for CID derivation.
const MAX_BLOCK_BYTES: u64 = 10 * 1024 * 1024;

/// The commit written by `commit_repo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoCommit {
    /// Content identity of the commit object, the value of `commit/head`.
    pub kappa: Kappa,
    /// Revision TID of the commit.
    pub rev: String,
}

/// Record changes of one call, keyed by `collection/rkey`: `Some` binds the
/// record content, `None` removes the record.
pub type RecordChanges = BTreeMap<String, Option<Kappa>>;

/// Build the repository's MST from its published records overlaid with
/// `changes`, write the MST nodes and a commit chained to the current head,
/// and move `commit/head`, `commit/rev` and `commit/rev/{rev}` to it.
///
/// Every write goes through `execution`, so the records, the MST, and the
/// commit publish together. Published records are listed through `store`;
/// the execution holds the namespace's single writer, so that listing is the
/// state the execution builds on.
pub fn commit_repo<E: ExecutionWrites + ?Sized>(
    store: &dyn KappaStore,
    execution: &mut E,
    repo_did: &str,
    changes: &RecordChanges,
) -> Result<RepoCommit, StoreError> {
    let records = current_records(store, &*execution, changes)?;
    let mut mst = Mst::new();
    for (key, kappa) in &records {
        let cid = content_cid(&*execution, kappa)?;
        mst.insert(key, cid)
            .map_err(|error| StoreError::Rejected(format!("MST insert: {error}")))?;
    }

    let mut mst_store = MemoryBlockStore::new();
    let (mst_root, mst_blocks) = mst.write_to_store(&mut mst_store);
    for (block_cid, block_bytes) in &mst_blocks {
        let kappa = install_record(execution, block_bytes)?;
        put_tag_if_changed(
            execution,
            &format!("mst/{}", hex::encode(block_cid)),
            &kappa,
        )?;
    }

    let prev = match execution.tag_get(HEAD_TAG)? {
        Some(head) => Some(content_cid(&*execution, &head.kappa)?.to_vec()),
        None => None,
    };
    let rev = TidGenerator::with_clock_id(0)
        .next(execution.now())
        .map_err(|error| StoreError::Internal(error.to_string()))?;

    let commit = UnsignedCommit {
        did: repo_did.to_string(),
        version: 3,
        data: mst_root.to_vec(),
        rev: rev.clone(),
        prev,
    };
    let commit_kappa = install_record(execution, &commit.to_cbor())?;
    execution.tag_put(
        HEAD_TAG,
        &TagUpdate::Set {
            kappa: commit_kappa.clone(),
        },
    )?;
    let rev_kappa = install_record(execution, rev.as_bytes())?;
    execution.tag_put(REV_TAG, &TagUpdate::Set { kappa: rev_kappa })?;
    execution.tag_put(
        &format!("{REV_TAG}/{rev}"),
        &TagUpdate::Set {
            kappa: commit_kappa.clone(),
        },
    )?;

    Ok(RepoCommit {
        kappa: commit_kappa,
        rev,
    })
}

/// Install `bytes`, a record this module produced (an MST node, a commit,
/// a revision), as verified SHA-256 content the execution holds.
pub fn install_record<E: ExecutionWrites + ?Sized>(
    execution: &mut E,
    bytes: &[u8],
) -> Result<Kappa, StoreError> {
    let content = VerifiedContent::compute(Axis::Sha256, bytes)?;
    execution.blob_put(&content)?;
    Ok(content.kappa().clone())
}

/// Bind `name` to `kappa` unless it is already bound to it. Content-named
/// tags (MST nodes, CID bridges) are rebound on every commit otherwise,
/// which would record a ledger mutation for unchanged state.
pub fn put_tag_if_changed<E: ExecutionWrites + ?Sized>(
    execution: &mut E,
    name: &str,
    kappa: &Kappa,
) -> Result<(), StoreError> {
    if execution
        .tag_get_raw(name)?
        .is_some_and(|entry| entry.kappa == *kappa)
    {
        return Ok(());
    }
    execution.tag_put(
        name,
        &TagUpdate::Set {
            kappa: kappa.clone(),
        },
    )
}

/// Published records keyed by `collection/rkey`, with `changes` applied.
fn current_records<E: ExecutionReads + ?Sized>(
    store: &dyn KappaStore,
    execution: &E,
    changes: &RecordChanges,
) -> Result<BTreeMap<String, Kappa>, StoreError> {
    let mut records = BTreeMap::new();
    let mut request = PageRequest::first(RECORD_PAGE_SIZE);
    loop {
        let page = store.tag_list(execution.namespace(), Some(RECORD_PREFIX), &request)?;
        for tag in page.items.iter() {
            let key = tag.name.strip_prefix(RECORD_PREFIX).ok_or_else(|| {
                StoreError::Internal(format!("tag '{}' missing record/ prefix", tag.name))
            })?;
            records.insert(key.to_string(), tag.kappa.clone());
        }
        let Some(next) = page.next_after else {
            break;
        };
        if page.items.is_empty()
            || request
                .after
                .as_ref()
                .is_some_and(|previous| previous >= &next)
        {
            return Err(StoreError::Internal(
                "record pagination did not advance".into(),
            ));
        }
        request.after = Some(next);
    }
    for (key, change) in changes {
        match change {
            Some(kappa) => records.insert(key.clone(), kappa.clone()),
            None => records.remove(key),
        };
    }
    Ok(records)
}

/// DAG-CBOR CID of the content stored at `kappa`.
///
/// A SHA-256 identity carries the CID's digest, so the CID is derived
/// without reading the content. Any other axis is read back through the
/// execution, which also sees content written earlier in the same call.
pub fn content_cid<E: ExecutionReads + ?Sized>(
    execution: &E,
    kappa: &Kappa,
) -> Result<[u8; 36], StoreError> {
    if kappa.axis() == Axis::Sha256 {
        let digest: [u8; 32] = kappa.digest_bytes().try_into().map_err(|_| {
            StoreError::Internal(format!("SHA-256 identity {kappa} is not 32 bytes"))
        })?;
        let mut cid = [0u8; 36];
        cid[..4].copy_from_slice(&[0x01, 0x71, 0x12, 0x20]);
        cid[4..].copy_from_slice(&digest);
        return Ok(cid);
    }
    let bytes = execution
        .blob_get_verified(kappa, MAX_BLOCK_BYTES)?
        .ok_or_else(|| StoreError::Internal(format!("repository block {kappa} is missing")))?;
    Ok(cid_for_cbor(&bytes))
}

/// Parse the "data" field CID from a DAG-CBOR encoded commit.
pub fn parse_commit_data_cid(commit_bytes: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    if pos >= commit_bytes.len() {
        return None;
    }
    let major = commit_bytes[pos] >> 5;
    if major != 5 {
        return None;
    }
    let map_len = (commit_bytes[pos] & 0x1F) as usize;
    pos += 1;

    for _ in 0..map_len {
        if pos >= commit_bytes.len() {
            return None;
        }
        let key_major = commit_bytes[pos] >> 5;
        let key_len = (commit_bytes[pos] & 0x1F) as usize;
        if key_major != 3 {
            return None;
        }
        pos += 1;
        if pos + key_len > commit_bytes.len() {
            return None;
        }
        let key = str::from_utf8(&commit_bytes[pos..pos + key_len]).ok()?;
        pos += key_len;

        if key == "data" {
            if pos + 1 >= commit_bytes.len() {
                return None;
            }
            if commit_bytes[pos] == 0xD8 && commit_bytes[pos + 1] == 42 {
                pos += 2;
                if pos >= commit_bytes.len() {
                    return None;
                }
                let bs_major = commit_bytes[pos] >> 5;
                let bs_len = (commit_bytes[pos] & 0x1F) as usize;
                if bs_major != 2 {
                    return None;
                }
                pos += 1;
                let actual_len = if bs_len < 24 {
                    bs_len
                } else if bs_len == 24 {
                    if pos >= commit_bytes.len() {
                        return None;
                    }
                    let l = commit_bytes[pos] as usize;
                    pos += 1;
                    l
                } else {
                    return None;
                };
                if pos + actual_len > commit_bytes.len() {
                    return None;
                }
                let cid_bytes = &commit_bytes[pos..pos + actual_len];
                if !cid_bytes.is_empty() && cid_bytes[0] == 0x00 {
                    return Some(cid_bytes[1..].to_vec());
                }
                return Some(cid_bytes.to_vec());
            }
            return None;
        } else {
            skip_cbor_value(commit_bytes, &mut pos)?;
        }
    }
    None
}

fn skip_cbor_value(data: &[u8], pos: &mut usize) -> Option<()> {
    if *pos >= data.len() {
        return None;
    }
    let major = data[*pos] >> 5;
    let additional = data[*pos] & 0x1F;
    *pos += 1;
    match major {
        0 | 1 => {
            if (24..=27).contains(&additional) {
                *pos += 1usize << (additional - 24);
            }
        }
        2 | 3 => {
            let len = if additional < 24 {
                additional as usize
            } else if additional == 24 {
                let l = *data.get(*pos)? as usize;
                *pos += 1;
                l
            } else {
                return None;
            };
            *pos += len;
        }
        4 => {
            let len = additional as usize;
            for _ in 0..len {
                skip_cbor_value(data, pos)?;
            }
        }
        5 => {
            let len = additional as usize;
            for _ in 0..len {
                skip_cbor_value(data, pos)?;
                skip_cbor_value(data, pos)?;
            }
        }
        6 => {
            if (24..=27).contains(&additional) {
                *pos += 1usize << (additional - 24);
            }
            skip_cbor_value(data, pos)?;
        }
        7 if (24..=27).contains(&additional) => {
            *pos += 1usize << (additional - 24);
        }
        _ => {}
    }
    Some(())
}

/// Walk an MST tree depth-first collecting CIDs only (for exclusion sets).
pub fn walk_mst_cids(
    store: &dyn KappaStore,
    ns: &kappa_store::NamespaceRef,
    node_cid: &[u8],
    visited: &mut HashSet<[u8; 36]>,
) -> Result<(), StoreError> {
    if node_cid.len() != 36 {
        return Ok(());
    }
    let mut cid_arr = [0u8; 36];
    cid_arr.copy_from_slice(node_cid);
    if !visited.insert(cid_arr) {
        return Ok(());
    }

    let cid_hex = hex::encode(node_cid);
    let tag_name = format!("mst/{}", cid_hex);
    let kappa = store.tag_get(ns, &tag_name)?.kappa;
    let node_bytes = store.blob_get_in(ns, &kappa)?;

    let (left, entries) = crate::mst_node::decode_node(&node_bytes)
        .map_err(|e| StoreError::Internal(format!("MST decode: {e}")))?;
    if let Some(left_cid) = left {
        walk_mst_cids(store, ns, &left_cid, visited)?;
    }
    for entry in &entries {
        visited.insert(entry.value);
        if let Some(right_cid) = &entry.tree {
            walk_mst_cids(store, ns, right_cid, visited)?;
        }
    }
    Ok(())
}

/// Walk an MST tree depth-first collecting blocks for CAR export.
pub fn walk_mst_node(
    store: &dyn KappaStore,
    ns: &kappa_store::NamespaceRef,
    node_cid: &[u8],
    blocks: &mut Vec<crate::car::CarBlock>,
    visited: &mut HashSet<[u8; 36]>,
) -> Result<(), StoreError> {
    if node_cid.len() != 36 {
        return Ok(());
    }
    let mut cid_arr = [0u8; 36];
    cid_arr.copy_from_slice(node_cid);
    if !visited.insert(cid_arr) {
        return Ok(());
    }

    let cid_hex = hex::encode(node_cid);
    let tag_name = format!("mst/{}", cid_hex);
    let kappa = store.tag_get(ns, &tag_name)?.kappa;
    let node_bytes = store.blob_get_in(ns, &kappa)?;

    blocks.push(crate::car::CarBlock {
        cid: node_cid.to_vec(),
        bytes: node_bytes.clone(),
    });

    let (left, entries) = crate::mst_node::decode_node(&node_bytes)
        .map_err(|e| StoreError::Internal(format!("MST decode: {e}")))?;
    if let Some(left_cid) = left {
        walk_mst_node(store, ns, &left_cid, blocks, visited)?;
    }
    for entry in &entries {
        let value_cid_hex = hex::encode(entry.value);
        let blob_tag = format!("blob/{}", value_cid_hex);
        let blob_entry = store.tag_get(ns, &blob_tag)?;
        let blob_data = store.blob_get_in(ns, &blob_entry.kappa)?;
        if visited.insert(entry.value) {
            blocks.push(crate::car::CarBlock {
                cid: entry.value.to_vec(),
                bytes: blob_data,
            });
        }
        if let Some(right_cid) = &entry.tree {
            walk_mst_node(store, ns, right_cid, blocks, visited)?;
        }
    }
    Ok(())
}
