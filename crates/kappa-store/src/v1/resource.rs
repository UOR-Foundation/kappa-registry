//! Staged resources composed from registry primitives.
//!
//! Every transition is a write in the caller's execution and therefore
//! epoch-committed. Open publishes a head under `CreateIfAbsent`; stage
//! installs the prepared member, adds a `Member` edge from the resource
//! anchor with its coordinate, names that edge from namespace metadata
//! keyed by the coordinate (so a replacement or a later retirement finds
//! it without enumerating the membership), and publishes the next head
//! revision with `CompareAndSwap` against the revision it read. Preparation
//! and completion are in `resource_completion`.
//!
//! Inside an execution the head and the members are read through the same
//! view (`ExecutionReads::edge_query` sees the execution's own stages), so
//! preparation and completion observe one consistent state; the head's
//! counts are checked against that membership as an invariant.
//!
//! There are no sessions, no staging files, and no store-level tables for
//! any of this. A lost response is resolved by reading the committed head.

use kappa_types::canonical::{canonical_bytes, from_canonical};
use kappa_types::{
    BuiltinRelation, ClockMs, Direction, EdgeInput, EdgeQuery, EdgeRelation, IngestResult, Kappa,
    MemberCoordinate, NamespaceRef, PageRequest, ResourceAnchor, ResourceHead, ResourceKind,
    ResourcePhase, StoreError, TagUpdate, VerifiedContent,
};

use crate::execution::{ExecutionReads, ExecutionWrites, PreparedContent};
use crate::traits::blob::BlobStore;
use crate::traits::edge::EdgeStore;
use crate::traits::tag::TagStore;

#[path = "resource_completion.rs"]
mod completion;
pub use completion::{
    Completed, Preparation, Resolution, complete, discard, expire, prepare, prepare_composition,
    resolve_completion,
};

/// Largest head record admitted when resolving a resource.
const MAX_HEAD_BYTES: u64 = 64 * 1024;

/// Member population bounds per kind. Numbered resources carry S3's part
/// limit; sequential and membership resources are bounded by the
/// selection record and the composite's two-level capacity.
pub const fn max_members(kind: ResourceKind) -> usize {
    match kind {
        ResourceKind::Numbered => 10_000,
        ResourceKind::Sequential | ResourceKind::Membership => 65_536,
    }
}

/// A member as the committed edges describe it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub identity: Kappa,
    pub coordinate: MemberCoordinate,
    /// The committed `Member` edge.
    pub edge: Kappa,
}

/// A resolved resource: its head record, the identity of that record, and
/// the version of the tag naming it (the expected version of the next
/// conditional transition).
#[derive(Debug, Clone)]
pub struct Resource {
    pub head_identity: Kappa,
    pub head_version: u64,
    pub head: ResourceHead,
}

fn head_from_bytes(ns: &NamespaceRef, id: &str, bytes: &[u8]) -> Result<ResourceHead, StoreError> {
    let head: ResourceHead = from_canonical(bytes)?;
    head.validate(ns.id())?;
    if head.id() != id {
        return Err(StoreError::Internal(format!(
            "resource {id} names a head of incarnation {}",
            head.id()
        )));
    }
    Ok(head)
}

/// Resolve `id` through the execution's view, including its private
/// writes. Absent when no head is named.
pub fn resolve_in(
    execution: &dyn ExecutionReads,
    id: &str,
) -> Result<Option<Resource>, StoreError> {
    let Some(entry) = execution.tag_get_raw(&ResourceHead::tag_name(id))? else {
        return Ok(None);
    };
    let bytes = execution
        .blob_get_verified(&entry.kappa, MAX_HEAD_BYTES)?
        .ok_or_else(|| StoreError::Internal(format!("resource {id} head content is missing")))?;
    Ok(Some(Resource {
        head: head_from_bytes(execution.namespace(), id, &bytes)?,
        head_identity: entry.kappa,
        head_version: entry.version,
    }))
}

/// Resolve `id` from committed state.
pub fn resolve<S: TagStore + BlobStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    id: &str,
) -> Result<Option<Resource>, StoreError> {
    let entry = match store.tag_get_raw(ns, &ResourceHead::tag_name(id)) {
        Ok(entry) => entry,
        Err(StoreError::NotFound(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    if store.blob_size_in(ns, &entry.kappa)? > MAX_HEAD_BYTES {
        return Err(StoreError::Internal(format!(
            "resource {id} head exceeds its bound"
        )));
    }
    let bytes = store.blob_get_verified_in(ns, &entry.kappa)?;
    Ok(Some(Resource {
        head: head_from_bytes(ns, id, &bytes)?,
        head_identity: entry.kappa,
        head_version: entry.version,
    }))
}

/// Members of a resource from the anchor's `Member` edges as `query`
/// pages them, bounded by the kind's member limit.
fn members_with(
    head: &ResourceHead,
    mut query: impl FnMut(
        &EdgeQuery,
        &PageRequest,
    ) -> Result<kappa_types::Page<kappa_types::Edge>, StoreError>,
) -> Result<Vec<Member>, StoreError> {
    let anchor = head.anchor().identity();
    let limit = max_members(head.kind);
    let mut members = Vec::new();
    let mut request = PageRequest::first(256);
    loop {
        let page = query(
            &EdgeQuery {
                anchor: anchor.clone(),
                direction: Direction::Outbound,
                relation: Some(EdgeRelation::Builtin(BuiltinRelation::Member)),
                asserter: None,
            },
            &request,
        )?;
        for edge in page.items {
            members.push(Member {
                identity: edge.target().clone(),
                coordinate: coordinate_of(edge.metadata())?,
                edge: edge.kappa.clone(),
            });
            if members.len() > limit {
                return Err(StoreError::CapacityExceeded(format!(
                    "resource exceeds {limit} members"
                )));
            }
        }
        match page.next_after {
            Some(next) if request.after.as_ref() != Some(&next) => request.after = Some(next),
            Some(_) => {
                return Err(StoreError::Internal(
                    "member traversal did not advance".into(),
                ));
            }
            None => break,
        }
    }
    Ok(members)
}

/// Committed members of a resource.
pub fn members<S: EdgeStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    head: &ResourceHead,
) -> Result<Vec<Member>, StoreError> {
    members_with(head, |query, page| store.edge_query(ns, query, page))
}

/// Members of a resource through the execution's view, including its own
/// stages.
pub fn members_in(
    execution: &dyn ExecutionReads,
    head: &ResourceHead,
) -> Result<Vec<Member>, StoreError> {
    members_with(head, |query, page| execution.edge_query(query, page))
}

/// Coordinate string used as the metadata key of a member edge.
fn coordinate_key(kind: ResourceKind, position: u64, identity: &Kappa) -> String {
    match kind {
        ResourceKind::Sequential | ResourceKind::Numbered => position.to_string(),
        ResourceKind::Membership => identity.to_string(),
    }
}

/// Publish `head` as the next revision: the record is installed as
/// content, the anchor's `Owns` edge moves from the previous head record
/// to the new one, and the tag transitions conditionally against the
/// version the caller read (`None` creates it). Any concurrent transition
/// of the same head conflicts here instead of being overwritten. The
/// encoded head is bounded before it is installed, so no committed head
/// exceeds what `resolve` admits.
fn publish_head(
    execution: &mut dyn ExecutionWrites,
    head: &ResourceHead,
    asserter: &Kappa,
    expected_version: Option<u64>,
) -> Result<Kappa, StoreError> {
    let id = head.id();
    let bytes = canonical_bytes(head);
    if bytes.len() as u64 > MAX_HEAD_BYTES {
        return Err(StoreError::CapacityExceeded(format!(
            "resource head of {} bytes exceeds its {MAX_HEAD_BYTES} byte bound",
            bytes.len()
        )));
    }
    let content = VerifiedContent::compute(kappa_types::Axis::Sha256, &bytes)?;
    execution.blob_put(&content)?;
    let identity = content.kappa().clone();
    if let Some(previous) = execution.namespace_get_meta(&ResourceHead::owns_key(&id))? {
        execution.edge_delete(&Kappa::from_key_bytes(&previous)?)?;
    }
    let owns = execution.edge_put(&EdgeInput {
        source: identity.clone(),
        target: head.anchor().identity(),
        relation: EdgeRelation::Builtin(BuiltinRelation::Owns),
        asserter: asserter.clone(),
        created_at_ms: execution.now().as_i64(),
        metadata: None,
    })?;
    execution.namespace_put_meta(&ResourceHead::owns_key(&id), &owns.key_bytes())?;
    let update = expected_version.map_or_else(
        || TagUpdate::CreateIfAbsent {
            kappa: identity.clone(),
        },
        |expected_version| TagUpdate::CompareAndSwap {
            kappa: identity.clone(),
            expected_version,
        },
    );
    execution.tag_put(&ResourceHead::tag_name(&id), &update)?;
    Ok(identity)
}

/// Open a resource in the execution's namespace.
///
/// `context` is the protocol's binding for the resource (an object key,
/// for instance),
/// committed in the head so every later request is checked against it,
/// including a replay of the completed outcome. Returns its head.
pub fn open(
    execution: &mut dyn ExecutionWrites,
    asserter: &Kappa,
    kind: ResourceKind,
    max_bytes: u64,
    expires_at: ClockMs,
    context: Option<Vec<u8>>,
) -> Result<ResourceHead, StoreError> {
    // The incarnation is minted the way every store-issued session id has
    // been: a v4 UUID from the OS entropy source.
    let head = ResourceHead {
        namespace_id: execution.namespace().id().to_vec(),
        incarnation: uuid::Uuid::new_v4().into_bytes().to_vec(),
        kind,
        revision: 0,
        phase: ResourcePhase::Open,
        total_bytes: 0,
        member_count: 0,
        max_bytes,
        created_at_ms: execution.now().as_i64(),
        expires_at_ms: expires_at.as_i64(),
        completion: None,
        prepared: None,
        context,
    };
    publish_head(execution, &head, asserter, None)?;
    Ok(head)
}

fn open_resource(execution: &dyn ExecutionReads, id: &str) -> Result<Resource, StoreError> {
    let resource =
        resolve_in(execution, id)?.ok_or_else(|| StoreError::NotFound(format!("resource {id}")))?;
    if resource.head.phase != ResourcePhase::Open {
        return Err(StoreError::Conflict(format!("resource {id} is not open")));
    }
    if execution.now().as_i64() > resource.head.expires_at_ms {
        return Err(StoreError::NotFound(format!("resource {id} expired")));
    }
    Ok(resource)
}

fn next_revision(revision: u64) -> Result<u64, StoreError> {
    revision
        .checked_add(1)
        .ok_or_else(|| StoreError::CapacityExceeded("resource revision overflows".into()))
}

/// Stage prepared content as a member at `position`.
///
/// The coordinate's length is taken from the content. Coordinates are
/// validated against
/// the resource kind: sequential positions are the committed offset,
/// numbered slots range from 1 to the kind's member limit, membership
/// takes no position. A numbered slot already held, or a membership
/// identity already present, is replaced. The replaced edge is found
/// through the coordinate's metadata key, never by enumerating members.
/// Returns the head after staging.
pub fn stage(
    execution: &mut dyn ExecutionWrites,
    asserter: &Kappa,
    id: &str,
    prepared: Box<dyn PreparedContent>,
    position: u64,
    receipt: Option<Vec<u8>>,
) -> Result<(ResourceHead, IngestResult), StoreError> {
    let resource = open_resource(execution, id)?;
    let mut head = resource.head;
    let length = prepared.total_size();
    if length == 0 {
        return Err(StoreError::Rejected("a member must not be empty".into()));
    }
    let key = ResourceHead::member_key(
        id,
        &coordinate_key(head.kind, position, prepared.identity()),
    );
    let replaced: Option<(Kappa, u64)> = match head.kind {
        ResourceKind::Sequential => {
            if position != head.total_bytes {
                return Err(StoreError::Conflict(format!(
                    "resource {id} expects offset {}, got {position}",
                    head.total_bytes
                )));
            }
            None
        }
        ResourceKind::Numbered | ResourceKind::Membership => {
            if head.kind == ResourceKind::Membership && position != 0 {
                return Err(StoreError::Rejected(
                    "membership resources take no position".into(),
                ));
            }
            let slots = max_members(ResourceKind::Numbered) as u64;
            if head.kind == ResourceKind::Numbered && !(1..=slots).contains(&position) {
                return Err(StoreError::Rejected(format!(
                    "numbered slots range from 1 to {slots}, got {position}"
                )));
            }
            match execution.namespace_get_meta(&key)? {
                Some(value) => Some(decode_member_ref(&value)?),
                None => None,
            }
        }
    };
    let limit = max_members(head.kind) as u64;
    if replaced.is_none() && head.member_count >= limit {
        return Err(StoreError::CapacityExceeded(format!(
            "resource {id} holds {limit} members"
        )));
    }
    let replaced_length = replaced.as_ref().map_or(0, |(_, length)| *length);
    let total = head
        .total_bytes
        .checked_sub(replaced_length)
        .and_then(|t| t.checked_add(length))
        .ok_or_else(|| StoreError::CapacityExceeded("resource size overflow".into()))?;
    if head.max_bytes > 0 && total > head.max_bytes {
        return Err(StoreError::CapacityExceeded(format!(
            "resource {id} exceeds {} bytes",
            head.max_bytes
        )));
    }
    let installed = execution.content_install(prepared)?;
    if let Some((edge, _)) = &replaced {
        execution.edge_delete(edge)?;
    }
    let edge = execution.edge_put(&EdgeInput {
        source: head.anchor().identity(),
        target: installed.kappa.clone(),
        relation: EdgeRelation::Builtin(BuiltinRelation::Member),
        asserter: asserter.clone(),
        created_at_ms: execution.now().as_i64(),
        metadata: Some(canonical_bytes(&MemberCoordinate {
            position,
            length,
            receipt,
        })),
    })?;
    execution.namespace_put_meta(&key, &encode_member_ref(&edge, length))?;
    head.total_bytes = total;
    if replaced.is_none() {
        head.member_count = head
            .member_count
            .checked_add(1)
            .ok_or_else(|| StoreError::CapacityExceeded("member count overflows".into()))?;
    }
    head.revision = next_revision(head.revision)?;
    publish_head(execution, &head, asserter, Some(resource.head_version))?;
    Ok((head, installed))
}

/// `[edge key bytes][length: 8 BE]`: the member edge and its length.
fn encode_member_ref(edge: &Kappa, length: u64) -> Vec<u8> {
    let mut value = edge.key_bytes();
    value.extend_from_slice(&length.to_be_bytes());
    value
}

fn decode_member_ref(value: &[u8]) -> Result<(Kappa, u64), StoreError> {
    if value.len() < 8 {
        return Err(StoreError::Internal("malformed member reference".into()));
    }
    let (edge, length) = value.split_at(value.len() - 8);
    let length = u64::from_be_bytes(
        length
            .try_into()
            .map_err(|_| StoreError::Internal("malformed member length".into()))?,
    );
    Ok((Kappa::from_key_bytes(edge)?, length))
}

/// Retire every `Member` edge of `head` and its coordinate metadata.
/// Composite retention of the selected members must already be established
/// by the caller; unselected members become unreferenced.
fn retire_members(
    execution: &mut dyn ExecutionWrites,
    id: &str,
    head: &ResourceHead,
) -> Result<(), StoreError> {
    for member in members_in(execution, head)? {
        execution.edge_delete(&member.edge)?;
        execution.namespace_delete_meta(&ResourceHead::member_key(
            id,
            &coordinate_key(head.kind, member.coordinate.position, &member.identity),
        ))?;
    }
    Ok(())
}

/// Members in assembly order for `selected` positions.
///
/// Validated against the kind: sequential resources require every member
/// contiguous from
/// zero; numbered resources require ascending distinct slots that exist;
/// membership resources select by identity hash order and ignore
/// `selected`.
pub fn select<'a>(
    head: &ResourceHead,
    all: &'a [Member],
    selected: &[u64],
) -> Result<Vec<&'a Member>, StoreError> {
    match head.kind {
        ResourceKind::Sequential => {
            let mut ordered: Vec<&Member> = all.iter().collect();
            ordered.sort_by_key(|m| m.coordinate.position);
            let mut expected = 0u64;
            for member in &ordered {
                if member.coordinate.position != expected {
                    return Err(StoreError::Internal(
                        "sequential members are not contiguous".into(),
                    ));
                }
                expected = expected
                    .checked_add(member.coordinate.length)
                    .ok_or_else(|| {
                        StoreError::CapacityExceeded("sequential length overflows".into())
                    })?;
            }
            Ok(ordered)
        }
        ResourceKind::Numbered => {
            if selected.is_empty() {
                return Err(StoreError::Rejected("completion selects no members".into()));
            }
            let mut ordered = Vec::with_capacity(selected.len());
            let mut previous = 0u64;
            for slot in selected {
                if *slot <= previous {
                    return Err(StoreError::Rejected(
                        "selected slots must be ascending".into(),
                    ));
                }
                let member = all
                    .iter()
                    .find(|m| m.coordinate.position == *slot)
                    .ok_or_else(|| StoreError::Rejected(format!("missing member {slot}")))?;
                ordered.push(member);
                previous = *slot;
            }
            Ok(ordered)
        }
        ResourceKind::Membership => {
            let mut ordered: Vec<&Member> = all.iter().collect();
            ordered.sort_by_key(|member| member.identity.key_bytes());
            Ok(ordered)
        }
    }
}

/// Decode a coordinate from a resource anchor's edge.
pub fn coordinate_of(edge_metadata: Option<&[u8]>) -> Result<MemberCoordinate, StoreError> {
    let metadata = edge_metadata
        .ok_or_else(|| StoreError::Internal("member edge without a coordinate".into()))?;
    Ok(from_canonical(metadata)?)
}

/// The anchor identity of a resource.
pub fn anchor_of(ns: &NamespaceRef, incarnation: &[u8]) -> Kappa {
    ResourceAnchor {
        namespace_id: ns.id().to_vec(),
        incarnation: incarnation.to_vec(),
    }
    .identity()
}
