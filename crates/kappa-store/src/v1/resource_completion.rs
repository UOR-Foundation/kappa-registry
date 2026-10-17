//! Preparation, completion, and discard of staged resources.
//!
//! ```text
//! resolve committed completion (replay from the head's binding)
//! -> prepare: freeze the ordered selection and bind the request (epoch)
//! -> prepare_composition: stream and verify that exact generation
//!    outside the writer, producing CompositionEvidence
//! -> complete: validate the head still names the generation, install the
//!    composite from the evidence, retire member edges, record the
//!    committed outcome (epoch)
//! ```
//!
//! A completion whose request already bound the head replays the committed
//! outcome before anything else is read: no staging state is required and
//! no final body is appended again. A different request against a prepared
//! head supersedes the preparation (nothing was published for it); against
//! a completed head it conflicts.

use kappa_types::canonical::canonical_bytes;
use kappa_types::{
    IngestResult, Kappa, NamespaceRef, ResourceCompletion, ResourceHead, ResourcePhase,
    ResourceSelection, SelectedMember, StoreError, VerifiedContent,
};

use super::{
    Resource, max_members, members_in, next_revision, publish_head, resolve_in, retire_members,
    select,
};
use crate::execution::{CompositionEvidence, ExecutionReads, ExecutionWrites};
use crate::traits::blob::BlobStore;

/// Largest selection record admitted.
const MAX_SELECTION_BYTES: u64 = 8 * 1024 * 1024;

/// What a completion request resolves to before any effect.
#[derive(Debug, Clone)]
pub enum Resolution {
    /// The request already completed the resource; this is its outcome.
    Replay(Box<ResourceCompletion>),
    /// The resource is open or prepared; completion may proceed.
    Pending(Box<Resource>),
}

/// Resolve `request` against the committed head of `id`.
pub fn resolve_completion<S: crate::traits::tag::TagStore + BlobStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    id: &str,
    request: &Kappa,
) -> Result<Option<Resolution>, StoreError> {
    let Some(resource) = super::resolve(store, ns, id)? else {
        return Ok(None);
    };
    Ok(Some(
        match (&resource.head.phase, &resource.head.completion) {
            (ResourcePhase::Completed, Some(binding)) if &binding.request == request => {
                Resolution::Replay(Box::new(binding.clone()))
            }
            (ResourcePhase::Completed, _) => {
                return Err(StoreError::Conflict(format!(
                    "resource {id} was completed by another request"
                )));
            }
            (ResourcePhase::Discarded, _) => {
                return Err(StoreError::NotFound(format!("resource {id} was discarded")));
            }
            _ => Resolution::Pending(Box::new(resource)),
        },
    ))
}

/// Outcome of [`prepare`].
#[derive(Debug, Clone)]
pub struct Preparation {
    pub head: ResourceHead,
    /// The frozen selection the head names.
    pub generation: Kappa,
    /// Whether this execution froze the generation. False when the head
    /// was already prepared for the same request: nothing was written, and
    /// a caller publishing only this preparation discards its execution.
    pub frozen: bool,
}

/// Freeze the ordered selection of `id` for `request` and bind them in
/// the head.
///
/// Admission closes: no member can be staged after this
/// publishes. The membership is read through the execution's view and must
/// agree with the head's counts. A head already prepared for the same
/// request is returned as is, with nothing written; one prepared for a
/// different request is superseded.
pub fn prepare(
    execution: &mut dyn ExecutionWrites,
    asserter: &Kappa,
    id: &str,
    request: &Kappa,
    selected: &[u64],
) -> Result<Preparation, StoreError> {
    let resource =
        resolve_in(execution, id)?.ok_or_else(|| StoreError::NotFound(format!("resource {id}")))?;
    let mut head = resource.head;
    match head.phase {
        ResourcePhase::Open => {}
        ResourcePhase::Prepared => {
            let generation = head
                .prepared
                .clone()
                .ok_or_else(|| StoreError::Internal("prepared head lacks a generation".into()))?;
            let selection = read_selection(execution, &head, &generation)?;
            if &selection.request == request {
                return Ok(Preparation {
                    head,
                    generation,
                    frozen: false,
                });
            }
        }
        ResourcePhase::Completed => {
            return Err(StoreError::Conflict(format!("resource {id} is completed")));
        }
        ResourcePhase::Discarded => {
            return Err(StoreError::NotFound(format!("resource {id} was discarded")));
        }
    }
    if execution.now().as_i64() > head.expires_at_ms {
        return Err(StoreError::NotFound(format!("resource {id} expired")));
    }
    let all = members_in(execution, &head)?;
    let committed_total = all
        .iter()
        .try_fold(0u64, |total, member| {
            total.checked_add(member.coordinate.length)
        })
        .ok_or_else(|| StoreError::CapacityExceeded("membership length overflows".into()))?;
    if all.len() as u64 != head.member_count || committed_total != head.total_bytes {
        return Err(StoreError::Internal(format!(
            "resource {id} head counts disagree with its membership"
        )));
    }
    let ordered = select(&head, &all, selected)?;
    if ordered.len() > max_members(head.kind) {
        return Err(StoreError::CapacityExceeded(
            "selection exceeds the member limit".into(),
        ));
    }
    let mut total = 0u64;
    let mut selection_members = Vec::with_capacity(ordered.len());
    for member in &ordered {
        total = total
            .checked_add(member.coordinate.length)
            .ok_or_else(|| StoreError::CapacityExceeded("selection length overflows".into()))?;
        selection_members.push(SelectedMember {
            identity: member.identity.clone(),
            position: member.coordinate.position,
            length: member.coordinate.length,
        });
    }
    let selection = ResourceSelection {
        namespace_id: head.namespace_id.clone(),
        incarnation: head.incarnation.clone(),
        revision: head.revision,
        request: request.clone(),
        members: selection_members,
        total_bytes: total,
    };
    selection.validate(&head.namespace_id, &head.incarnation)?;
    let bytes = canonical_bytes(&selection);
    if bytes.len() as u64 > MAX_SELECTION_BYTES {
        return Err(StoreError::CapacityExceeded(
            "selection record exceeds its bound".into(),
        ));
    }
    let content = VerifiedContent::compute(kappa_types::Axis::Sha256, &bytes)?;
    execution.blob_put(&content)?;
    let generation = content.kappa().clone();
    head.phase = ResourcePhase::Prepared;
    head.prepared = Some(generation.clone());
    head.revision = next_revision(head.revision)?;
    publish_head(execution, &head, asserter, Some(resource.head_version))?;
    Ok(Preparation {
        head,
        generation,
        frozen: true,
    })
}

fn read_selection(
    execution: &dyn ExecutionReads,
    head: &ResourceHead,
    generation: &Kappa,
) -> Result<ResourceSelection, StoreError> {
    let bytes = execution
        .blob_get_verified(generation, MAX_SELECTION_BYTES)?
        .ok_or_else(|| StoreError::Internal(format!("generation {generation} is missing")))?;
    let selection: ResourceSelection = kappa_types::canonical::from_canonical(&bytes)?;
    selection.validate(&head.namespace_id, &head.incarnation)?;
    Ok(selection)
}

/// Stream the frozen `generation` of `resource` through the store outside
/// any writer and produce the evidence of its composition.
///
/// Every member is verified against its committed identity and length,
/// and the whole is hashed under `primary` and every other mandatory
/// axis. The evidence binds the result to this exact generation.
///
/// Bounded by the monotonic `deadline`, checked before every buffer is
/// read: a blocking worker outlives its caller's timeout, so the bound is
/// enforced where the bytes are streamed, not by the caller.
pub fn prepare_composition<S: BlobStore + crate::traits::tag::TagStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    id: &str,
    generation: &Kappa,
    primary: kappa_types::Axis,
    deadline: std::time::Instant,
) -> Result<CompositionEvidence, StoreError> {
    let resource = super::resolve(store, ns, id)?
        .ok_or_else(|| StoreError::NotFound(format!("resource {id}")))?;
    if resource.head.prepared.as_ref() != Some(generation) {
        return Err(StoreError::Conflict(format!(
            "resource {id} no longer names generation {generation}"
        )));
    }
    if store.blob_size_in(ns, generation)? > MAX_SELECTION_BYTES {
        return Err(StoreError::Internal(
            "selection record exceeds its bound".into(),
        ));
    }
    let bytes = store.blob_get_verified_in(ns, generation)?;
    let selection: ResourceSelection = kappa_types::canonical::from_canonical(&bytes)?;
    selection.validate(&resource.head.namespace_id, &resource.head.incarnation)?;
    let mut axes = vec![primary];
    for axis in store.mandatory_axes() {
        if !axes.contains(&axis) {
            axes.push(axis);
        }
    }
    let mut hashers: Vec<kappa_types::IncrementalHasher> = axes
        .iter()
        .map(|axis| kappa_types::IncrementalHasher::new(*axis))
        .collect();
    let total = stream_selected(store, ns, &selection.members, deadline, |chunk| {
        for hasher in &mut hashers {
            hasher.update(chunk);
        }
        Ok(())
    })?;
    if total != selection.total_bytes {
        return Err(StoreError::Internal(
            "streamed length disagrees with the frozen selection".into(),
        ));
    }
    let mut identities = hashers
        .into_iter()
        .map(kappa_types::IncrementalHasher::finalize)
        .collect::<Result<Vec<Kappa>, _>>()?;
    let identity = identities.remove(0);
    let components = selection
        .members
        .iter()
        .map(|member| (member.identity.clone(), member.length))
        .collect();
    Ok(CompositionEvidence::new(
        selection.namespace_id,
        selection.incarnation,
        generation.clone(),
        identity,
        identities,
        components,
        total,
    ))
}

/// Outcome of [`complete`].
pub struct Completed {
    pub head: ResourceHead,
    pub installed: IngestResult,
    pub binding: ResourceCompletion,
    /// Whether the outcome was replayed from a head another execution
    /// already completed for this generation. A replay wrote nothing: the
    /// caller returns the committed outcome and performs none of the
    /// effects that accompanied the original completion, which may since
    /// have been superseded.
    pub replayed: bool,
}

/// Complete `id` from `evidence`.
///
/// The head must still name the evidenced generation and the bound request
/// must be `evidence`'s. The composite is
/// installed from the evidence (components retained by it), the member
/// edges are retired, and the outcome is recorded in the head with the
/// aliases and `receipt` a replay returns. A head already completed by the
/// same request replays its outcome, marked as such.
pub fn complete(
    execution: &mut dyn ExecutionWrites,
    asserter: &Kappa,
    id: &str,
    evidence: &CompositionEvidence,
    receipt: Option<Vec<u8>>,
) -> Result<Completed, StoreError> {
    let resource =
        resolve_in(execution, id)?.ok_or_else(|| StoreError::NotFound(format!("resource {id}")))?;
    let mut head = resource.head;
    if head.namespace_id != evidence.namespace_id() || head.incarnation != evidence.incarnation() {
        return Err(StoreError::Rejected(
            "composition evidence belongs to another resource".into(),
        ));
    }
    if let (ResourcePhase::Completed, Some(binding)) = (&head.phase, &head.completion) {
        if &binding.generation == evidence.generation() {
            let replay = IngestResult::new(binding.result.clone(), false)
                .with_additional(binding.aliases.clone());
            return Ok(Completed {
                binding: binding.clone(),
                head: head.clone(),
                installed: replay,
                replayed: true,
            });
        }
        return Err(StoreError::Conflict(format!(
            "resource {id} was completed by another request"
        )));
    }
    if head.phase != ResourcePhase::Prepared
        || head.prepared.as_ref() != Some(evidence.generation())
    {
        return Err(StoreError::Conflict(format!(
            "resource {id} does not name generation {}",
            evidence.generation()
        )));
    }
    let selection = read_selection(execution, &head, evidence.generation())?;
    let installed = execution.content_compose(evidence)?;
    // The composite now retains its components; the staging references
    // can go. Unselected members become unreferenced.
    retire_members(execution, id, &head)?;
    let binding = ResourceCompletion {
        request: selection.request,
        generation: evidence.generation().clone(),
        result: installed.kappa.clone(),
        aliases: installed.additional_kappas.clone(),
        receipt,
    };
    head.completion = Some(binding.clone());
    head.phase = ResourcePhase::Completed;
    head.total_bytes = evidence.total_bytes();
    head.member_count = 0;
    head.revision = next_revision(head.revision)?;
    publish_head(execution, &head, asserter, Some(resource.head_version))?;
    Ok(Completed {
        head,
        installed,
        binding,
        replayed: false,
    })
}

/// Discard a resource.
///
/// Its member edges and coordinate metadata are retired, its `Owns` edge
/// removed, and its name retired. A completed
/// resource's outcome stays replayable until it is discarded, which the
/// expiry task does after the resource's window. Idempotent on an absent
/// or discarded head.
pub fn discard(
    execution: &mut dyn ExecutionWrites,
    asserter: &Kappa,
    id: &str,
) -> Result<bool, StoreError> {
    let Some(resource) = resolve_in(execution, id)? else {
        return Ok(false);
    };
    let mut head = resource.head;
    if head.phase == ResourcePhase::Discarded {
        return Ok(false);
    }
    retire_members(execution, id, &head)?;
    head.phase = ResourcePhase::Discarded;
    head.member_count = 0;
    head.revision = next_revision(head.revision)?;
    publish_head(execution, &head, asserter, Some(resource.head_version))?;
    if let Some(owns) = execution.namespace_get_meta(&ResourceHead::owns_key(id))? {
        execution.edge_delete(&Kappa::from_key_bytes(&owns)?)?;
        execution.namespace_delete_meta(&ResourceHead::owns_key(id))?;
    }
    execution.tag_delete(&ResourceHead::tag_name(id))?;
    Ok(true)
}

/// Discard a resource whose expiry has passed. Guarded: a head renewed,
/// prepared, or completed since the caller observed it is left alone.
pub fn expire(
    execution: &mut dyn ExecutionWrites,
    asserter: &Kappa,
    id: &str,
    observed_revision: u64,
) -> Result<bool, StoreError> {
    let Some(resource) = resolve_in(execution, id)? else {
        return Ok(false);
    };
    if resource.head.revision != observed_revision
        || execution.now().as_i64() <= resource.head.expires_at_ms
    {
        return Ok(false);
    }
    discard(execution, asserter, id)
}

/// Stream the frozen selection's `ordered` members through `sink` in order,
/// verifying each against its identity and frozen length. Returns the
/// total length. Refused once `deadline` passes.
fn stream_selected<S: BlobStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    ordered: &[SelectedMember],
    deadline: std::time::Instant,
    mut sink: impl FnMut(&[u8]) -> Result<(), StoreError>,
) -> Result<u64, StoreError> {
    let mut total = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];
    for member in ordered {
        let mut reader = store.blob_open_in(ns, &member.identity)?;
        let mut hasher = kappa_types::IncrementalHasher::new(member.identity.axis());
        let mut seen = 0u64;
        loop {
            if std::time::Instant::now() >= deadline {
                return Err(StoreError::Rejected(
                    "composition preparation deadline exceeded".into(),
                ));
            }
            let count = std::io::Read::read(&mut reader, &mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            sink(&buffer[..count])?;
            seen = seen
                .checked_add(count as u64)
                .ok_or_else(|| StoreError::CapacityExceeded("member length overflows".into()))?;
            if seen > member.length {
                return Err(StoreError::Internal(format!(
                    "member {} exceeds its committed length",
                    member.identity
                )));
            }
        }
        if seen != member.length || hasher.finalize()? != member.identity {
            return Err(StoreError::Internal(format!(
                "member {} disagrees with its frozen selection",
                member.identity
            )));
        }
        total = total
            .checked_add(seen)
            .ok_or_else(|| StoreError::CapacityExceeded("selection length overflows".into()))?;
    }
    Ok(total)
}
