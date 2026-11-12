//! What one decoded ledger mutation admits, emitted as it is decoded
//! (`settlement_ledger`): the rows it installed, its retirements, the
//! admitted assignment, the directory record and identity projections.
//!
//! Every row this epoch installed is admitted: the records the seal
//! produced, the record every mutation names, and the content a
//! commitment, alias or composition names. Admission is decided by the
//! namespace's own row, so a mutation naming no row of this namespace (an
//! anchor, a tag target held elsewhere) admits nothing. Emission is not
//! deduplicated: an identity named twice is admitted twice, and every
//! consumer applies admission idempotently, so the reader holds no set of
//! the epoch's identities.
//!
//! Every read is refused before it is read when larger than the record
//! limit (rows after, being single values), and charged by the reader that
//! performs it, inside the unit the cursor admitted the mutation as
//! (`SettlementLimits::mutation`, derived from those readers' costs).

use redb::{ReadOnlyTable, ReadTransaction};

use kappa_store::canonical::from_canonical;
use kappa_store::epoch::EpochMutation;
use kappa_store::transition::{PreparedTransition, RecordTransition, TransitionDomain};
use kappa_store::work::{Dimension, Meter};
use kappa_store::{
    Kappa, LogicalIncarnation, MetadataSubject, NamespaceRef, StoreError, VerifiedContent,
};

use crate::content_read::ReadView;
use crate::control_plane::{ASSIGNMENT_KEY, AssignmentRecord};
use crate::representation::Representation;
use crate::settlement_identity::{IdentityEffect, collect, collect_grace};

/// One admitted effect of an epoch.
pub enum Staged {
    /// A row of this instance the epoch installed; `allocation` and
    /// `stored` describe an External row's physical ownership.
    Admitted {
        identity: Kappa,
        allocation: Option<[u8; 16]>,
        stored: u64,
    },
    Retired(Kappa),
    Assignment(AssignmentRecord),
    Directory(Vec<u8>),
    Identity(IdentityEffect),
}

/// Effects one ledger element emits at most. A mutation admits the record
/// it names (1), then either the record its content transition admits (1)
/// or its other effects: a retirement, an assignment or a directory record
/// (1), or an identity row and, for a credential, its grace row (2). A seal
/// record or an edge target admits one row. An emission beyond this is a
/// defect of this module, refused ([`collect_effects`]), never truncated.
pub const MAX_ELEMENT_EFFECTS: usize = 3;

/// Bytes of the buffer one element's effects are collected into, requested
/// at [`MAX_ELEMENT_EFFECTS`]; the effects' own payloads are the reads that
/// produced them.
pub const EFFECTS_BUFFER_BYTES: u64 = (MAX_ELEMENT_EFFECTS * std::mem::size_of::<Staged>()) as u64;

/// The effects `produce` emits for one element, in emission order, in a
/// buffer of [`EFFECTS_BUFFER_BYTES`] its caller accounted.
pub fn collect_effects(
    produce: impl FnOnce(&mut dyn FnMut(Staged) -> Result<(), StoreError>) -> Result<(), StoreError>,
) -> Result<Vec<Staged>, StoreError> {
    let mut effects = Vec::with_capacity(MAX_ELEMENT_EFFECTS);
    produce(&mut |effect| {
        if effects.len() == MAX_ELEMENT_EFFECTS {
            return Err(StoreError::Internal(format!(
                "a ledger element emitted more than its {MAX_ELEMENT_EFFECTS} effects"
            )));
        }
        effects.push(effect);
        Ok(())
    })?;
    Ok(effects)
}

#[cfg(test)]
#[path = "settlement_stage_tests.rs"]
mod tests;

/// The snapshot one cursor reads, and its record limit.
pub struct Reads<'a> {
    pub view: &'a ReadView,
    pub txn: &'a ReadTransaction,
    pub index: &'a ReadOnlyTable<&'static [u8], &'static [u8]>,
    pub ns: NamespaceRef,
    /// The instance the epoch's authenticated state names.
    pub incarnation: LogicalIncarnation,
    pub limit: u64,
}

impl Reads<'_> {
    /// The verified content of `identity`, refused unread when larger than
    /// the limit, read and hashed once on `work` (`verified_epoch_content`).
    fn record(
        &self,
        identity: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<VerifiedContent, StoreError> {
        self.view
            .verified_epoch_content(self.index, identity, Some(self.limit), work)
    }
}

/// Admit `identity` when this instance holds a row for it, its row read on
/// `work` by the one metered row reader (`ReadView::sized_record`). A work
/// refusal propagates; only absence admits nothing.
pub fn admit(
    reads: &Reads<'_>,
    identity: &Kappa,
    work: &mut dyn Meter,
    sink: &mut dyn FnMut(Staged) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let (record, row) = match reads.view.sized_record(reads.index, identity, work) {
        Ok(found) => found,
        Err(StoreError::NotFound(_)) => return Ok(()),
        Err(error) => return Err(error),
    };
    if row > reads.limit {
        return Err(StoreError::CapacityExceeded(format!(
            "row of {identity} is {row} bytes, beyond the settlement record limit {}",
            reads.limit
        )));
    }
    let (allocation, stored) = match record.representation() {
        Representation::External { allocation, .. } => (Some(allocation.0), record.stored_size()),
        _ => (None, 0),
    };
    sink(Staged::Admitted {
        identity: identity.clone(),
        allocation,
        stored,
    })
}

/// Stage `mutation`: the rows it admits, then its other effects.
pub fn stage_mutation(
    reads: &Reads<'_>,
    mutation: &EpochMutation,
    work: &mut dyn Meter,
    sink: &mut dyn FnMut(Staged) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let evidence = reads.record(&mutation.kappa, work)?;
    let transition = PreparedTransition::decode(
        TransitionDomain::new(*reads.ns.id(), reads.incarnation),
        mutation,
        evidence,
    )?;
    // Deletion evidence is retained content too; its identity is not the
    // identity of the payload or member removed by the transition.
    admit(reads, &mutation.kappa, work, sink)?;
    match transition.record() {
        RecordTransition::ContentPublish(record)
        | RecordTransition::ContentAlias(record)
        | RecordTransition::ContentCompose(record)
        | RecordTransition::RecordPublish(record) => {
            admit(reads, record.admission().identity(), work, sink)?;
        }
        _ => {}
    }
    effect(reads, &transition, work, sink)
}

/// The registry effects of one ledger `mutation` beyond the rows it
/// admits: retirements, the admitted assignment, the directory record and
/// the identity projections. A mutation whose only effect is the row it
/// names emits nothing here.
fn effect(
    reads: &Reads<'_>,
    transition: &PreparedTransition,
    work: &mut dyn Meter,
    sink: &mut dyn FnMut(Staged) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    match transition.record() {
        RecordTransition::ContentRetire(record) => {
            sink(Staged::Retired(record.removed().identity().clone()))
        }
        RecordTransition::Metadata(record) => {
            if matches!(record.subject(), MetadataSubject::Namespace)
                && record.key() == ASSIGNMENT_KEY
                && let Some(value) = record.value()
            {
                let assignment: AssignmentRecord = from_canonical(value)?;
                if assignment.namespace_id != reads.ns.id().as_slice() {
                    return Err(StoreError::Rejected(
                        "assignment record names another namespace".into(),
                    ));
                }
                return sink(Staged::Assignment(assignment));
            }
            Ok(())
        }
        RecordTransition::NamespaceUpdate(_) => {
            sink(Staged::Directory(transition.evidence().content().to_vec()))
        }
        RecordTransition::Assertion(_)
        | RecordTransition::Revocation(_)
        | RecordTransition::Watermark(_)
        | RecordTransition::Succession(_)
        | RecordTransition::Member(_)
        | RecordTransition::Session(_)
        | RecordTransition::Credential(_)
        | RecordTransition::Trust(_) => {
            let (identity, read) = collect(reads.txn, &reads.ns, transition, reads.limit)?;
            work.account(Dimension::BytesRead, read)?;
            sink(Staged::Identity(identity))?;
            if let Some((grace, read)) = collect_grace(reads.txn, transition, reads.limit)? {
                work.account(Dimension::BytesRead, read)?;
                sink(Staged::Identity(grace))?;
            }
            Ok(())
        }
        RecordTransition::ContentPublish(_)
        | RecordTransition::ContentAlias(_)
        | RecordTransition::ContentCompose(_)
        | RecordTransition::TagSet(_)
        | RecordTransition::TagDelete(_)
        | RecordTransition::EdgePut(_)
        | RecordTransition::EdgeDelete(_)
        | RecordTransition::OperationPublish(_)
        | RecordTransition::Sequence(_)
        | RecordTransition::RecordPublish(_) => Ok(()),
    }
}
