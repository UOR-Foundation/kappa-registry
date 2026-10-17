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
//! limit (rows after, being single values), and charged to the step's
//! [`Work`] under the reservation the cursor took for the mutation.

use redb::{ReadOnlyTable, ReadTransaction};

use kappa_store::canonical::from_canonical;
use kappa_store::epoch::{EpochMutation, MetadataRecord, MutationOp};
use kappa_store::{ContentCommitment, Kappa, NamespaceInfo, NamespaceRef, StoreError};
use kappa_types::content::{ContentAlias, ContentComposition};

use super::work::Work;
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

/// The snapshot one cursor reads, and its record limit.
pub struct Reads<'a> {
    pub view: &'a ReadView,
    pub txn: &'a ReadTransaction,
    pub index: &'a ReadOnlyTable<&'static [u8], &'static [u8]>,
    pub ns: NamespaceRef,
    pub limit: u64,
}

impl Reads<'_> {
    /// The verified content of `identity`, refused unread when larger than
    /// the limit, charged.
    fn record(&self, identity: &Kappa, work: &mut Work) -> Result<Vec<u8>, StoreError> {
        let bytes = self
            .view
            .epoch_content_from_index(self.index, identity, Some(self.limit))?;
        work.charge_bytes(bytes.len() as u64)?;
        Ok(bytes)
    }
}

/// Admit `identity` when this instance holds a row for it.
pub fn admit(
    reads: &Reads<'_>,
    identity: &Kappa,
    work: &mut Work,
    sink: &mut dyn FnMut(Staged) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let (record, row) = match reads.view.sized_record(reads.index, identity) {
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
    work.charge_bytes(row)?;
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
    work: &mut Work,
    sink: &mut dyn FnMut(Staged) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    if !matches!(
        mutation.op,
        MutationOp::ContentRetire | MutationOp::TagDelete | MutationOp::EdgeDelete
    ) {
        admit(reads, &mutation.kappa, work, sink)?;
    }
    if let Some(named) = named_content(reads, mutation, work)? {
        admit(reads, &named, work, sink)?;
    }
    effect(reads, mutation, work, sink)
}

/// Content identities `mutation` names whose rows the epoch may have
/// installed, beyond the identity the mutation itself names: the content
/// a commitment, an alias or a composition record identifies.
fn named_content(
    reads: &Reads<'_>,
    mutation: &EpochMutation,
    work: &mut Work,
) -> Result<Option<Kappa>, StoreError> {
    Ok(match mutation.op {
        MutationOp::ContentPublish => {
            let commitment: ContentCommitment =
                from_canonical(&reads.record(&mutation.kappa, work)?)?;
            Some(commitment.identity().clone())
        }
        MutationOp::ContentAlias => {
            let alias: ContentAlias = from_canonical(&reads.record(&mutation.kappa, work)?)?;
            Some(alias.alias().clone())
        }
        MutationOp::ContentCompose => {
            let composition: ContentComposition =
                from_canonical(&reads.record(&mutation.kappa, work)?)?;
            Some(composition.identity().clone())
        }
        _ => None,
    })
}

/// The registry effects of one ledger `mutation` beyond the rows it
/// admits: retirements, the admitted assignment, the directory record and
/// the identity projections. A mutation whose only effect is the row it
/// names emits nothing here.
fn effect(
    reads: &Reads<'_>,
    mutation: &EpochMutation,
    work: &mut Work,
    sink: &mut dyn FnMut(Staged) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    match mutation.op {
        MutationOp::ContentRetire => sink(Staged::Retired(mutation.kappa.clone())),
        MutationOp::MetadataUpdate => {
            let record: MetadataRecord = from_canonical(&reads.record(&mutation.kappa, work)?)?;
            if record.key == ASSIGNMENT_KEY
                && let Some(value) = &record.value
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
        MutationOp::NamespaceUpdate => {
            let bytes = reads.record(&mutation.kappa, work)?;
            let record: NamespaceInfo = from_canonical(&bytes)?;
            if record.ns.id() != reads.ns.id() {
                return Err(StoreError::Rejected(
                    "namespace record names another namespace".into(),
                ));
            }
            sink(Staged::Directory(bytes))
        }
        MutationOp::AssertionPublish | MutationOp::RevocationPublish | MutationOp::AnchorOrigin => {
            let (identity, read) = collect(
                reads.view,
                reads.txn,
                reads.index,
                &reads.ns,
                mutation,
                reads.limit,
            )?;
            work.charge_bytes(read)?;
            sink(Staged::Identity(identity))?;
            if let Some((grace, read)) = collect_grace(reads.txn, mutation, reads.limit)? {
                work.charge_bytes(read)?;
                sink(Staged::Identity(grace))?;
            }
            Ok(())
        }
        MutationOp::ContentPublish
        | MutationOp::ContentAlias
        | MutationOp::ContentCompose
        | MutationOp::TagSet
        | MutationOp::TagDelete
        | MutationOp::EdgePut
        | MutationOp::EdgeDelete
        | MutationOp::OperationPublish
        | MutationOp::SequenceUpdate
        | MutationOp::RecordPublish => Ok(()),
        // `MutationOp` is non-exhaustive by declaration; an operation this
        // build does not know carries effects it cannot project, and
        // projecting around it would settle a checkpoint past unapplied
        // effects.
        other => Err(StoreError::NotSupported(format!(
            "settlement of mutation {other:?} is not implemented by this build"
        ))),
    }
}
