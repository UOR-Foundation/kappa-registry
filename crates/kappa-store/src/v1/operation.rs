//! Shared admission of operation outcomes subordinate to signed epochs.

use kappa_types::{
    EpochRoot, Kappa, LogicalIncarnation, MutationOp, NamespaceRef, OperationReceipt, StoreError,
    VerifiedContent,
    canonical::from_canonical,
    work::{Dimension, Meter},
};

#[derive(Clone, Copy)]
pub struct OperationOutcomeInput<'a> {
    pub epoch: &'a EpochRoot,
    /// The epoch's complete ledger, its identity established.
    pub ledger: &'a VerifiedContent,
    /// The receipt the operation index names, its identity established.
    pub receipt: &'a VerifiedContent,
    pub namespace: &'a NamespaceRef,
    /// The namespace instance the request is admitted to; a receipt of
    /// another incarnation does not answer it.
    pub incarnation: &'a LogicalIncarnation,
    pub identity: &'a [u8; 32],
    pub request: &'a Kappa,
}

/// The receipt that answers `input`'s request, on `work`: its epoch is
/// admitted with its ledger once (`admit_persisted_epoch`), the receipt
/// (identified by its caller) is decoded and matched to the request, and
/// the ledger's mutations must commit it exactly once. Each step is charged
/// before it runs.
pub fn admit_operation_outcome(
    input: OperationOutcomeInput<'_>,
    authority: &crate::epoch_authority::EpochAuthority,
    work: &mut dyn Meter,
) -> Result<OperationReceipt, StoreError> {
    let OperationOutcomeInput {
        epoch,
        ledger,
        receipt,
        namespace,
        incarnation,
        identity,
        request,
    } = input;
    let mutations =
        crate::epoch_publication::admit_persisted_epoch(epoch, authority, ledger, work)?;
    if epoch.namespace_id() != namespace.id() {
        return Err(StoreError::Rejected(
            "operation epoch crosses namespace".into(),
        ));
    }
    let length = receipt.len() as u64;
    work.charge_all(&[
        (Dimension::BytesDecoded, length),
        (Dimension::BytesAllocated, length),
    ])?;
    let decoded: OperationReceipt = from_canonical(receipt.content())?;
    decoded.validate()?;
    if !decoded.matches(namespace, incarnation, identity, request) {
        return Err(StoreError::Conflict(
            "operation identity reused with a different request".into(),
        ));
    }
    work.charge(Dimension::Entries, mutations.len() as u64)?;
    if mutations
        .iter()
        .filter(|mutation| {
            mutation.op == MutationOp::OperationPublish
                && mutation.kappa == *receipt.kappa()
                && mutation.context.is_none()
        })
        .count()
        != 1
    {
        return Err(StoreError::Rejected(
            "operation receipt is not committed by its epoch ledger".into(),
        ));
    }
    Ok(decoded)
}
