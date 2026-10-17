//! Shared admission of operation outcomes subordinate to signed epochs.

use kappa_types::{
    EpochMutation, EpochRoot, Kappa, MutationOp, NamespaceRef, OperationReceipt, StoreError,
    VerifiedContent, canonical::from_canonical,
};

#[derive(Clone, Copy)]
pub struct OperationOutcomeInput<'a> {
    pub epoch: &'a EpochRoot,
    pub ledger: &'a [u8],
    pub receipt_identity: &'a Kappa,
    pub receipt_bytes: &'a [u8],
    pub namespace: &'a NamespaceRef,
    pub identity: &'a [u8; 32],
    pub request: &'a Kappa,
}

pub fn admit_operation_outcome(
    input: OperationOutcomeInput<'_>,
    authority: &crate::epoch_authority::EpochAuthority,
) -> Result<OperationReceipt, StoreError> {
    let OperationOutcomeInput {
        epoch,
        ledger,
        receipt_identity,
        receipt_bytes,
        namespace,
        identity,
        request,
    } = input;
    crate::epoch_publication::verify_persisted_epoch(epoch, authority, ledger)?;
    if epoch.namespace_id() != namespace.id() {
        return Err(StoreError::Rejected(
            "operation epoch crosses namespace".into(),
        ));
    }
    VerifiedContent::verify(receipt_identity, receipt_bytes)?;
    let receipt: OperationReceipt = from_canonical(receipt_bytes)?;
    receipt.validate()?;
    if !receipt.matches(namespace, identity, request) {
        return Err(StoreError::Conflict(
            "operation identity reused with a different request".into(),
        ));
    }
    let mutations: Vec<EpochMutation> = from_canonical(ledger)?;
    if mutations
        .iter()
        .filter(|mutation| {
            mutation.op == MutationOp::OperationPublish
                && mutation.kappa == *receipt_identity
                && mutation.context.is_none()
        })
        .count()
        != 1
    {
        return Err(StoreError::Rejected(
            "operation receipt is not committed by its epoch ledger".into(),
        ));
    }
    Ok(receipt)
}
