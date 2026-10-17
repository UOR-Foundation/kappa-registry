//! The one path from an execution to its sealed, then committed,
//! publication.

use kappa_store::{Kappa, StoreError};

use super::{EpochExecution, ExecutionOwnership, PreparedEpochPublication};

impl<'a> EpochExecution<'a> {
    /// Publish an execution that carries no operation identity.
    pub fn publish(self) -> Result<(u64, Kappa), StoreError> {
        self.into_publication(None)?.publish()
    }

    /// Publish an operation execution with its durable `result`.
    pub fn publish_result(self, result: Vec<u8>) -> Result<(u64, Kappa), StoreError> {
        self.into_publication(Some(result))?.publish()
    }

    /// The one path from an execution to its sealed publication. Refused
    /// when the execution failed, when an operation execution has no
    /// result or a plain one has one, and when an authorization row it read
    /// changed. An operation's receipt is installed and recorded before the
    /// seal, and its coordinates stored in the sealed transaction; the
    /// execution's ownership (gate, grant, release grant), deadline and pins
    /// move into the publication.
    fn into_publication(
        self,
        result: Option<Vec<u8>>,
    ) -> Result<PreparedEpochPublication<'a>, StoreError> {
        self.ensure_active()?;
        self.authorization_holds()?;
        let receipt = match (&self.operation, result) {
            (None, None) => None,
            (Some(_), None) => {
                return Err(StoreError::Conflict(
                    "operation execution requires a persisted result".into(),
                ));
            }
            (None, Some(_)) => {
                return Err(StoreError::Conflict(
                    "execution has no operation identity".into(),
                ));
            }
            (Some((identity, request)), Some(result)) => {
                let receipt = kappa_store::OperationReceipt::new(
                    &self.namespace,
                    identity,
                    request.clone(),
                    result,
                )?;
                let content = kappa_store::VerifiedContent::compute(
                    kappa_store::Axis::Sha256,
                    &kappa_store::canonical::canonical_bytes(&receipt),
                )?;
                let pin = self.install_record(&content)?;
                self.store.record_mutation_in_txn(
                    &self.transaction,
                    &self.namespace,
                    kappa_store::MutationOp::OperationPublish,
                    content.kappa().clone(),
                    self.now,
                    None,
                )?;
                Some((*identity, content.kappa().clone(), pin))
            }
        };
        let Self {
            store,
            transaction,
            directory,
            writer,
            active,
            release,
            namespace,
            creation,
            now,
            signer_override,
            deadline,
            content_pins,
            ..
        } = self;
        let mut prepared = store.prepare_epoch_transaction(
            ExecutionOwnership {
                directory,
                writer,
                active,
                release,
            },
            transaction,
            &namespace,
            creation,
            now,
            signer_override.as_ref(),
        )?;
        prepared.deadline = deadline;
        prepared.content_pins.extend(content_pins);
        if let Some((identity, receipt, pin)) = receipt {
            prepared.content_pins.extend(pin);
            store.store_operation_coordinates(
                &prepared.transaction,
                &namespace,
                &identity,
                prepared.root.kappa(),
                &receipt,
            )?;
        }
        Ok(prepared)
    }
}
