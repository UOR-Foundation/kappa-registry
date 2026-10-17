//! Namespace record, alias, and configuration writes owned by an execution.

use kappa_store::{Kappa, NamespaceRef, StoreError, namespace::ProtocolId};

use super::EpochExecution;

impl EpochExecution<'_> {
    /// Creates the namespace this execution was opened for, in the same
    /// transaction as every other write of the execution.
    pub fn namespace_create(
        &mut self,
        owner: Option<&Kappa>,
        protocol: Option<&ProtocolId>,
    ) -> Result<(), StoreError> {
        self.ensure_active()?;
        self.directory.touch();
        let result = self.store.namespace_create_in_txn(
            &self.transaction,
            &self.namespace,
            owner,
            protocol,
            self.now,
        );
        self.admit_result(result)
    }

    /// Renames the alias this execution was opened under. The alias must
    /// resolve to the execution's namespace UUID inside the same writer.
    pub fn namespace_rename(&mut self, new_name: &str) -> Result<(), StoreError> {
        self.ensure_active()?;
        self.directory.touch();
        let result = self.store.namespace_rename_in_txn(
            &self.transaction,
            self.namespace.display_name(),
            new_name,
            self.namespace.protocol(),
            Some(self.namespace.id()),
            self.now,
        );
        let renamed: NamespaceRef = self.admit_result(result)?;
        self.namespace = renamed;
        Ok(())
    }

    pub fn namespace_add_alias(
        &mut self,
        alias: &str,
        protocol: Option<&ProtocolId>,
    ) -> Result<(), StoreError> {
        self.ensure_active()?;
        self.directory.touch();
        let result = self.store.namespace_add_alias_in_txn(
            &self.transaction,
            &self.namespace,
            alias,
            protocol,
            self.now,
        );
        self.admit_result(result)
    }

    pub fn namespace_get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.ensure_active()?;
        self.admit_result(kappa_store::absent(self.store.namespace_get_meta_in_txn(
            &self.transaction,
            &self.namespace,
            key,
        )))
    }

    pub fn namespace_put_meta(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.ensure_active()?;
        let result = self.store.namespace_put_meta_in_txn(
            &self.transaction,
            &self.namespace,
            key,
            value,
            self.now,
        );
        self.admit_result(result)
    }

    pub fn namespace_delete_meta(&mut self, key: &str) -> Result<(), StoreError> {
        self.ensure_active()?;
        let result = self.store.namespace_delete_meta_in_txn(
            &self.transaction,
            &self.namespace,
            key,
            self.now,
        );
        self.admit_result(result)
    }
}
