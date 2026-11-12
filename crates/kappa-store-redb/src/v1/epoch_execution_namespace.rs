//! Namespace record, alias, and configuration writes owned by an execution,
//! each on the execution's allowance (`EpochExecution::write`).

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
        self.write(|store, txn, ns, now, meter| {
            store.namespace_create_in_txn(txn, ns, owner, protocol, now, meter)
        })
    }

    /// Renames the alias this execution was opened under. The alias must
    /// resolve to the execution's namespace UUID inside the same writer.
    pub fn namespace_rename(&mut self, new_name: &str) -> Result<(), StoreError> {
        self.ensure_active()?;
        self.directory.touch();
        let renamed: NamespaceRef = self.write(|store, txn, ns, now, meter| {
            store.namespace_rename_in_txn(
                txn,
                ns.display_name(),
                new_name,
                ns.protocol(),
                Some(ns.id()),
                now,
                meter,
            )
        })?;
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
        self.write(|store, txn, ns, now, meter| {
            store.namespace_add_alias_in_txn(txn, ns, alias, protocol, now, meter)
        })
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
        self.write(|store, txn, ns, now, meter| {
            store.namespace_put_meta_in_txn(txn, ns, key, value, now, meter)
        })
    }

    pub fn namespace_delete_meta(&mut self, key: &str) -> Result<(), StoreError> {
        self.write(|store, txn, ns, now, meter| {
            store.namespace_delete_meta_in_txn(txn, ns, key, now, meter)
        })
    }
}
