//! Opening a store: the registry database, the encryptors under the
//! configured key, and the state persisted before the store is returned
//! (authority history, one bounded recovery step, one bounded inventory
//! step).

use std::sync::Arc;

use redb::Database;

use kappa_store::error::StoreError;

use crate::config::PersistentStoreConfig;
use crate::{
    PersistentStore, backend, blob_encryption, control_plane, durability, encrypted, error,
    retirement_record, settlement, storage, store_access, tables,
};

/// The encryptors a store opens with: both or neither, from one key.
pub struct Encryptors {
    pub(crate) blob: Option<Arc<blob_encryption::BlobEncryption>>,
    pub(crate) table: Option<Arc<encrypted::TableEncryptor>>,
}

impl PersistentStore {
    /// The registry database, with every registry table committed before
    /// the handle is returned.
    pub(crate) fn open_registry(
        config: &PersistentStoreConfig,
    ) -> Result<Arc<Database>, StoreError> {
        std::fs::create_dir_all(&config.blob_root)?;
        if let Some(parent) = config.db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = match &config.backend {
            Some(backend_factory) => Arc::new(
                Database::builder()
                    .create_with_backend(backend::OwnedBackend(backend_factory()))
                    .map_err(error::redb)?,
            ),
            None => Arc::new(Database::create(&config.db_path).map_err(error::redb)?),
        };
        let txn = db.begin_write().map_err(error::redb)?;
        tables::create_registry_tables(&txn).map_err(error::redb)?;
        txn.commit().map_err(error::redb)?;
        Ok(db)
    }

    /// The blob and table encryptors under `config`'s encryption key, which
    /// is taken from the configuration and zeroized when this returns;
    /// neither without a key.
    pub(crate) fn encryptors(config: &mut PersistentStoreConfig) -> Result<Encryptors, StoreError> {
        let Some(key) = config.encryption_key.take().map(zeroize::Zeroizing::new) else {
            return Ok(Encryptors {
                blob: None,
                table: None,
            });
        };
        let kms = kappa_crypto::kms::FileKms::new(*key, config.blob_root.join("_erased"))
            .map_err(error::crypto)?;
        let blob = blob_encryption::BlobEncryption::new(kms, config.resource_owner.clone())?;
        let table = encrypted::TableEncryptor::new(&key).map_err(|error| {
            StoreError::Internal(format!("table encryption initialization: {error}"))
        })?;
        Ok(Encryptors {
            blob: Some(Arc::new(blob)),
            table: Some(Arc::new(table)),
        })
    }

    /// The content durability pipeline under `config`'s blob root and
    /// queue and batch bounds.
    pub(crate) fn content_durability(
        config: &PersistentStoreConfig,
    ) -> Result<durability::Durability, StoreError> {
        durability::Durability::new(
            config.blob_root.clone(),
            config.fsync,
            durability::DurabilityLimits {
                queue_entries: config.preparation_entries,
                queue_bytes: config.preparation_bytes,
                batch_entries: config.durability_batch_entries,
                batch_bytes: config.durability_batch_bytes,
            },
        )
    }

    /// The namespace storage beside the registry database: assignments
    /// resolved under `table` encryption against `planes`, and retirement
    /// fences read from `registry`. Takes the configured namespace backend.
    pub(crate) fn namespace_storage(
        config: &mut PersistentStoreConfig,
        planes: &Arc<control_plane::ControlPlanes>,
        table: Option<Arc<encrypted::TableEncryptor>>,
        registry: &Arc<Database>,
    ) -> storage::NamespaceStorage {
        let root = config.db_path.parent().map_or_else(
            || std::path::PathBuf::from("."),
            std::path::Path::to_path_buf,
        );
        storage::NamespaceStorage::new(
            root,
            config.max_idle_namespaces,
            config.max_active_namespaces,
            Arc::clone(planes),
            Arc::new(store_access::AdmittedAssignments {
                table_encryptor: table,
            }),
            Arc::new(retirement_record::RetirementRecords {
                registry: Arc::clone(registry),
            }),
            config.namespace_backend.take(),
            config.fsync,
        )
    }

    /// Bring persisted state into force before the store is returned: the
    /// authority history, one bounded recovery step, and one bounded
    /// inventory step. The store returns with recovery in progress when one
    /// step does not finish it: discovery reports itself incomplete and the
    /// unsettled pool stays closed until maintenance steps
    /// (`settlement_step`) finish the enumeration of the obligations
    /// present at open (`settlement_recovery`).
    pub(crate) fn recover_at_open(
        &self,
        configured: kappa_crypto::SigningAuthority,
        alternates: Vec<kappa_crypto::SigningAuthority>,
        require_history: bool,
        recovery_budget: settlement::StepBudget,
        inventory_entries: usize,
    ) -> Result<(), StoreError> {
        // The authority history must be in force before any persisted epoch
        // is admitted below.
        self.restore_authority(configured, alternates, require_history)?;
        // Every settled epoch bounds rotation from here; the recovery step
        // raises the bound from the heads of the instances it visits.
        self.restore_settled_epoch_time()?;
        self.set_settlement_pass(false)?;
        let settled = self.recovery_step(recovery_budget)?;
        if settled > 0 {
            tracing::info!(epochs = settled, "recovery step at open");
        }
        // Reclamation decides each allocation from its installer's own
        // committed rows (`content_reclaim`); it does not depend on the
        // recovery above having finished.
        let reclaimed = kappa_store::MaintenanceStore::reclaim_unowned(self, inventory_entries)?;
        if reclaimed.files > 0 || !reclaimed.complete {
            tracing::info!(
                files = reclaimed.files,
                bytes = reclaimed.bytes,
                owned = reclaimed.owned,
                protected = reclaimed.protected,
                unrecognized = reclaimed.unrecognized,
                complete = reclaimed.complete,
                "allocation inventory step at open"
            );
        }
        Ok(())
    }
}
