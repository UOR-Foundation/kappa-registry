//! Opening a store: the registry database (`registry`), the projection
//! bound it was established under, the encryptors under the configured
//! key, and the state persisted before the store is returned (authority
//! history, one bounded recovery step, one bounded inventory step).

use std::sync::Arc;

use redb::{Database, ReadableTableMetadata, WriteTransaction};

use kappa_store::MaintenanceStore;
use kappa_store::error::StoreError;
use kappa_store::work::{Dimension, WorkMeter};

use crate::config::PersistentStoreConfig;
use crate::error::CommitFailure;
use crate::projection_stage::{VERSION_RECORD_BYTES, set_counter, stored};
use crate::registry::Registry;
use crate::settlement::SettlementLimits;
use crate::tables::{
    PROJECTION_ATTEMPTS, PROJECTION_COMPLETED, PROJECTION_COUNTERS, PROJECTION_INSTANCES,
    PROJECTION_LOG, PROJECTION_VERSIONS, SETTLED,
};
use crate::{
    PersistentStore, backend, blob_encryption, control_plane, durability, encrypted, error,
    retirement_record, storage, store_access, tables,
};

/// The encryptors a store opens with: both or neither, from one key.
pub struct Encryptors {
    pub(crate) blob: Option<Arc<blob_encryption::BlobEncryption>>,
    pub(crate) table: Option<Arc<encrypted::TableEncryptor>>,
}

/// Whether `txn`'s registry holds any projection state: a version, a log
/// entry, a completion, an instance's last completion, an attempt, a
/// counter or a checkpoint. Each table's length is read from its root, one
/// page at most.
fn projection_holds_state(txn: &WriteTransaction) -> Result<bool, StoreError> {
    for table in [
        PROJECTION_VERSIONS,
        PROJECTION_LOG,
        PROJECTION_COMPLETED,
        PROJECTION_INSTANCES,
        PROJECTION_ATTEMPTS,
        PROJECTION_COUNTERS,
        SETTLED,
    ] {
        let rows = txn
            .open_table(table)
            .map_err(error::redb)?
            .len()
            .map_err(error::redb)?;
        if rows > 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

impl PersistentStore {
    /// The registry, with every registry table committed under its writer
    /// slot before it is returned.
    pub(crate) fn open_registry(
        config: &PersistentStoreConfig,
    ) -> Result<Arc<Registry>, StoreError> {
        std::fs::create_dir_all(&config.blob_root)?;
        if let Some(parent) = config.db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let database = match &config.backend {
            Some(backend_factory) => Database::builder()
                .create_with_backend(backend::OwnedBackend(backend_factory()))
                .map_err(error::redb)?,
            None => Database::create(&config.db_path).map_err(error::redb)?,
        };
        let registry = Arc::new(Registry::new(database));
        let txn = registry.begin_write()?;
        tables::create_registry_tables(&txn).map_err(error::redb)?;
        match txn.commit() {
            Ok(()) => Ok(registry),
            // The store is not constructed: an open whose table creation
            // may or may not have persisted creates them again, and table
            // creation is idempotent.
            Err(CommitFailure::Known(error) | CommitFailure::Unknown(error)) => Err(error),
        }
    }

    /// Establish `limits`' settlement record limit as `registry`'s
    /// projection limit while the store is opened, before any consumer of
    /// the projection exists: the recorded value is the largest limit
    /// successfully established for this registry, so every version it
    /// holds is within that limit's `VersionBounds`. The policy is
    /// monotonic: a limit below the recorded one is refused even when no
    /// version was ever staged under the larger, and a larger one is
    /// recorded before the store is used. A registry holding projection
    /// state but no recorded limit was staged under no established bound
    /// and is refused rather than given the current one. Each refusal is
    /// `UpgradeRequired` and leaves the registry unchanged; any commit
    /// failure fails the open, so no handle runs on an unestablished bound.
    pub(crate) fn establish_version_bounds(
        registry: &Registry,
        limits: SettlementLimits,
    ) -> Result<(), StoreError> {
        let record_bytes = limits.record_bytes();
        let txn = registry.begin_write()?;
        let recorded = {
            let counters = txn.open_table(PROJECTION_COUNTERS).map_err(error::redb)?;
            stored(&counters, VERSION_RECORD_BYTES)?
        };
        match recorded {
            Some(recorded) if recorded > record_bytes => {
                txn.abort()?;
                return Err(StoreError::UpgradeRequired(format!(
                    "settlement_record_bytes {record_bytes} is below the {recorded} this registry's projection was established under; open with at least {recorded}"
                )));
            }
            Some(recorded) if recorded == record_bytes => return txn.abort(),
            Some(_) => {}
            None if projection_holds_state(&txn)? => {
                txn.abort()?;
                return Err(StoreError::UpgradeRequired(
                    "the registry holds projection state but records no settlement record limit it was staged under".into(),
                ));
            }
            None => {}
        }
        set_counter(
            &mut txn.open_table(PROJECTION_COUNTERS).map_err(error::redb)?,
            VERSION_RECORD_BYTES,
            record_bytes,
        )?;
        match txn.commit() {
            Ok(()) => Ok(()),
            // The store is not returned: the next open reads whatever
            // persisted and decides again.
            Err(CommitFailure::Known(error) | CommitFailure::Unknown(error)) => Err(error),
        }
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
        registry: &Arc<Registry>,
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
    /// authority history, one recovery step of the configured
    /// `recovery_step` limit, and one bounded inventory step. The store
    /// returns with recovery in progress when one step does not finish it:
    /// discovery reports itself incomplete and the unsettled pool stays
    /// closed until maintenance steps finish the enumeration of the
    /// obligations present at open (`settlement_recovery`).
    pub(crate) fn recover_at_open(
        &self,
        configured: kappa_crypto::SigningAuthority,
        alternates: Vec<kappa_crypto::SigningAuthority>,
        require_history: bool,
        inventory_entries: usize,
    ) -> Result<(), StoreError> {
        // The authority history must be in force before any persisted epoch
        // is admitted below.
        self.restore_authority(configured, alternates, require_history)?;
        // Every settled epoch bounds rotation from here; the recovery step
        // raises the bound from the heads of the instances it visits.
        self.restore_settled_epoch_time()?;
        self.set_settlement_pass(false)?;
        let mut meter = WorkMeter::new(self.step_limit);
        let stepped = self.recovery_step(&mut meter)?;
        if stepped.settled > 0 {
            tracing::info!(epochs = stepped.settled, "recovery step at open");
        }
        // Reclamation decides each allocation from its installer's own
        // committed rows (`content_reclaim`); it does not depend on the
        // recovery above having finished. The step's continuation is
        // dropped: maintenance starts its own pass.
        let entries = u64::try_from(inventory_entries).unwrap_or(u64::MAX);
        let limit = self.step_limit.with(Dimension::Entries, entries);
        let step = self.reclaim_unowned(&limit, None)?;
        let reclaimed = step.outcome;
        if reclaimed.files > 0 || !step.complete() {
            tracing::info!(
                files = reclaimed.files,
                bytes = reclaimed.bytes,
                owned = reclaimed.owned,
                protected = reclaimed.protected,
                unrecognized = reclaimed.unrecognized,
                failed = reclaimed.failed,
                complete = step.complete(),
                "allocation inventory step at open"
            );
        }
        Ok(())
    }
}
