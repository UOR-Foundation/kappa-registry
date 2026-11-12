//! Crate-private test seams over namespace writers: hold a namespace's
//! writer the way an execution does, publish it, read its database, and
//! settle, for tests that drive the seal and commit directly.

use std::sync::Arc;

use kappa_store::clock::ClockMs;
use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;

use kappa_crypto::Signer;
use kappa_crypto::ed25519::Ed25519Signer;
use kappa_crypto::signed_types::{admit_retirement_request, sign_retirement_request};
use kappa_store::governed_retirement::VerifiedRetirement;
use kappa_store::{Disposition, EpochStore, ObservedHead, RetirementRequest, canonical_bytes};

use crate::PersistentStore;
use crate::control_plane::{ASSIGNMENT_KEY, AssignmentRecord, Guarantees};
use crate::storage::{Active, Opening, Publish, WriterGate, WriterToken};
use crate::storage_instance::{Incarnation, StorageInstance};

/// Seed of the principal that owns the namespaces tests retire.
const RETIREMENT_PRINCIPAL: [u8; 32] = [21; 32];

/// The principal that owns the namespaces tests retire, and its anchor:
/// a test namespace is created under it to be retirable
/// (`governed_retirement` authorizes only the target's owner).
pub fn retirement_principal() -> Result<(Ed25519Signer, Kappa), StoreError> {
    let signer = Ed25519Signer::from_bytes(&RETIREMENT_PRINCIPAL).map_err(crate::error::crypto)?;
    let anchor = Kappa::from_key(signer.algorithm(), signer.public_key())?;
    Ok((signer, anchor))
}

/// A namespace writer held the way an execution holds it: the activity
/// grant, the writer gate and the open transaction. Fields drop in the
/// order an execution's do.
pub struct TestWriter {
    pub(crate) txn: redb::WriteTransaction,
    pub(crate) writer: WriterToken,
    pub(crate) active: Active<Publish>,
}

impl PersistentStore {
    /// Create `name` under this node's local plane, owned by `owner`, with
    /// its first assignment admitting `requires`, published at 1000: the
    /// one creation every schedule shares.
    pub(crate) fn create_for_test(
        &self,
        name: &str,
        owner: Option<&Kappa>,
        requires: Guarantees,
    ) -> Result<NamespaceRef, StoreError> {
        let ns = NamespaceRef::deterministic(name);
        let plane = Arc::clone(self.namespaces.planes().local());
        let assignment = AssignmentRecord {
            namespace_id: ns.id().to_vec(),
            plane: plane.id.0.to_vec(),
            generation: 0,
            requires,
        };
        let clock = kappa_handler::clock_at(ClockMs::from_raw(1000))?;
        let mut execution = self.begin_creation_execution(&ns, plane, &clock, None)?;
        execution.namespace_create(owner, None)?;
        execution.namespace_put_meta(ASSIGNMENT_KEY, &canonical_bytes(&assignment))?;
        execution.publish()?;
        Ok(ns)
    }

    /// Open `ns` (creating its storage under the local plane when absent)
    /// and hold its writer.
    pub(crate) fn test_writer(&self, ns: &NamespaceRef) -> Result<TestWriter, StoreError> {
        let active = match self.namespaces.admit_publish(ns.id(), &Opening::Existing) {
            Ok(active) => active,
            Err(StoreError::NotFound(_)) => self.namespaces.admit_publish(
                ns.id(),
                &Opening::Create {
                    plane: Arc::clone(self.control_planes().local()),
                },
            )?,
            Err(error) => return Err(error),
        };
        let controller = Arc::clone(active.controller());
        let writer = WriterGate::acquire(&active)?;
        self.recover_namespace_head(&controller, &mut self.read_meter())?;
        let txn = controller.db.begin_write().map_err(crate::error::redb)?;
        controller
            .mutation_seq
            .store(0, std::sync::atomic::Ordering::Relaxed);
        Ok(TestWriter {
            txn,
            writer,
            active,
        })
    }

    /// Prepare `writer`'s transaction as `ns`'s next epoch under the
    /// installed authority, unsigned and unpublished: the stage a schedule
    /// drops, inspects or faults before its commit, which consumes no
    /// coordinate when dropped. The one test construction of an
    /// execution's ownership.
    pub(crate) fn prepare_test_writer(
        &self,
        writer: TestWriter,
        ns: &NamespaceRef,
        now: ClockMs,
    ) -> Result<
        crate::epoch_execution::PreparedEpochPublication<'_, crate::epoch::SharedAuthority<'_>>,
        StoreError,
    > {
        let controller = Arc::clone(writer.active.controller());
        let guard = self.shared_authority()?;
        self.prepare_epoch_transaction(
            crate::epoch_execution::ExecutionOwnership {
                guard,
                // The seam writes through the transaction directly and
                // reserves nothing in the directory.
                directory: crate::namespace_write::DirectoryGuard::new(self, controller),
                writer: writer.writer,
                active: writer.active,
                release: None,
            },
            writer.txn,
            crate::epoch_execution::Preparation {
                namespace: ns,
                // `test_writer` creates a missing namespace under the local
                // plane, as a plain execution does.
                creation: crate::epoch_execution::Creation::LocalDefault,
                now,
                signer_override: None,
                deadline: None,
                // The allowance an execution of this store is admitted with.
                meter: kappa_store::work::WorkMeter::new(self.publication_work),
                reads: Vec::new(),
                clock: Arc::new(kappa_handler::clock_at(now)?),
            },
        )
        .map_err(|(error, _)| error)
    }

    /// Prepare and sign `writer`'s transaction as `ns`'s next epoch, its
    /// custody stored and its records installed, without deciding or
    /// committing it: the seam that shows a signed root binds only the
    /// transaction it was sealed in. The writer stays usable; the custody
    /// record it leaves is the test's to ignore.
    pub(crate) fn sign_test_writer(
        &self,
        writer: &TestWriter,
        ns: &NamespaceRef,
        now: ClockMs,
    ) -> Result<kappa_store::EpochRoot, StoreError> {
        let guard = self.shared_authority()?;
        let authority = self.sealing_authority(None)?;
        let mut meter = kappa_store::work::WorkMeter::unbounded();
        let (preparation, _) = self.prepare_seal(
            &writer.txn,
            writer.active.controller(),
            ns,
            now,
            None,
            None,
            &authority,
            &mut meter,
        )?;
        let completion = self.complete_seal(
            &writer.writer,
            &writer.txn,
            ns,
            preparation,
            &authority,
            None,
            Vec::new(),
            &mut meter,
        )?;
        drop(guard);
        Ok(completion.root)
    }

    /// Seal and publish `writer`'s transaction as `ns`'s next epoch.
    pub(crate) fn publish_test_writer(
        &self,
        writer: TestWriter,
        ns: &NamespaceRef,
        now: ClockMs,
    ) -> Result<(u64, Kappa), StoreError> {
        self.prepare_test_writer(writer, ns, now)?.publish()
    }

    /// The database of `ns`, held open by the returned grant.
    pub(crate) fn namespace_db(
        &self,
        ns: &NamespaceRef,
    ) -> Result<(Arc<redb::Database>, Active), StoreError> {
        let active = self.namespaces.admit_read(ns.id())?;
        Ok((Arc::clone(&active.controller().db), active))
    }

    /// Settle every pending namespace to its head.
    pub(crate) fn settle_all(&self) -> Result<u64, StoreError> {
        self.settlement_step(u64::MAX)
    }

    /// Retire `instance` as `disposition`, governed by `governing`, on a
    /// request the retirement principal signs at `at` naming `head`: the
    /// one path every test retirement takes, the production one.
    pub(crate) fn retire_for_test(
        &self,
        governing: &NamespaceRef,
        instance: &StorageInstance,
        disposition: Disposition,
        head: Option<ObservedHead>,
        at: ClockMs,
    ) -> Result<VerifiedRetirement, StoreError> {
        let (signer, _) = retirement_principal()?;
        let Incarnation::Known(incarnation) = instance.incarnation() else {
            return Err(StoreError::Rejected(format!(
                "{instance} has no incarnation a retirement can name"
            )));
        };
        let request = RetirementRequest::new(
            *governing.id(),
            *instance.namespace(),
            incarnation,
            disposition,
            head,
            at.as_i64(),
            signer.algorithm(),
            signer.public_key(),
        )?;
        let request = sign_retirement_request(request, &signer)
            .and_then(admit_retirement_request)
            .map_err(crate::error::crypto)?;
        self.retire_governed(governing, &request, &kappa_handler::clock_at(at)?)
    }

    /// Retire the present storage of `instance` at its current head.
    pub(crate) fn retire_present_for_test(
        &self,
        governing: &NamespaceRef,
        instance: &StorageInstance,
        at: ClockMs,
    ) -> Result<VerifiedRetirement, StoreError> {
        let target = crate::storage::NamespaceStorage::namespace_ref(*instance.namespace());
        let (epoch_number, root) = self.epoch_current(&target)?;
        let head = Some(ObservedHead { epoch_number, root });
        self.retire_for_test(governing, instance, Disposition::RetirePresent, head, at)
    }

    /// Release lost `instance` at its last settled head.
    pub(crate) fn release_lost_for_test(
        &self,
        governing: &NamespaceRef,
        instance: &StorageInstance,
        at: ClockMs,
    ) -> Result<VerifiedRetirement, StoreError> {
        let head = self
            .established_checkpoint(instance)?
            .map(|(epoch_number, root)| ObservedHead { epoch_number, root });
        self.retire_for_test(governing, instance, Disposition::ReleaseLost, head, at)
    }

    /// `resolve_epoch_publication` over `ns`'s controller, under the
    /// installed authority.
    pub(crate) fn verify_committed_publication(
        &self,
        ns: &NamespaceRef,
        number: u64,
        identity: &Kappa,
    ) -> Result<(), StoreError> {
        let snapshot = self.namespace_snapshot(ns)?;
        self.resolve_epoch_publication(
            snapshot.controller(),
            ns,
            number,
            identity,
            None,
            &mut kappa_store::work::WorkMeter::unbounded(),
        )
    }
}

/// An open namespace controller in a fresh store, created under the local
/// plane, for unit tests of controller-level mechanisms. The store is
/// leaked for the process: the controller borrows nothing from it, and a
/// test process holds a bounded number.
pub fn controller_for_tests() -> Result<Arc<crate::storage::NamespaceController>, StoreError> {
    let store: &'static PersistentStore = Box::leak(Box::new(
        super::persistent_store()
            .map_err(|error| StoreError::Internal(error.to_string()))?
            .into_store(),
    ));
    let id = NamespaceRef::deterministic("controller-under-test");
    let active = store.namespaces.admit_publish(
        id.id(),
        &Opening::Create {
            plane: Arc::clone(store.control_planes().local()),
        },
    )?;
    Ok(Arc::clone(active.controller()))
}
