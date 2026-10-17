//! Store-level access to namespaces and the registry: the assignment
//! source controllers resolve their plane from, the identity locator, the
//! open-controller lookup write helpers use, and the mutation record.
//!
//! An identity-only read finds a storage instance holding the identity
//! without trusting any projection's absence. Candidates come from keyed
//! lookups only, never from the namespace or pending population, and each
//! names a storage instance (`storage_instance`):
//!
//! 1. the owners the completed catalog projection names
//!    (`projection::Family::Catalog`);
//! 2. the unsettled identity index (`unsettled_index`), which holds every
//!    identity a commit wrote a row for until settlement projects it, and
//!    the identities recovery reconstructed for epochs a restart found
//!    unsettled;
//! 3. the catalog owners again, which observe an epoch settled (and its
//!    registration dropped) between the first two lookups.
//!
//! A registration is made before its commit and dropped only after its
//! epoch is in the catalog, so content committed before a read is named by
//! one of the lookups, unless discovery is incomplete
//! ([`Coverage::Incomplete`]): recovery has not yet enumerated every
//! obligation present at open, or an obligation it found could not be
//! reconstructed (unreadable or missing storage, a reconstruction still in
//! progress). That state is read under one short lock
//! (`discovery_coverage`); no obligation is visited by a lookup.
//!
//! Each candidate is probed once per call, through the one classification
//! of a recorded instance's storage (`namespace_snapshot::admit_instance`):
//! the caller's read runs over the candidate's held storage, so the row that
//! confirms the candidate is the row the read uses. A candidate whose row is
//! absent released the identity; one whose storage is missing or replaced is
//! released only when its retirement record explains it and unavailable
//! otherwise, as is one whose evidence cannot be read. A held result answers
//! the read, whatever the coverage. Otherwise the read is
//! `Unavailable` when any candidate was unavailable or coverage is
//! incomplete, and `NotFound` only when coverage is complete and every
//! candidate released the identity. A list of every holder is
//! `Unavailable` under incomplete coverage: it cannot claim completeness.
//! An admission concurrent with the call may or may not be observed: the
//! answer is a consistent read, not a snapshot of all owners and not a
//! deletion certificate.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use redb::{Database, ReadableDatabase};

use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;

use crate::content_read::ReadView;
use crate::namespace_snapshot::InstanceAdmission;
use crate::projection::Family;
use crate::storage_instance::StorageInstance;
use crate::unsettled_index::DiscoveryKey;
use crate::{PersistentStore, control_plane, encrypted, error, namespace, storage, tables};

/// What one candidate instance says about an identity, by the read run
/// over its storage.
enum Probe<T> {
    /// Its committed row held the identity and the read succeeded.
    Held(T),
    /// Its committed rows do not hold the identity, or its retirement
    /// record explains its missing storage.
    Released,
    /// Its evidence could not be read.
    Unavailable(StoreError),
    /// The read refused the request on its own terms (a compressed
    /// representation, a capacity bound): the answer, whatever the
    /// other candidates hold.
    Refused(StoreError),
}

/// Whether identity discovery names every storage instance holding
/// committed content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    Complete,
    Incomplete {
        /// Obligations recovery found whose identities are not registered:
        /// storage missing or unreadable, or reconstruction in progress.
        unregistered: usize,
        /// Recovery has not yet enumerated every obligation present at
        /// open.
        enumerating: bool,
    },
}

impl Coverage {
    /// The refusal of an answer that would claim complete discovery.
    pub(crate) fn unavailable(self, subject: &str) -> Option<StoreError> {
        match self {
            Self::Complete => None,
            Self::Incomplete {
                unregistered,
                enumerating,
            } => Some(StoreError::Unavailable(format!(
                "{subject}: discovery is incomplete: {unregistered} recovered obligations hold unregistered identities{}; recovery steps complete it",
                if enumerating {
                    ", and obligations present at open are still being enumerated"
                } else {
                    ""
                }
            ))),
        }
    }
}

#[cfg(test)]
#[path = "store_access_tests.rs"]
mod tests;

/// Reads a namespace's admitted control-plane assignment from its own
/// database, decrypting it under the store's table key.
pub struct AdmittedAssignments {
    pub(crate) table_encryptor: Option<Arc<encrypted::TableEncryptor>>,
}

impl storage::AssignmentSource for AdmittedAssignments {
    fn assignment(
        &self,
        namespace: &[u8; 16],
        db: &Database,
    ) -> Result<Option<control_plane::AssignmentRecord>, StoreError> {
        let ns = storage::NamespaceStorage::namespace_ref(*namespace);
        let txn = db.begin_read().map_err(error::redb)?;
        let table = txn
            .open_table(tables::NAMESPACE_CONFIG)
            .map_err(error::redb)?;
        let key = namespace::config_key(&ns, control_plane::ASSIGNMENT_KEY);
        let Some(raw) = table.get(key.as_slice()).map_err(error::redb)? else {
            return Ok(None);
        };
        let plain = match &self.table_encryptor {
            Some(enc) => enc
                .decrypt_value(&namespace::config_context(&key), raw.value())
                .map_err(|e| StoreError::Internal(format!("decrypt: {e}")))?,
            None => raw.value().to_vec(),
        };
        Ok(Some(kappa_store::canonical::from_canonical(&plain)?))
    }
}

impl PersistentStore {
    /// The settled routing projection of `ns`'s assignment: the plane and
    /// generation its last settled epoch admitted. A locator for routing
    /// a request to a node serving that plane; the controller decides
    /// from the namespace's own record.
    pub fn assigned_plane(
        &self,
        ns: &NamespaceRef,
    ) -> Result<Option<(control_plane::ControlPlaneId, u64)>, StoreError> {
        // Instances of a namespace settle one after another; the one
        // completed last holds the namespace's current routing.
        self.projection()?
            .get(Family::Assignment, ns.id())?
            .into_iter()
            .max_by_key(|visible| visible.completion)
            .map(|visible| control_plane::decode_assignment(&visible.value))
            .transpose()
    }

    /// The storage instances whose completed epochs select a
    /// representation for `identity`, from the settled catalog. A locator
    /// only.
    pub(crate) fn catalog_owners(
        &self,
        identity: &Kappa,
    ) -> Result<Vec<StorageInstance>, StoreError> {
        Ok(self
            .projection()?
            .get(Family::Catalog, &identity.key_bytes())?
            .into_iter()
            .map(|visible| visible.instance)
            .collect())
    }

    /// Candidates no settlement has projected yet: the storage instances
    /// the unsettled index registers `key` under. Independent of the
    /// pending population and of the failed-settlement population.
    pub(crate) fn unsettled_candidates(&self, key: &DiscoveryKey) -> Vec<StorageInstance> {
        self.unsettled_index.candidates(key)
    }

    /// The result of `read` in every instance the unsettled index registers
    /// `key` under, each confirmed inside its own storage, for a caller that
    /// merges them with the settled projection read before and after this
    /// call (a registration is dropped only once its epoch is projected).
    /// `Unavailable` under incomplete discovery or when a candidate's
    /// evidence cannot be read: the answer is a complete list or none. A
    /// candidate whose `read` finds nothing contributes nothing.
    pub(crate) fn every_unsettled_holder<T>(
        &self,
        key: &DiscoveryKey,
        subject: &str,
        mut read: impl FnMut(&ReadView) -> Result<T, StoreError>,
    ) -> Result<Vec<T>, StoreError> {
        if let Some(refusal) = self.discovery_coverage().unavailable(subject) {
            return Err(refusal);
        }
        let mut answers = Vec::new();
        for candidate in self.unsettled_candidates(key) {
            match self.probe(&candidate, &mut read) {
                Probe::Held(value) => answers.push(value),
                Probe::Released => {}
                Probe::Refused(error) => return Err(error),
                Probe::Unavailable(error) => {
                    return Err(StoreError::Unavailable(format!(
                        "{subject}: candidate {candidate} cannot be read: {error}"
                    )));
                }
            }
        }
        Ok(answers)
    }

    /// Run `read` over `candidate`'s held storage, inside which `read`
    /// confirms and uses the instance's committed row of the identity; the
    /// view retains the storage for whatever `read` returns.
    fn probe<T>(
        &self,
        candidate: &StorageInstance,
        read: &mut impl FnMut(&ReadView) -> Result<T, StoreError>,
    ) -> Probe<T> {
        match self.admit_instance(candidate) {
            InstanceAdmission::Held { snapshot, .. } => match read(snapshot.view()) {
                Ok(value) => Probe::Held(value),
                Err(StoreError::NotFound(_)) => Probe::Released,
                Err(
                    error @ (StoreError::Rejected(_)
                    | StoreError::CapacityExceeded(_)
                    | StoreError::NotSupported(_)),
                ) => Probe::Refused(error),
                Err(error) => Probe::Unavailable(error),
            },
            InstanceAdmission::Released(_) => Probe::Released,
            InstanceAdmission::Unexplained(error) | InstanceAdmission::Unreadable(error) => {
                Probe::Unavailable(error)
            }
        }
    }

    /// The result of `read` in the first candidate namespace holding a
    /// committed representation of `identity`, under the contract in the
    /// module documentation.
    pub(crate) fn with_holder<T>(
        &self,
        identity: &Kappa,
        mut read: impl FnMut(&ReadView) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut tried = BTreeSet::new();
        let mut unavailable = None;
        let key = DiscoveryKey::Content(identity.clone());
        for stage in 0..3 {
            let candidates = if stage == 1 {
                self.unsettled_candidates(&key)
            } else {
                self.catalog_owners(identity)?
            };
            for candidate in candidates {
                if !tried.insert(candidate) {
                    continue;
                }
                match self.probe(&candidate, &mut read) {
                    Probe::Held(value) => return Ok(value),
                    Probe::Released => {}
                    Probe::Refused(error) => return Err(error),
                    Probe::Unavailable(error) => {
                        unavailable.get_or_insert((candidate, error));
                    }
                }
            }
        }
        if let Some((candidate, error)) = unavailable {
            return Err(StoreError::Unavailable(format!(
                "blob {identity}: candidate {candidate} cannot be read: {error}"
            )));
        }
        Err(self
            .discovery_coverage()
            .unavailable(&format!("blob {identity}"))
            .unwrap_or_else(|| StoreError::NotFound(format!("blob {identity}"))))
    }

    /// Every namespace holding a committed representation of `identity`,
    /// in identity order, each once, by the candidates and probing of
    /// `with_holder`. `Unavailable` when discovery is incomplete or a
    /// candidate's evidence cannot be read: the list would otherwise claim
    /// completeness it does not have.
    pub(crate) fn holders(&self, identity: &Kappa) -> Result<Vec<[u8; 16]>, StoreError> {
        if let Some(refusal) = self
            .discovery_coverage()
            .unavailable(&format!("owners of {identity}"))
        {
            return Err(refusal);
        }
        let mut candidates: BTreeSet<StorageInstance> =
            self.catalog_owners(identity)?.into_iter().collect();
        candidates.extend(self.unsettled_candidates(&DiscoveryKey::Content(identity.clone())));
        candidates.extend(self.catalog_owners(identity)?);
        let mut holders = BTreeSet::new();
        let mut confirm = |view: &ReadView| view.record(identity).map(drop);
        for candidate in candidates {
            match self.probe(&candidate, &mut confirm) {
                Probe::Held(()) => {
                    holders.insert(*candidate.namespace());
                }
                Probe::Released => {}
                Probe::Refused(error) => return Err(error),
                Probe::Unavailable(error) => {
                    return Err(StoreError::Unavailable(format!(
                        "owners of {identity}: candidate {candidate} cannot be read: {error}"
                    )));
                }
            }
        }
        Ok(holders.into_iter().collect())
    }

    /// The open controller of `ns`. An execution or reader holds its grant,
    /// so a write helper called inside one always finds it.
    pub(crate) fn controller(
        &self,
        ns: &NamespaceRef,
    ) -> Result<Arc<storage::NamespaceController>, StoreError> {
        self.namespaces
            .open_controller(ns.id())
            .ok_or_else(|| StoreError::Internal(format!("namespace {ns} has no open controller")))
    }

    /// Record a mutation inside the namespace's write transaction, with the
    /// data write it describes. Both commit atomically.
    pub(crate) fn record_mutation_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        op: kappa_store::epoch::MutationOp,
        kappa: Kappa,
        now: kappa_store::clock::ClockMs,
        context: Option<String>,
    ) -> Result<(), StoreError> {
        let mutation = kappa_store::epoch::EpochMutation {
            op,
            kappa,
            timestamp_ms: now.as_i64(),
            context,
        };
        self.record_time_in_txn(txn, now)?;
        let controller = self.controller(ns)?;
        let seq = controller
            .mutation_seq
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| StoreError::Internal("mutation sequence exhausted".into()))?;
        let mut key = Vec::with_capacity(24);
        key.extend_from_slice(ns.id());
        key.extend_from_slice(&seq.to_be_bytes());
        let value = kappa_store::canonical::canonical_bytes(&mutation);
        let mut mbuf = txn
            .open_table(tables::MUTATION_BUFFER)
            .map_err(error::redb)?;
        mbuf.insert(key.as_slice(), value.as_slice())
            .map_err(error::redb)?;
        Ok(())
    }
}
