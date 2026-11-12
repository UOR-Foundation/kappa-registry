//! Namespace storage: one redb database per namespace, each owned by a
//! controller, plus the registry database the projections live in.
//!
//! A [`NamespaceController`] is the unit of publication: it owns its
//! database handle, its single writer, the state that must not be shared
//! across namespaces (publication fence, parked preparation pins, the
//! mutation sequence, the epoch number), and the admitted assignment to
//! the control plane that decides its proposals (`control_plane`).
//! Executions of different namespaces hold different writers and publish
//! concurrently; a namespace whose commit outcome is unknown fences itself
//! and no other. Namespaces sharing a plane share its decision authority,
//! not a writer; namespaces on different planes are independent in
//! decision, recovery and failure.
//!
//! Handles are bounded. A controller is retained while it is in use (an
//! execution, a retained reader, or settlement holds it); idle controllers
//! past the bound are evicted least recently used, their database closed,
//! and reopened on demand from the same path. Controller state that must
//! survive eviction is persisted: the fence as a file-level marker beside
//! the database, the settlement cursor in the registry's `SETTLED` table,
//! the assignment in the namespace's own admitted record
//! (`NAMESPACE_CONFIG`, read through [`AssignmentSource`]), and the
//! retirement state in the registry's `RETIRED` record (read through
//! [`RetirementSource`]).
//!
//! Each namespace's slot holds one lifecycle (`storage_lifecycle`), and
//! every activity is a grant admitted for one purpose by that lifecycle's
//! one policy (`storage_grant`): reading, publishing, or rewriting derived
//! state under the writer gate. Retirement is a transition of that
//! lifecycle (`storage_retiring`), never a flag checked by its callers.
//!
//! The directory of namespaces (alias to identity) is the registry's. A
//! creation opens the namespace's database first (created, its owner row
//! committed and its directory entries synced), then, inside its
//! execution, marks the namespace pending and claims its alias in one
//! small registry transaction no ordinary publication takes, then
//! publishes the creation epoch. Storage therefore exists before any
//! marker or claim names the namespace: settlement treats a creation whose
//! readable database holds no epoch, examined under its writer gate, as
//! proven never committed and releases its claim; a marker whose storage
//! is missing is lost storage, resolved only by restored storage or a
//! recorded retirement (`settlement_recovery`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use redb::{Database, ReadableDatabase};

use kappa_store::LogicalIncarnation;
use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;

use crate::allocation::Pin;
use crate::control_plane::{AssignmentRecord, ControlPlane, ControlPlanes, Proposal};
use crate::storage_instance::{Incarnation, StorageInstance};
use crate::tables;

#[path = "storage_handles.rs"]
mod handles;
pub(crate) use handles::ActivityAdmission;
use handles::Slot;

#[path = "storage_grant.rs"]
mod grant;
pub use grant::{Active, Exclusive, Maintain, Publish, Purpose, Read, Use};

#[path = "storage_lifecycle.rs"]
mod lifecycle;
pub use lifecycle::{Fence, Refusal, RetirementSource};

#[path = "storage_retiring.rs"]
mod retiring;
pub(crate) use retiring::{Recording, RetirementIntent};

#[path = "writer_gate.rs"]
mod gate;
pub(crate) use gate::{WriterGate, WriterToken};

#[path = "storage_open.rs"]
mod opening;

#[cfg(test)]
#[path = "storage_test_fixture.rs"]
mod fixture;

/// Open namespace handles the storage keeps at most while idle. Active
/// handles (held by an execution, reader, settlement or maintenance) are
/// never evicted and are bounded separately by admission
/// (`storage_handles`).
pub(crate) const DEFAULT_MAX_IDLE_HANDLES: usize = 1024;

/// Namespace controllers that may be active at once: every execution,
/// retained reader, settlement step and maintenance holds one activity
/// grant.
pub(crate) const DEFAULT_MAX_ACTIVE_HANDLES: usize = 4096;

/// How a controller reads the admitted assignment of its namespace.
///
/// The record lives in the namespace's own database (`NAMESPACE_CONFIG`
/// key `_assign`), encrypted under the store's table key, hence a
/// store-level decoder.
pub trait AssignmentSource: Send + Sync {
    /// The admitted assignment recorded in `db`, or `None` when the
    /// namespace has never admitted one.
    fn assignment(
        &self,
        namespace: &[u8; 16],
        db: &Database,
    ) -> Result<Option<AssignmentRecord>, StoreError>;
}

/// A storage backend factory for namespace databases: called with the
/// namespace identity at every open; `None` selects the file backend at
/// the namespace's path.
pub type NamespaceBackend =
    Arc<dyn Fn(&[u8; 16]) -> Option<Box<dyn redb::StorageBackend>> + Send + Sync>;

/// How a controller is opened: for a namespace being created, under the
/// plane whose execution creates it (the creation epoch admits that
/// assignment); otherwise from the assignment the namespace admitted.
pub enum Opening {
    Existing,
    Create { plane: Arc<ControlPlane> },
}

/// Per-namespace state an execution and settlement depend on.
pub struct NamespaceController {
    pub(crate) id: [u8; 16],
    /// The storage instance this controller's database is
    /// (`storage_instance`): every record naming storage outside it names
    /// this.
    pub(crate) instance: StorageInstance,
    pub(crate) db: Arc<Database>,
    pub(crate) path: PathBuf,
    /// Set when a commit's outcome is unknown; cleared by recovery.
    pub(crate) publication_fenced: AtomicBool,
    /// Whether the fence, if set, may be lifted by settling to the head
    /// this controller reads. True only when the fence was already on disk
    /// when this controller opened its database and the store syncs content
    /// before installing it: redb's open recovered the last durable commit
    /// slot (namespace commits run at redb's default `Immediate`
    /// durability, persistent once `commit` returns, and commits are atomic
    /// over the two slots), so the head read is the commit's outcome, and
    /// every allocation that outcome names was synced before it could
    /// commit. A fence set by this controller's own commit is never
    /// resolvable by it: its handle may read state redb never made durable.
    pub(crate) fence_resolvable: AtomicBool,
    /// Pins of records installed by write helpers inside the open
    /// transaction; drained into the execution at seal, cleared when a new
    /// execution begins.
    pub(crate) writer_pins: Mutex<Vec<Pin>>,
    /// What the open transaction made discoverable: the identities it wrote
    /// `BLOB_INDEX` rows for (`content_install`) and the asserters of the
    /// revocations and watermarks it wrote (`identity_write`). Taken by the
    /// publication, which registers them in the unsettled index before it
    /// commits, and cleared when a new execution begins.
    pub(crate) installed_rows: Mutex<Vec<crate::unsettled_index::DiscoveryKey>>,
    /// Pins an execution with an unknown commit outcome left behind, held
    /// until recovery settles the outcome; their charge on the unsettled
    /// budget is held with them.
    pub(crate) unresolved_content: Mutex<crate::unsettled::Parked>,
    /// Mutation sequence for `MUTATION_BUFFER` key ordering.
    pub(crate) mutation_seq: AtomicU64,
    /// Current epoch number, recovered at open.
    pub(crate) epoch_number: AtomicU64,
    /// The plane the namespace is assigned to and the assignment
    /// generation, resolved from the namespace's admitted record at open
    /// and refreshed when a reassignment epoch commits. `None` until the
    /// creation epoch admits the first assignment: no decision is made
    /// for an unassigned namespace.
    pub(crate) plane: Mutex<Option<(Arc<ControlPlane>, u64)>>,
    /// Activity grants held (executions, readers, settlement); an active
    /// controller is never evicted.
    pub(crate) active: AtomicUsize,
    /// Last use, for idle eviction.
    pub(crate) last_used: AtomicU64,
    /// Pins of allocations admitted by committed epochs that settlement
    /// has not yet projected, by epoch number. Released by the settlement
    /// of that epoch; after a restart the settlement pass at open stands
    /// in for them before anything is reclaimed.
    pub(crate) pending_pins: Mutex<BTreeMap<u64, crate::unsettled::Parked>>,
    /// Set when a committed assignment epoch could not be installed on
    /// this controller: its decision authority is stale until admission
    /// refreshes it from the admitted record (`refresh_assignment`).
    pub(crate) assignment_stale: AtomicBool,
    /// Serializes admission with the commit-outcome-to-fence transition
    /// (`writer_gate`). Held by an execution from admission until its
    /// commit is classified.
    pub(crate) writer_gate: WriterGate,
    /// Set once the head (epoch number, time floor) was recovered from
    /// the database under the writer gate; cleared never, the controller
    /// tracks its own publications afterwards.
    pub(crate) head_recovered: AtomicBool,
    /// Held by the one settlement attempt advancing this instance's
    /// checkpoint (`settlement::SettlementAttempt`), from before it observes
    /// the checkpoint until it has released what it settled.
    pub(crate) settlement_running: AtomicBool,
    /// A lower bound of this instance's settlement checkpoint, raised only
    /// from a checkpoint known committed (a settlement whose commit
    /// succeeded, or an established observation): what admission subtracts
    /// from the head when no established read can be taken now. Never an
    /// authority over the checkpoint itself.
    known_settled: AtomicU64,
}

/// What a namespace's logical incarnation is taken for: every
/// authenticated record that binds it, and every check that compares a
/// record against the live namespace instance. Each use is one variant, so
/// a refusal names exactly which evidence could not be bound or checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IncarnationUse {
    /// The transition domain every write of an execution binds
    /// (`TxnWriter`, `PreparedTransition::bind`).
    Transition,
    /// The authority and namespace-state records a seal commits
    /// (`epoch_seal::prepare_seal`).
    Seal,
    /// The namespace-state record of a sealed transaction, compared before
    /// its commit (`verify_sealed_transaction`).
    SealVerification,
    /// The namespace-state record of each settled epoch, compared before
    /// its effects are projected (`settlement_ledger`).
    Settlement,
    /// The receipt of a committed operation, compared before it answers a
    /// replayed request (`admit_operation_outcome`).
    OperationOutcome,
    /// The activation domain a rotation witness signs and its governing
    /// epoch binds (`activation_domain`).
    ActivationDomain,
    /// The control namespace instance holding an activation's governing
    /// evidence, compared against the domain the evidence names
    /// (`ActivationHold::admits`, `activation_evidence`).
    ActivationEvidence,
}

impl std::fmt::Display for IncarnationUse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Transition => "binding a namespace transition to its instance",
            Self::Seal => "sealing the authority and namespace-state records of an epoch",
            Self::SealVerification => {
                "verifying the namespace-state record of a sealed transaction"
            }
            Self::Settlement => "settling the namespace-state record of a committed epoch",
            Self::OperationOutcome => "answering a replayed operation from its committed receipt",
            Self::ActivationDomain => "binding an authority activation to its control namespace",
            Self::ActivationEvidence => {
                "verifying the governing evidence of an authority activation"
            }
        })
    }
}

impl NamespaceController {
    /// The logical incarnation this namespace's authenticated records bind,
    /// taken for `binding`: the one accessor every live consumer reads it
    /// from. Its value is currently the incarnation the storage instance
    /// records. Storage that records none (`Incarnation::Unknown`) has no
    /// logical incarnation: refused as `Rejected`, naming the namespace,
    /// its storage instance and the evidence that could not be bound.
    pub(crate) fn logical_incarnation(
        &self,
        binding: IncarnationUse,
    ) -> Result<LogicalIncarnation, StoreError> {
        match self.instance.incarnation() {
            Incarnation::Known(incarnation) => Ok(LogicalIncarnation::from_bytes(incarnation)),
            Incarnation::Unknown => Err(StoreError::Rejected(format!(
                "namespace {} storage instance {} records no incarnation; {binding} requires one",
                hex::encode(self.id),
                self.instance
            ))),
        }
    }

    /// Directory of this namespace's storage.
    pub(crate) fn directory(root: &Path, id: &[u8; 16]) -> PathBuf {
        root.join("namespaces").join(hex::encode(id))
    }

    pub(super) fn database_path(directory: &Path) -> PathBuf {
        directory.join("state.redb")
    }

    /// The publication fence marker beside the database in `directory`.
    pub(crate) fn fence_path(directory: &Path) -> PathBuf {
        directory.join("publication.fenced")
    }

    /// Whether `db`, the database of namespace `id`, holds a committed
    /// epoch: its head pointer exists. Read in one snapshot; the epoch
    /// pointer commits atomically with the epoch, so `false` read while no
    /// writer can commit proves that no epoch ever committed.
    pub(crate) fn holds_head(db: &Database, id: &[u8; 16]) -> Result<bool, StoreError> {
        let txn = db.begin_read().map_err(crate::error::redb)?;
        let table = txn
            .open_table(tables::EPOCH_CURRENT)
            .map_err(crate::error::redb)?;
        Ok(table
            .get(id.as_slice())
            .map_err(crate::error::redb)?
            .is_some())
    }

    /// Park the pins of the epoch `epoch_number` just committed, until it
    /// settles. An epoch without pins is parked too, so the parked set
    /// mirrors the committed-but-unsettled epochs; admission bounds the
    /// backlog from the durable checkpoint distance
    /// (`PersistentStore::unsettled_backlog`), which this set agrees with
    /// while the process lives.
    pub(crate) fn park_until_settled(&self, epoch_number: u64, parked: crate::unsettled::Parked) {
        tracing::trace!(
            namespace = %hex::encode(self.id),
            epoch_number,
            entries = parked.entries(),
            bytes = parked.bytes(),
            "publication ownership parked until settlement"
        );
        self.pending_pins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(epoch_number)
            .or_default()
            .append(parked);
    }

    /// Release the pins parked for every epoch at or below `epoch_number`.
    /// Their charge on the unsettled budget drops with them.
    pub(crate) fn release_settled(&self, epoch_number: u64) {
        let mut pending = self
            .pending_pins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let later = epoch_number
            .checked_add(1)
            .map_or_else(BTreeMap::new, |next| pending.split_off(&next));
        let released = std::mem::replace(&mut *pending, later);
        drop(pending);
        drop(released);
    }

    /// Raise the known-committed bound of this instance's checkpoint to
    /// `epoch`, an epoch known settled and committed.
    pub(crate) fn raise_known_settled(&self, epoch: u64) {
        self.known_settled.fetch_max(epoch, Ordering::AcqRel);
    }

    /// The highest epoch of this instance known settled and committed; 0
    /// when none is known.
    pub(crate) fn known_settled(&self) -> u64 {
        self.known_settled.load(Ordering::Acquire)
    }

    /// Whether admission must refresh this controller's assignment from
    /// the admitted record before deciding anything.
    pub(crate) fn assignment_is_stale(&self) -> bool {
        self.assignment_stale.load(Ordering::Acquire)
    }

    /// Record whether the controller's in-memory authority agrees with
    /// the admitted record: set when an admitted assignment could not be
    /// installed, cleared when it was.
    pub(crate) fn set_assignment_stale(&self, stale: bool) {
        self.assignment_stale.store(stale, Ordering::Release);
    }

    /// Fence publication durably: the marker survives eviction and
    /// restart, so an unknown outcome is never forgotten.
    pub(crate) fn fence(&self) -> Result<(), StoreError> {
        self.fence_resolvable.store(false, Ordering::Release);
        self.publication_fenced.store(true, Ordering::Release);
        let marker =
            Self::fence_path(self.path.parent().ok_or_else(|| {
                StoreError::Internal("namespace database has no directory".into())
            })?);
        std::fs::write(&marker, b"fenced")?;
        std::fs::File::open(&marker)?.sync_all()?;
        // The directory entry is what survives a crash; the file's own
        // sync does not cover it.
        if let Some(directory) = marker.parent() {
            std::fs::File::open(directory)?.sync_all()?;
        }
        Ok(())
    }

    /// Lift the fence after recovery resolved the outcome.
    pub(crate) fn unfence(&self) -> Result<(), StoreError> {
        let marker =
            Self::fence_path(self.path.parent().ok_or_else(|| {
                StoreError::Internal("namespace database has no directory".into())
            })?);
        match std::fs::remove_file(&marker) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(StoreError::Io(error)),
        }
        if let Some(directory) = marker.parent() {
            std::fs::File::open(directory)?.sync_all()?;
        }
        self.publication_fenced.store(false, Ordering::Release);
        Ok(())
    }

    pub(crate) fn fenced(&self) -> bool {
        self.publication_fenced.load(Ordering::Acquire)
    }

    /// Whether settlement may lift this controller's fence
    /// ([`Self::fence_resolvable`]).
    pub(crate) fn fence_resolvable(&self) -> bool {
        self.fence_resolvable.load(Ordering::Acquire)
    }

    /// The plane deciding this namespace and the assignment generation.
    /// Refused while the namespace has admitted no assignment.
    pub(crate) fn plane(&self) -> Result<(Arc<ControlPlane>, u64), StoreError> {
        self.plane
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                StoreError::Rejected(format!(
                    "namespace {} has no admitted control-plane assignment",
                    hex::encode(self.id)
                ))
            })
    }

    /// Install an admitted reassignment after its epoch committed. A
    /// generation at or below the current one is stale and ignored,
    /// except the first assignment of a namespace just created.
    pub(crate) fn reassign(&self, plane: Arc<ControlPlane>, generation: u64) {
        let mut current = self
            .plane
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match current.as_ref() {
            Some((_, held)) if generation <= *held && !(generation == 0 && *held == 0) => {}
            _ => *current = Some((plane, generation)),
        }
    }

    /// A proposal for the sealed epoch `root` extending `predecessor`,
    /// bound to the plane and generation this controller serves under.
    pub(crate) fn proposal(
        &self,
        predecessor: Option<Kappa>,
        epoch_number: u64,
        root: Kappa,
        dependencies: Vec<Kappa>,
        timestamp_ms: i64,
    ) -> Result<Proposal, StoreError> {
        let (plane, assignment_generation) = self.plane()?;
        Ok(Proposal {
            namespace: self.id,
            plane: plane.id,
            predecessor,
            epoch_number,
            root,
            generation: plane.membership().generation,
            assignment_generation,
            dependencies,
            timestamp_ms,
        })
    }
}

struct NamespaceStorageInner {
    root: PathBuf,
    open: DashMap<[u8; 16], Arc<Slot>>,
    max_idle: usize,
    max_active: usize,
    active_total: AtomicUsize,
    planes: Arc<ControlPlanes>,
    assignments: Arc<dyn AssignmentSource>,
    /// The retirement records storage is fenced by when it opens.
    fences: Arc<dyn RetirementSource>,
    backend: Option<NamespaceBackend>,
    /// Whether content is synced before it is installed
    /// (`PersistentStoreConfig::fsync`): a precondition of resolving a
    /// fence found at open (`NamespaceController::fence_resolvable`).
    fsync: bool,
    /// Monotonic use counter standing in for time in eviction order.
    uses: AtomicU64,
}

/// The namespace databases of a store.
pub struct NamespaceStorage {
    inner: Arc<NamespaceStorageInner>,
}

#[path = "storage_catalog.rs"]
mod catalog;
pub use catalog::StorageEvidence;
