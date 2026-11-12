//! Control planes: the decision authority a namespace is assigned to.
//!
//! A namespace is an ownership and isolation boundary; a control plane is
//! the authority that decides which sealed epoch becomes the namespace's
//! next admitted epoch. The two are separate selections: many namespaces
//! may share one plane, planes may run on this node alone or on a quorum
//! of nodes, and each plane selects its agreement mechanism, its conflict
//! policy and its protocol independently. Compatibility between the
//! guarantees a plane provides and the guarantees a namespace requires is
//! checked at assignment; an incompatible assignment is refused.
//!
//! The assignment of a namespace to a plane is admitted state of the
//! namespace itself: the creation epoch records an `AssignmentRecord`
//! under the metadata key [`ASSIGNMENT_KEY`], decided by the plane that
//! created the namespace, and a reassignment is a later epoch decided by
//! the current plane with the generation raised by one, so the previous
//! plane's proposals are fenced. A controller resolves its plane from that
//! record in its own database; a namespace without one is refused every
//! decision, never defaulted to any plane. The registry's assignment
//! projection (`projection::Family::Assignment`), settled from the same
//! evidence, serves routing only.
//!
//! A database writer is local storage; it applies a decided proposal and
//! never stands in for the decision. The local plane's agreement decides
//! in writer order because this node is the plane's only member; a
//! replicated plane's agreement decides by its quorum and its transport.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use dcbor::prelude::CBORCodable;
use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;

#[path = "control_plane_assignment.rs"]
mod assignment;

pub use assignment::{AssignmentRecord, Guarantee, Guarantees};
pub(crate) use assignment::{decode_assignment, encode_assignment};

/// Namespace metadata key holding the namespace's admitted
/// `AssignmentRecord` (canonical dCBOR).
pub const ASSIGNMENT_KEY: &str = "_assign";

/// Identity of a control plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ControlPlaneId(pub [u8; 16]);

impl ControlPlaneId {
    /// This node's own single-member plane, deciding in writer order. A
    /// namespace is assigned to it only by an admitted record naming it,
    /// as to any other plane.
    pub const LOCAL: Self = Self([0; 16]);

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Identity of a node in a plane's membership.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, CBORCodable)]
pub struct NodeId(pub String);

/// The members of a plane under one configuration generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Membership {
    pub generation: u64,
    pub nodes: Vec<NodeId>,
}

impl Membership {
    pub fn single(node: NodeId) -> Self {
        Self {
            generation: 0,
            nodes: vec![node],
        }
    }

    pub const fn quorum_size(&self) -> usize {
        self.nodes.len() / 2 + 1
    }
}

/// What a proposal to publish resolves to under the plane's agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Admitted at `position` of the namespace's order under configuration
    /// `generation`; the controller may commit it.
    Decided { position: u64, generation: u64 },
    /// Refused; nothing is committed.
    Rejected(String),
    /// Unknown; the controller fences the namespace until
    /// [`Agreement::resolve`] settles it.
    Unresolved(String),
}

/// A proposal to publish one epoch of a namespace, bound to the exact
/// predecessor, configuration and assignment it was prepared against.
#[derive(Debug, Clone)]
pub struct Proposal {
    pub namespace: [u8; 16],
    /// The plane the proposer believes owns the namespace.
    pub plane: ControlPlaneId,
    /// The predecessor epoch the proposal extends (`None` for the first).
    pub predecessor: Option<Kappa>,
    /// The epoch number the proposal claims.
    pub epoch_number: u64,
    /// The signed root identity of the sealed epoch.
    pub root: Kappa,
    /// Configuration generation of the plane the proposer observed.
    pub generation: u64,
    /// Generation of the namespace's admitted assignment the proposer
    /// serves under. A reassignment raises it, so a proposal made under
    /// the previous plane is fenced by the generation the next plane
    /// checks (`Agreement::decide` receives the assignment the plane
    /// currently holds for the namespace).
    pub assignment_generation: u64,
    /// Content the epoch depends on, which the deciding members must hold
    /// or be able to acquire before deciding.
    pub dependencies: Vec<Kappa>,
    /// Causal time of the proposal, for conflict policies that order by it.
    pub timestamp_ms: i64,
}

/// The agreement seam: how a plane decides a proposal.
pub trait Agreement: Send + Sync {
    /// What this mechanism guarantees for a decided proposal.
    fn guarantees(&self) -> Guarantees;
    /// Decide `proposal`. Called with the namespace writer held, so this
    /// node proposes at most one epoch of the namespace at a time.
    fn decide(&self, membership: &Membership, proposal: &Proposal) -> Decision;
    /// Resolve an earlier unresolved decision after recovery; `None`
    /// while still unknown.
    fn resolve(&self, membership: &Membership, proposal: &Proposal) -> Option<Decision>;
}

/// Two proposals extending the same predecessor of one namespace.
///
/// Each was decided by a member before the other was known to it. A plane
/// whose agreement is totally ordered never produces one; a plane that
/// reconciles independently decided histories must select.
#[derive(Debug, Clone)]
pub struct Conflict {
    pub namespace: [u8; 16],
    pub predecessor: Option<Kappa>,
    pub candidates: Vec<Proposal>,
}

/// Outcome of a conflict policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The candidate at this index wins; the others are superseded and
    /// their proposers must rebase.
    Accept(usize),
    /// No candidate wins; every proposer must rebase on the predecessor.
    RejectAll(String),
}

/// The conflict seam: how a plane selects among concurrently decided
/// proposals of one namespace.
pub trait ConflictPolicy: Send + Sync {
    fn resolve(&self, conflict: &Conflict) -> Resolution;
}

/// A plane's transport binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolBinding {
    /// In-process only; the plane has one member, this node.
    Local,
    /// Named transport the agreement implementation drives (`veilid`,
    /// `http`, a test transport); the name selects the registered
    /// `PeerTransport`.
    Named(String),
}

/// The local agreement: this node is the plane's only member.
///
/// A sealed epoch is decided in writer order. The agreement checks
/// membership and generations only; that the proposal extends the
/// namespace's current head is established by the proposer, which seals
/// under the namespace's writer gate and verifies the head pointer in the
/// same transaction (`commit_epoch_transaction`). A replicated agreement
/// must check the predecessor itself, since its members do not share that
/// gate.
pub struct LocalAgreement;

impl Agreement for LocalAgreement {
    /// Total order and linearizable reads from the single member deciding
    /// in writer order; fenced because `decide` refuses every proposal
    /// whose generation is not the membership's, and `reconfigure` only
    /// raises it.
    fn guarantees(&self) -> Guarantees {
        Guarantees::NONE
            .with(Guarantee::TotalOrder)
            .with(Guarantee::Fenced)
            .with(Guarantee::LinearizableReads)
    }

    fn decide(&self, membership: &Membership, proposal: &Proposal) -> Decision {
        if membership.nodes.len() != 1 {
            return Decision::Rejected(format!(
                "local agreement requires one member, membership has {}",
                membership.nodes.len()
            ));
        }
        if proposal.generation != membership.generation {
            return Decision::Rejected(format!(
                "proposal at generation {} under membership generation {}",
                proposal.generation, membership.generation
            ));
        }
        Decision::Decided {
            position: proposal.epoch_number,
            generation: membership.generation,
        }
    }

    fn resolve(&self, _membership: &Membership, _proposal: &Proposal) -> Option<Decision> {
        None
    }
}

/// Agreement by a leadership lease: the proposal is decided while this
/// node holds the lease at the proposal's generation. Not replicated by
/// itself; fenced only when the lease source fences by generation.
pub struct LeaseAgreement {
    coordinator: Arc<dyn kappa_types::coordinator::Coordinator>,
    node: NodeId,
    fenced_by_generation: bool,
}

impl LeaseAgreement {
    pub fn new(
        coordinator: Arc<dyn kappa_types::coordinator::Coordinator>,
        node: NodeId,
        fenced_by_generation: bool,
    ) -> Self {
        Self {
            coordinator,
            node,
            fenced_by_generation,
        }
    }
}

impl Agreement for LeaseAgreement {
    fn guarantees(&self) -> Guarantees {
        let ordered = Guarantees::NONE.with(Guarantee::TotalOrder);
        if self.fenced_by_generation {
            ordered.with(Guarantee::Fenced)
        } else {
            ordered
        }
    }

    fn decide(&self, membership: &Membership, proposal: &Proposal) -> Decision {
        if !membership.nodes.contains(&self.node) {
            return Decision::Rejected("this node is not a member of the plane".into());
        }
        if proposal.generation != membership.generation {
            return Decision::Rejected("proposal generation is stale".into());
        }
        // The coordinator is keyed by the plane: every namespace on the
        // plane is decided under the one lease.
        let scope = hex::encode(proposal.plane.0);
        if self.coordinator.is_leader(&scope) {
            return Decision::Decided {
                position: proposal.epoch_number,
                generation: membership.generation,
            };
        }
        self.coordinator.leader_id(&scope).map_or_else(
            // No leader known: the lease state is unknown, not refused.
            || Decision::Unresolved(format!("plane {scope} has no known leader")),
            |leader| {
                Decision::Rejected(format!(
                    "this node does not hold the lease of plane {scope}; leader is {leader}"
                ))
            },
        )
    }

    fn resolve(&self, membership: &Membership, proposal: &Proposal) -> Option<Decision> {
        match self.decide(membership, proposal) {
            Decision::Unresolved(_) => None,
            decided => Some(decided),
        }
    }
}

/// Conflict policy of a totally ordered plane: a conflict cannot occur,
/// so any is an invariant failure and every candidate is rejected.
pub struct NoConflicts;

impl ConflictPolicy for NoConflicts {
    fn resolve(&self, conflict: &Conflict) -> Resolution {
        Resolution::RejectAll(format!(
            "plane is totally ordered; {} concurrent proposals of {} are an invariant failure",
            conflict.candidates.len(),
            hex::encode(conflict.namespace)
        ))
    }
}

/// Conflict policy selecting the candidate with the greatest causal time,
/// ties broken by the lowest root identity, so every member selects the
/// same winner from the same candidates.
pub struct LatestWriterWins;

impl ConflictPolicy for LatestWriterWins {
    fn resolve(&self, conflict: &Conflict) -> Resolution {
        let winner = conflict
            .candidates
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| {
                a.timestamp_ms
                    .cmp(&b.timestamp_ms)
                    .then_with(|| b.root.key_bytes().cmp(&a.root.key_bytes()))
            })
            .map(|(index, _)| index);
        winner.map_or_else(
            || Resolution::RejectAll("no candidates".into()),
            Resolution::Accept,
        )
    }
}

/// One control plane: its membership, agreement, conflict policy and
/// transport, under a configuration generation.
pub struct ControlPlane {
    pub id: ControlPlaneId,
    membership: RwLock<Membership>,
    pub agreement: Arc<dyn Agreement>,
    pub conflicts: Arc<dyn ConflictPolicy>,
    pub protocol: ProtocolBinding,
}

impl ControlPlane {
    pub fn new(
        id: ControlPlaneId,
        membership: Membership,
        agreement: Arc<dyn Agreement>,
        conflicts: Arc<dyn ConflictPolicy>,
        protocol: ProtocolBinding,
    ) -> Self {
        Self {
            id,
            membership: RwLock::new(membership),
            agreement,
            conflicts,
            protocol,
        }
    }

    /// The local plane of `node`: one member, writer-ordered decisions.
    pub fn local(node: NodeId) -> Self {
        Self::new(
            ControlPlaneId::LOCAL,
            Membership::single(node),
            Arc::new(LocalAgreement),
            Arc::new(NoConflicts),
            ProtocolBinding::Local,
        )
    }

    pub fn membership(&self) -> Membership {
        self.membership
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Activate `next` membership. Its generation must exceed the
    /// current one: an activation never regresses, so proposals of the
    /// previous generation are fenced by the generation check of
    /// `decide`.
    pub fn reconfigure(&self, next: Membership) -> Result<(), StoreError> {
        let mut current = self
            .membership
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if next.generation <= current.generation {
            return Err(StoreError::Rejected(format!(
                "membership generation {} does not exceed {}",
                next.generation, current.generation
            )));
        }
        *current = next;
        drop(current);
        Ok(())
    }

    pub fn decide(&self, proposal: &Proposal) -> Decision {
        self.agreement.decide(&self.membership(), proposal)
    }

    pub fn resolve(&self, proposal: &Proposal) -> Option<Decision> {
        self.agreement.resolve(&self.membership(), proposal)
    }
}

/// The planes this node participates in, and how a namespace's admitted
/// assignment is resolved.
pub struct ControlPlanes {
    planes: RwLock<BTreeMap<ControlPlaneId, Arc<ControlPlane>>>,
    local: Arc<ControlPlane>,
}

impl ControlPlanes {
    pub fn new(node: NodeId) -> Self {
        let local = Arc::new(ControlPlane::local(node));
        let mut planes = BTreeMap::new();
        planes.insert(local.id, Arc::clone(&local));
        Self {
            planes: RwLock::new(planes),
            local,
        }
    }

    pub const fn local(&self) -> &Arc<ControlPlane> {
        &self.local
    }

    /// Register a plane this node is a member of. A plane already
    /// registered under the id is refused: planes are reconfigured, not
    /// replaced.
    pub fn register(&self, plane: ControlPlane) -> Result<Arc<ControlPlane>, StoreError> {
        let mut planes = self
            .planes
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if planes.contains_key(&plane.id) {
            return Err(StoreError::AlreadyExists(format!(
                "control plane {}",
                plane.id.hex()
            )));
        }
        let plane = Arc::new(plane);
        planes.insert(plane.id, Arc::clone(&plane));
        drop(planes);
        Ok(plane)
    }

    pub fn get(&self, id: &ControlPlaneId) -> Option<Arc<ControlPlane>> {
        self.planes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .cloned()
    }

    /// The plane an admitted assignment names, checked against the
    /// guarantees the assignment requires. An assignment to a plane this
    /// node does not participate in is a routing fact, not a decision this
    /// node may make: refused here so the caller routes elsewhere. A
    /// namespace with no admitted assignment is refused: absence is not
    /// authority.
    pub fn plane_for(
        &self,
        assignment: Option<&AssignmentRecord>,
    ) -> Result<Arc<ControlPlane>, StoreError> {
        let Some(assignment) = assignment else {
            return Err(StoreError::Rejected(
                "namespace has no admitted control-plane assignment".into(),
            ));
        };
        let id = assignment.plane_id()?;
        let plane = self.get(&id).ok_or_else(|| {
            StoreError::NotSupported(format!(
                "namespace is assigned to control plane {} which this node does not serve",
                id.hex()
            ))
        })?;
        let provided = plane.agreement.guarantees();
        if !provided.satisfies(assignment.requires) {
            return Err(StoreError::Rejected(format!(
                "control plane {} provides {provided:?}, assignment requires {:?}",
                id.hex(),
                assignment.requires
            )));
        }
        Ok(plane)
    }
}

#[cfg(test)]
#[path = "control_plane_tests.rs"]
mod tests;
