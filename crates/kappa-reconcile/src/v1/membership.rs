//! Who a node reconciles with.
//!
//! A peer has an identity and a locator: the identity is the `Kappa`
//! derived from its key (`Kappa::from_key`), which is what membership and
//! the self-check compare; the locator is the transport-layer address
//! (`ReconcileTransport::call_peer` takes it), which is how it is reached.
//! The persistent membership state is content-addressed dCBOR and keyed by
//! the same identity.

use dcbor::prelude::*;

use kappa_store::kappa::Kappa;

/// One peer as the reconciliation loop sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    /// Identity: the content address of the peer's key.
    pub id: Kappa,
    /// Locator the transport reaches the peer by.
    pub address: String,
    /// Whether the transport can reach it now; an unhealthy peer is
    /// skipped, not failed.
    pub healthy: bool,
}

/// Read interface for cluster membership.
pub trait MembershipView: Send + Sync {
    fn members(&self) -> Vec<PeerInfo>;
    fn is_member(&self, peer_id: &Kappa) -> bool;
    fn self_id(&self) -> &Kappa;
}

/// Where a reconciliation round takes its peers from: the live transport
/// registry in production, a fixed set in tests.
pub trait PeerSource: Send + Sync {
    fn peers(&self) -> Vec<PeerInfo>;
}

/// Static membership for fixed-topology clusters.
pub struct StaticMembership {
    self_id: Kappa,
    peers: Vec<PeerInfo>,
}

impl StaticMembership {
    pub const fn new(self_id: Kappa, peers: Vec<PeerInfo>) -> Self {
        Self { self_id, peers }
    }

    pub fn single_node(self_id: Kappa, address: String) -> Self {
        Self {
            peers: vec![PeerInfo {
                id: self_id.clone(),
                address,
                healthy: true,
            }],
            self_id,
        }
    }
}

impl MembershipView for StaticMembership {
    fn members(&self) -> Vec<PeerInfo> {
        self.peers.clone()
    }

    fn is_member(&self, peer_id: &Kappa) -> bool {
        self.peers.iter().any(|peer| peer.id == *peer_id)
    }

    fn self_id(&self) -> &Kappa {
        &self.self_id
    }
}

impl PeerSource for StaticMembership {
    fn peers(&self) -> Vec<PeerInfo> {
        self.peers.clone()
    }
}

/// Role of a cluster member in the consensus protocol.
///
/// CBOR key assignments (PERMANENT): 0 Voter, 1 Learner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable)]
pub enum MemberRole {
    #[cbor(n = 0)]
    Voter,
    #[cbor(n = 1)]
    Learner,
}

/// A single member record. The anchor is the member's identity Kappa
/// derived from its signing key via `Kappa::from_key`.
///
/// CBOR key assignments (PERMANENT): 0 anchor, 1 endpoint, 2 joined_at_ms,
/// 3 role.
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable)]
pub struct MemberRecord {
    #[cbor(n = 0)]
    pub anchor: Kappa,
    #[cbor(n = 1)]
    pub endpoint: String,
    #[cbor(n = 2)]
    pub joined_at_ms: i64,
    #[cbor(n = 3)]
    pub role: MemberRole,
}

/// Persistent membership state. Content-addressed via `CBORCodable`; the
/// epoch increments on every add and remove.
///
/// CBOR key assignments (PERMANENT): 0 members, 1 epoch.
#[derive(Debug, Clone, Default, PartialEq, Eq, CBORCodable)]
pub struct MembershipState {
    #[cbor(n = 0)]
    pub members: Vec<MemberRecord>,
    #[cbor(n = 1)]
    pub epoch: u64,
}

impl MembershipState {
    pub const fn new() -> Self {
        Self {
            members: Vec::new(),
            epoch: 0,
        }
    }

    /// Quorum size: a majority of voters, `voters / 2 + 1`.
    pub fn quorum_size(&self) -> usize {
        self.voter_count() / 2 + 1
    }

    pub fn is_member(&self, anchor: &Kappa) -> bool {
        self.members.iter().any(|member| member.anchor == *anchor)
    }

    /// Add a member. Idempotent by anchor; the epoch increments only on
    /// an insertion.
    pub fn add_member(&mut self, record: MemberRecord) {
        if !self.is_member(&record.anchor) {
            self.members.push(record);
            self.epoch += 1;
        }
    }

    /// Remove a member by anchor; the epoch increments only on a removal.
    pub fn remove_member(&mut self, anchor: &Kappa) {
        let before = self.members.len();
        self.members.retain(|member| member.anchor != *anchor);
        if self.members.len() < before {
            self.epoch += 1;
        }
    }

    pub fn voter_count(&self) -> usize {
        self.members
            .iter()
            .filter(|member| matches!(member.role, MemberRole::Voter))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn anchor(seed: &str) -> Result<Kappa, kappa_store::kappa::KappaParseError> {
        Kappa::from_key("ed25519", seed.as_bytes())
    }

    fn voter(seed: &str, joined_at_ms: i64) -> Result<MemberRecord, Box<dyn std::error::Error>> {
        Ok(MemberRecord {
            anchor: anchor(seed)?,
            endpoint: format!("http://{seed}"),
            joined_at_ms,
            role: MemberRole::Voter,
        })
    }

    #[test]
    fn single_node_membership() -> TestResult {
        let id = anchor("node-1")?;
        let membership = StaticMembership::single_node(id.clone(), "localhost".into());
        assert_eq!(*membership.self_id(), id);
        assert!(membership.is_member(&id));
        assert!(!membership.is_member(&anchor("node-2")?));
        assert_eq!(membership.members().len(), 1);
        assert_eq!(PeerSource::peers(&membership), membership.members());
        Ok(())
    }

    #[test]
    fn multi_node_membership() -> TestResult {
        let (n1, n2) = (anchor("n1")?, anchor("n2")?);
        let membership = StaticMembership::new(
            n1.clone(),
            vec![
                PeerInfo {
                    id: n1.clone(),
                    address: "a1".into(),
                    healthy: true,
                },
                PeerInfo {
                    id: n2.clone(),
                    address: "a2".into(),
                    healthy: false,
                },
            ],
        );
        assert!(membership.is_member(&n1));
        assert!(membership.is_member(&n2));
        assert!(!membership.is_member(&anchor("n3")?));
        assert_eq!(
            membership
                .peers()
                .iter()
                .filter(|peer| peer.healthy)
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn state_add_remove_and_quorum() -> TestResult {
        let mut state = MembershipState::new();
        assert_eq!(state.quorum_size(), 1, "no voters: quorum of one");
        let (a, b) = (anchor("node-a")?, anchor("node-b")?);
        state.add_member(voter("node-a", 1000)?);
        assert_eq!(state.epoch, 1);
        assert!(state.is_member(&a));
        state.add_member(voter("node-b", 2000)?);
        assert_eq!(state.epoch, 2);
        assert_eq!(state.voter_count(), 2);
        assert_eq!(state.quorum_size(), 2);
        for seed in ["c", "d", "e"] {
            state.add_member(voter(seed, 0)?);
        }
        assert_eq!(state.voter_count(), 5);
        assert_eq!(state.quorum_size(), 3);
        state.remove_member(&a);
        assert_eq!(state.epoch, 6);
        assert!(!state.is_member(&a));
        assert!(state.is_member(&b));
        state.remove_member(&anchor("ghost")?);
        assert_eq!(state.epoch, 6, "removing a non-member changes nothing");
        Ok(())
    }

    #[test]
    fn learners_do_not_count_for_quorum_and_adds_are_idempotent() -> TestResult {
        let mut state = MembershipState::new();
        state.add_member(voter("voter", 0)?);
        state.add_member(MemberRecord {
            anchor: anchor("learner")?,
            endpoint: String::new(),
            joined_at_ms: 0,
            role: MemberRole::Learner,
        });
        assert_eq!(state.voter_count(), 1);
        assert_eq!(state.quorum_size(), 1);
        assert_eq!(state.members.len(), 2);
        let epoch = state.epoch;
        state.add_member(MemberRecord {
            anchor: anchor("voter")?,
            endpoint: "different".into(),
            joined_at_ms: 999,
            role: MemberRole::Learner,
        });
        assert_eq!(state.epoch, epoch, "a repeated anchor is not an insertion");
        assert_eq!(state.members.len(), 2);
        assert_eq!(
            state.members[0].endpoint, "http://voter",
            "the first record stands"
        );
        Ok(())
    }

    #[test]
    fn cbor_round_trip_is_exact() -> TestResult {
        let mut state = MembershipState::new();
        state.add_member(voter("node-x", 12_345)?);
        let cbor: dcbor::CBOR = state.clone().into();
        let bytes = cbor.to_cbor_data();
        let decoded = MembershipState::try_from(dcbor::CBOR::try_from_data(&bytes)?)?;
        assert_eq!(decoded, state);
        Ok(())
    }
}
