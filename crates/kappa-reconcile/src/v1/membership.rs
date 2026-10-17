use dcbor::prelude::*;

use kappa_store::kappa::Kappa;

/// Peer information for membership tracking.
///
/// The id is the peer's identity Kappa derived from their signing key.
/// The address is the transport-layer locator (URL, Veilid route, etc).
/// Identity is what you compare. Locator is how you reach it.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub id: Kappa,
    pub address: String,
    pub healthy: bool,
}

/// Read interface for cluster membership.
pub trait MembershipView: Send + Sync {
    fn members(&self) -> Vec<PeerInfo>;
    fn is_member(&self, peer_id: &Kappa) -> bool;
    fn self_id(&self) -> &Kappa;
}

/// Static membership for fixed-topology clusters.
pub struct StaticMembership {
    self_id: Kappa,
    peers: Vec<PeerInfo>,
}

impl StaticMembership {
    pub fn new(self_id: Kappa, peers: Vec<PeerInfo>) -> Self {
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
    fn members(&self) -> Vec<PeerInfo> { self.peers.clone() }
    fn is_member(&self, peer_id: &Kappa) -> bool { self.peers.iter().any(|p| p.id == *peer_id) }
    fn self_id(&self) -> &Kappa { &self.self_id }
}

/// Role of a cluster member in the consensus protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable)]
pub enum MemberRole {
    #[cbor(n = 0)]
    Voter,
    #[cbor(n = 1)]
    Learner,
}

/// A single member record. The anchor is the member's identity Kappa
/// derived from their signing key via Kappa::from_key.
///
/// CBOR key assignments (PERMANENT):
///   0: anchor, 1: endpoint, 2: joined_at_ms, 3: role
#[derive(Debug, Clone, CBORCodable)]
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

/// Persistent membership state. Content-addressed via CBORCodable.
/// Epoch increments on every add/remove.
#[derive(Debug, Clone, CBORCodable)]
pub struct MembershipState {
    #[cbor(n = 0)]
    pub members: Vec<MemberRecord>,
    #[cbor(n = 1)]
    pub epoch: u64,
}

impl MembershipState {
    pub fn new() -> Self {
        Self { members: Vec::new(), epoch: 0 }
    }

    /// Quorum size: majority of voters. (voters / 2) + 1.
    pub fn quorum_size(&self) -> usize {
        let voters = self.members.iter()
            .filter(|m| matches!(m.role, MemberRole::Voter))
            .count();
        voters / 2 + 1
    }

    /// Checks membership by identity Kappa.
    pub fn is_member(&self, anchor: &Kappa) -> bool {
        self.members.iter().any(|m| m.anchor == *anchor)
    }

    /// Adds a member. Idempotent by anchor. Increments epoch on insert.
    pub fn add_member(&mut self, record: MemberRecord) {
        if !self.is_member(&record.anchor) {
            self.members.push(record);
            self.epoch += 1;
        }
    }

    /// Removes a member by anchor. Increments epoch on removal.
    pub fn remove_member(&mut self, anchor: &Kappa) {
        let before = self.members.len();
        self.members.retain(|m| m.anchor != *anchor);
        if self.members.len() < before {
            self.epoch += 1;
        }
    }

    /// Count of voting members.
    pub fn voter_count(&self) -> usize {
        self.members.iter()
            .filter(|m| matches!(m.role, MemberRole::Voter))
            .count()
    }
}

impl Default for MembershipState {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_anchor(seed: &str) -> Kappa {
        Kappa::from_key("ed25519", seed.as_bytes())
    }

    #[test]
    fn single_node_membership() {
        let id = test_anchor("node-1");
        let m = StaticMembership::single_node(id.clone(), "localhost".into());
        assert_eq!(*m.self_id(), id);
        assert!(m.is_member(&id));
        assert!(!m.is_member(&test_anchor("node-2")));
        assert_eq!(m.members().len(), 1);
    }

    #[test]
    fn multi_node_membership() {
        let n1 = test_anchor("n1");
        let n2 = test_anchor("n2");
        let m = StaticMembership::new(
            n1.clone(),
            vec![
                PeerInfo { id: n1.clone(), address: "a1".into(), healthy: true },
                PeerInfo { id: n2.clone(), address: "a2".into(), healthy: true },
            ],
        );
        assert!(m.is_member(&n1));
        assert!(m.is_member(&n2));
        assert!(!m.is_member(&test_anchor("n3")));
    }

    #[test]
    fn state_empty() {
        let ms = MembershipState::new();
        assert_eq!(ms.members.len(), 0);
        assert_eq!(ms.epoch, 0);
        assert_eq!(ms.quorum_size(), 1);
    }

    #[test]
    fn state_add_remove() {
        let mut ms = MembershipState::new();
        let anchor_a = test_anchor("node-a");
        let anchor_b = test_anchor("node-b");

        ms.add_member(MemberRecord {
            anchor: anchor_a.clone(), endpoint: "http://a".into(),
            joined_at_ms: 1000, role: MemberRole::Voter,
        });
        assert_eq!(ms.epoch, 1);
        assert!(ms.is_member(&anchor_a));

        ms.add_member(MemberRecord {
            anchor: anchor_b.clone(), endpoint: "http://b".into(),
            joined_at_ms: 2000, role: MemberRole::Voter,
        });
        assert_eq!(ms.epoch, 2);
        assert_eq!(ms.voter_count(), 2);

        ms.remove_member(&anchor_a);
        assert_eq!(ms.epoch, 3);
        assert!(!ms.is_member(&anchor_a));
        assert!(ms.is_member(&anchor_b));
    }

    #[test]
    fn quorum_sizes() {
        let mut ms = MembershipState::new();
        for i in 0..5u8 {
            ms.add_member(MemberRecord {
                anchor: test_anchor(&format!("voter-{i}")),
                endpoint: String::new(),
                joined_at_ms: 0,
                role: MemberRole::Voter,
            });
        }
        assert_eq!(ms.quorum_size(), 3);
    }

    #[test]
    fn learner_does_not_count_for_quorum() {
        let mut ms = MembershipState::new();
        ms.add_member(MemberRecord {
            anchor: test_anchor("voter"),
            endpoint: String::new(),
            joined_at_ms: 0,
            role: MemberRole::Voter,
        });
        ms.add_member(MemberRecord {
            anchor: test_anchor("learner"),
            endpoint: String::new(),
            joined_at_ms: 0,
            role: MemberRole::Learner,
        });
        assert_eq!(ms.voter_count(), 1);
        assert_eq!(ms.quorum_size(), 1);
        assert_eq!(ms.members.len(), 2);
    }

    #[test]
    fn add_idempotent() {
        let mut ms = MembershipState::new();
        let anchor = test_anchor("a");
        ms.add_member(MemberRecord {
            anchor: anchor.clone(),
            endpoint: String::new(),
            joined_at_ms: 0,
            role: MemberRole::Voter,
        });
        assert_eq!(ms.epoch, 1);
        ms.add_member(MemberRecord {
            anchor: anchor.clone(),
            endpoint: "different".into(),
            joined_at_ms: 999,
            role: MemberRole::Learner,
        });
        assert_eq!(ms.epoch, 1);
        assert_eq!(ms.members.len(), 1);
    }

    #[test]
    fn remove_nonexistent_is_noop() {
        let mut ms = MembershipState::new();
        let ghost = test_anchor("ghost");
        ms.remove_member(&ghost);
        assert_eq!(ms.epoch, 0);
    }

    #[test]
    fn cbor_roundtrip() {
        let mut ms = MembershipState::new();
        let anchor = test_anchor("node-x");
        ms.add_member(MemberRecord {
            anchor: anchor.clone(),
            endpoint: "http://x".into(),
            joined_at_ms: 12345,
            role: MemberRole::Voter,
        });
        let cbor: dcbor::CBOR = ms.clone().into();
        let bytes = cbor.to_cbor_data();
        let decoded_cbor = dcbor::CBOR::try_from_data(&bytes).expect("cbor decode");
        let decoded = MembershipState::try_from(decoded_cbor).expect("membership decode");
        assert_eq!(decoded.members.len(), 1);
        assert_eq!(decoded.members[0].anchor, anchor);
        assert_eq!(decoded.epoch, 1);
    }
}
