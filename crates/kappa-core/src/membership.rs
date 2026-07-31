//! MembershipView trait (seam S9): cluster membership state.
//!
//! MembershipView is the read interface for cluster membership.
//! MembershipState is the persistent data structure that backs it,
//! storing member records with roles and epoch tracking.

use dcbor::prelude::*;

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub id: String,
    pub address: String,
    pub healthy: bool,
}

pub trait MembershipView: Send + Sync {
    fn members(&self) -> Vec<PeerInfo>;
    fn is_member(&self, peer_id: &str) -> bool;
    fn self_id(&self) -> &str;
}

pub struct StaticMembership {
    self_id: String,
    peers: Vec<PeerInfo>,
}

impl StaticMembership {
    pub fn new(self_id: String, peers: Vec<PeerInfo>) -> Self {
        Self { self_id, peers }
    }

    pub fn single_node(self_id: String) -> Self {
        Self {
            peers: vec![PeerInfo {
                id: self_id.clone(),
                address: "localhost".into(),
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

    fn is_member(&self, peer_id: &str) -> bool {
        self.peers.iter().any(|p| p.id == peer_id)
    }

    fn self_id(&self) -> &str {
        &self.self_id
    }
}

// -- Persistent membership state -----------------------------------------------

/// Role of a cluster member.
///
/// CBOR key assignments (PERMANENT):
///   0: Voter (participates in quorum), 1: Learner (replicates only)
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable)]
pub enum MemberRole {
    #[cbor(n = 0)]
    Voter,
    #[cbor(n = 1)]
    Learner,
}

/// A single member record in the cluster.
///
/// CBOR key assignments (PERMANENT):
///   0: anchor, 1: endpoint, 2: joined_at_ms, 3: role
#[derive(Debug, Clone, CBORCodable)]
pub struct MemberRecord {
    #[cbor(n = 0)]
    pub anchor: String,
    #[cbor(n = 1)]
    pub endpoint: String,
    #[cbor(n = 2)]
    pub joined_at_ms: u64,
    #[cbor(n = 3)]
    pub role: MemberRole,
}

/// Persistent membership state for the cluster.
///
/// Content-addressed via CBORCodable. The epoch field increments
/// on every add/remove operation to track membership changes.
///
/// CBOR key assignments (PERMANENT):
///   0: members, 1: epoch
#[derive(Debug, Clone, CBORCodable)]
pub struct MembershipState {
    #[cbor(n = 0)]
    pub members: Vec<MemberRecord>,
    #[cbor(n = 1)]
    pub epoch: u64,
}

impl MembershipState {
    pub fn new() -> Self {
        Self {
            members: Vec::new(),
            epoch: 0,
        }
    }

    /// Quorum size: majority of voters. (voters / 2) + 1.
    pub fn quorum_size(&self) -> usize {
        let voters = self
            .members
            .iter()
            .filter(|m| matches!(m.role, MemberRole::Voter))
            .count();
        voters / 2 + 1
    }

    /// Check if a node is a member by anchor.
    pub fn is_member(&self, anchor: &str) -> bool {
        self.members.iter().any(|m| m.anchor == anchor)
    }

    /// Add a member. Idempotent: does nothing if already present.
    /// Increments epoch on successful add.
    pub fn add_member(&mut self, record: MemberRecord) {
        if !self.is_member(&record.anchor) {
            self.members.push(record);
            self.epoch += 1;
        }
    }

    /// Remove a member by anchor. Increments epoch on successful removal.
    pub fn remove_member(&mut self, anchor: &str) {
        let before = self.members.len();
        self.members.retain(|m| m.anchor != anchor);
        if self.members.len() < before {
            self.epoch += 1;
        }
    }

    /// Count of voting members.
    pub fn voter_count(&self) -> usize {
        self.members
            .iter()
            .filter(|m| matches!(m.role, MemberRole::Voter))
            .count()
    }
}

impl Default for MembershipState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_node_membership() {
        let m = StaticMembership::single_node("node-1".into());
        assert_eq!(m.self_id(), "node-1");
        assert!(m.is_member("node-1"));
        assert!(!m.is_member("node-2"));
        assert_eq!(m.members().len(), 1);
    }

    #[test]
    fn multi_node_membership() {
        let m = StaticMembership::new(
            "n1".into(),
            vec![
                PeerInfo {
                    id: "n1".into(),
                    address: "a1".into(),
                    healthy: true,
                },
                PeerInfo {
                    id: "n2".into(),
                    address: "a2".into(),
                    healthy: true,
                },
            ],
        );
        assert!(m.is_member("n1"));
        assert!(m.is_member("n2"));
        assert!(!m.is_member("n3"));
    }

    #[test]
    fn membership_state_empty() {
        let ms = MembershipState::new();
        assert_eq!(ms.members.len(), 0);
        assert_eq!(ms.epoch, 0);
        assert_eq!(ms.quorum_size(), 1); // 0 voters: 0/2 + 1 = 1
    }

    #[test]
    fn membership_state_add_remove() {
        let mut ms = MembershipState::new();
        ms.add_member(MemberRecord {
            anchor: "node-a".into(),
            endpoint: "http://a:8080".into(),
            joined_at_ms: 1000,
            role: MemberRole::Voter,
        });
        assert_eq!(ms.epoch, 1);
        assert!(ms.is_member("node-a"));

        ms.add_member(MemberRecord {
            anchor: "node-b".into(),
            endpoint: "http://b:8080".into(),
            joined_at_ms: 2000,
            role: MemberRole::Voter,
        });
        assert_eq!(ms.epoch, 2);
        assert_eq!(ms.voter_count(), 2);

        ms.remove_member("node-a");
        assert_eq!(ms.epoch, 3);
        assert!(!ms.is_member("node-a"));
        assert!(ms.is_member("node-b"));
    }

    #[test]
    fn membership_state_quorum_sizes() {
        let mut ms = MembershipState::new();
        // 1 voter: quorum = 1
        ms.add_member(MemberRecord {
            anchor: "a".into(),
            endpoint: "".into(),
            joined_at_ms: 0,
            role: MemberRole::Voter,
        });
        assert_eq!(ms.quorum_size(), 1);

        // 3 voters: quorum = 2
        ms.add_member(MemberRecord {
            anchor: "b".into(),
            endpoint: "".into(),
            joined_at_ms: 0,
            role: MemberRole::Voter,
        });
        ms.add_member(MemberRecord {
            anchor: "c".into(),
            endpoint: "".into(),
            joined_at_ms: 0,
            role: MemberRole::Voter,
        });
        assert_eq!(ms.quorum_size(), 2);

        // 5 voters: quorum = 3
        ms.add_member(MemberRecord {
            anchor: "d".into(),
            endpoint: "".into(),
            joined_at_ms: 0,
            role: MemberRole::Voter,
        });
        ms.add_member(MemberRecord {
            anchor: "e".into(),
            endpoint: "".into(),
            joined_at_ms: 0,
            role: MemberRole::Voter,
        });
        assert_eq!(ms.quorum_size(), 3);
    }

    #[test]
    fn membership_state_learner_does_not_count_for_quorum() {
        let mut ms = MembershipState::new();
        ms.add_member(MemberRecord {
            anchor: "voter".into(),
            endpoint: "".into(),
            joined_at_ms: 0,
            role: MemberRole::Voter,
        });
        ms.add_member(MemberRecord {
            anchor: "learner".into(),
            endpoint: "".into(),
            joined_at_ms: 0,
            role: MemberRole::Learner,
        });
        assert_eq!(ms.voter_count(), 1);
        assert_eq!(ms.quorum_size(), 1); // only 1 voter
        assert_eq!(ms.members.len(), 2); // but 2 total members
    }

    #[test]
    fn membership_state_add_idempotent() {
        let mut ms = MembershipState::new();
        ms.add_member(MemberRecord {
            anchor: "a".into(),
            endpoint: "".into(),
            joined_at_ms: 0,
            role: MemberRole::Voter,
        });
        assert_eq!(ms.epoch, 1);
        // Adding same anchor again is idempotent
        ms.add_member(MemberRecord {
            anchor: "a".into(),
            endpoint: "http://different".into(),
            joined_at_ms: 999,
            role: MemberRole::Learner,
        });
        assert_eq!(ms.epoch, 1); // unchanged
        assert_eq!(ms.members.len(), 1);
    }

    #[test]
    fn membership_state_remove_nonexistent_is_noop() {
        let mut ms = MembershipState::new();
        ms.remove_member("ghost");
        assert_eq!(ms.epoch, 0); // unchanged
    }

    #[test]
    fn membership_state_cbor_roundtrip() {
        use crate::canonical::{canonical_bytes, from_canonical};
        let mut ms = MembershipState::new();
        ms.add_member(MemberRecord {
            anchor: "node-x".into(),
            endpoint: "http://x:8080".into(),
            joined_at_ms: 12345,
            role: MemberRole::Voter,
        });
        let bytes = canonical_bytes(&ms);
        let decoded: MembershipState = from_canonical(&bytes).unwrap();
        assert_eq!(decoded.members.len(), 1);
        assert_eq!(decoded.members[0].anchor, "node-x");
        assert_eq!(decoded.epoch, 1);
    }
}
