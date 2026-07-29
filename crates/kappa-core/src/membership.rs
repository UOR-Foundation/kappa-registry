//! MembershipView trait (seam S9): cluster membership state.

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
}
