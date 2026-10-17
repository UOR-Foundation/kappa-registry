//! Leader election and coordination for distributed operations.
//!
//! The Coordinator trait abstracts leadership so that namespace-level
//! operations (epoch advance, GC sweep, schema migration) can check
//! whether this node is the leader before mutating shared state.
//! Multi-node implementations use Raft, Paxos, or lease-based election.

/// Leader election and step-down for namespace-scoped operations.
pub trait Coordinator: Send + Sync {
    /// Whether this node is the current leader for the namespace.
    fn is_leader(&self, namespace: &str) -> bool;

    /// Voluntarily relinquish leadership. Recovery to leader state
    /// is handled by the implementation's internal election mechanism.
    fn step_down(&self, namespace: &str);

    /// The identity of the current leader. None if unknown or unelected.
    fn leader_id(&self, namespace: &str) -> Option<String>;

    /// Request leadership for a namespace. Returns true if granted.
    /// Default: always granted (single-node).
    fn request_leadership(&self, _namespace: &str) -> bool {
        true
    }
}

/// Single-node coordinator. Always the leader. Step-down is a no-op.
pub struct SingleNodeCoordinator;

impl Coordinator for SingleNodeCoordinator {
    fn is_leader(&self, _namespace: &str) -> bool {
        true
    }

    fn step_down(&self, _namespace: &str) {}

    fn leader_id(&self, _namespace: &str) -> Option<String> {
        Some("self".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_node_is_always_leader() {
        let c = SingleNodeCoordinator;
        assert!(c.is_leader("any-namespace"));
        assert_eq!(c.leader_id("any-namespace"), Some("self".into()));
    }

    #[test]
    fn single_node_step_down_is_noop() {
        let c = SingleNodeCoordinator;
        c.step_down("any-namespace");
        assert!(c.is_leader("any-namespace"));
    }

    #[test]
    fn single_node_request_leadership_always_granted() {
        let c = SingleNodeCoordinator;
        assert!(c.request_leadership("any-namespace"));
    }
}
