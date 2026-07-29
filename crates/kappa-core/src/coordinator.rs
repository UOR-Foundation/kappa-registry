//! Coordinator trait (seam S3): leader election and step-down.

pub trait Coordinator: Send + Sync {
    fn is_leader(&self, namespace: &str) -> bool;
    /// Voluntarily relinquish leadership. Recovery to leader state
    /// is handled by the implementation's internal election mechanism,
    /// not by a trait method. SingleNodeCoordinator is always leader
    /// and step_down is a no-op.
    fn step_down(&self, namespace: &str);
    fn leader_id(&self, namespace: &str) -> Option<String>;
}

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
}
