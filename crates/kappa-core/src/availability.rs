//! AvailabilityIndex trait (seam S10): blob availability soft state.

pub trait AvailabilityIndex: Send + Sync {
    fn announce(&self, kappa: &str);
    fn retract(&self, kappa: &str);
    fn holders(&self, kappa: &str) -> Vec<String>;
}

pub struct NoOpAvailabilityIndex;

impl AvailabilityIndex for NoOpAvailabilityIndex {
    fn announce(&self, _kappa: &str) {}
    fn retract(&self, _kappa: &str) {}
    fn holders(&self, _kappa: &str) -> Vec<String> {
        Vec::new()
    }
}
