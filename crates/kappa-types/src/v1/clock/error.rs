/// Time-domain failures must not become wrapped timestamps or extended validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TimeError {
    #[error("causal logical counter exhausted; physical progress is required")]
    LogicalExhausted,
    #[error("time interval is empty or reversed")]
    InvalidInterval,
    #[error("time arithmetic exceeds the representable range")]
    OutOfRange,
    #[error("duration must be nonnegative")]
    NegativeDuration,
}
