/// Value returned by sequence operations. Name and counter only.
/// The store does not inject clock dependencies for sequences.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SequenceValue {
    pub name: String,
    pub value: u64,
}
