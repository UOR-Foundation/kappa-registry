//! Operation outcomes are evidence subordinate to an epoch publication.
//!
//! A receipt binds the namespace instance (identity and incarnation), the
//! operation identity, the canonical request and the result. A receipt of
//! an earlier incarnation of the same namespace identity never answers a
//! request to a later one.

use crate::{Kappa, LogicalIncarnation, NamespaceRef, StoreError};

#[derive(Clone, Debug)]
pub struct OperationReceipt {
    namespace: Vec<u8>,
    identity: Vec<u8>,
    request: Kappa,
    result: Vec<u8>,
    incarnation: Vec<u8>,
}

crate::wire_map::wire_map!(OperationReceipt {
    namespace: bytes = 0,
    identity: bytes = 1,
    request: value = 2,
    result: bytes = 3,
    incarnation: bytes = 4,
});

impl OperationReceipt {
    pub const MAX_RESULT_SIZE: usize = 1024 * 1024;

    pub fn new(
        namespace: &NamespaceRef,
        incarnation: &[u8; 16],
        identity: &[u8; 32],
        request: Kappa,
        result: Vec<u8>,
    ) -> Result<Self, StoreError> {
        let receipt = Self {
            namespace: namespace.id().to_vec(),
            identity: identity.to_vec(),
            request,
            result,
            incarnation: incarnation.to_vec(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        if self.namespace.len() != 16 || self.incarnation.len() != 16 || self.identity.len() != 32 {
            return Err(StoreError::Rejected(
                "invalid operation publication coordinates".into(),
            ));
        }
        if self.result.len() > Self::MAX_RESULT_SIZE {
            return Err(StoreError::CapacityExceeded(
                "operation result exceeds receipt limit".into(),
            ));
        }
        Ok(())
    }

    /// Whether this receipt answers `request` for operation `identity` in
    /// the namespace instance `(namespace, incarnation)`.
    pub fn matches(
        &self,
        namespace: &NamespaceRef,
        incarnation: &LogicalIncarnation,
        identity: &[u8; 32],
        request: &Kappa,
    ) -> bool {
        self.namespace == namespace.id().as_slice()
            && incarnation.names(&self.incarnation)
            && self.identity == identity.as_slice()
            && self.request == *request
    }

    pub fn result(&self) -> &[u8] {
        &self.result
    }

    pub fn namespace_id(&self) -> &[u8] {
        &self.namespace
    }

    pub fn incarnation(&self) -> &[u8] {
        &self.incarnation
    }

    pub fn operation_id(&self) -> Result<&[u8; 32], StoreError> {
        self.identity
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Rejected("invalid operation identity length".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{canonical_bytes, from_canonical};

    fn receipt(incarnation: [u8; 16]) -> Result<OperationReceipt, StoreError> {
        OperationReceipt::new(
            &NamespaceRef::deterministic("receipt"),
            &incarnation,
            &[4; 32],
            Kappa::sha256(b"request"),
            b"result".to_vec(),
        )
    }

    /// The receipt round-trips with its incarnation, and answers only the
    /// instance, operation and request it was issued for.
    #[test]
    fn a_receipt_answers_only_its_namespace_instance() -> Result<(), StoreError> {
        let namespace = NamespaceRef::deterministic("receipt");
        let request = Kappa::sha256(b"request");
        let issued_to = LogicalIncarnation::from_bytes([1; 16]);
        let successor = LogicalIncarnation::from_bytes([2; 16]);
        let issued = receipt([1; 16])?;
        let decoded: OperationReceipt = from_canonical(&canonical_bytes(&issued))?;
        assert_eq!(decoded.incarnation(), &[1; 16]);
        assert!(decoded.matches(&namespace, &issued_to, &[4; 32], &request));
        assert!(!decoded.matches(&namespace, &successor, &[4; 32], &request));
        assert!(!decoded.matches(&namespace, &issued_to, &[5; 32], &request));
        assert!(!decoded.matches(&namespace, &issued_to, &[4; 32], &Kappa::sha256(b"other")));
        assert_ne!(
            canonical_bytes(&issued),
            canonical_bytes(&receipt([2; 16])?),
            "the incarnation is part of the evidence identity"
        );
        Ok(())
    }
}
