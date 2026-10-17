//! Operation outcomes are evidence subordinate to an epoch publication.

use crate::{Kappa, NamespaceRef, StoreError};

#[derive(Clone, Debug)]
pub struct OperationReceipt {
    namespace: Vec<u8>,
    identity: Vec<u8>,
    request: Kappa,
    result: Vec<u8>,
}

crate::wire_map::wire_map!(OperationReceipt {
    namespace: bytes = 0,
    identity: bytes = 1,
    request: value = 2,
    result: bytes = 3,
});

impl OperationReceipt {
    pub const MAX_RESULT_SIZE: usize = 1024 * 1024;

    pub fn new(
        namespace: &NamespaceRef,
        identity: &[u8; 32],
        request: Kappa,
        result: Vec<u8>,
    ) -> Result<Self, StoreError> {
        let receipt = Self {
            namespace: namespace.id().to_vec(),
            identity: identity.to_vec(),
            request,
            result,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        if self.namespace.len() != 16 || self.identity.len() != 32 {
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

    pub fn matches(&self, namespace: &NamespaceRef, identity: &[u8; 32], request: &Kappa) -> bool {
        self.namespace == namespace.id().as_slice()
            && self.identity == identity.as_slice()
            && self.request == *request
    }

    pub fn result(&self) -> &[u8] {
        &self.result
    }

    pub fn namespace_id(&self) -> &[u8] {
        &self.namespace
    }

    pub fn operation_id(&self) -> Result<&[u8; 32], StoreError> {
        self.identity
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Rejected("invalid operation identity length".into()))
    }
}
