//! The vocabulary of a write execution: where it writes, what it decides,
//! how its result is persisted in an operation receipt, and what it
//! reports.

use topcoat::context::{Cx, try_request_context};

use kappa_store::canonical::{canonical_bytes, from_canonical};
use kappa_store::clock::ClockMs;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::{NamespaceRef, ProtocolId};

use super::{IDEMPOTENT_REPLAYED, KAPPA_EPOCH, KAPPA_EPOCH_ROOT};
use crate::error::HandlerError;
use crate::namespace::ResolvedNamespace;

/// Namespace a write executes against: an existing namespace, or one the
/// execution creates before its first write.
#[derive(Debug, Clone)]
pub struct WriteTarget {
    pub(super) namespace: NamespaceRef,
    pub(super) creation: Option<Creation>,
}

#[derive(Debug, Clone)]
pub(super) struct Creation {
    pub(super) owner: Option<Kappa>,
    pub(super) protocol: Option<ProtocolId>,
}

impl WriteTarget {
    pub const fn existing(namespace: NamespaceRef) -> Self {
        Self {
            namespace,
            creation: None,
        }
    }

    /// A namespace created by the execution under `name` within `protocol`.
    pub fn create(
        name: &str,
        owner: Option<Kappa>,
        protocol: Option<ProtocolId>,
        now: ClockMs,
    ) -> Result<Self, HandlerError> {
        let generated = NamespaceRef::generate(name, now)?;
        let namespace = match &protocol {
            Some(protocol) => generated.with_protocol(protocol.clone()),
            None => generated,
        };
        Ok(Self {
            namespace,
            creation: Some(Creation { owner, protocol }),
        })
    }

    pub const fn namespace(&self) -> &NamespaceRef {
        &self.namespace
    }

    /// True when the execution creates the namespace.
    pub const fn creates(&self) -> bool {
        self.creation.is_some()
    }
}

/// Write target for the request's resolved namespace. A namespace that does
/// not exist yet is created by the execution and owned by the caller.
///
/// # Errors
///
/// `BadRequest` when the request names no namespace.
pub fn write_target(cx: &Cx) -> Result<WriteTarget, HandlerError> {
    match try_request_context::<ResolvedNamespace>(cx) {
        Some(ResolvedNamespace::Exists(namespace)) => Ok(WriteTarget::existing(namespace.clone())),
        Some(ResolvedNamespace::NotFound { name, protocol }) => WriteTarget::create(
            name,
            crate::store::caller_anchor(cx),
            protocol.clone(),
            crate::store::clock_now(cx)?,
        ),
        Some(ResolvedNamespace::NoNamespace) | None => {
            Err(HandlerError::bad_request("no namespace in request path"))
        }
    }
}

/// Whether an execution's writes are published or discarded.
pub enum Outcome<T> {
    /// Publish the writes with a signed epoch.
    Publish(T),
    /// Nothing to publish; discard the execution. A namespace pending
    /// creation is not created.
    Discard(T),
}

/// Encoding of a handler result persisted in an operation receipt.
pub trait OperationResult: Sized {
    fn encode(&self) -> Vec<u8>;
    /// # Errors
    ///
    /// Fails when a committed receipt does not decode as this result.
    fn decode(bytes: &[u8]) -> Result<Self, HandlerError>;
}

fn corrupt_receipt(error: impl std::fmt::Display) -> HandlerError {
    HandlerError::internal(format!("operation receipt result: {error}"))
}

impl OperationResult for () {
    fn encode(&self) -> Vec<u8> {
        Vec::new()
    }
    fn decode(bytes: &[u8]) -> Result<Self, HandlerError> {
        if bytes.is_empty() {
            Ok(())
        } else {
            Err(corrupt_receipt("unit result carries bytes"))
        }
    }
}

impl OperationResult for String {
    fn encode(&self) -> Vec<u8> {
        canonical_bytes(self)
    }
    fn decode(bytes: &[u8]) -> Result<Self, HandlerError> {
        from_canonical(bytes).map_err(corrupt_receipt)
    }
}

impl OperationResult for Vec<String> {
    fn encode(&self) -> Vec<u8> {
        canonical_bytes(self)
    }
    fn decode(bytes: &[u8]) -> Result<Self, HandlerError> {
        from_canonical(bytes).map_err(corrupt_receipt)
    }
}

impl OperationResult for Kappa {
    fn encode(&self) -> Vec<u8> {
        canonical_bytes(self)
    }
    fn decode(bytes: &[u8]) -> Result<Self, HandlerError> {
        from_canonical(bytes).map_err(corrupt_receipt)
    }
}

/// Result of a write execution.
#[derive(Debug)]
pub struct Committed<T> {
    pub value: T,
    /// The namespace written; for a created namespace, its new identity.
    pub namespace: NamespaceRef,
    /// Epoch that published the write; `None` when the execution was
    /// discarded.
    pub epoch: Option<u64>,
    /// Signed root of that epoch.
    pub root: Option<Kappa>,
    /// True when the value was replayed from a committed operation.
    pub replayed: bool,
}

impl<T> Committed<T> {
    /// Attach publication evidence to a response.
    pub fn annotate(&self, response: &mut topcoat::router::response::Response) {
        let headers = response.headers_mut();
        if let Some(epoch) = self.epoch {
            headers.insert(KAPPA_EPOCH, http::HeaderValue::from(epoch));
        }
        if let Some(root) = &self.root
            && let Ok(value) = http::HeaderValue::from_str(&root.to_string())
        {
            headers.insert(KAPPA_EPOCH_ROOT, value);
        }
        if self.replayed {
            headers.insert(IDEMPOTENT_REPLAYED, http::HeaderValue::from_static("true"));
        }
    }
}
