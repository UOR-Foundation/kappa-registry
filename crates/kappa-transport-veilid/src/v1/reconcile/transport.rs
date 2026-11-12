//! The Veilid transport as the reconciliation transport: one `app_call`
//! per request, every other capability of `Transport` outside the seam.

use std::sync::Arc;

use async_trait::async_trait;
use kappa_reconcile::{ReconcileTransport, TransportError as ReconcileTransportError};
use rekindle_types::transport::Transport;

/// A `Transport` behind the one call reconciliation makes.
pub struct VeilidReconcileTransport<T: ?Sized> {
    inner: Arc<T>,
}

impl<T: ?Sized> VeilidReconcileTransport<T> {
    pub const fn new(inner: Arc<T>) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &Arc<T> {
        &self.inner
    }
}

impl<T: ?Sized> Clone for VeilidReconcileTransport<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[async_trait]
impl<T: Transport + ?Sized> ReconcileTransport for VeilidReconcileTransport<T> {
    async fn call_peer(
        &self,
        peer: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, ReconcileTransportError> {
        self.inner
            .call_peer(peer, request)
            .await
            .map_err(|error| crate::error::TransportError::from(error).into())
    }

    fn is_operational(&self) -> bool {
        self.inner.is_attached()
    }
}
