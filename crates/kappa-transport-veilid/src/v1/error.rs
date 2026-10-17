//! Typed error taxonomy with retryable classification.
//!
//! Maps VeilidTransportError variants to a consumer-actionable set.
//! Consumers call `is_retryable()` to decide retry vs backoff vs give up.

use rekindle_transport_veilid::VeilidTransportError;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("not attached to network")]
    NotAttached,

    #[error("timeout: {0}")]
    Timeout(String),

    #[error("try again: {0}")]
    TryAgain(String),

    #[error("circuit open for peer: {0}")]
    CircuitOpen(String),

    #[error("peer not found: {0}")]
    PeerNotFound(String),

    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("payload too large: {size} bytes, max {max}")]
    PayloadTooLarge { size: usize, max: usize },

    #[error("route allocation failed: {0}")]
    RouteAllocationFailed(String),

    #[error("dht error: {0}")]
    DhtError(String),

    #[error("codec error: {0}")]
    CodecError(String),

    #[error("internal: {0}")]
    Internal(String),
}

impl TransportError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::NotAttached
                | Self::Timeout(_)
                | Self::TryAgain(_)
                | Self::CircuitOpen(_)
                | Self::RouteAllocationFailed(_)
        )
    }
}

impl From<VeilidTransportError> for TransportError {
    fn from(e: VeilidTransportError) -> Self {
        match e {
            VeilidTransportError::NotStarted | VeilidTransportError::NetworkNotReady => {
                Self::NotAttached
            }

            VeilidTransportError::Timeout { .. } => Self::Timeout(e.to_string()),

            VeilidTransportError::CircuitOpen { peer, .. } => Self::CircuitOpen(peer),

            VeilidTransportError::RouteAllocationFailed { reason } => {
                Self::RouteAllocationFailed(reason)
            }

            VeilidTransportError::NoRoute { peer }
            | VeilidTransportError::RouteExpired { peer } => Self::PeerNotFound(peer),

            VeilidTransportError::RouteImportFailed { peer, reason } => {
                Self::PeerNotFound(format!("{peer}: {reason}"))
            }

            VeilidTransportError::PayloadTooLarge { size, max } => {
                Self::PayloadTooLarge { size, max }
            }

            VeilidTransportError::SendFailed { .. } => Self::ConnectionFailed(e.to_string()),

            VeilidTransportError::RecordNotOpen { .. }
            | VeilidTransportError::RecordCreateFailed { .. }
            | VeilidTransportError::SubkeyTooLarge { .. }
            | VeilidTransportError::StaleWrite { .. }
            | VeilidTransportError::WatchDied { .. }
            | VeilidTransportError::DhtError { .. } => Self::DhtError(e.to_string()),

            VeilidTransportError::SerializationFailed { .. }
            | VeilidTransportError::DeserializationFailed { .. } => Self::CodecError(e.to_string()),

            VeilidTransportError::AlreadyStarted
            | VeilidTransportError::AttachFailed { .. }
            | VeilidTransportError::ShutdownFailed { .. } => Self::Internal(e.to_string()),

            _ => Self::ConnectionFailed(e.to_string()),
        }
    }
}

impl From<rekindle_types::transport::TransportError> for TransportError {
    fn from(e: rekindle_types::transport::TransportError) -> Self {
        use rekindle_types::transport::TransportError as T;
        match e {
            T::NotAttached => Self::NotAttached,
            T::Timeout { .. } => Self::Timeout(e.to_string()),
            T::RouteFailed { reason } => Self::RouteAllocationFailed(reason),
            T::PeerUnreachable { peer_key } => Self::PeerNotFound(peer_key),
            T::RecordNotFound { key } => Self::DhtError(format!("record not found: {key}")),
            T::RecordFailed { reason } => Self::DhtError(reason),
            T::SendFailed { reason } => Self::ConnectionFailed(reason),
            T::Serialization(s) | T::Deserialization(s) => Self::CodecError(s),
            T::StartFailed(s) | T::Internal(s) => Self::Internal(s),
            T::BroadcastFailed { reason } => Self::ConnectionFailed(reason),
        }
    }
}

impl From<postcard::Error> for TransportError {
    fn from(e: postcard::Error) -> Self {
        Self::CodecError(format!("postcard: {e}"))
    }
}
