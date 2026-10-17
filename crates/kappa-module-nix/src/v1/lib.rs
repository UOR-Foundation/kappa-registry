use kappa_types::ProtocolId;
use std::sync::LazyLock;

static PROTOCOL_ID: LazyLock<ProtocolId> =
    LazyLock::new(|| ProtocolId::new("nix").expect("valid protocol id"));

/// Nix binary cache protocol surface identifier.
pub fn protocol_id() -> &'static ProtocolId {
    &PROTOCOL_ID
}

pub mod detect;
pub mod handlers;
pub mod narinfo;
pub mod publish;
pub mod refs;
pub mod sign;

pub use handlers::register;
