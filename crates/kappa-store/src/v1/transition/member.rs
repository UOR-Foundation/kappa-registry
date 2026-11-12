//! Member evidence encodes the action and the exact affected member.

use crate::identity_scope::AnchorScope;
use dcbor::prelude::*;
use kappa_types::canonical::canonical_bytes;
use kappa_types::identity::{
    DeviceBinding, HandleRecord, IdentityBinding, LocatorRecord, PrekeyBinding,
    RevocationCommitment,
};
use kappa_types::state_index::Change;
use kappa_types::state_key::{self, Family};

#[derive(Clone, Debug, CBORCodable)]
pub enum MemberTransition {
    #[cbor(n = 0)]
    BindingPut(IdentityBinding),
    #[cbor(n = 1)]
    BindingDelete(IdentityBinding),
    #[cbor(n = 2)]
    HandlePut(HandleRecord),
    #[cbor(n = 3)]
    HandleDelete(HandleRecord),
    #[cbor(n = 4)]
    DevicePut(DeviceBinding),
    #[cbor(n = 5)]
    DeviceRevoke(DeviceBinding),
    #[cbor(n = 6)]
    PrekeyPut(PrekeyBinding),
    #[cbor(n = 7)]
    LocatorPut(LocatorRecord),
    #[cbor(n = 8)]
    CommitmentPut(RevocationCommitment),
}

impl MemberTransition {
    pub(super) fn scope(&self) -> AnchorScope {
        match self {
            Self::BindingPut(v) | Self::BindingDelete(v) => AnchorScope::Binding {
                source: v.source.clone(),
            },
            Self::HandlePut(v) | Self::HandleDelete(v) => AnchorScope::Handle {
                key: format!("{}:{}", v.protocol, v.handle),
            },
            Self::DevicePut(_) | Self::DeviceRevoke(_) => AnchorScope::Device,
            Self::PrekeyPut(_) => AnchorScope::Prekey,
            Self::LocatorPut(_) => AnchorScope::Locator,
            Self::CommitmentPut(_) => AnchorScope::Commitment,
        }
    }

    pub(super) fn index_change(&self) -> Change {
        let (family, key, bytes, remove) = match self {
            Self::BindingPut(v) | Self::BindingDelete(v) => (
                Family::Binding,
                state_key::binding_member_key(&v.source, &v.target),
                canonical_bytes(v),
                matches!(self, Self::BindingDelete(_)),
            ),
            Self::HandlePut(v) | Self::HandleDelete(v) => (
                Family::Handle,
                state_key::handle_key(v.protocol.as_str(), &v.handle),
                canonical_bytes(v),
                matches!(self, Self::HandleDelete(_)),
            ),
            Self::DevicePut(v) | Self::DeviceRevoke(v) => (
                Family::Device,
                state_key::device_member_key(&v.anchor, &v.device_key),
                canonical_bytes(v),
                matches!(self, Self::DeviceRevoke(_)),
            ),
            Self::PrekeyPut(v) => (
                Family::Prekey,
                state_key::prekey_member_key(&v.anchor, v.epoch, &v.bundle_hash),
                canonical_bytes(v),
                false,
            ),
            Self::LocatorPut(v) => (
                Family::Locator,
                v.anchor.key_bytes(),
                canonical_bytes(v),
                false,
            ),
            Self::CommitmentPut(v) => (
                Family::Commitment,
                v.anchor.key_bytes(),
                canonical_bytes(v),
                false,
            ),
        };
        (
            state_key::path(family, &key),
            (!remove).then(|| state_key::value(&bytes)),
        )
    }
}
