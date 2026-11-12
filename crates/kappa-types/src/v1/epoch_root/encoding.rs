//! Borrowed root transformations: no symbolic tree or deep field copies.

use super::*;
use crate::canonical::{Canonical, bounded_canonical_bytes};

#[cfg(test)]
mod tests;

#[derive(CBORBoundedEncodable)]
struct Encoding<'a> {
    #[cbor(n = 0)]
    namespace_id: &'a ByteString,
    #[cbor(n = 1)]
    epoch_number: u64,
    #[cbor(n = 2)]
    prev_identifier: Option<&'a Kappa>,
    #[cbor(n = 3)]
    state_digest: &'a ByteString,
    #[cbor(n = 4)]
    mutations_root: &'a ByteString,
    #[cbor(n = 5)]
    timestamp_ms: i64,
    #[cbor(n = 6)]
    signer_anchor: &'a Kappa,
    #[cbor(n = 7)]
    tag_count: u64,
    #[cbor(n = 8)]
    rotation_kappa: Option<&'a Kappa>,
    #[cbor(n = 9)]
    cose_signature: Option<&'a SignedPayload>,
    #[cbor(n = 10)]
    ledger_root: &'a Kappa,
    #[cbor(n = 11)]
    state: &'a Kappa,
    #[cbor(n = 12)]
    format_version: u64,
}

impl EpochRoot {
    fn encode_with_signature(
        &self,
        signature: Option<&SignedPayload>,
        work: &mut dyn Meter,
        storage: &Arc<CapacityPool>,
    ) -> Result<Canonical, StoreError> {
        let data = self.data();
        bounded_canonical_bytes(
            &Encoding {
                namespace_id: &data.namespace_id,
                epoch_number: data.epoch_number,
                prev_identifier: data.prev_identifier.as_ref(),
                state_digest: &data.state_digest,
                mutations_root: &data.mutations_root,
                timestamp_ms: data.timestamp_ms,
                signer_anchor: &data.signer_anchor,
                tag_count: data.tag_count,
                rotation_kappa: data.rotation_kappa.as_ref(),
                cose_signature: signature,
                ledger_root: &data.ledger_root,
                state: &data.state,
                format_version: data.format_version,
            },
            work,
            storage,
        )
    }

    /// Canonical root bytes retaining their encoding-storage reservation.
    pub fn bounded_bytes(
        &self,
        work: &mut dyn Meter,
        storage: &Arc<CapacityPool>,
    ) -> Result<Canonical, StoreError> {
        self.encode_with_signature(Some(self.cose_signature()), work, storage)
    }

    /// Signing payload, with key 9 absent, borrowing all source fields.
    pub fn bounded_signable_bytes(
        &self,
        work: &mut dyn Meter,
        storage: &Arc<CapacityPool>,
    ) -> Result<Canonical, StoreError> {
        self.encode_with_signature(None, work, storage)
    }

    /// Unsigned identity includes an empty envelope at key 9. Its temporary
    /// encoding stays reserved until hashing completes on the same meter.
    pub fn bounded_unsigned_identity(
        &self,
        work: &mut dyn Meter,
        storage: &Arc<CapacityPool>,
    ) -> Result<Kappa, StoreError> {
        let bytes = self.encode_with_signature(Some(&SignedPayload::empty()), work, storage)?;
        work.charge(Dimension::BytesHashed, bytes.as_ref().len() as u64)?;
        Ok(Kappa::sha256(bytes.as_ref()))
    }
}
