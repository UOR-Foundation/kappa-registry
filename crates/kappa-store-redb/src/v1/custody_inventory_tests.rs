//! Physical ownership accounting and refusal before representation decoding.

use super::*;
use crate::custody::{CustodyParts, CustodyTransition};
use crate::representation::{BlobRecord, RepresentationLimits};
use kappa_store::Kappa;
use kappa_store::work::{Work, WorkLimit, WorkMeter};

fn inventory_record(payload: CustodyPayload) -> CustodyRecord {
    // Only the physical payload is inspected by inventory. These bytes are
    // never passed to transition application or admitted as epoch evidence.
    CustodyRecord::new(CustodyParts {
        namespace: [1; 16],
        incarnation: [2; 16],
        epoch_number: 1,
        predecessor: None,
        unsigned: Kappa::sha256(b"inventory candidate"),
        now_ms: 1,
        activation: None,
        transitions: vec![CustodyTransition {
            mutation: Vec::new(),
            evidence: Vec::new(),
            payload,
        }],
        reads: Vec::new(),
        work: Work::default(),
    })
}

#[test]
fn inline_prepared_content_is_not_physical_allocation_debt() -> Result<(), StoreError> {
    let bytes = b"inline custody".to_vec();
    let identity = Kappa::sha256(&bytes);
    let row = BlobRecord::inline(
        bytes,
        None,
        RepresentationLimits {
            inline_limit: 4096,
            max_components: 16,
        },
    )?;
    let record = inventory_record(CustodyPayload::Content {
        identity,
        aliases: Vec::new(),
        record: crate::representation_codec::encode(&row),
        allocated_bytes: 0,
    });
    let mut meter = WorkMeter::unbounded();
    assert!(record.allocations(&mut meter).next().is_none());
    assert_eq!(meter.used().get(Dimension::Entries), 1);
    assert!(meter.used().get(Dimension::BytesDecoded) > 0);
    Ok(())
}

#[test]
fn refused_inventory_does_not_decode_and_corruption_is_not_absence() -> Result<(), StoreError> {
    let record = inventory_record(CustodyPayload::Content {
        identity: Kappa::sha256(b"unreadable representation"),
        aliases: Vec::new(),
        record: vec![0xff],
        allocated_bytes: 1,
    });
    let mut refused = WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesDecoded, 0));
    assert!(
        record
            .allocations(&mut refused)
            .next()
            .ok_or_else(|| {
                StoreError::Internal("inventory discarded a refused allocation".into())
            })?
            .is_err()
    );
    assert_eq!(refused.used().get(Dimension::BytesAllocated), 0);
    assert_eq!(refused.used().get(Dimension::BytesDecoded), 0);

    let mut admitted = WorkMeter::unbounded();
    assert!(
        record
            .allocations(&mut admitted)
            .next()
            .ok_or_else(|| {
                StoreError::Internal("inventory treated corruption as absence".into())
            })?
            .is_err()
    );
    assert_eq!(admitted.used().get(Dimension::BytesDecoded), 1);
    Ok(())
}
