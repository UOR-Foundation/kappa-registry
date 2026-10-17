use std::sync::Arc;

use super::*;

fn budget(limit: usize) -> Arc<DeltaBudget> {
    Arc::new(DeltaBudget::new(limit))
}

fn apply(base: &[u8], delta: &[u8]) -> Result<Vec<u8>, DeltaError> {
    apply_delta(base, delta, usize::MAX, &budget(usize::MAX)).map(|(out, _)| out)
}

#[test]
fn varint_maximum_roundtrips_and_high_payload_overflow_is_rejected() -> Result<(), DeltaError> {
    let mut encoded = Vec::new();
    encode_varint(usize::MAX, &mut encoded);
    assert_eq!(decode_varint(&encoded, &mut 0)?, usize::MAX);
    let last = encoded.len() - 1;
    encoded[last] = 0x7f;
    assert!(matches!(
        decode_varint(&encoded, &mut 0),
        Err(DeltaError::VarintOverflow)
    ));
    Ok(())
}

#[test]
fn copy_larger_than_wire_size_is_split_without_truncation() -> Result<(), DeltaError> {
    let base = vec![42; 0x100_0000];
    let mut encoded = Vec::new();
    encode_varint(base.len(), &mut encoded);
    encode_varint(base.len(), &mut encoded);
    assert_eq!(emit_copy(&mut encoded, 0, base.len()), Some(()));
    assert_eq!(apply(&base, &encoded)?, base);
    let mut at_boundary = Vec::new();
    encode_varint(base.len(), &mut at_boundary);
    encode_varint(0x10000, &mut at_boundary);
    assert_eq!(emit_copy(&mut at_boundary, 0, 0x10000), Some(()));
    assert_eq!(apply(&base, &at_boundary)?.len(), 0x10000);
    Ok(())
}

#[test]
fn unrepresentable_offsets_decline_instead_of_truncating() -> Result<(), std::num::TryFromIntError>
{
    let mut out = Vec::new();
    let beyond_wire = usize::try_from(u64::from(u32::MAX) + 1)?;
    assert_eq!(emit_copy(&mut out, beyond_wire, 16), None);
    assert!(out.is_empty());
    assert_eq!(
        emit_copy(&mut out, usize::try_from(u32::MAX)?, 16),
        Some(())
    );
    Ok(())
}

#[test]
fn a_declared_size_past_the_limit_is_refused_before_allocation() {
    let mut delta = Vec::new();
    encode_varint(0, &mut delta);
    encode_varint(usize::MAX, &mut delta);
    assert!(matches!(
        apply_delta(b"", &delta, 1024, &budget(usize::MAX)),
        Err(DeltaError::ResultTooLarge {
            declared: usize::MAX,
            limit: 1024
        })
    ));
    let mut within = Vec::new();
    encode_varint(0, &mut within);
    encode_varint(100, &mut within);
    assert!(matches!(
        apply_delta(b"", &within, 1024, &budget(50)),
        Err(DeltaError::BudgetExhausted {
            requested: 100,
            available: 50
        })
    ));
}

#[test]
fn instructions_cannot_grow_the_result_past_its_declaration() {
    // Declares 3 bytes, inserts 5.
    let mut delta = Vec::new();
    encode_varint(0, &mut delta);
    encode_varint(3, &mut delta);
    delta.push(5);
    delta.extend_from_slice(b"hello");
    assert!(matches!(
        apply(b"", &delta),
        Err(DeltaError::ResultOverrun { declared: 3 })
    ));
    // Declares 3 bytes, copies 0x10000 (the zero-size encoding).
    let base = vec![1u8; 0x10000];
    let mut copy = Vec::new();
    encode_varint(base.len(), &mut copy);
    encode_varint(3, &mut copy);
    copy.push(0x80);
    assert!(matches!(
        apply(&base, &copy),
        Err(DeltaError::ResultOverrun { declared: 3 })
    ));
    // A short result is a mismatch, not an acceptance.
    let mut short = Vec::new();
    encode_varint(0, &mut short);
    encode_varint(4, &mut short);
    short.push(2);
    short.extend_from_slice(b"hi");
    assert!(matches!(
        apply(b"", &short),
        Err(DeltaError::ResultSizeMismatch {
            expected: 4,
            got: 2
        })
    ));
}

#[test]
fn copies_past_the_base_are_refused_without_overflow() {
    let base = b"short";
    let mut delta = Vec::new();
    encode_varint(base.len(), &mut delta);
    encode_varint(10, &mut delta);
    delta.extend_from_slice(&[0x80 | 0x01 | 0x10, 0, 10]);
    assert!(matches!(
        apply(base, &delta),
        Err(DeltaError::CopyOutOfBounds { .. })
    ));
    let mut overflowing = Vec::new();
    encode_varint(base.len(), &mut overflowing);
    encode_varint(1, &mut overflowing);
    overflowing.extend_from_slice(&[0x80 | 0x0f | 0x70, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    assert!(matches!(
        apply(base, &overflowing),
        Err(DeltaError::CopyOutOfBounds { .. })
    ));
}

#[test]
fn the_budget_is_held_by_the_result_and_shared_across_decodes() -> Result<(), DeltaError> {
    let shared = budget(10);
    let mut delta = Vec::new();
    encode_varint(0, &mut delta);
    encode_varint(6, &mut delta);
    delta.push(6);
    delta.extend_from_slice(b"abcdef");
    let (first, held) = apply_delta(b"", &delta, 100, &shared)?;
    assert_eq!(first, b"abcdef");
    assert_eq!(shared.used(), 6);
    assert!(matches!(
        apply_delta(b"", &delta, 100, &shared),
        Err(DeltaError::BudgetExhausted {
            requested: 6,
            available: 4
        })
    ));
    drop(held);
    assert_eq!(shared.used(), 0);
    let (_, mut again) = apply_delta(b"", &delta, 100, &shared)?;
    again.grow(4)?;
    assert_eq!(again.bytes(), 10);
    assert!(again.grow(1).is_err());
    drop(again);
    assert_eq!(shared.used(), 0);
    Ok(())
}

#[test]
fn roundtrip_and_identical_input_compress() -> Result<(), DeltaError> {
    let base = b"the quick brown fox jumps over the lazy dog and more text to exceed the window size threshold";
    let target = b"the quick brown cat jumps over the lazy dog and more text to exceed the window size threshold";
    let (delta, stats) =
        compute_delta_with_stats(base, target).ok_or(DeltaError::Truncated("declined"))?;
    assert!(delta.len() < target.len());
    assert!(!stats.budget_exhausted);
    assert!(stats.copied_bytes > target.len() / 2);
    assert_eq!(apply(base, &delta)?, target);
    let delta = compute_delta(base, base).ok_or(DeltaError::Truncated("declined"))?;
    assert!(delta.len() < 30);
    assert_eq!(apply(base, &delta)?, base);
    assert!(compute_delta(b"hi", b"yo").is_none());
    assert!(compute_delta(b"", b"hello").is_none());
    Ok(())
}

#[test]
fn repetitive_input_is_bounded_in_work_and_still_compresses() -> Result<(), DeltaError> {
    // Every window of the base has the same fingerprint: an unbounded
    // matcher compares every candidate at every position.
    let base = vec![b'a'; 64 * 1024];
    let mut target = base.clone();
    target.extend_from_slice(b"tail that differs");
    let (delta, stats) =
        compute_delta_with_stats(&base, &target).ok_or(DeltaError::Truncated("declined"))?;
    let work_limit = (base.len() + target.len()) * WORK_FACTOR;
    assert!(
        stats.compared_bytes <= work_limit + target.len(),
        "{stats:?} exceeded the work budget"
    );
    assert!(stats.candidates_examined <= HASH_LIMIT * target.len());
    assert!(
        delta.len() < target.len() / 100,
        "delta {} of {}",
        delta.len(),
        target.len()
    );
    assert_eq!(apply(&base, &delta)?, target);
    // Adversarial: the target repeats a block the base holds everywhere,
    // interleaved so no long match exists; the budget ends extension and
    // the literal fallback keeps the delta valid.
    let mut adversarial = Vec::new();
    for i in 0..4096u32 {
        adversarial.extend_from_slice(&[b'a'; 16]);
        adversarial.extend_from_slice(&i.to_le_bytes());
    }
    if let Some((delta, stats)) = compute_delta_with_stats(&base, &adversarial) {
        assert!(stats.compared_bytes <= work_limit + adversarial.len());
        assert_eq!(apply(&base, &delta)?, adversarial);
    }
    Ok(())
}

#[test]
fn index_keeps_evenly_spaced_positions_per_fingerprint() {
    let base = vec![b'z'; 4096];
    let index = build_index(&base);
    let positions = index.values().next().map_or(0, Vec::len);
    assert!(positions <= HASH_LIMIT, "{positions} positions kept");
    assert!(positions >= HASH_LIMIT / 2, "{positions} positions kept");
    let last = index
        .values()
        .next()
        .and_then(|p| p.last().copied())
        .unwrap_or(0);
    assert!(last > base.len() / 2, "kept positions do not span the base");
}
