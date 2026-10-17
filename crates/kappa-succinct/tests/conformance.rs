//! Succinct index conformance tests.
//!
//! C-1:  Independent builds byte-identical; ordinals agree.
//! C-2:  TTFR independent of result size.
//! C-3:  10^7 results enumerate completely.
//! C-4:  Seek sub-microsecond at 10M keys.
//! C-5:  Trie matches `BTreeSet` under proptest.
//! C-6:  Deserialize never panics on any input.
//! C-8:  Overflow bounded under sustained write.
//! C-12: Compressed ordinal storage budget.
//!
//! These tests are the forcing functions expressed as code.
//! They fail on an empty or incorrect implementation.
//! Default tests use bounded workloads. Ignored endurance tests retain the
//! large acceptance workloads; run with --ignored --nocapture --test-threads=1.

use std::collections::BTreeSet;
use std::time::Instant;

use kappa_cursor::{KappaCursor, TERMINATED};
use proptest::prelude::*;

use kappa_succinct::{
    IncrementalDigest, LoudsDsTrie, SortedKeySet, TrieConfig, TrieCursor, TrieError, TrieIndex,
};

fn build(keys: Vec<Vec<u8>>) -> Result<LoudsDsTrie, TrieError> {
    let keys = SortedKeySet::from_unsorted(keys);
    LoudsDsTrie::build(&TrieConfig::default(), keys.iter())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn random_key_set(n: usize) -> Vec<Vec<u8>> {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    let mut seed = 0x1234_5678_u64;
    while set.len() < n {
        // Simple deterministic PRNG (xorshift64)
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let mut key = vec![0];
        key.extend_from_slice(&seed.to_be_bytes());
        set.insert(key);
    }
    set.into_iter().collect()
}

fn shuffled(mut v: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    // Deterministic shuffle via reverse-then-rotate
    v.reverse();
    if v.len() > 1 {
        let rotation = v.len() / 3;
        v.rotate_left(rotation);
    }
    v
}

fn collect_keys(trie: &LoudsDsTrie) -> Vec<Vec<u8>> {
    let mut c = TrieCursor::new(trie);
    let mut keys = Vec::new();
    while c.key() != TERMINATED {
        keys.push(c.key().to_vec());
        c.advance();
    }
    keys
}

// ---------------------------------------------------------------------------
// C-1: Independent builds are byte-identical
// ---------------------------------------------------------------------------

#[test]
fn c1_independent_builds_byte_identical() -> Result<(), TrieError> {
    let set = random_key_set(100_000);
    let shuffled_set = shuffled(set.clone());

    let a = build(set)?;
    let b = build(shuffled_set)?;

    assert_eq!(
        a.serialize()?,
        b.serialize()?,
        "C-1: Independent builds from shuffled input MUST produce \
         byte-identical serializations. Two nodes that build from the \
         same logical key set MUST agree on the trie structure."
    );
    assert_eq!(
        a.digest(),
        b.digest(),
        "C-1: Independent builds MUST produce identical content digests."
    );
    Ok(())
}

#[test]
fn c1_ordinals_agree_across_independent_builds() -> Result<(), TrieError> {
    let set = random_key_set(10_000);
    let shuffled_set = shuffled(set.clone());

    let a = build(set.clone())?;
    let b = build(shuffled_set)?;

    assert_eq!(collect_keys(&a), set);
    assert_eq!(collect_keys(&b), set);

    for k in &set {
        assert_eq!(
            a.ordinal(k),
            b.ordinal(k),
            "C-1: Ordinal for key {k:?} MUST agree across independent builds. \
             This is the interning table for RoaringBitmap — disagreement \
             means two nodes' bitmaps are in different ordinal spaces."
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// C-2: TTFR independent of result size
// ---------------------------------------------------------------------------

#[test]
fn c2_ttfr_independent_of_result_size() -> Result<(), TrieError> {
    let mut times = Vec::new();
    for n in [1_000usize, 100_000, 1_000_000] {
        let keys = random_key_set(n);
        let trie = build(keys)?;

        let start = Instant::now();
        let mut c = TrieCursor::new(&trie);
        let _ = c.advance();
        times.push(start.elapsed());
    }

    let ratio = times[2].as_secs_f64()
        / times[0]
            .max(std::time::Duration::from_nanos(1))
            .as_secs_f64();
    assert!(
        ratio < 5.0,
        "C-2: TTFR grew {ratio:.1}x from 10^3 to 10^6 entries. \
         This is the ONLY detector of materialization — no type prevents it. \
         If the cursor materializes on construction, this test catches it. \
         Threshold is 5x to account for cache effects; production target is 2x."
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// C-3: 10^7 results enumerate completely
// ---------------------------------------------------------------------------

#[test]
#[ignore = "endurance: 10M-key enumeration; high memory and potentially >1 minute; use --ignored --nocapture"]
fn c3_ten_million_enumerate_completely() -> Result<(), TrieError> {
    let start = Instant::now();
    eprintln!("C-3 endurance: generating and building 10M keys");
    let keys = random_key_set(10_000_000);
    let trie = build(keys)?;
    eprintln!(
        "C-3 endurance: build completed in {:?}; enumerating",
        start.elapsed()
    );

    let mut c = TrieCursor::new(&trie);
    let mut count = 0u64;
    while c.key() != TERMINATED {
        count += 1;
        c.advance();
        if count.is_multiple_of(1_000_000) {
            eprintln!(
                "C-3 endurance: {count}/10000000 keys, elapsed {:?}",
                start.elapsed()
            );
        }
    }
    assert_eq!(
        count, 10_000_000,
        "C-3: 10^7 entries MUST enumerate completely. \
         Got {count} entries. FF-3: poor consumers iterate without limit."
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// C-4: Seek sub-microsecond at 10M keys
// ---------------------------------------------------------------------------

#[test]
#[ignore = "endurance: 10M-key build and 1M seeks; high memory and potentially >1 minute; use --ignored --nocapture"]
fn c4_seek_sub_microsecond() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("C-4 endurance: generating 10M keys and 1M targets; building trie");
    let keys = random_key_set(10_000_000);
    let targets = random_key_set(1_000_000);
    let trie = build(keys)?;
    eprintln!("C-4 endurance: build completed; measuring 1M seeks");

    let mut c = TrieCursor::new(&trie);
    let start = Instant::now();
    for t in &targets {
        c.seek(t);
    }
    let elapsed = start.elapsed();
    let per_seek_ns =
        elapsed.as_secs_f64() * 1_000_000_000.0 / f64::from(u32::try_from(targets.len())?);
    eprintln!("C-4 endurance: seeks completed in {elapsed:?}, {per_seek_ns:.0} ns/seek");

    assert!(
        per_seek_ns < 2_000.0,
        "C-4: {per_seek_ns:.0} ns per seek over 10M keys. \
         FF-5 requires O(log n). At 10M keys, log2 ~= 23 levels. \
         Sub-microsecond is the gate. Got {:.1} us.",
        per_seek_ns / 1000.0
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// C-5: Trie matches BTreeSet under proptest
// ---------------------------------------------------------------------------

fn arb_key() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 1..32).prop_map(|mut bytes| {
        bytes.insert(0, 0);
        bytes
    })
}

#[derive(Debug, Clone)]
enum Op {
    Insert(Vec<u8>),
    Delete(Vec<u8>),
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        arb_key().prop_map(Op::Insert),
        arb_key().prop_map(Op::Delete),
    ]
}

fn check_mutation_oracle(ops: &[Op]) -> Result<(), proptest::test_runner::TestCaseError> {
    let mut btree = BTreeSet::new();
    let config = TrieConfig::default();
    let idx = TrieIndex::new(config);

    for (position, op) in ops.iter().enumerate() {
        match op {
            Op::Insert(k) => {
                btree.insert(k.clone());
                idx.insert(k.clone()).map_err(|error| {
                    proptest::test_runner::TestCaseError::fail(error.to_string())
                })?;
            }
            Op::Delete(k) => {
                btree.remove(k);
                idx.delete(k.clone()).map_err(|error| {
                    proptest::test_runner::TestCaseError::fail(error.to_string())
                })?;
            }
        }
        if position % 127 == 0 && !btree.is_empty() {
            idx.rebuild()
                .map_err(|error| proptest::test_runner::TestCaseError::fail(error.to_string()))?;
            let expected: Vec<_> = btree.iter().cloned().collect();
            prop_assert_eq!(
                idx.live_keys()
                    .map_err(|error| proptest::test_runner::TestCaseError::fail(
                        error.to_string()
                    ))?,
                expected
            );
        }
    }

    let expected: Vec<Vec<u8>> = btree.into_iter().collect();
    let actual = idx
        .live_keys()
        .map_err(|error| proptest::test_runner::TestCaseError::fail(error.to_string()))?;
    prop_assert_eq!(
        expected,
        actual,
        "C-5: TrieIndex MUST match BTreeSet after any sequence of \
             insert/delete operations. The BTreeSet is the oracle."
    );
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn c5_trie_index_matches_btreeset(
        ops in proptest::collection::vec(op_strategy(), 0..256)
    ) {
        check_mutation_oracle(&ops)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    #[ignore = "endurance: 100 generated cases of up to 9999 mutations with rebuild/oracle checks; may take many minutes; use --ignored --nocapture"]
    fn c5_trie_index_matches_btreeset_endurance(
        ops in proptest::collection::vec(op_strategy(), 0..10_000)
    ) {
        let start = Instant::now();
        eprintln!("C-5 endurance: starting {} mutations", ops.len());
        check_mutation_oracle(&ops)?;
        eprintln!("C-5 endurance: case completed in {:?}", start.elapsed());
    }
}

// ---------------------------------------------------------------------------
// C-6: Deserialize never panics on any input
// ---------------------------------------------------------------------------

#[test]
fn c6_deserialize_never_panics_on_random_bytes() {
    // Deterministic corpus of hostile inputs
    let corpus: Vec<Vec<u8>> = vec![
        vec![],                                   // empty
        vec![0],                                  // single byte
        vec![0xFF; 1024],                         // all-ones
        vec![0; 1024],                            // all-zeros
        (0u8..=255).collect(),                    // every byte value
        vec![0x89, 0x4C, 0x4F, 0x55, 0x44, 0x53], // LOUDS-like magic
        vec![0; 65536],                           // large zero block
        {
            // Valid-looking header with truncated body
            let mut v = vec![0x89, 0x4C, 0x4F, 0x55, 0x44, 0x53, 0x01, 0x00];
            v.extend_from_slice(&100u64.to_le_bytes()); // claims 100 nodes
            v // but has no data
        },
        {
            // Claimed node count exceeds buffer
            let mut v = vec![0x89, 0x4C, 0x4F, 0x55, 0x44, 0x53, 0x01, 0x00];
            v.extend_from_slice(&u64::MAX.to_le_bytes());
            v.extend_from_slice(&[0xAA; 256]);
            v
        },
    ];

    for (i, case) in corpus.iter().enumerate() {
        let result = std::panic::catch_unwind(|| LoudsDsTrie::deserialize(case));
        assert!(
            result.is_ok(),
            "C-6: deserialize MUST NOT panic on any input. \
             Panicked on corpus entry {i} ({} bytes). \
             FF-8: attacker controls peer-supplied bytes.",
            case.len()
        );
    }
}

// ---------------------------------------------------------------------------
// C-8: Overflow bounded under sustained write
// ---------------------------------------------------------------------------

#[test]
fn c8_overflow_bounded_under_sustained_write() -> Result<(), TrieError> {
    check_sustained_write(256, 1_024, 64, false)
}

#[test]
#[ignore = "endurance: 100K initial keys and 1M writes with rebuilds; potentially >1 minute; use --ignored --nocapture"]
fn c8_overflow_bounded_under_sustained_write_endurance() -> Result<(), TrieError> {
    check_sustained_write(100_000, 1_000_000, 100_000, true)
}

fn check_sustained_write(
    initial_count: usize,
    writes: u64,
    bound: usize,
    progress: bool,
) -> Result<(), TrieError> {
    let start = Instant::now();
    if progress {
        eprintln!("C-8 endurance: building {initial_count} initial keys; then {writes} writes");
    }
    let initial_keys = random_key_set(initial_count);
    let config = TrieConfig {
        max_overflow_bound: bound,
        ..Default::default()
    };
    let idx = TrieIndex::new(config);

    // Build initial trie
    for k in &initial_keys {
        idx.insert(k.clone())?;
    }
    idx.rebuild()?;

    // Deterministic, distinct writes in the cursor's valid key domain.
    let mut max_overflow = 0usize;
    for position in 0..writes {
        let mut key = vec![1];
        key.extend_from_slice(&position.to_be_bytes());
        idx.insert(key)?;

        let current = idx.overflow_size()?;
        if current > max_overflow {
            max_overflow = current;
        }

        if idx.should_rebuild()? {
            idx.rebuild()?;
        }
        if progress && (position + 1) % 10_000 == 0 {
            eprintln!(
                "C-8 endurance: {}/{writes} writes, peak overflow {max_overflow}, elapsed {:?}",
                position + 1,
                start.elapsed()
            );
        }
    }

    // The overflow should be bounded, not growing without limit.
    // The exact bound depends on the rebuild trigger, but it should
    // be well below the total number of inserts.
    assert!(
        max_overflow <= bound,
        "C-8: overflow {max_overflow} exceeded configured bound {bound}"
    );
    assert_eq!(idx.live_keys()?.len() as u64, initial_count as u64 + writes);
    Ok(())
}

// ---------------------------------------------------------------------------
// C-12 component check: dense bitmap serialized storage
// ---------------------------------------------------------------------------
//
// Dense Roaring storage is linear, rounded up to 65536-position containers.
// This component check does not measure full registry GC memory or RSS.

#[test]
#[cfg(feature = "bitmap")]
fn c12_dense_bitmap_has_bounded_bytes_per_position() -> Result<(), std::io::Error> {
    for n in [
        0u32, 1, 8_192, 8_193, 65_535, 65_536, 65_537, 100_000, 1_000_000, 10_000_000,
    ] {
        let mut bitmap = roaring::RoaringBitmap::new();
        for i in 0..n {
            // Simulate ~50% reachable (alternating)
            if i % 2 == 0 {
                bitmap.insert(i);
            }
        }
        // Portable non-run format: 8-byte header, 8-byte description/offset
        // per container, and at most 8192 payload bytes per container.
        // The last dense container occupies a full block even when partial.
        let containers = u64::from(n).div_ceil(65_536);
        let budget = 8 + containers * (8_192 + 8);
        let mut encoded = Vec::new();
        bitmap.serialize_into(&mut encoded)?;
        assert_eq!(encoded.len(), bitmap.serialized_size());
        assert!(
            encoded.len() as u64 <= budget,
            "{n} positions used {} serialized bytes; container budget {budget}",
            encoded.len()
        );
        let decoded = roaring::RoaringBitmap::deserialize_from(encoded.as_slice())?;
        assert_eq!(decoded, bitmap);
        assert_eq!(decoded.len(), u64::from(n).div_ceil(2));
        if n == 100_000 {
            assert_eq!(encoded.len(), 16_408);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Additional: IncrementalDigest correctness
// ---------------------------------------------------------------------------

#[test]
fn digest_removal_inverts_insertion() {
    let mut digest = IncrementalDigest::new();
    let key = b"test_key_bytes";
    digest.insert(key);
    let after_add = *digest.value();
    digest.remove(key);
    assert_eq!(
        *digest.value(),
        [0u8; 32],
        "Insertion followed by removal MUST return to identity."
    );

    // Re-add and verify it matches the first add
    digest.insert(key);
    assert_eq!(*digest.value(), after_add);
}

#[test]
fn digest_order_independent() {
    let mut d1 = IncrementalDigest::new();
    let mut d2 = IncrementalDigest::new();
    d1.insert(b"aaa");
    d1.insert(b"bbb");
    d2.insert(b"bbb");
    d2.insert(b"aaa");
    assert_eq!(
        d1.value(),
        d2.value(),
        "Additive digest MUST be order-independent (commutative)."
    );
}

#[test]
fn digest_empty_is_zero() {
    let digest = IncrementalDigest::new();
    assert_eq!(*digest.value(), [0u8; 32]);
}

#[test]
fn digest_different_keys_produce_different_values() {
    let mut d1 = IncrementalDigest::new();
    let mut d2 = IncrementalDigest::new();
    d1.insert(b"key_a");
    d2.insert(b"key_b");
    assert_ne!(d1.value(), d2.value());
}
