use super::*;
use crate::representation_codec::{decode, inline_encoded_len};
use dcbor::prelude::*;

const LIMITS: RepresentationLimits = RepresentationLimits {
    inline_limit: 64,
    max_components: 4,
};

fn allocation() -> AllocationId {
    AllocationId([3; 16])
}

fn component(seed: &[u8], length: u64) -> Component {
    Component {
        identity: Kappa::sha256(seed),
        length,
    }
}

fn layout(stored: u64, chunk_size: u32, chunk_count: u32) -> ExternalLayout {
    ExternalLayout {
        stored_size: stored,
        chunk_size,
        chunk_count,
        allocation: allocation(),
        publication_id: [5; 32],
        chunk_root: [6; 32],
    }
}

fn external(stored: u64, chunk_size: u32, chunk_count: u32) -> Result<BlobRecord, StoreError> {
    BlobRecord::external(layout(stored, chunk_size, chunk_count), None, LIMITS)
}

#[test]
fn validated_constructors_roundtrip() -> Result<(), StoreError> {
    let inline = BlobRecord::inline(b"small".to_vec(), None, LIMITS)?;
    assert_eq!(decode(inline.canonical())?, inline);
    let empty = BlobRecord::inline(Vec::new(), None, LIMITS)?;
    assert_eq!(decode(empty.canonical())?, empty);
    let big = external(65_537, 65_536, 2)?;
    assert_eq!(decode(big.canonical())?, big);
    assert_eq!(big.total_size(), 65_537);
    let compressed = BlobRecord::external(
        layout(100, 65_536, 1),
        Some(Compression {
            algorithm: "zstd".into(),
            uncompressed_size: 400,
        }),
        LIMITS,
    )?;
    assert_eq!(decode(compressed.canonical())?, compressed);
    assert_eq!(compressed.total_size(), 400);
    assert_eq!(compressed.stored_size(), 100);
    assert_eq!(compressed.compression(), Some("zstd"));
    let inline_compressed = BlobRecord::inline(
        vec![1; 8],
        Some(Compression {
            algorithm: "zstd".into(),
            uncompressed_size: 4_000,
        }),
        LIMITS,
    )?;
    assert_eq!(decode(inline_compressed.canonical())?, inline_compressed);
    assert_eq!(inline_compressed.total_size(), 4_000);
    for leaf_children in [true, false] {
        let composite = BlobRecord::composite(
            vec![component(b"a", 10), component(b"c", 7)],
            leaf_children,
            RepresentationLimits {
                inline_limit: 1024,
                max_components: 4,
            },
        )?;
        assert_eq!(decode(composite.canonical())?, composite);
        assert_eq!(composite.total_size(), 17);
        assert_eq!(composite.leaf_children(), Some(leaf_children));
    }
    Ok(())
}

#[test]
fn format_ceilings_bound_construction_and_configuration() {
    let ceiling = RepresentationLimits {
        inline_limit: MAX_RECORD_BYTES as u64,
        max_components: MAX_COMPONENTS,
    };
    assert!(ceiling.validate().is_ok());
    assert!(
        RepresentationLimits {
            inline_limit: MAX_RECORD_BYTES as u64 + 1,
            max_components: 1,
        }
        .validate()
        .is_err()
    );
    assert!(
        RepresentationLimits {
            inline_limit: 0,
            max_components: 1,
        }
        .validate()
        .is_err()
    );
    assert!(
        RepresentationLimits {
            inline_limit: 1,
            max_components: MAX_COMPONENTS + 1,
        }
        .validate()
        .is_err()
    );
    assert!(matches!(
        BlobRecord::inline(vec![0; MAX_RECORD_BYTES + 1], None, ceiling),
        Err(StoreError::CapacityExceeded(_))
    ));
    // Exactly the ceiling of payload still exceeds it once framed.
    assert!(matches!(
        BlobRecord::inline(vec![0; MAX_RECORD_BYTES], None, ceiling),
        Err(StoreError::CapacityExceeded(_))
    ));
    assert!(
        BlobRecord::external(
            layout(1 << 40, 65_536, 1 << 24),
            Some(Compression {
                algorithm: "x".repeat(MAX_COMPRESSION_NAME + 1),
                uncompressed_size: 1,
            }),
            LIMITS,
        )
        .is_err()
    );
}

/// The inline encoding length is exact at every byte-string argument
/// width, so external selection is the exact complement of inline
/// eligibility.
#[test]
fn inline_encoded_length_is_exact() -> Result<(), StoreError> {
    let generous = RepresentationLimits {
        inline_limit: u64::MAX,
        max_components: 1,
    };
    for size in [0usize, 1, 23, 24, 255, 256, 65_535, 65_536, 70_000] {
        let record = BlobRecord::inline(vec![7; size], None, generous)?;
        assert_eq!(
            inline_encoded_len(size as u64, size as u64, None),
            record.canonical().len() as u64,
            "uncompressed {size}"
        );
        let compression = Some(Compression {
            algorithm: "zstd".into(),
            uncompressed_size: 9_999_999,
        });
        let record = BlobRecord::inline(vec![7; size], compression, generous)?;
        assert_eq!(
            inline_encoded_len(size as u64, 9_999_999, Some("zstd")),
            record.canonical().len() as u64,
            "compressed {size}"
        );
    }
    Ok(())
}

#[test]
fn inline_and_external_partition_by_encoded_size() -> Result<(), Box<dyn std::error::Error>> {
    // Find the largest payload whose encoded inline row fits the limit.
    let mut largest_inline = 0;
    for size in 0..=LIMITS.inline_limit {
        if inline_encoded_len(size, size, None) <= LIMITS.inline_limit {
            largest_inline = size;
        }
    }
    assert!(largest_inline > 0 && largest_inline < LIMITS.inline_limit);
    let largest = usize::try_from(largest_inline)?;
    assert!(BlobRecord::inline(vec![0; largest], None, LIMITS).is_ok());
    assert!(matches!(
        BlobRecord::inline(vec![0; largest + 1], None, LIMITS),
        Err(StoreError::CapacityExceeded(_))
    ));
    assert!(matches!(
        external(largest_inline, 65_536, 1),
        Err(StoreError::Rejected(_))
    ));
    assert!(external(largest_inline + 1, 65_536, 1).is_ok());
    // A compressed representation is selected on its complete record:
    // stored bytes that fit uncompressed may not fit with the compression
    // the record names, and are then external.
    let compression = || {
        Some(Compression {
            algorithm: "zstd".into(),
            uncompressed_size: 1 << 30,
        })
    };
    assert!(matches!(
        BlobRecord::inline(vec![0; largest], compression(), LIMITS),
        Err(StoreError::CapacityExceeded(_))
    ));
    assert!(BlobRecord::external(layout(largest_inline, 65_536, 1), compression(), LIMITS).is_ok());
    Ok(())
}

/// Every stored size, compressed or not, is admitted by exactly one of
/// inline and external: the two representations partition the sizes, with
/// no size refused by both and none admitted by both.
#[test]
fn every_size_is_inline_or_external_never_both_never_neither()
-> Result<(), Box<dyn std::error::Error>> {
    let compressions = [
        None,
        Some(Compression {
            algorithm: "zstd".into(),
            uncompressed_size: 1 << 30,
        }),
    ];
    for compression in compressions {
        for stored in 0..=LIMITS.inline_limit + 8 {
            let inline = BlobRecord::inline(
                vec![0; usize::try_from(stored)?],
                compression.clone(),
                LIMITS,
            );
            let external =
                BlobRecord::external(layout(stored, 65_536, 1), compression.clone(), LIMITS);
            assert!(
                inline.is_ok() != external.is_ok(),
                "{stored} stored bytes, {compression:?}: inline {inline:?}, external {external:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn framing_and_composite_admission_are_enforced_at_construction() {
    // Empty content always encodes inline, so it is never external.
    assert!(matches!(external(0, 16, 1), Err(StoreError::Rejected(_))));
    assert!(external(70_000, 65_536, 2).is_ok());
    assert!(external(70_000, 65_536, 1).is_err());
    assert!(external(70_000, 0, 1).is_err());
    assert!(external(70_000, MAX_CHUNK_SIZE + 1, 1).is_err());
    assert!(
        BlobRecord::external(
            layout(70_000, 65_536, 2),
            Some(Compression {
                algorithm: String::new(),
                uncompressed_size: 1,
            }),
            LIMITS,
        )
        .is_err()
    );
    let roomy = RepresentationLimits {
        inline_limit: 4096,
        max_components: 4,
    };
    assert!(matches!(
        BlobRecord::composite((0..5).map(|i| component(&[i], 1)).collect(), true, roomy),
        Err(StoreError::CapacityExceeded(_))
    ));
    assert!(matches!(
        BlobRecord::composite(Vec::new(), true, roomy),
        Err(StoreError::Rejected(_))
    ));
    assert!(matches!(
        BlobRecord::composite(vec![component(b"a", 0)], true, roomy),
        Err(StoreError::Rejected(_))
    ));
    assert!(
        BlobRecord::composite(
            vec![component(b"a", u64::MAX), component(b"b", 1)],
            true,
            roomy
        )
        .is_err()
    );
    // The descriptor itself is subject to the inline limit.
    assert!(matches!(
        BlobRecord::composite(vec![component(b"a", 1)], true, LIMITS),
        Err(StoreError::CapacityExceeded(_))
    ));
}

/// The CBOR map a record encodes as.
fn map(bytes: &[u8]) -> Result<Map, Box<dyn std::error::Error>> {
    match CBOR::try_from_data(bytes)?.into_case() {
        CBORCase::Map(map) => Ok(map),
        _ => Err("record must be a map".into()),
    }
}

/// A representation entry of `items`.
fn rep(items: Vec<CBOR>) -> CBOR {
    items.into()
}

#[test]
fn malformed_records_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let valid = BlobRecord::inline(b"x".to_vec(), None, LIMITS)?
        .canonical()
        .to_vec();
    let mut unknown = map(&valid)?;
    unknown.insert(9u64, 1u64);
    assert!(decode(&CBOR::from(unknown).to_cbor_data()).is_err());
    let mut mistyped_compression = map(&valid)?;
    mistyped_compression.insert(2u64, 7u64);
    assert!(decode(&CBOR::from(mistyped_compression).to_cbor_data()).is_err());
    let mut empty_compression = map(&valid)?;
    empty_compression.insert(2u64, "");
    assert!(decode(&CBOR::from(empty_compression).to_cbor_data()).is_err());
    let mut bad_shape = map(&valid)?;
    bad_shape.insert(3u64, rep(vec![CBOR::from(7u64)]));
    assert!(decode(&CBOR::from(bad_shape).to_cbor_data()).is_err());
    for (allocation, publication, root) in [(15usize, 32usize, 32usize), (16, 31, 32), (16, 32, 31)]
    {
        let mut widths = map(&valid)?;
        widths.insert(1u64, 70_000u64);
        widths.insert(0u64, 70_000u64);
        widths.insert(
            3u64,
            rep(vec![
                CBOR::from(1u64),
                CBOR::from(ByteString::from(vec![3; allocation])),
                CBOR::from(2u32),
                CBOR::from(65_536u32),
                CBOR::from(ByteString::from(vec![5; publication])),
                CBOR::from(ByteString::from(vec![6; root])),
            ]),
        );
        assert!(
            decode(&CBOR::from(widths).to_cbor_data()).is_err(),
            "{allocation} {publication} {root}"
        );
    }
    let mut inline_length_lie = map(&valid)?;
    inline_length_lie.insert(1u64, 2u64);
    inline_length_lie.insert(0u64, 2u64);
    assert!(decode(&CBOR::from(inline_length_lie).to_cbor_data()).is_err());
    let mut uncompressed_mismatch = map(&valid)?;
    uncompressed_mismatch.insert(0u64, 9u64);
    assert!(decode(&CBOR::from(uncompressed_mismatch).to_cbor_data()).is_err());
    for ends in [
        vec![CBOR::from(5u64), CBOR::from(3u64)],
        vec![CBOR::from(5u64), CBOR::from(5u64)],
        vec![CBOR::from(0u64), CBOR::from(5u64)],
    ] {
        let mut composite = map(&valid)?;
        composite.insert(1u64, 5u64);
        composite.insert(0u64, 5u64);
        composite.insert(
            3u64,
            rep(vec![
                CBOR::from(2u64),
                CBOR::from(vec![
                    CBOR::from(&Kappa::sha256(b"a")),
                    CBOR::from(&Kappa::sha256(b"b")),
                ]),
                CBOR::from(ends),
                CBOR::from(true),
            ]),
        );
        assert!(decode(&CBOR::from(composite).to_cbor_data()).is_err());
    }
    let mut uneven = map(&valid)?;
    uneven.insert(1u64, 5u64);
    uneven.insert(0u64, 5u64);
    uneven.insert(
        3u64,
        rep(vec![
            CBOR::from(2u64),
            CBOR::from(vec![CBOR::from(&Kappa::sha256(b"a"))]),
            CBOR::from(vec![CBOR::from(5u64), CBOR::from(5u64)]),
            CBOR::from(true),
        ]),
    );
    let mut untyped_kind = map(&valid)?;
    untyped_kind.insert(1u64, 5u64);
    untyped_kind.insert(0u64, 5u64);
    untyped_kind.insert(
        3u64,
        rep(vec![
            CBOR::from(2u64),
            CBOR::from(vec![CBOR::from(&Kappa::sha256(b"a"))]),
            CBOR::from(vec![CBOR::from(5u64)]),
            CBOR::from(1u64),
        ]),
    );
    assert!(decode(&CBOR::from(untyped_kind).to_cbor_data()).is_err());
    assert!(decode(&CBOR::from(uneven).to_cbor_data()).is_err());
    assert!(decode(&CBOR::from(1u64).to_cbor_data()).is_err());
    assert!(decode(&vec![0; MAX_RECORD_BYTES + 1]).is_err());
    Ok(())
}

#[test]
fn component_lookup_uses_cumulative_lengths() -> Result<(), StoreError> {
    let roomy = RepresentationLimits {
        inline_limit: 4096,
        max_components: 4,
    };
    let composite =
        BlobRecord::composite(vec![component(b"a", 10), component(b"c", 7)], true, roomy)?;
    let representation = composite.representation();
    assert_eq!(representation.component_at(0), Some((0, 0)));
    assert_eq!(representation.component_at(9), Some((0, 0)));
    assert_eq!(representation.component_at(10), Some((1, 10)));
    assert_eq!(representation.component_at(16), Some((1, 10)));
    assert_eq!(representation.component_at(17), None);
    assert_eq!(
        BlobRecord::inline(Vec::new(), None, LIMITS)?
            .representation()
            .component_at(0),
        None
    );
    Ok(())
}

#[test]
fn allocation_hex_roundtrip_and_canonical_form() -> Result<(), StoreError> {
    let id = AllocationId::generate()?;
    assert_eq!(AllocationId::parse_hex(&id.hex()), Some(id));
    assert_eq!(AllocationId::parse_hex("zz"), None);
    assert_eq!(AllocationId::parse_hex("00"), None);
    assert_eq!(AllocationId::parse_hex(&id.hex().to_uppercase()), None);
    assert_eq!(AllocationId::parse_hex(&format!("{}0", id.hex())), None);
    Ok(())
}
