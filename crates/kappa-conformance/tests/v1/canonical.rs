use dcbor::prelude::*;
use kappa_store::canonical::{canonical_bytes, from_canonical};

#[test]
fn integer_roundtrip() {
    let bytes = canonical_bytes(&42u64);
    let decoded: u64 = from_canonical(&bytes).unwrap();
    assert_eq!(decoded, 42);
}

#[test]
fn string_roundtrip() {
    let bytes = canonical_bytes(&"hello".to_string());
    let decoded: String = from_canonical(&bytes).unwrap();
    assert_eq!(decoded, "hello");
}

#[test]
fn deterministic() {
    let a = canonical_bytes(&"same".to_string());
    let b = canonical_bytes(&"same".to_string());
    assert_eq!(a, b);
}

#[test]
fn different_values_different_bytes() {
    let a = canonical_bytes(&"one".to_string());
    let b = canonical_bytes(&"two".to_string());
    assert_ne!(a, b);
}

#[test]
fn rejects_non_canonical_integer() {
    // 0x1900ff encodes 255 in 3 bytes; canonical dCBOR is 0x18ff (2 bytes)
    let non_canonical: &[u8] = &[0x19, 0x00, 0xff];
    assert!(CBOR::try_from_data(non_canonical).is_err());
}

#[test]
fn rejects_empty_input() {
    let result: Result<u64, _> = from_canonical(&[]);
    assert!(result.is_err());
}

#[test]
fn bool_roundtrip() {
    let bytes = canonical_bytes(&true);
    let decoded: bool = from_canonical(&bytes).unwrap();
    assert!(decoded);
}

#[test]
fn negative_integer_decodes_distinctly_from_unsigned() {
    // dCBOR major type 1 (negative -1, wire byte 0x20) and major type 0
    // (unsigned 0, wire byte 0x00) must not produce the same u64 value.
    // The dcbor crate may accept or reject negative-to-u64 depending on
    // version. Either outcome is valid as long as it is deterministic
    // and does not silently alias a valid unsigned value.
    let neg: &[u8] = &[0x20]; // -1 in CBOR
    let zero: &[u8] = &[0x00]; // 0 in CBOR
    let neg_result: Result<u64, _> = from_canonical(neg);
    let zero_result: Result<u64, _> = from_canonical(zero);
    match neg_result {
        Err(_) => {} // rejection is valid
        Ok(neg_val) => {
            // acceptance is valid only if the value differs from 0
            let zero_val = zero_result.expect("unsigned 0 must decode");
            assert_ne!(
                neg_val, zero_val,
                "negative and unsigned must not alias the same u64"
            );
        }
    }
}

#[test]
fn large_integer_roundtrip() {
    let val: u64 = u64::MAX;
    let bytes = canonical_bytes(&val);
    let decoded: u64 = from_canonical(&bytes).unwrap();
    assert_eq!(decoded, val);
}

#[test]
fn empty_string_roundtrip() {
    let bytes = canonical_bytes(&String::new());
    let decoded: String = from_canonical(&bytes).unwrap();
    assert_eq!(decoded, "");
}
