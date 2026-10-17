//! Fixed vectors generated independently with Python hashlib and integers.
use kappa_types::StateDigest;

#[test]
fn independently_generated_leaf_and_sum_vectors() {
    let vectors: &[(&[u8], &[u8], &str)] = &[
        (
            b"",
            b"",
            "e3f6ee3c3c028148e825e8dcb49d568168d04b711d0daa64fa8f126bdb88ae89",
        ),
        (
            b"a",
            b"b",
            "f138c9c41863d88a762ef0808327f5091d0cfec81c8ee4a800a2edab28423d8f",
        ),
        (
            b"a=b",
            b"c",
            "55f4966087f3ac9b47d5fd8be85dfd893c570989d692423b89f621acf8091f0c",
        ),
        (
            b"a",
            b"b=c",
            "bd15fa1d341065f5f0b5b7eac9f7e919ef577b5833f123d784462d69c50e2909",
        ),
        (
            b"\x00\xff",
            b"\xff\x00",
            "fc52dd2083336c18a0a4acaa0ca8801271f24f962de6350f9802890325cd0e6c",
        ),
    ];
    let mut sum = StateDigest::default();
    for &(name, value, expected) in vectors {
        let mut leaf = StateDigest::default();
        leaf.insert_raw(name, value);
        assert_eq!(hex::encode(leaf.as_bytes()), expected);
        sum.merge(leaf);
    }
    assert_eq!(
        hex::encode(sum.as_bytes()),
        "e28c26a1939cd77c37843a7ff7c2b341227e1eb271052b2fa171d82fe7b0429a"
    );
    for &(name, value, _) in vectors {
        sum.remove_raw(name, value);
    }
    assert_eq!(sum, StateDigest::default());
}

#[test]
fn duplicate_leaf_preserves_multiplicity_with_modular_carry() {
    let mut digest = StateDigest::default();
    digest.insert_raw(b"a", b"b");
    digest.insert_raw(b"a", b"b");
    assert_eq!(
        hex::encode(digest.as_bytes()),
        "e271928931c6b015ed5ce001074fea133a18fc91391cc9510144db5751847a1e"
    );
    digest.remove_raw(b"a", b"b");
    assert_eq!(
        hex::encode(digest.as_bytes()),
        "f138c9c41863d88a762ef0808327f5091d0cfec81c8ee4a800a2edab28423d8f"
    );
}
