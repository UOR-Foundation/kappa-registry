use kappa_types::kappa::{Kappa, KappaParseError};

#[test]
fn key_anchor_preserves_canonical_u16_framing() -> Result<(), KappaParseError> {
    let mut framed = vec![0, 7];
    framed.extend_from_slice(b"ed25519");
    framed.extend_from_slice(&[0, 32]);
    framed.extend_from_slice(&[42; 32]);
    assert_eq!(
        Kappa::from_key("ed25519", &[42; 32])?,
        Kappa::sha256(&framed)
    );
    Ok(())
}

#[test]
fn framing_accepts_the_boundary_and_rejects_each_oversized_field() -> Result<(), KappaParseError> {
    let algorithm = "a".repeat(usize::from(u16::MAX));
    let key = vec![7; usize::from(u16::MAX)];
    Kappa::from_key(&algorithm, &key)?;
    let oversized_algorithm = format!("{algorithm}a");
    assert!(matches!(
        Kappa::from_key(&oversized_algorithm, &key),
        Err(KappaParseError::KeyFramingLength {
            field: "algorithm",
            length: 65_536
        })
    ));
    let oversized_key = vec![7; 65_536];
    assert!(matches!(
        Kappa::from_key("ed25519", &oversized_key),
        Err(KappaParseError::KeyFramingLength {
            field: "public_key",
            length: 65_536
        })
    ));
    Ok(())
}
